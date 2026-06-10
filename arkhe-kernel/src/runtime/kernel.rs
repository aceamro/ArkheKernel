//! `Kernel` — top-level orchestrator.
//!
//! Step path: `pop_due → deserialize → compute → authorize → dispatch
//! → apply_stage → digest → observer.deliver → signal router`. Per-instance
//! step ordering is `InstanceId` ascending (A23).
//!
//! Under the Canonical Input Log model the kernel emits exactly two record
//! kinds: a `Submit` when an external action is admitted ([`Kernel::submit`])
//! and one `Step` per pop ([`Kernel::step`]). Every deterministic effect —
//! child schedules, cross-instance signal routing, internal ids — is left
//! unlogged and re-derived on replay by re-executing `compute()`.

use std::collections::BTreeMap;

use crate::abi::{ArkheError, CapabilityMask, EntityId, InstanceId, Principal, Tick, TypeCode};
use crate::state::authz::{authorize, effective_caps};
use crate::state::{
    Action, ActionContext, Effect, InboundSignal, Instance, InstanceConfig, ScheduledActionId,
    Unverified,
};

use super::apply::apply_stage;
use super::dispatch::dispatch;
use super::event::{KernelEvent, ObserverHandle, SignalDropReason};
use super::observer::{KernelObserver, ObserverRegistry};
use super::registry::ActionRegistry;
use super::stage::{PendingSignal, StepStage};

use crate::persist::{SkipReason, StepVerdict, Wal, WalWriter};

/// Top-level kernel orchestrator.
///
/// Lifecycle: [`Kernel::new`] (or [`Kernel::new_with_wal`] /
/// [`Kernel::new_with_wal_signed`]) → [`register_action`](Kernel::register_action)
/// → [`create_instance`](Kernel::create_instance) →
/// [`submit`](Kernel::submit) → [`step`](Kernel::step) (repeat) →
/// optional [`snapshot`](Kernel::snapshot) / [`export_wal`](Kernel::export_wal).
///
/// `Kernel` is `!Sync` (A2 single-thread) and is owned by the caller —
/// no internal locking, no async. All determinism guarantees depend on
/// the caller driving a single kernel from one thread.
pub struct Kernel {
    instances: BTreeMap<InstanceId, Instance>,
    action_registry: ActionRegistry,
    observers: ObserverRegistry,
    next_instance_id: u64,
    /// The kernel's declared `ModuleManifest` digest (A14). Pinned in any
    /// attached WAL's header and checked by `replay_into` against the WAL it
    /// replays — closing the otherwise-vacuous default-path manifest gate.
    /// `[0u8; 32]` for a kernel constructed without one.
    manifest_digest: [u8; 32],
    wal: Option<WalWriter>,
    /// Per-step staging scratch, reused across actions to avoid reallocating
    /// the `StepStage` buckets every step. `clear()`ed before each action;
    /// never serialized (not part of `KernelSnapshot`) and never read across
    /// `step()` calls, so it carries no observable state.
    step_scratch: StepStage,
}

/// Aggregated counters returned by [`Kernel::step`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StepReport {
    /// Number of scheduled actions whose `compute()` ran this step.
    pub actions_executed: u32,
    /// Number of effects (Ops) that committed.
    pub effects_applied: u32,
    /// Number of effects denied (authorize-deny or budget-deny).
    pub effects_denied: u32,
    /// Number of observers newly evicted (first-panic).
    pub observers_evicted: u32,
    /// Number of `KernelEvent::DomainEventEmitted` events produced.
    pub domain_events_emitted: u32,
}

/// Cross-instance aggregate observability returned by [`Kernel::stats`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Total instances currently alive.
    pub instance_count: usize,
    /// Total scheduled actions pending across all instances.
    pub scheduled_action_count: usize,
    /// Total entities across all instances.
    pub entity_count: u32,
    /// Total component bytes across all ledgers.
    pub component_byte_count: u64,
    /// Live observer count (pre-eviction).
    pub observer_count: usize,
    /// WAL record count; `0` if no WAL is attached.
    pub wal_record_count: usize,
}

impl Default for Kernel {
    fn default() -> Self {
        Self::new()
    }
}

impl Kernel {
    /// Construct a fresh kernel with no instances, no observers, and
    /// no WAL. Use [`new_with_wal`](Kernel::new_with_wal) or
    /// [`new_with_wal_signed`](Kernel::new_with_wal_signed) instead if
    /// you want WAL recording from step zero.
    pub fn new() -> Self {
        Self {
            instances: BTreeMap::new(),
            action_registry: ActionRegistry::new(),
            observers: ObserverRegistry::new(),
            next_instance_id: 0,
            manifest_digest: [0u8; 32],
            wal: None,
            step_scratch: StepStage::default(),
        }
    }

    /// Construct a Kernel with an attached WAL writer. Each successfully
    /// committed step appends one record (A13/A14).
    pub fn new_with_wal(world_id: [u8; 32], manifest_digest: [u8; 32]) -> Self {
        Self {
            instances: BTreeMap::new(),
            action_registry: ActionRegistry::new(),
            observers: ObserverRegistry::new(),
            next_instance_id: 0,
            manifest_digest,
            wal: Some(WalWriter::new(world_id, manifest_digest)),
            step_scratch: StepStage::default(),
        }
    }

    /// Construct a Kernel with a WAL writer that signs each record under
    /// the supplied `SignatureClass` (A16 — Ed25519 (Tier 2) or Hybrid (Ed25519 + ML-DSA 65, CNSA 2.0)). The
    /// verifying key is pinned in the WAL header so post-hoc verification
    /// is self-contained.
    pub fn new_with_wal_signed(
        world_id: [u8; 32],
        manifest_digest: [u8; 32],
        sig_class: crate::persist::SignatureClass,
    ) -> Self {
        Self {
            instances: BTreeMap::new(),
            action_registry: ActionRegistry::new(),
            observers: ObserverRegistry::new(),
            next_instance_id: 0,
            manifest_digest,
            wal: Some(WalWriter::with_signature(
                world_id,
                manifest_digest,
                sig_class,
            )),
            step_scratch: StepStage::default(),
        }
    }

    /// The kernel's declared `ModuleManifest` digest (A14). `[0u8; 32]` if the
    /// kernel was built without one. `replay_into` rejects a WAL whose header
    /// pins a different digest.
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    /// Current chain tip if the kernel has a WAL attached.
    pub fn wal_chain_tip(&self) -> Option<[u8; 32]> {
        self.wal.as_ref().map(|w| w.chain_tip())
    }

    /// Number of WAL records currently buffered (None if no WAL attached).
    pub fn wal_record_count(&self) -> Option<usize> {
        self.wal.as_ref().map(|w| w.record_count())
    }

    /// Consume the kernel and return the accumulated WAL (if any).
    pub fn export_wal(self) -> Option<Wal> {
        self.wal.map(Wal::from_writer)
    }

    /// Register a domain action type with the kernel's dispatch
    /// registry. Required before [`submit`](Kernel::submit) accepts
    /// the action's `TYPE_CODE`.
    pub fn register_action<A: Action>(&mut self) {
        self.action_registry.register::<A>();
    }

    /// Register an observer for every kernel event. Equivalent to
    /// [`register_observer_filtered`](Kernel::register_observer_filtered)
    /// with `EventMask::ALL`.
    pub fn register_observer(&mut self, obs: Box<dyn KernelObserver>) -> ObserverHandle {
        self.observers.register(obs)
    }

    /// Register an observer with an event-class filter. Only events
    /// whose variant bit is set in `mask` are delivered to this observer
    /// — useful when an observer cares about a narrow slice of the event
    /// stream (e.g. only `DOMAIN_EVENT_EMITTED`). `EventMask::ALL` is
    /// equivalent to `register_observer`.
    pub fn register_observer_filtered(
        &mut self,
        obs: Box<dyn KernelObserver>,
        mask: super::event::EventMask,
    ) -> ObserverHandle {
        self.observers.register_filtered(obs, mask)
    }

    /// Create a new instance with the supplied config. Returns the
    /// freshly-allocated `InstanceId` (monotonic per kernel lifetime).
    pub fn create_instance(&mut self, config: InstanceConfig) -> InstanceId {
        self.next_instance_id = self.next_instance_id.saturating_add(1);
        let id = InstanceId::new(self.next_instance_id).expect("instance id > 0");
        self.instances.insert(id, Instance::new(id, config));
        id
    }

    /// Number of live instances.
    pub fn instances_len(&self) -> usize {
        self.instances.len()
    }

    /// Read-only view of one instance's state. Returns `None` if `id`
    /// does not exist. The borrow is `&self`, so callers cannot mutate
    /// the kernel concurrently while a view is live.
    pub fn instance_view(&self, id: InstanceId) -> Option<super::view::InstanceView<'_>> {
        self.instances
            .get(&id)
            .map(|instance| super::view::InstanceView { instance })
    }

    /// Capture current kernel state as a serializable snapshot.
    /// Excludes observers and action registry — caller re-registers those
    /// after `Kernel::from_snapshot(...)`. WAL is independent and not
    /// captured here.
    pub fn snapshot(&self) -> crate::persist::KernelSnapshot {
        let instances = self
            .instances
            .iter()
            .map(|(id, inst)| (*id, inst.to_snapshot()))
            .collect();
        crate::persist::KernelSnapshot::__construct(instances, self.next_instance_id)
    }

    /// Restore a `Kernel` from a snapshot. The returned kernel has no
    /// observers, an empty action registry, and no attached WAL — caller
    /// must re-register everything before resuming `step()`.
    pub fn from_snapshot(snap: crate::persist::KernelSnapshot) -> Self {
        let (instances_in, next_instance_id) = snap.__into_parts();
        let instances = instances_in
            .into_iter()
            .map(|(id, s)| (id, Instance::from_snapshot(s)))
            .collect();
        Self {
            instances,
            action_registry: ActionRegistry::new(),
            observers: ObserverRegistry::new(),
            next_instance_id,
            manifest_digest: [0u8; 32],
            wal: None,
            step_scratch: StepStage::default(),
        }
    }

    /// Aggregate observability across all instances. See [`Stats`].
    pub fn stats(&self) -> Stats {
        let mut scheduled = 0usize;
        let mut entities = 0u32;
        let mut bytes = 0u64;
        for inst in self.instances.values() {
            scheduled = scheduled.saturating_add(inst.scheduler().len());
            entities = entities.saturating_add(inst.ledger().total_entities());
            bytes = bytes.saturating_add(inst.ledger().total_bytes());
        }
        Stats {
            instance_count: self.instances.len(),
            scheduled_action_count: scheduled,
            entity_count: entities,
            component_byte_count: bytes,
            observer_count: self.observers.len(),
            wal_record_count: self.wal.as_ref().map(|w| w.record_count()).unwrap_or(0),
        }
    }

    /// Force-unload: drop every instance's inflight-refs entry for
    /// `route_id` and emit `KernelEvent::ModuleForceUnloaded` with the
    /// summed live-ref count for the audit trail. Requires `ADMIN_UNLOAD`.
    ///
    /// Returns the total live refs that were dropped (`Ok(0)` if no
    /// instance held the route).
    pub fn force_unload(
        &mut self,
        route_id: crate::abi::RouteId,
        caps: CapabilityMask,
    ) -> Result<usize, ArkheError> {
        if !caps.contains(CapabilityMask::ADMIN_UNLOAD) {
            return Err(ArkheError::CapabilityDenied);
        }

        let mut total_live_refs: u32 = 0;
        for inst in self.instances.values_mut() {
            if let Some(refs) = inst.inflight_refs_mut().remove(&route_id) {
                total_live_refs = total_live_refs.saturating_add(refs);
            }
        }

        let event = KernelEvent::ModuleForceUnloaded {
            route_id,
            live_refs_at_unload: total_live_refs,
        };
        let _ = self.observers.deliver(&event);

        Ok(total_live_refs as usize)
    }

    /// Schedule a serialized action against an instance for execution
    /// at tick `at`. The bytes must be the canonical postcard encoding
    /// produced by `<A as Action>::canonical_bytes()` for some
    /// previously-registered action type matching `action_type_code`.
    /// Returns the freshly-allocated [`ScheduledActionId`].
    ///
    /// `caps` is the capability ceiling granted to this submission — it is
    /// pinned on the scheduled entry and bounds the action's effective caps
    /// at execution (see [`effective_caps`]). It is the only non-reproducible
    /// scheduling input, so an attached WAL records one `Submit` here (a
    /// CIL admission); the resulting `ScheduledActionId` is recorded with it
    /// so replay re-injects the action under the exact same id.
    ///
    /// Errors with [`ArkheError::InstanceNotFound`] if `instance` is
    /// unknown.
    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &mut self,
        instance: InstanceId,
        principal: Principal,
        actor: Option<EntityId>,
        caps: CapabilityMask,
        at: Tick,
        action_type_code: TypeCode,
        action_bytes: Vec<u8>,
    ) -> Result<ScheduledActionId, ArkheError> {
        // Clone the bytes for the WAL record only when a WAL is attached
        // (the scheduler takes ownership of the original).
        let wal_bytes = if self.wal.is_some() {
            Some(action_bytes.clone())
        } else {
            None
        };
        let id = {
            let inst = self
                .instances
                .get_mut(&instance)
                .ok_or(ArkheError::InstanceNotFound)?;
            // Back-pressure (#15): bound the scheduler so an external caller
            // cannot flood `submit` into unbounded growth. `max_scheduled == 0`
            // means unlimited (default `InstanceConfig`).
            let max_scheduled = inst.config().max_scheduled;
            if max_scheduled > 0 && inst.scheduler().len() >= max_scheduled as usize {
                return Err(ArkheError::QuotaExceeded);
            }
            let counters = inst.id_counters_mut();
            counters.next_scheduled = counters.next_scheduled.saturating_add(1);
            let id = ScheduledActionId::new(counters.next_scheduled).expect("scheduled id > 0");
            inst.scheduler_mut().schedule_with_id(
                id,
                at,
                actor,
                principal.clone(),
                caps,
                action_type_code,
                action_bytes,
            );
            id
        };
        if let (Some(wal), Some(bytes)) = (self.wal.as_mut(), wal_bytes) {
            let _ = wal.append_submit(
                instance,
                principal,
                actor,
                caps.bits(),
                at,
                action_type_code,
                bytes,
                id,
            );
        }
        Ok(id)
    }

    /// Replay-side admission: inject a previously-recorded `Submit` under its
    /// exact `id`, capability ceiling, and inputs. No WAL is written (replay
    /// re-measures the chain through its own writer) and the scheduler/id
    /// counters are advanced so subsequent internal id allocation reproduces
    /// the original sequence bit-for-bit. The back-pressure check is skipped
    /// — a recorded submit already passed it at original-admission time.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn submit_with_id(
        &mut self,
        instance: InstanceId,
        principal: Principal,
        actor: Option<EntityId>,
        caps: CapabilityMask,
        id: ScheduledActionId,
        at: Tick,
        action_type_code: TypeCode,
        action_bytes: Vec<u8>,
    ) -> Result<(), ArkheError> {
        let inst = self
            .instances
            .get_mut(&instance)
            .ok_or(ArkheError::InstanceNotFound)?;
        // Mirror `submit`'s counter advance so a re-executed `Op::ScheduleAction`
        // mints the same next id (the kernel-level `next_scheduled` seeds
        // dispatch's allocator; the scheduler's own `next_id` is bumped by
        // `schedule_with_id`).
        let counters = inst.id_counters_mut();
        if id.get() > counters.next_scheduled {
            counters.next_scheduled = id.get();
        }
        inst.scheduler_mut().schedule_with_id(
            id,
            at,
            actor,
            principal,
            caps,
            action_type_code,
            action_bytes,
        );
        Ok(())
    }

    /// Process at most one due action per instance, in ascending InstanceId
    /// order (A23). `caps` is the operator SESSION CEILING — it intersects
    /// (never widens) each action's resolved capabilities. Returns aggregated
    /// counters and, with a WAL attached, appends one `Step` record per pop.
    pub fn step(&mut self, now: Tick, caps: CapabilityMask) -> StepReport {
        let mut report = StepReport::default();
        // The digest is the per-step bit-identity witness; it is only needed
        // when it will be recorded (WAL attached) — skip the full-state hash
        // on the plain stepping path so it costs nothing there.
        let measure_digest = self.wal.is_some();

        // Ascending-InstanceId key snapshot (A23). A snapshot is required —
        // not `iter_mut` — because the post-step signal router needs the whole
        // instance map (a sender routes into *other* instances' inboxes), so
        // the per-instance borrow cannot be held across the round.
        let ids: Vec<InstanceId> = self.instances.keys().copied().collect();
        for inst_id in ids {
            let Some(result) = self.process_instance_record(inst_id, now, caps, measure_digest)
            else {
                continue;
            };
            report.actions_executed = report.actions_executed.saturating_add(1);
            report.effects_applied = report
                .effects_applied
                .saturating_add(result.effects_applied);
            report.effects_denied = report.effects_denied.saturating_add(result.effects_denied);
            report.domain_events_emitted = report
                .domain_events_emitted
                .saturating_add(result.domain_events_emitted);
            report.observers_evicted = report
                .observers_evicted
                .saturating_add(result.observers_evicted);
            // CIL: one `Step` record per pop — Committed / AuthDenied /
            // BudgetPartial / Skipped alike (the verdict + post-state digest
            // are the only non-reproducible facts; routing/scheduling effects
            // are re-derived on replay).
            if let Some(wal) = self.wal.as_mut() {
                let _ = wal.append_step(
                    inst_id,
                    result.popped_id,
                    now,
                    caps.bits(),
                    result.verdict,
                    result.digest,
                );
            }
        }

        report
    }

    /// Run one due action for `inst_id` end-to-end: pop → gate → dispatch →
    /// apply → digest → deliver observer events → route outbound signals.
    /// Returns `None` if nothing was due. Shared verbatim by the live `step`
    /// loop and `replay` so both reach bit-identical state and verdicts.
    ///
    /// The signal router runs here, immediately after this instance's own
    /// apply and digest, so a signal this instance sends is delivered into the
    /// target's inbox before any later instance steps this round — and is
    /// witnessed by that target's next `Step` digest. The ordering is
    /// identical on replay (records are re-driven in the same order), so the
    /// digests match.
    pub(crate) fn process_instance_record(
        &mut self,
        inst_id: InstanceId,
        now: Tick,
        session_caps: CapabilityMask,
        measure_digest: bool,
    ) -> Option<InstanceStepResult> {
        // ---- 1. step_one core (partial borrow: one instance + registry + scratch) ----
        // A missing instance returns `None` (not a panic): the live `step` loop
        // only ever passes ids drawn from the live key set, but `replay` passes
        // the `instance` from a (possibly malformed / adversarial) WAL Step
        // record — which `replay_records` then surfaces as a graceful
        // `ReplayError::StepUnderflow` rather than a panic (A12 panic-free
        // discipline holds for untrusted input).
        let core = {
            let Self {
                instances,
                action_registry,
                step_scratch,
                ..
            } = self;
            let inst = instances.get_mut(&inst_id)?;
            step_one_core(
                inst_id,
                inst,
                action_registry,
                step_scratch,
                now,
                session_caps,
                measure_digest,
            )
        }?;

        let mut result = InstanceStepResult {
            popped_id: core.popped_id,
            verdict: core.verdict,
            digest: core.digest,
            effects_applied: core.effects_applied,
            effects_denied: core.effects_denied,
            domain_events_emitted: core.domain_events_emitted,
            observers_evicted: 0,
        };

        // ---- 2. observer delivery (staged events, then ActionExecuted) ----
        for event in &core.events {
            let evicted = self.observers.deliver(event);
            result.observers_evicted = result
                .observers_evicted
                .saturating_add(evicted.len() as u32);
        }
        // `ActionExecuted` fires only when the action actually committed (fully
        // or partially) — exactly the pre-epoch contract, where a rolled-back
        // step (`any_denied`) and an unexecuted skip both delivered no
        // `ActionExecuted`. AuthDenied (full rollback) and Skipped are excluded.
        if matches!(
            core.verdict,
            StepVerdict::Committed | StepVerdict::BudgetPartial { .. }
        ) {
            let action_executed = KernelEvent::ActionExecuted {
                instance: inst_id,
                action_type: core.action_type,
                at: now,
            };
            let evicted = self.observers.deliver(&action_executed);
            result.observers_evicted = result
                .observers_evicted
                .saturating_add(evicted.len() as u32);
        }

        // ---- 3. signal router (cross-instance; needs the full map) ----
        // A signal's in-flight refcount is a conserved quantity: it is
        // credited on the TARGET's route here, at delivery (a delivered
        // signal increments; a dropped one does not) — never speculatively at
        // dispatch. Delivery is unlogged; replay re-derives it identically.
        for sig in core.pending_signals {
            let route = sig.route;
            let target_id = sig.target;
            let event = match self.instances.get_mut(&target_id) {
                Some(target) => {
                    let max_inbox = target.config().max_inbox_per_route;
                    if max_inbox > 0 && target.inbox_len(route) >= max_inbox as usize {
                        KernelEvent::SignalDropped {
                            target: target_id,
                            route,
                            reason: SignalDropReason::QueueFull,
                        }
                    } else {
                        target.deliver_signal(
                            route,
                            InboundSignal {
                                from: inst_id,
                                principal: sig.principal,
                                payload: sig.payload,
                                // Assigned by `deliver_signal` from the target's
                                // own monotonic `inbox_seq`.
                                seq: 0,
                            },
                        );
                        let entry = target.inflight_refs_mut().entry(route).or_insert(0);
                        *entry = entry.saturating_add(1);
                        KernelEvent::SignalDelivered {
                            from: inst_id,
                            target: target_id,
                            route,
                        }
                    }
                }
                None => KernelEvent::SignalDropped {
                    target: target_id,
                    route,
                    reason: SignalDropReason::TargetNotFound,
                },
            };
            let evicted = self.observers.deliver(&event);
            result.observers_evicted = result
                .observers_evicted
                .saturating_add(evicted.len() as u32);
        }

        Some(result)
    }
}

/// Per-pop outcome carried out of [`Kernel::process_instance_record`] to the
/// live `step` loop / `replay` driver: the WAL `Step` fields plus the
/// observability counters.
pub(crate) struct InstanceStepResult {
    /// ScheduledActionId popped this step (scheduler-order witness).
    pub popped_id: ScheduledActionId,
    /// Step outcome verdict.
    pub verdict: StepVerdict,
    /// Full post-step state digest (`[0u8; 32]` when `measure_digest` was
    /// false — the plain no-WAL stepping path, where it is unused).
    pub digest: [u8; 32],
    /// Effects committed this step.
    pub effects_applied: u32,
    /// Effects denied (authorize / budget / quota) this step.
    pub effects_denied: u32,
    /// `DomainEventEmitted` events produced this step.
    pub domain_events_emitted: u32,
    /// Observers newly evicted while delivering this step's events.
    pub observers_evicted: u32,
}

/// Internal result of the pop → gate → dispatch → apply → digest core, before
/// observer delivery and signal routing (which need kernel-wide state).
struct StepCore {
    popped_id: ScheduledActionId,
    action_type: TypeCode,
    verdict: StepVerdict,
    digest: [u8; 32],
    pending_signals: Vec<PendingSignal>,
    events: Vec<KernelEvent>,
    effects_applied: u32,
    effects_denied: u32,
    domain_events_emitted: u32,
}

/// Pop one due action for `inst` and run it through the gate loop, producing
/// a [`StepCore`] (verdict + post-state digest + staged outputs). Pure with
/// respect to other instances — observer delivery and the cross-instance
/// signal router run in [`Kernel::process_instance_record`], which owns the
/// kernel-wide borrows. Returns `None` if no action was due.
#[allow(clippy::too_many_arguments)]
fn step_one_core(
    inst_id: InstanceId,
    inst: &mut Instance,
    registry: &ActionRegistry,
    scratch: &mut StepStage,
    now: Tick,
    session_caps: CapabilityMask,
    measure_digest: bool,
) -> Option<StepCore> {
    let entry = inst.scheduler_mut().pop_due(now)?;
    let popped_id = entry.id;
    let action_type = entry.action_type_code;

    // A digest helper closure that elides the full-state hash when unneeded.
    let digest_of = |inst: &Instance| -> [u8; 32] {
        if measure_digest {
            inst.state_digest()
        } else {
            [0u8; 32]
        }
    };

    // Skipped: no registry entry for the popped type. The pop already mutated
    // the scheduler (the entry is gone), which the digest witnesses.
    let reg = match registry.get(entry.action_type_code).cloned() {
        Some(r) => r,
        None => {
            return Some(StepCore {
                popped_id,
                action_type,
                verdict: StepVerdict::Skipped {
                    reason: SkipReason::Unregistered,
                },
                digest: digest_of(inst),
                pending_signals: Vec::new(),
                events: Vec::new(),
                effects_applied: 0,
                effects_denied: 0,
                domain_events_emitted: 0,
            });
        }
    };

    // Skipped: bytes fail to deserialize under the registered schema.
    let action = match (reg.deserializer)(reg.schema_version, &entry.action_bytes) {
        Ok(a) => a,
        Err(_) => {
            return Some(StepCore {
                popped_id,
                action_type,
                verdict: StepVerdict::Skipped {
                    reason: SkipReason::DeserFailed,
                },
                digest: digest_of(inst),
                pending_signals: Vec::new(),
                events: Vec::new(),
                effects_applied: 0,
                effects_denied: 0,
                domain_events_emitted: 0,
            });
        }
    };

    // Resolve the capabilities this action runs under: the unified ceiling
    // model (config default_caps bounded by the entry's inherited ceiling per
    // principal) intersected with the operator session ceiling. There is no
    // System blanket bypass — a System action is privileged only insofar as
    // `default_caps` grants and the session permits.
    let eff = effective_caps(inst.config().default_caps, &entry.principal, entry.caps_ceiling)
        & session_caps;

    let ctx = ActionContext::new(entry.actor, now, inst_id, &*inst);
    let ops = action.compute_dyn(&ctx);

    // Immutable read view for the gate loop; its borrow ends before the
    // mutable `apply_stage` below (NLL).
    let inst_ref = &*inst;
    // Reuse the kernel-owned scratch (capacity retained across actions)
    // rather than allocating a fresh StepStage each step. `clear()`
    // makes it identical to `StepStage::default()`.
    scratch.clear();
    let stage = &mut *scratch;
    let mut next_scheduled_id = inst_ref.id_counters_snapshot().next_scheduled;
    let budget = inst_ref.config().memory_budget_bytes;
    let baseline_bytes: u64 = inst_ref.ledger().total_bytes();
    let mut any_denied = false;
    // Provisional applied count — folded in only on the commit path. If the
    // step rolls back (`any_denied`), these ops are discarded.
    let mut applied_this_action: u32 = 0;
    // Per-Op budget/quota skips (do NOT roll back). A committed step with one
    // or more of these records `BudgetPartial { denied }`.
    let mut denied_this_action: u32 = 0;
    for op in ops {
        let unverified: Effect<'_, Unverified> = Effect::new(inst_id, entry.principal.clone(), op);
        match authorize(eff, unverified) {
            Ok(authorized) => {
                // Budget enforcement (per-Op, post-authorize, pre-dispatch).
                // `budget == 0` means unlimited (default `InstanceConfig`).
                // Authorize-deny rolls back the whole stage (any_denied);
                // budget-deny is a per-Op skip that does NOT rollback.
                if budget > 0 {
                    // Project the post-commit component-byte total in
                    // saturating u64 (matching ResourceLedger's own
                    // arithmetic): the baseline + every already-staged
                    // component delta + this Op. A SetComponent adds its
                    // caller-declared `size`; a RemoveComponent credits
                    // only the bytes the ledger will actually free (its
                    // stored size), never the untrusted caller-declared
                    // `size` — an inflated remove would otherwise poison
                    // the projection and disable the budget for the rest
                    // of the step. Working in u64 (not i64) means an
                    // oversized add saturates to u64::MAX and trips any
                    // budget below u64::MAX — including budgets above
                    // i64::MAX, which the old i64 threshold silently
                    // disabled.
                    let staged = super::stage::projected_component_bytes(
                        baseline_bytes,
                        &*stage,
                        inst_ref.ledger(),
                    );
                    let projected = match &authorized.op {
                        crate::state::Op::SetComponent { size, .. } => staged.saturating_add(*size),
                        crate::state::Op::RemoveComponent {
                            entity, type_code, ..
                        } => {
                            let freed = inst_ref
                                .ledger()
                                .component_size(*entity, *type_code)
                                .unwrap_or(0);
                            staged.saturating_sub(freed)
                        }
                        crate::state::Op::SpawnEntity { .. }
                        | crate::state::Op::DespawnEntity { .. }
                        | crate::state::Op::EmitEvent { .. }
                        | crate::state::Op::ScheduleAction { .. }
                        | crate::state::Op::SendSignal { .. } => staged,
                    };
                    if projected > budget {
                        denied_this_action = denied_this_action.saturating_add(1);
                        stage.events.push_back(KernelEvent::EffectFailed {
                            instance: inst_id,
                            reason: bytes::Bytes::from_static(b"budget_exceeded"),
                        });
                        continue;
                    }
                }
                // Entity quota (#5; `max_entities == 0` = unlimited).
                // Conservative projection = committed live entities +
                // entity-spawns staged so far this step (favors
                // false-deny, like the byte-budget gate).
                let max_entities = inst_ref.config().max_entities;
                if max_entities > 0
                    && matches!(&authorized.op, crate::state::Op::SpawnEntity { .. })
                {
                    let projected_entities = (inst_ref.entities_len() as u64)
                        .saturating_add(stage.id_counters.next_entity_advance);
                    if projected_entities >= max_entities as u64 {
                        denied_this_action = denied_this_action.saturating_add(1);
                        stage.events.push_back(KernelEvent::EffectFailed {
                            instance: inst_id,
                            reason: bytes::Bytes::from_static(b"entity_quota_exceeded"),
                        });
                        continue;
                    }
                }
                // Scheduled-action quota (#8; `max_scheduled == 0` =
                // unlimited). Projection = current scheduler depth +
                // schedule-adds staged so far this step.
                let max_scheduled = inst_ref.config().max_scheduled;
                if max_scheduled > 0
                    && matches!(&authorized.op, crate::state::Op::ScheduleAction { .. })
                {
                    let projected_scheduled = (inst_ref.scheduler().len() as u64)
                        .saturating_add(stage.id_counters.next_scheduled_advance);
                    if projected_scheduled >= max_scheduled as u64 {
                        denied_this_action = denied_this_action.saturating_add(1);
                        stage.events.push_back(KernelEvent::EffectFailed {
                            instance: inst_id,
                            reason: bytes::Bytes::from_static(b"scheduled_quota_exceeded"),
                        });
                        continue;
                    }
                }
                dispatch(authorized, stage, now, &mut next_scheduled_id, eff);
                applied_this_action = applied_this_action.saturating_add(1);
            }
            Err(_) => {
                denied_this_action = denied_this_action.saturating_add(1);
                any_denied = true;
            }
        }
    }

    if any_denied {
        // Rollback: skip apply entirely (no effects, no signals, no events).
        // The pop still happened, so the digest reflects the scheduler with
        // the entry removed. The scratch is `clear()`ed at the top of the
        // next action, so nothing staged here leaks.
        return Some(StepCore {
            popped_id,
            action_type,
            verdict: StepVerdict::AuthDenied,
            digest: digest_of(inst),
            pending_signals: Vec::new(),
            events: Vec::new(),
            effects_applied: 0,
            effects_denied: denied_this_action,
            domain_events_emitted: 0,
        });
    }

    // Commit path. Domain emit count covers only `DomainEventEmitted`; other
    // staged events (e.g. `EffectFailed` from a budget deny) are kernel events.
    let domain_emit_count = stage
        .events
        .iter()
        .filter(|e| matches!(e, KernelEvent::DomainEventEmitted { .. }))
        .count() as u32;
    let events_to_deliver: Vec<KernelEvent> = stage.events.iter().cloned().collect();
    let pending_signals = apply_stage(inst, stage);
    let digest = digest_of(inst);

    let verdict = if denied_this_action > 0 {
        StepVerdict::BudgetPartial {
            denied: denied_this_action,
        }
    } else {
        StepVerdict::Committed
    };

    Some(StepCore {
        popped_id,
        action_type,
        verdict,
        digest,
        pending_signals,
        events: events_to_deliver,
        effects_applied: applied_this_action,
        effects_denied: denied_this_action,
        domain_events_emitted: domain_emit_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use crate::abi::{ExternalId, RouteId};
    use crate::state::traits::_sealed::Sealed;
    use crate::state::{ActionCompute, ActionDeriv, Op};
    use serde::{Deserialize, Serialize};

    // ---- Test Action: spawns a single entity with id=42 ----
    #[derive(Serialize, Deserialize)]
    struct SpawnOneAction;
    impl Sealed for SpawnOneAction {}
    impl ActionDeriv for SpawnOneAction {
        const TYPE_CODE: TypeCode = TypeCode(100);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SpawnOneAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::SpawnEntity {
                id: EntityId::new(42).unwrap(),
                owner: Principal::System,
            }]
        }
    }

    #[derive(Serialize, Deserialize)]
    struct EmitAction;
    impl Sealed for EmitAction {}
    impl ActionDeriv for EmitAction {
        const TYPE_CODE: TypeCode = TypeCode(101);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for EmitAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::EmitEvent {
                actor: None,
                event_type_code: TypeCode(7),
                event_bytes: Bytes::from_static(b"hello"),
            }]
        }
    }

    #[derive(Serialize, Deserialize)]
    struct SignalAction;
    impl Sealed for SignalAction {}
    impl ActionDeriv for SignalAction {
        const TYPE_CODE: TypeCode = TypeCode(102);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SignalAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            // SendSignal requires SYSTEM cap (state::authz policy).
            vec![Op::SendSignal {
                target: InstanceId::new(1).unwrap(),
                route: RouteId(1),
                payload: Bytes::new(),
            }]
        }
    }

    // Emits three SpawnEntity ops with distinct ids (max_entities quota test).
    #[derive(Serialize, Deserialize)]
    struct SpawnThreeAction;
    impl Sealed for SpawnThreeAction {}
    impl ActionDeriv for SpawnThreeAction {
        const TYPE_CODE: TypeCode = TypeCode(103);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SpawnThreeAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            (1..=3)
                .map(|n| Op::SpawnEntity {
                    id: EntityId::new(n).unwrap(),
                    owner: Principal::System,
                })
                .collect()
        }
    }

    // Emits a SetComponent with a declared size above i64::MAX (budget-bypass
    // regression: the size must NOT wrap negative past the budget gate).
    #[derive(Serialize, Deserialize)]
    struct OversizedSetAction;
    impl Sealed for OversizedSetAction {}
    impl ActionDeriv for OversizedSetAction {
        const TYPE_CODE: TypeCode = TypeCode(104);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for OversizedSetAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::SetComponent {
                entity: EntityId::new(1).unwrap(),
                type_code: TypeCode(7),
                bytes: Bytes::from_static(b"x"),
                size: u64::MAX,
            }]
        }
    }

    // Spawns an entity, issues a phantom RemoveComponent with an inflated
    // caller `size` against a component that does not exist, then two 90-byte
    // SetComponents (budget-poison regression: the phantom remove must NOT
    // credit its declared size into the projection and disable the budget).
    #[derive(Serialize, Deserialize)]
    struct PhantomRemovePoisonAction;
    impl Sealed for PhantomRemovePoisonAction {}
    impl ActionDeriv for PhantomRemovePoisonAction {
        const TYPE_CODE: TypeCode = TypeCode(105);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for PhantomRemovePoisonAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let e = EntityId::new(1).unwrap();
            vec![
                Op::SpawnEntity {
                    id: e,
                    owner: Principal::System,
                },
                Op::RemoveComponent {
                    entity: e,
                    type_code: TypeCode(99), // never set — phantom
                    size: u64::MAX,          // inflated free — must be ignored
                },
                Op::SetComponent {
                    entity: e,
                    type_code: TypeCode(8),
                    bytes: Bytes::from_static(b"a"),
                    size: 90,
                },
                Op::SetComponent {
                    entity: e,
                    type_code: TypeCode(9),
                    bytes: Bytes::from_static(b"b"),
                    size: 90,
                },
            ]
        }
    }

    // Emits a SpawnEntity (allowed for External) then a ScheduleAction (needs
    // SYSTEM). Under non-SYSTEM caps the schedule authorize-denies, rolling
    // back the whole step — the earlier spawn must not count as applied.
    #[derive(Serialize, Deserialize)]
    struct SpawnThenScheduleAction;
    impl Sealed for SpawnThenScheduleAction {}
    impl ActionDeriv for SpawnThenScheduleAction {
        const TYPE_CODE: TypeCode = TypeCode(106);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SpawnThenScheduleAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![
                Op::SpawnEntity {
                    id: EntityId::new(1).unwrap(),
                    owner: Principal::System,
                },
                Op::ScheduleAction {
                    at: Tick(10),
                    actor: None,
                    action_type_code: TypeCode(100),
                    action_bytes: Bytes::from_static(b""),
                },
            ]
        }
    }

    struct CountingObserver {
        count: Arc<AtomicU32>,
    }
    impl KernelObserver for CountingObserver {
        fn on_event(&self, _event: &KernelEvent) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PanicObserver;
    impl KernelObserver for PanicObserver {
        fn on_event(&self, _event: &KernelEvent) {
            panic!("observer intentional panic");
        }
    }

    #[test]
    fn create_instance_returns_monotonic_ids() {
        let mut k = Kernel::new();
        let i1 = k.create_instance(InstanceConfig::default());
        let i2 = k.create_instance(InstanceConfig::default());
        let i3 = k.create_instance(InstanceConfig::default());
        assert!(i1 < i2);
        assert!(i2 < i3);
        assert_eq!(i1.get(), 1);
        assert_eq!(i3.get(), 3);
        assert_eq!(k.instances_len(), 3);
    }

    #[test]
    fn submit_unknown_instance_returns_error() {
        let mut k = Kernel::new();
        let bogus = InstanceId::new(99).unwrap();
        let result = k.submit(
            bogus,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        );
        assert!(matches!(result, Err(ArkheError::InstanceNotFound)));
    }

    #[test]
    fn submit_back_pressures_at_max_scheduled() {
        // Regression (#15/#8): submit must bound the scheduler, returning
        // QuotaExceeded rather than admitting unbounded growth.
        let mut k = Kernel::new();
        let inst = k.create_instance(InstanceConfig {
            max_scheduled: 2,
            ..Default::default()
        });
        let sub = |k: &mut Kernel| {
            k.submit(inst, Principal::System, None, CapabilityMask::SYSTEM, Tick(0), TypeCode(100), Vec::new())
        };
        assert!(sub(&mut k).is_ok());
        assert!(sub(&mut k).is_ok());
        assert!(matches!(sub(&mut k), Err(ArkheError::QuotaExceeded)));
    }

    #[test]
    fn step_denies_spawns_past_max_entities() {
        // Regression (#5): the entity quota is enforced per-Op in step();
        // exactly max_entities commit, the rest deny without rollback.
        let mut k = Kernel::new();
        k.register_action::<SpawnThreeAction>();
        let inst = k.create_instance(InstanceConfig {
            max_entities: 2,
            ..Default::default()
        });
        k.submit(inst, Principal::System, None, CapabilityMask::SYSTEM, Tick(0), TypeCode(103), Vec::new())
            .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 2);
        assert_eq!(report.effects_denied, 1);
        assert_eq!(k.instances.get(&inst).unwrap().entities_len(), 2);
    }

    #[test]
    fn step_denies_oversized_component_no_budget_bypass() {
        // Regression (#4): a declared size > i64::MAX must trip the budget
        // deny path, not wrap negative and slip past it.
        let mut k = Kernel::new();
        k.register_action::<OversizedSetAction>();
        let inst = k.create_instance(InstanceConfig {
            memory_budget_bytes: 1000,
            ..Default::default()
        });
        k.submit(inst, Principal::System, None, CapabilityMask::SYSTEM, Tick(0), TypeCode(104), Vec::new())
            .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 0);
        assert_eq!(report.effects_denied, 1);
    }

    #[test]
    fn step_budget_above_i64_max_still_enforced() {
        // Regression: a memory_budget_bytes above i64::MAX must NOT silently
        // disable enforcement. The old i64 threshold round-trip collapsed to
        // i64::MAX, so an oversized add (which projects to i64::MAX) never
        // exceeded it and always committed. In u64 space, a u64::MAX add
        // saturates the projection above the (still-finite) budget and denies.
        let mut k = Kernel::new();
        k.register_action::<OversizedSetAction>();
        let inst = k.create_instance(InstanceConfig {
            memory_budget_bytes: 1u64 << 63, // i64::MAX + 1, above i64::MAX
            ..Default::default()
        });
        k.submit(inst, Principal::System, None, CapabilityMask::SYSTEM, Tick(0), TypeCode(104), Vec::new())
            .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 0);
        assert_eq!(
            report.effects_denied, 1,
            "a u64::MAX add must trip a budget above i64::MAX"
        );
    }

    #[test]
    fn step_phantom_remove_does_not_bypass_budget() {
        // Regression: a RemoveComponent with an inflated caller `size` against
        // a nonexistent component must NOT credit phantom freed bytes into the
        // budget projection. Spawn + phantom-remove + the first 90-byte
        // SetComponent commit (90 <= 100); the second 90-byte SetComponent
        // would push the total to 180 > 100 and is denied.
        let mut k = Kernel::new();
        k.register_action::<PhantomRemovePoisonAction>();
        let inst = k.create_instance(InstanceConfig {
            memory_budget_bytes: 100,
            ..Default::default()
        });
        k.submit(inst, Principal::System, None, CapabilityMask::SYSTEM, Tick(0), TypeCode(105), Vec::new())
            .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(
            report.effects_denied, 1,
            "the second SetComponent must be denied, not slipped past a poisoned budget"
        );
        let total = k.instances.get(&inst).unwrap().ledger().total_bytes();
        assert_eq!(
            total, 90,
            "exactly the first 90-byte component is accounted (budget held at 100)"
        );
    }

    #[test]
    fn step_rollback_does_not_count_applied_effects() {
        // Regression: when a later Op authorize-denies and the whole step
        // rolls back, an earlier dispatched Op must NOT be counted in
        // effects_applied (it was discarded), and instance state is unchanged.
        let mut k = Kernel::new();
        k.register_action::<SpawnThenScheduleAction>();
        let counters = Arc::new(VariantCounters::default());
        k.register_observer(Box::new(VariantTallyObserver {
            counters: counters.clone(),
        }));
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::External(ExternalId(7)),
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(106),
            Vec::new(),
        )
        .unwrap();
        // Non-SYSTEM caps: External may SpawnEntity but not ScheduleAction →
        // the schedule authorize-denies → any_denied → rollback.
        let report = k.step(Tick(0), CapabilityMask::empty());
        assert_eq!(
            report.effects_applied, 0,
            "a rolled-back spawn must not count as applied"
        );
        assert!(report.effects_denied >= 1);
        assert_eq!(
            k.instances.get(&inst).unwrap().entities_len(),
            0,
            "rollback restores instance state"
        );
        // A rolled-back step delivers NO ActionExecuted (the action did not
        // commit) — preserving the pre-epoch observer contract.
        assert_eq!(
            counters.action_executed.load(Ordering::SeqCst),
            0,
            "AuthDenied rollback must not emit ActionExecuted"
        );
    }

    #[test]
    fn submit_then_step_executes_action_and_spawns_entity() {
        let mut k = Kernel::new();
        k.register_action::<SpawnOneAction>();
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();

        let report = k.step(Tick(5), CapabilityMask::SYSTEM);
        assert_eq!(report.actions_executed, 1);
        assert_eq!(report.effects_applied, 1);
        assert_eq!(report.effects_denied, 0);
        // Entity with id=42 added via SpawnEntity Op
        let inst_ref = k.instances.get(&inst).unwrap();
        assert_eq!(inst_ref.entities_len(), 1);
    }

    #[test]
    fn step_with_unknown_type_code_skips_action() {
        let mut k = Kernel::new();
        // Don't register SpawnOneAction — submit with its type_code.
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(999),
            Vec::new(),
        )
        .unwrap();

        let report = k.step(Tick(5), CapabilityMask::SYSTEM);
        assert_eq!(report.actions_executed, 1);
        assert_eq!(report.effects_applied, 0);
        assert_eq!(k.instances.get(&inst).unwrap().entities_len(), 0);
    }

    #[test]
    fn observer_receives_action_executed_event() {
        let mut k = Kernel::new();
        k.register_action::<SpawnOneAction>();
        let count = Arc::new(AtomicU32::new(0));
        let _h = k.register_observer(Box::new(CountingObserver {
            count: count.clone(),
        }));
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        k.step(Tick(5), CapabilityMask::SYSTEM);
        // Observer received ActionExecuted (1 event from this Spawn — no DomainEventEmitted).
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn observer_receives_domain_event_emitted() {
        let mut k = Kernel::new();
        k.register_action::<EmitAction>();
        let count = Arc::new(AtomicU32::new(0));
        k.register_observer(Box::new(CountingObserver {
            count: count.clone(),
        }));
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(101),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(5), CapabilityMask::SYSTEM);
        assert_eq!(report.domain_events_emitted, 1);
        // DomainEventEmitted + ActionExecuted = 2.
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn panic_observer_evicted_after_first_event() {
        let mut k = Kernel::new();
        k.register_action::<SpawnOneAction>();
        let h = k.register_observer(Box::new(PanicObserver));
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(5), CapabilityMask::SYSTEM);
        assert!(report.observers_evicted >= 1);
        assert!(k.observers.is_evicted(h));
    }

    #[test]
    fn unauthenticated_principal_denies_all_effects() {
        let mut k = Kernel::new();
        k.register_action::<SpawnOneAction>();
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::Unauthenticated,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(5), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_denied, 1);
        assert_eq!(report.effects_applied, 0);
        // Stage discarded; entity not spawned.
        assert_eq!(k.instances.get(&inst).unwrap().entities_len(), 0);
    }

    #[test]
    fn external_without_system_cap_denies_signal() {
        let mut k = Kernel::new();
        k.register_action::<SignalAction>();
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::External(ExternalId(7)),
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(102),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(5), CapabilityMask::default());
        assert_eq!(report.effects_denied, 1);
        assert_eq!(report.effects_applied, 0);
    }

    #[test]
    fn wal_attached_kernel_records_submit_then_step() {
        // CIL: `submit` appends one `Submit` record; the committed `step`
        // appends one `Step` record (2 records total for one admitted action).
        let mut k = Kernel::new_with_wal([7u8; 32], [3u8; 32]);
        k.register_action::<SpawnOneAction>();
        let inst = k.create_instance(InstanceConfig::default());
        assert_eq!(k.wal_record_count(), Some(0));
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(k.wal_record_count(), Some(1));
        let pre_tip = k.wal_chain_tip().unwrap();
        k.step(Tick(5), CapabilityMask::SYSTEM);
        assert_eq!(k.wal_record_count(), Some(2));
        let post_tip = k.wal_chain_tip().unwrap();
        assert_ne!(pre_tip, post_tip);
    }

    #[test]
    fn wal_kernel_export_then_verify_chain() {
        let mut k = Kernel::new_with_wal([11u8; 32], [0u8; 32]);
        k.register_action::<SpawnOneAction>();
        let inst = k.create_instance(InstanceConfig::default());
        for _ in 0..3 {
            k.submit(
                inst,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(0),
                TypeCode(100),
                Vec::new(),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM);
        }
        let wal = k.export_wal().expect("wal attached");
        // 3 admitted actions → 3 Submit + 3 Step records.
        assert_eq!(wal.records.len(), 6);
        wal.verify_chain([11u8; 32]).expect("chain verifies");
    }

    #[test]
    fn replay_reconstructs_chain_tip() {
        use crate::persist::replay_into;
        // Original kernel: write WAL with several committed steps.
        let mut k1 = Kernel::new_with_wal([42u8; 32], [0u8; 32]);
        k1.register_action::<SpawnOneAction>();
        let i1 = k1.create_instance(InstanceConfig::default());
        for _ in 0..4 {
            k1.submit(
                i1,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(0),
                TypeCode(100),
                Vec::new(),
            )
            .unwrap();
            k1.step(Tick(0), CapabilityMask::SYSTEM);
        }
        let original_tip = k1.wal_chain_tip().unwrap();
        let wal = k1.export_wal().unwrap();

        // Reconstructed kernel: same WAL → same chain tip after replay.
        let mut k2 = Kernel::new_with_wal([42u8; 32], [0u8; 32]);
        k2.register_action::<SpawnOneAction>();
        // Caller pre-creates instances; the integrated path is
        // `Kernel::from_snapshot` (persist::snapshot).
        let _i2 = k2.create_instance(InstanceConfig::default());
        let report = replay_into(&mut k2, &wal).expect("replay ok");
        // 4 admitted actions → 4 Submit + 4 Step records re-driven.
        assert_eq!(report.submits_replayed, 4);
        assert_eq!(report.steps_replayed, 4);
        // The tip is MEASURED by replay's own header-rebuilt writer (replay
        // does not write back into k2's attached WAL), and must equal the
        // original sealed tip — the A1 D1-Total bit-identity witness.
        assert_eq!(report.final_chain_tip, original_tip);
    }

    #[test]
    fn step_processes_instances_in_ascending_order() {
        // Two instances; both submit a SpawnOneAction. After step,
        // both should have an entity. Per A23, processing order is
        // InstanceId ascending — observable via ActionExecuted event order.
        let mut k = Kernel::new();
        k.register_action::<SpawnOneAction>();
        let i1 = k.create_instance(InstanceConfig::default());
        let i2 = k.create_instance(InstanceConfig::default());
        k.submit(
            i2,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        k.submit(
            i1,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(5), CapabilityMask::SYSTEM);
        assert_eq!(report.actions_executed, 2);
        assert_eq!(report.effects_applied, 2);
    }

    #[test]
    fn stats_aggregate_reflects_instances_and_scheduler() {
        let mut k = Kernel::new();
        k.register_action::<SpawnOneAction>();
        assert_eq!(k.stats(), Stats::default());

        let i1 = k.create_instance(InstanceConfig::default());
        let i2 = k.create_instance(InstanceConfig::default());
        let stats_pre = k.stats();
        assert_eq!(stats_pre.instance_count, 2);
        assert_eq!(stats_pre.scheduled_action_count, 0);
        assert_eq!(stats_pre.entity_count, 0);

        k.submit(
            i1,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        k.submit(
            i2,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        let stats_queued = k.stats();
        assert_eq!(stats_queued.scheduled_action_count, 2);

        let _ = k.step(Tick(1), CapabilityMask::SYSTEM);
        let stats_post = k.stats();
        assert_eq!(stats_post.scheduled_action_count, 0);
        assert_eq!(stats_post.entity_count, 2);
    }

    #[test]
    fn stats_counts_observers() {
        struct NullObs;
        impl KernelObserver for NullObs {
            fn on_event(&self, _e: &KernelEvent) {}
        }

        let mut k = Kernel::new();
        k.register_observer(Box::new(NullObs));
        k.register_observer(Box::new(NullObs));
        assert_eq!(k.stats().observer_count, 2);
    }

    #[test]
    fn stats_wal_record_count_reflects_writer() {
        let mut k = Kernel::new_with_wal([1u8; 32], [0u8; 32]);
        k.register_action::<SpawnOneAction>();
        assert_eq!(k.stats().wal_record_count, 0);

        let i = k.create_instance(InstanceConfig::default());
        k.submit(
            i,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(1), CapabilityMask::SYSTEM);
        // One Submit + one Step record.
        assert_eq!(k.stats().wal_record_count, 2);
    }

    // ---- force_unload ----

    /// Observer that records every `ModuleForceUnloaded` event it sees.
    struct ForceUnloadCapture {
        seen: Arc<std::sync::Mutex<Vec<(RouteId, u32)>>>,
    }
    impl KernelObserver for ForceUnloadCapture {
        fn on_event(&self, event: &KernelEvent) {
            if let KernelEvent::ModuleForceUnloaded {
                route_id,
                live_refs_at_unload,
            } = event
            {
                self.seen
                    .lock()
                    .unwrap()
                    .push((*route_id, *live_refs_at_unload));
            }
        }
    }

    #[test]
    fn force_unload_without_cap_denied() {
        let mut k = Kernel::new();
        let result = k.force_unload(RouteId(1), CapabilityMask::default());
        assert!(matches!(result, Err(ArkheError::CapabilityDenied)));
    }

    #[test]
    fn force_unload_removes_inflight_refs() {
        let mut k = Kernel::new();
        k.register_action::<SignalAction>();
        // SendSignal needs SYSTEM in the action's effective caps. Under the
        // unified model a System principal is bounded by `default_caps`, so the
        // instance must grant it (no blanket bypass).
        let inst = k.create_instance(InstanceConfig {
            default_caps: CapabilityMask::SYSTEM,
            ..Default::default()
        });
        // SignalAction emits Op::SendSignal { target: self, route: RouteId(1) };
        // the post-step router delivers it into the inbox and credits
        // inflight_refs[RouteId(1)] at delivery (not speculatively at dispatch).
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(102),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 1);
        assert_eq!(
            k.instances
                .get(&inst)
                .unwrap()
                .inflight_refs_for(RouteId(1)),
            1
        );

        let dropped = k
            .force_unload(RouteId(1), CapabilityMask::ADMIN_UNLOAD)
            .expect("admin_unload caps");
        assert_eq!(dropped, 1);
        assert_eq!(
            k.instances
                .get(&inst)
                .unwrap()
                .inflight_refs_for(RouteId(1)),
            0
        );
        assert_eq!(k.instances.get(&inst).unwrap().inflight_refs_len(), 0);
    }

    #[test]
    fn force_unload_emits_module_unloaded_event() {
        let mut k = Kernel::new();
        k.register_action::<SignalAction>();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        k.register_observer(Box::new(ForceUnloadCapture { seen: seen.clone() }));
        let inst = k.create_instance(InstanceConfig {
            default_caps: CapabilityMask::SYSTEM,
            ..Default::default()
        });
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(102),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);

        k.force_unload(RouteId(1), CapabilityMask::ADMIN_UNLOAD)
            .expect("admin_unload caps");

        let captured = seen.lock().unwrap().clone();
        assert_eq!(captured, vec![(RouteId(1), 1)]);
    }

    #[test]
    fn force_unload_no_live_refs_returns_zero() {
        let mut k = Kernel::new();
        let _ = k.create_instance(InstanceConfig::default());
        let dropped = k
            .force_unload(RouteId(99), CapabilityMask::ADMIN_UNLOAD)
            .expect("admin_unload caps");
        assert_eq!(dropped, 0);
    }

    // ---- CIL signal routing + unified capability model ----

    /// Sends two signals to instance 1 on route 1 (queue-full exercise).
    #[derive(Serialize, Deserialize)]
    struct SignalTwiceAction;
    impl Sealed for SignalTwiceAction {}
    impl ActionDeriv for SignalTwiceAction {
        const TYPE_CODE: TypeCode = TypeCode(110);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SignalTwiceAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let one = || Op::SendSignal {
                target: InstanceId::new(1).unwrap(),
                route: RouteId(1),
                payload: Bytes::new(),
            };
            vec![one(), one()]
        }
    }

    /// Sends a signal to a nonexistent instance (target-not-found exercise).
    #[derive(Serialize, Deserialize)]
    struct SignalMissingAction;
    impl Sealed for SignalMissingAction {}
    impl ActionDeriv for SignalMissingAction {
        const TYPE_CODE: TypeCode = TypeCode(111);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SignalMissingAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::SendSignal {
                target: InstanceId::new(99).unwrap(),
                route: RouteId(1),
                payload: Bytes::new(),
            }]
        }
    }

    /// Schedules a `SignalAction` child for tick 1 (cap time-shift exercise).
    #[derive(Serialize, Deserialize)]
    struct ScheduleSignalChildAction;
    impl Sealed for ScheduleSignalChildAction {}
    impl ActionDeriv for ScheduleSignalChildAction {
        const TYPE_CODE: TypeCode = TypeCode(112);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for ScheduleSignalChildAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::ScheduleAction {
                at: Tick(1),
                actor: None,
                action_type_code: SignalAction::TYPE_CODE,
                action_bytes: Bytes::from_static(b""),
            }]
        }
    }

    #[derive(Default)]
    struct SignalEventCounters {
        delivered: AtomicU32,
        dropped_not_found: AtomicU32,
        dropped_queue_full: AtomicU32,
    }
    struct SignalEventCapture {
        c: Arc<SignalEventCounters>,
    }
    impl KernelObserver for SignalEventCapture {
        fn on_event(&self, event: &KernelEvent) {
            match event {
                KernelEvent::SignalDelivered { .. } => {
                    self.c.delivered.fetch_add(1, Ordering::SeqCst);
                }
                KernelEvent::SignalDropped { reason, .. } => match reason {
                    crate::runtime::event::SignalDropReason::TargetNotFound => {
                        self.c.dropped_not_found.fetch_add(1, Ordering::SeqCst);
                    }
                    crate::runtime::event::SignalDropReason::QueueFull => {
                        self.c.dropped_queue_full.fetch_add(1, Ordering::SeqCst);
                    }
                    crate::runtime::event::SignalDropReason::Cancelled => {}
                },
                // Exhaustive (no catch-all `_`) so a new KernelEvent variant
                // forces a conscious decision here — the file's convention.
                KernelEvent::ActionExecuted { .. }
                | KernelEvent::ActionFailed { .. }
                | KernelEvent::EffectFailed { .. }
                | KernelEvent::ObserverPanic { .. }
                | KernelEvent::ObserverEvicted { .. }
                | KernelEvent::ModuleForceUnloaded { .. }
                | KernelEvent::ActionDeferredToNextTick { .. }
                | KernelEvent::ObserversFlushed { .. }
                | KernelEvent::DomainEventEmitted { .. } => {}
            }
        }
    }

    fn cfg_sys() -> InstanceConfig {
        InstanceConfig {
            default_caps: CapabilityMask::SYSTEM,
            max_inbox_per_route: 8,
            ..Default::default()
        }
    }

    #[test]
    fn system_no_longer_blanket_bypasses() {
        // A System action whose instance does NOT grant SYSTEM in default_caps
        // cannot SendSignal — System is gated by effective_caps, not bypassed.
        let mut k = Kernel::new();
        k.register_action::<SignalAction>();
        let inst = k.create_instance(InstanceConfig::default()); // default_caps empty
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(102),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(
            report.effects_denied, 1,
            "System SendSignal denied when default_caps withholds SYSTEM"
        );
        assert_eq!(report.effects_applied, 0);
    }

    #[test]
    fn signal_delivered_routes_to_inbox() {
        let mut k = Kernel::new();
        k.register_action::<SignalAction>();
        let counters = Arc::new(SignalEventCounters::default());
        k.register_observer(Box::new(SignalEventCapture {
            c: counters.clone(),
        }));
        let inst = k.create_instance(cfg_sys());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(102),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 1);
        let target = k.instances.get(&inst).unwrap();
        assert_eq!(target.inbox_len(RouteId(1)), 1);
        assert_eq!(target.inflight_refs_for(RouteId(1)), 1);
        assert_eq!(counters.delivered.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn signal_dropped_target_not_found() {
        let mut k = Kernel::new();
        k.register_action::<SignalMissingAction>();
        let counters = Arc::new(SignalEventCounters::default());
        k.register_observer(Box::new(SignalEventCapture {
            c: counters.clone(),
        }));
        let inst = k.create_instance(cfg_sys());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(111),
            Vec::new(),
        )
        .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        // The op is applied (authorized + dispatched); the DROP happens at the
        // delivery router (no target), so no inbox and no refcount anywhere.
        assert_eq!(report.effects_applied, 1);
        assert_eq!(counters.dropped_not_found.load(Ordering::SeqCst), 1);
        assert_eq!(counters.delivered.load(Ordering::SeqCst), 0);
        assert_eq!(
            k.instances.get(&inst).unwrap().inflight_refs_for(RouteId(1)),
            0
        );
    }

    #[test]
    fn signal_dropped_queue_full() {
        let mut k = Kernel::new();
        k.register_action::<SignalTwiceAction>();
        let counters = Arc::new(SignalEventCounters::default());
        k.register_observer(Box::new(SignalEventCapture {
            c: counters.clone(),
        }));
        // Inbox capacity 1: first signal delivered, second dropped (QueueFull).
        let inst = k.create_instance(InstanceConfig {
            default_caps: CapabilityMask::SYSTEM,
            max_inbox_per_route: 1,
            ..Default::default()
        });
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(110),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(counters.delivered.load(Ordering::SeqCst), 1);
        assert_eq!(counters.dropped_queue_full.load(Ordering::SeqCst), 1);
        let target = k.instances.get(&inst).unwrap();
        assert_eq!(target.inbox_len(RouteId(1)), 1, "exactly one fit the inbox");
        assert_eq!(target.inflight_refs_for(RouteId(1)), 1);
    }

    #[test]
    fn cap_time_shift_unrepresentable() {
        // A scheduling parent cannot bake elevated caps into a future child:
        // the child's effective caps are re-resolved at execution under the
        // CURRENT operator session ceiling. Parent schedules a SendSignal child
        // while the session grants SYSTEM; when the child later runs under an
        // empty session, its SendSignal is denied — no time-shifted escalation.
        let mut k = Kernel::new();
        k.register_action::<ScheduleSignalChildAction>();
        k.register_action::<SignalAction>();
        let inst = k.create_instance(cfg_sys());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(112),
            Vec::new(),
        )
        .unwrap();
        // tick 0, full session: parent schedules the child.
        let r0 = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(r0.effects_applied, 1);
        // tick 1, EMPTY session: the child SendSignal is denied.
        let r1 = k.step(Tick(1), CapabilityMask::empty());
        assert_eq!(r1.actions_executed, 1, "child popped");
        assert_eq!(r1.effects_applied, 0, "child SendSignal denied under narrowed session");
        assert_eq!(
            k.instances.get(&inst).unwrap().inbox_len(RouteId(1)),
            0,
            "no signal delivered — caps could not be time-shifted"
        );
    }

    // ---- memory_budget_bytes enforcement (A21) ----

    /// Test action: spawns entity `entity_id` and attaches one
    /// `SetComponent` of `size` bytes. The ledger tracks bytes only for
    /// registered entities, so the spawn must precede the set; this
    /// action emits both in one compute() — production-realistic.
    #[derive(Serialize, Deserialize)]
    struct SetCompAction {
        size: u64,
        entity_id: u64,
    }
    impl Sealed for SetCompAction {}
    impl ActionDeriv for SetCompAction {
        const TYPE_CODE: TypeCode = TypeCode(200);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SetCompAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let entity = EntityId::new(self.entity_id).unwrap();
            vec![
                Op::SpawnEntity {
                    id: entity,
                    owner: Principal::System,
                },
                Op::SetComponent {
                    entity,
                    type_code: TypeCode(7),
                    bytes: Bytes::from(vec![0u8; self.size as usize]),
                    size: self.size,
                },
            ]
        }
    }

    /// Test action: spawns entities 1 and 2, then attaches one
    /// `SetComponent` of size `a` to entity 1 and one of size `b` to
    /// entity 2 (4 ops total).
    #[derive(Serialize, Deserialize)]
    struct TwoSetCompAction {
        a: u64,
        b: u64,
    }
    impl Sealed for TwoSetCompAction {}
    impl ActionDeriv for TwoSetCompAction {
        const TYPE_CODE: TypeCode = TypeCode(201);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for TwoSetCompAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let e1 = EntityId::new(1).unwrap();
            let e2 = EntityId::new(2).unwrap();
            vec![
                Op::SpawnEntity {
                    id: e1,
                    owner: Principal::System,
                },
                Op::SpawnEntity {
                    id: e2,
                    owner: Principal::System,
                },
                Op::SetComponent {
                    entity: e1,
                    type_code: TypeCode(7),
                    bytes: Bytes::from(vec![0u8; self.a as usize]),
                    size: self.a,
                },
                Op::SetComponent {
                    entity: e2,
                    type_code: TypeCode(7),
                    bytes: Bytes::from(vec![0u8; self.b as usize]),
                    size: self.b,
                },
            ]
        }
    }

    fn cfg_with_budget(budget: u64) -> InstanceConfig {
        InstanceConfig {
            memory_budget_bytes: budget,
            ..Default::default()
        }
    }

    fn submit_set(k: &mut Kernel, inst: InstanceId, size: u64, entity_id: u64) {
        let action = SetCompAction { size, entity_id };
        let bytes = Action::canonical_bytes(&action);
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            SetCompAction::TYPE_CODE,
            bytes,
        )
        .expect("submit ok");
    }

    #[test]
    fn budget_zero_allows_unlimited() {
        // Default config has memory_budget_bytes = 0 → no enforcement.
        // SetCompAction emits Spawn + SetComponent (2 ops).
        let mut k = Kernel::new();
        k.register_action::<SetCompAction>();
        let inst = k.create_instance(InstanceConfig::default());
        submit_set(&mut k, inst, 1_000_000, 1);
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 2);
        assert_eq!(report.effects_denied, 0);
        assert_eq!(k.instances.get(&inst).unwrap().components_len(), 1);
    }

    #[test]
    fn budget_exceeded_denies_op() {
        // budget=100; Spawn passes (size 0), SetComponent denied (500 > 100).
        // Per-Op deny — Spawn still applies, no rollback (any_denied=false).
        let mut k = Kernel::new();
        k.register_action::<SetCompAction>();
        let inst = k.create_instance(cfg_with_budget(100));
        submit_set(&mut k, inst, 500, 1);
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 1); // Spawn only
        assert_eq!(report.effects_denied, 1); // SetComponent
        assert_eq!(report.actions_executed, 1);
        assert_eq!(k.instances.get(&inst).unwrap().entities_len(), 1);
        assert_eq!(k.instances.get(&inst).unwrap().components_len(), 0);
    }

    #[test]
    fn budget_at_edge_allows_equal() {
        // budget=500, projected = 0 + 0 (Spawn) + 500 (Set) = 500.
        // 500 == budget is allowed (only `>` denies).
        let mut k = Kernel::new();
        k.register_action::<SetCompAction>();
        let inst = k.create_instance(cfg_with_budget(500));
        submit_set(&mut k, inst, 500, 1);
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 2);
        assert_eq!(report.effects_denied, 0);
        assert_eq!(k.instances.get(&inst).unwrap().components_len(), 1);
        assert_eq!(k.instances.get(&inst).unwrap().ledger().total_bytes(), 500);
    }

    #[test]
    fn multi_op_stage_respects_running_delta() {
        // budget=600. TwoSetCompAction emits: Spawn(1), Spawn(2),
        // SetComp(1, size=400), SetComp(2, size=400).
        // Spawns fit (size 0). SetComp(1): projected=0+0+400=400 → allow.
        // SetComp(2): projected=0+400+400=800 > 600 → deny.
        // 3 applied, 1 denied; entity 2 spawned but uncomponented.
        let mut k = Kernel::new();
        k.register_action::<TwoSetCompAction>();
        let inst = k.create_instance(cfg_with_budget(600));
        let action = TwoSetCompAction { a: 400, b: 400 };
        let bytes = Action::canonical_bytes(&action);
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TwoSetCompAction::TYPE_CODE,
            bytes,
        )
        .unwrap();
        let report = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(report.effects_applied, 3);
        assert_eq!(report.effects_denied, 1);
        assert_eq!(k.instances.get(&inst).unwrap().entities_len(), 2);
        assert_eq!(k.instances.get(&inst).unwrap().components_len(), 1);
        assert_eq!(k.instances.get(&inst).unwrap().ledger().total_bytes(), 400);
    }

    /// Observer that records every `EffectFailed` reason it sees.
    struct EffectFailedCapture {
        seen: Arc<std::sync::Mutex<Vec<Bytes>>>,
    }
    impl KernelObserver for EffectFailedCapture {
        fn on_event(&self, event: &KernelEvent) {
            if let KernelEvent::EffectFailed { reason, .. } = event {
                self.seen.lock().unwrap().push(reason.clone());
            }
        }
    }

    #[test]
    fn effect_failed_event_on_budget_deny() {
        let mut k = Kernel::new();
        k.register_action::<SetCompAction>();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        k.register_observer(Box::new(EffectFailedCapture { seen: seen.clone() }));
        let inst = k.create_instance(cfg_with_budget(100));
        submit_set(&mut k, inst, 500, 1);
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);

        let captured = seen.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].as_ref(), b"budget_exceeded");
    }

    // ---- EventMask filter ----

    use crate::runtime::event::EventMask;

    /// Per-variant counter observer — used to verify that only the
    /// expected variant arms increment.
    #[derive(Default)]
    struct VariantCounters {
        action_executed: AtomicU32,
        action_failed: AtomicU32,
        domain_event: AtomicU32,
        effect_failed: AtomicU32,
        other: AtomicU32,
    }

    struct VariantTallyObserver {
        counters: Arc<VariantCounters>,
    }
    impl KernelObserver for VariantTallyObserver {
        fn on_event(&self, event: &KernelEvent) {
            match event {
                KernelEvent::ActionExecuted { .. } => {
                    self.counters.action_executed.fetch_add(1, Ordering::SeqCst);
                }
                KernelEvent::ActionFailed { .. } => {
                    self.counters.action_failed.fetch_add(1, Ordering::SeqCst);
                }
                KernelEvent::DomainEventEmitted { .. } => {
                    self.counters.domain_event.fetch_add(1, Ordering::SeqCst);
                }
                KernelEvent::EffectFailed { .. } => {
                    self.counters.effect_failed.fetch_add(1, Ordering::SeqCst);
                }
                KernelEvent::ObserverPanic { .. }
                | KernelEvent::ObserverEvicted { .. }
                | KernelEvent::SignalDropped { .. }
                | KernelEvent::SignalDelivered { .. }
                | KernelEvent::ModuleForceUnloaded { .. }
                | KernelEvent::ActionDeferredToNextTick { .. }
                | KernelEvent::ObserversFlushed { .. } => {
                    self.counters.other.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    #[test]
    fn event_mask_default_is_all() {
        let m = EventMask::default();
        assert_eq!(m, EventMask::ALL);
        assert!(m.contains(EventMask::ACTION_EXECUTED));
        assert!(m.contains(EventMask::DOMAIN_EVENT_EMITTED));
        assert!(m.contains(EventMask::MODULE_FORCE_UNLOADED));
    }

    #[test]
    fn register_observer_backward_compat_receives_all() {
        // EmitAction yields a DomainEventEmitted + an ActionExecuted —
        // a default-mask observer must see both.
        let mut k = Kernel::new();
        k.register_action::<EmitAction>();
        let counters = Arc::new(VariantCounters::default());
        k.register_observer(Box::new(VariantTallyObserver {
            counters: counters.clone(),
        }));
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(101),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(counters.action_executed.load(Ordering::SeqCst), 1);
        assert_eq!(counters.domain_event.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn filter_only_action_executed() {
        // Mask = ACTION_EXECUTED only — DomainEventEmitted should be muted.
        let mut k = Kernel::new();
        k.register_action::<EmitAction>();
        let counters = Arc::new(VariantCounters::default());
        k.register_observer_filtered(
            Box::new(VariantTallyObserver {
                counters: counters.clone(),
            }),
            EventMask::ACTION_EXECUTED,
        );
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(101),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(counters.action_executed.load(Ordering::SeqCst), 1);
        assert_eq!(counters.domain_event.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn filter_domain_event_only() {
        // Mask = DOMAIN_EVENT_EMITTED only — ActionExecuted should be muted.
        let mut k = Kernel::new();
        k.register_action::<EmitAction>();
        let counters = Arc::new(VariantCounters::default());
        k.register_observer_filtered(
            Box::new(VariantTallyObserver {
                counters: counters.clone(),
            }),
            EventMask::DOMAIN_EVENT_EMITTED,
        );
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(101),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(counters.action_executed.load(Ordering::SeqCst), 0);
        assert_eq!(counters.domain_event.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multiple_observers_independent_masks() {
        // obs_a wants ACTION_EXECUTED, obs_b wants DOMAIN_EVENT_EMITTED.
        // After one EmitAction step, each observer sees exactly its slice.
        let mut k = Kernel::new();
        k.register_action::<EmitAction>();
        let ca = Arc::new(VariantCounters::default());
        let cb = Arc::new(VariantCounters::default());
        k.register_observer_filtered(
            Box::new(VariantTallyObserver {
                counters: ca.clone(),
            }),
            EventMask::ACTION_EXECUTED,
        );
        k.register_observer_filtered(
            Box::new(VariantTallyObserver {
                counters: cb.clone(),
            }),
            EventMask::DOMAIN_EVENT_EMITTED,
        );
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(101),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(ca.action_executed.load(Ordering::SeqCst), 1);
        assert_eq!(ca.domain_event.load(Ordering::SeqCst), 0);
        assert_eq!(cb.action_executed.load(Ordering::SeqCst), 0);
        assert_eq!(cb.domain_event.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn filter_empty_mask_receives_nothing() {
        // EventMask::empty() — observer is registered but receives zero events.
        let mut k = Kernel::new();
        k.register_action::<EmitAction>();
        let counters = Arc::new(VariantCounters::default());
        k.register_observer_filtered(
            Box::new(VariantTallyObserver {
                counters: counters.clone(),
            }),
            EventMask::empty(),
        );
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            TypeCode(101),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        assert_eq!(counters.action_executed.load(Ordering::SeqCst), 0);
        assert_eq!(counters.domain_event.load(Ordering::SeqCst), 0);
        assert_eq!(counters.action_failed.load(Ordering::SeqCst), 0);
        assert_eq!(counters.effect_failed.load(Ordering::SeqCst), 0);
        assert_eq!(counters.other.load(Ordering::SeqCst), 0);
    }
}

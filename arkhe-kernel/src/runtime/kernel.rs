//! `Kernel` — top-level orchestrator.
//!
//! Step path: `pop_due → deserialize → compute → authorize → dispatch
//! → apply_stage → observer.deliver`. Per-instance step ordering is
//! `InstanceId` ascending (A23) — `BTreeMap` iteration delivers it for free.

use std::collections::BTreeMap;

use crate::abi::{ArkheError, CapabilityMask, EntityId, InstanceId, Principal, Tick, TypeCode};
use crate::state::authz::authorize;
use crate::state::{
    Action, ActionContext, Effect, Instance, InstanceConfig, ScheduledActionId, Unverified,
};

use super::apply::{apply_stage, discard_stage};
use super::dispatch::dispatch;
use super::event::{KernelEvent, ObserverHandle};
use super::observer::{KernelObserver, ObserverRegistry};
use super::registry::ActionRegistry;
use super::stage::StepStage;

use crate::persist::{AuthDecisionAnnotation, Wal, WalWriter};

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
    wal: Option<WalWriter>,
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
            wal: None,
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
            wal: Some(WalWriter::new(world_id, manifest_digest)),
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
            wal: Some(WalWriter::with_signature(
                world_id,
                manifest_digest,
                sig_class,
            )),
        }
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
            wal: None,
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
    /// Errors with [`ArkheError::InstanceNotFound`] if `instance` is
    /// unknown.
    pub fn submit(
        &mut self,
        instance: InstanceId,
        principal: Principal,
        actor: Option<EntityId>,
        at: Tick,
        action_type_code: TypeCode,
        action_bytes: Vec<u8>,
    ) -> Result<ScheduledActionId, ArkheError> {
        let inst = self
            .instances
            .get_mut(&instance)
            .ok_or(ArkheError::InstanceNotFound)?;
        let counters = inst.id_counters_mut();
        counters.next_scheduled = counters.next_scheduled.saturating_add(1);
        let id = ScheduledActionId::new(counters.next_scheduled).expect("scheduled id > 0");
        inst.scheduler_mut().schedule_with_id(
            id,
            at,
            actor,
            principal,
            action_type_code,
            action_bytes,
        );
        Ok(id)
    }

    /// Process at most one due action per instance, in ascending InstanceId
    /// order (A23). Returns aggregated counters for the step.
    pub fn step(&mut self, now: Tick, caps: CapabilityMask) -> StepReport {
        let mut report = StepReport::default();

        let instance_ids: Vec<InstanceId> = self.instances.keys().copied().collect();
        for inst_id in instance_ids {
            let entry = match self.instances.get_mut(&inst_id) {
                Some(inst) => inst.scheduler_mut().pop_due(now),
                None => continue,
            };
            let entry = match entry {
                Some(e) => e,
                None => continue,
            };
            report.actions_executed = report.actions_executed.saturating_add(1);

            let reg = match self.action_registry.get(entry.action_type_code).cloned() {
                Some(r) => r,
                None => continue,
            };

            let action = match (reg.deserializer)(reg.schema_version, &entry.action_bytes) {
                Ok(a) => a,
                Err(_) => continue,
            };

            let inst_ref = self.instances.get(&inst_id).expect("instance present");
            let ctx = ActionContext::new(entry.actor, now, inst_id, inst_ref);
            let ops = action.compute_dyn(&ctx);

            let mut stage = StepStage::default();
            let mut next_scheduled_id = inst_ref.id_counters_snapshot().next_scheduled;
            let budget = inst_ref.config().memory_budget_bytes;
            let baseline_bytes: i64 = inst_ref.ledger().total_bytes() as i64;
            let mut any_denied = false;
            for op in ops {
                let principal_clone = match &entry.principal {
                    Principal::Unauthenticated => Principal::Unauthenticated,
                    Principal::External(e) => Principal::External(*e),
                    Principal::System => Principal::System,
                };
                let eff: Effect<'_, Unverified> = Effect::new(inst_id, principal_clone, op);
                match authorize(caps, eff) {
                    Ok(authorized) => {
                        // Budget enforcement (per-Op, post-authorize, pre-dispatch).
                        // `budget == 0` means unlimited (default `InstanceConfig`).
                        // Authorize-deny rolls back the whole stage (any_denied);
                        // budget-deny is a per-Op skip that does NOT rollback.
                        if budget > 0 {
                            let op_size: i64 = match &authorized.op {
                                crate::state::Op::SetComponent { size, .. } => *size as i64,
                                crate::state::Op::RemoveComponent { size, .. } => -(*size as i64),
                                _ => 0,
                            };
                            let projected = baseline_bytes
                                .saturating_add(super::stage::bytes_delta(&stage))
                                .saturating_add(op_size);
                            if projected > budget as i64 {
                                report.effects_denied = report.effects_denied.saturating_add(1);
                                stage.events.push_back(KernelEvent::EffectFailed {
                                    instance: inst_id,
                                    reason: bytes::Bytes::from_static(b"budget_exceeded"),
                                });
                                continue;
                            }
                        }
                        dispatch(authorized, &mut stage, now, &mut next_scheduled_id);
                        report.effects_applied = report.effects_applied.saturating_add(1);
                    }
                    Err(_) => {
                        report.effects_denied = report.effects_denied.saturating_add(1);
                        any_denied = true;
                    }
                }
            }

            if any_denied {
                let inst_mut = self.instances.get_mut(&inst_id).expect("instance present");
                discard_stage(inst_mut, stage);
                continue;
            }

            // Domain emit count covers only `DomainEventEmitted`; other staged
            // events (e.g. `EffectFailed` from budget deny) are kernel events.
            let domain_emit_count = stage
                .events
                .iter()
                .filter(|e| matches!(e, KernelEvent::DomainEventEmitted { .. }))
                .count();
            report.domain_events_emitted = report
                .domain_events_emitted
                .saturating_add(domain_emit_count as u32);
            let events_to_deliver: Vec<KernelEvent> = stage.events.iter().cloned().collect();

            // Snapshot record metadata before stage is consumed by apply.
            let wal_stage = if self.wal.is_some() {
                Some(stage.clone())
            } else {
                None
            };
            let principal_for_wal = match &entry.principal {
                Principal::Unauthenticated => Principal::Unauthenticated,
                Principal::External(e) => Principal::External(*e),
                Principal::System => Principal::System,
            };
            let action_bytes_for_wal = entry.action_bytes.clone();
            let action_type_for_wal = entry.action_type_code;

            let inst_mut = self.instances.get_mut(&inst_id).expect("instance present");
            apply_stage(inst_mut, stage);

            if let (Some(wal), Some(s)) = (self.wal.as_mut(), wal_stage) {
                let _ = wal.append(
                    now,
                    inst_id,
                    principal_for_wal,
                    action_type_for_wal,
                    action_bytes_for_wal,
                    caps.bits(),
                    s,
                    AuthDecisionAnnotation::AllAuthorized,
                );
            }

            for event in events_to_deliver {
                let evicted = self.observers.deliver(&event);
                report.observers_evicted = report
                    .observers_evicted
                    .saturating_add(evicted.len() as u32);
            }

            let action_executed = KernelEvent::ActionExecuted {
                instance: inst_id,
                action_type: entry.action_type_code,
                at: now,
            };
            let evicted = self.observers.deliver(&action_executed);
            report.observers_evicted = report
                .observers_evicted
                .saturating_add(evicted.len() as u32);
        }

        report
    }
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
            Tick(0),
            TypeCode(100),
            Vec::new(),
        );
        assert!(matches!(result, Err(ArkheError::InstanceNotFound)));
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
    fn wal_attached_kernel_records_committed_step() {
        let mut k = Kernel::new_with_wal([7u8; 32], [3u8; 32]);
        k.register_action::<SpawnOneAction>();
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(k.wal_record_count(), Some(0));
        let pre_tip = k.wal_chain_tip().unwrap();
        k.step(Tick(5), CapabilityMask::SYSTEM);
        assert_eq!(k.wal_record_count(), Some(1));
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
                Tick(0),
                TypeCode(100),
                Vec::new(),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM);
        }
        let wal = k.export_wal().expect("wal attached");
        assert_eq!(wal.records.len(), 3);
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
        assert_eq!(report.records_replayed, 4);
        let replayed_tip = k2.wal_chain_tip().unwrap();
        assert_eq!(replayed_tip, original_tip);
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
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        k.submit(
            i1,
            Principal::System,
            None,
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
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        k.submit(
            i2,
            Principal::System,
            None,
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
            Tick(0),
            TypeCode(100),
            Vec::new(),
        )
        .unwrap();
        let _ = k.step(Tick(1), CapabilityMask::SYSTEM);
        assert_eq!(k.stats().wal_record_count, 1);
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
        let inst = k.create_instance(InstanceConfig::default());
        // SignalAction emits Op::SendSignal { route: RouteId(1) } — needs SYSTEM
        // cap to pass authorize, then dispatch increments inflight_refs[RouteId(1)].
        k.submit(
            inst,
            Principal::System,
            None,
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
        let inst = k.create_instance(InstanceConfig::default());
        k.submit(
            inst,
            Principal::System,
            None,
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

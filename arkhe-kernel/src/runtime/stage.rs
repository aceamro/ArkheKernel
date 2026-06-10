//! `StepStage` — transactional COW staging for one `step()` (9 buckets).
//!
//! Every commit-conditional write the kernel performs during a step is
//! buffered here; on commit, `Instance::apply_stage` drains in canonical
//! canonical order; on rollback, the stage is dropped without effect.
//!
//! Buckets (9):
//! 1. `state_ops` — entity/component mutations
//! 2. `events` — KernelEvent emissions (kernel-level drain)
//! 3. `schedule_deltas` — scheduler add/cancel
//! 4. `pending_signals` — outbound IPC (kernel routes post-commit)
//! 5. `id_counters` — monotonic ID counter advances
//! 6. `ledger_delta` — ResourceLedger updates
//! 7. `wall_remainder_delta` — sub-tick time accumulator advance
//! 8. `local_tick_delta` — logical tick advance
//! 9. `observer_eviction_pending` — observers slated for eviction
//!
//! In-flight signal refcounts are NOT staged: the only refcount writers are
//! the cross-instance signal router (delivery-side increment — it spans
//! instances and so cannot route through a single instance's stage) and
//! `force_unload` (drain), both mutating `Instance::inflight_refs` directly.

use std::collections::VecDeque;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, InstanceId, Principal, RouteId, TypeCode};
use crate::state::ledger::ResourceLedger;
use crate::state::{EntityMeta, ScheduledActionId, ScheduledEntry};

use super::event::{KernelEvent, ObserverHandle};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct StepStage {
    pub state_ops: Vec<StagedStateDelta>,
    pub events: VecDeque<KernelEvent>,
    pub schedule_deltas: Vec<ScheduledEntryDelta>,
    pub pending_signals: Vec<PendingSignal>,
    pub id_counters: IdCountersDelta,
    pub ledger_delta: ResourceLedgerDelta,
    pub wall_remainder_delta: u128,
    pub local_tick_delta: u64,
    pub observer_eviction_pending: Vec<ObserverHandle>,
}

impl StepStage {
    /// Reset every bucket to its empty/zero state, retaining allocated
    /// capacity so the kernel can reuse one `StepStage` as a per-step scratch
    /// across actions without reallocating the staging buffers. After
    /// `clear()` the stage is behaviourally identical to
    /// `StepStage::default()` (all nine buckets empty / zero), which
    /// `clear_resets_all_buckets` pins. The `let Self { .. }` destructure is
    /// exhaustive on purpose: a newly added bucket fails to compile here until
    /// it is cleared too, so the scratch can never silently leak state across
    /// actions (which would break determinism).
    pub(crate) fn clear(&mut self) {
        let Self {
            state_ops,
            events,
            schedule_deltas,
            pending_signals,
            id_counters,
            ledger_delta,
            wall_remainder_delta,
            local_tick_delta,
            observer_eviction_pending,
        } = self;
        state_ops.clear();
        events.clear();
        schedule_deltas.clear();
        pending_signals.clear();
        *id_counters = IdCountersDelta::default();
        ledger_delta.ops.clear();
        *wall_remainder_delta = 0;
        *local_tick_delta = 0;
        observer_eviction_pending.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum StagedStateDelta {
    SpawnEntity {
        id: EntityId,
        meta: EntityMeta,
    },
    DespawnEntity {
        id: EntityId,
    },
    SetComponent {
        entity: EntityId,
        type_code: TypeCode,
        bytes: Bytes,
        size: u64,
    },
    RemoveComponent {
        entity: EntityId,
        type_code: TypeCode,
        size: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum ScheduledEntryDelta {
    Add(ScheduledEntry),
    Remove(ScheduledActionId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingSignal {
    pub target: InstanceId,
    pub route: RouteId,
    pub payload: Bytes,
    pub principal: Principal,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct IdCountersDelta {
    pub next_entity_advance: u64,
    pub next_scheduled_advance: u64,
    pub next_source_seq_advance: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct ResourceLedgerDelta {
    pub ops: Vec<LedgerOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum LedgerOp {
    AddEntity(EntityId),
    RemoveEntity(EntityId),
    AddComponent {
        entity: EntityId,
        type_code: TypeCode,
        size: u64,
    },
    RemoveComponent {
        entity: EntityId,
        type_code: TypeCode,
        size: u64,
    },
}

/// Project the post-commit component-byte total: `baseline` (the ledger's
/// current `total_bytes`) with every staged component delta in `stage`
/// applied, in saturating `u64` — matching [`ResourceLedger`]'s own
/// arithmetic exactly. `step()` budget enforcement compares this (plus the
/// not-yet-staged current Op) against `memory_budget_bytes`.
///
/// - `AddComponent` adds its caller-declared `size`. A replace over-counts
///   by the prior size (the ledger would adjust by the delta) — conservative,
///   favoring false-deny, so the projection stays an upper bound on the
///   post-commit total.
/// - `RemoveComponent` credits only the bytes the removal will actually free
///   (the ledger's *stored* size), never the untrusted caller-declared
///   `size`, so an inflated remove cannot poison the projection. A component
///   added earlier in this same step is not yet in `ledger`, so its removal
///   credits 0 — conservative.
/// - `AddEntity` / `RemoveEntity` carry no component bytes here.
///
/// Working in `u64` (not `i64`) is deliberate: an oversized add saturates to
/// `u64::MAX` and trips any budget below `u64::MAX`, including budgets above
/// `i64::MAX` that an i64 threshold round-trip would silently disable.
pub(crate) fn projected_component_bytes(
    baseline: u64,
    stage: &StepStage,
    ledger: &ResourceLedger,
) -> u64 {
    let mut total = baseline;
    for op in &stage.ledger_delta.ops {
        match op {
            LedgerOp::AddComponent { size, .. } => {
                total = total.saturating_add(*size);
            }
            LedgerOp::RemoveComponent {
                entity, type_code, ..
            } => {
                let freed = ledger.component_size(*entity, *type_code).unwrap_or(0);
                total = total.saturating_sub(freed);
            }
            LedgerOp::AddEntity(_) | LedgerOp::RemoveEntity(_) => {}
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{CapabilityMask, Tick};

    #[test]
    fn step_stage_default_all_buckets_empty() {
        let s = StepStage::default();
        assert!(s.state_ops.is_empty());
        assert!(s.events.is_empty());
        assert!(s.schedule_deltas.is_empty());
        assert!(s.pending_signals.is_empty());
        assert_eq!(s.id_counters.next_entity_advance, 0);
        assert_eq!(s.id_counters.next_scheduled_advance, 0);
        assert_eq!(s.id_counters.next_source_seq_advance, 0);
        assert!(s.ledger_delta.ops.is_empty());
        assert_eq!(s.wall_remainder_delta, 0);
        assert_eq!(s.local_tick_delta, 0);
        assert!(s.observer_eviction_pending.is_empty());
    }

    #[test]
    fn clear_resets_all_buckets() {
        // Populate every bucket, then assert clear() returns the stage to the
        // same emptiness as StepStage::default() (so scratch reuse cannot leak
        // state across actions).
        let id = EntityId::new(1).unwrap();
        let mut s = StepStage::default();
        s.state_ops.push(StagedStateDelta::DespawnEntity { id });
        s.events.push_back(KernelEvent::ActionExecuted {
            instance: InstanceId::new(1).unwrap(),
            action_type: TypeCode(1),
            at: Tick(1),
        });
        s.schedule_deltas
            .push(ScheduledEntryDelta::Remove(ScheduledActionId::new(1).unwrap()));
        s.pending_signals.push(PendingSignal {
            target: InstanceId::new(1).unwrap(),
            route: RouteId(1),
            payload: Bytes::from_static(b"x"),
            principal: Principal::System,
        });
        s.id_counters.next_entity_advance = 9;
        s.id_counters.next_scheduled_advance = 9;
        s.id_counters.next_source_seq_advance = 9;
        s.ledger_delta.ops.push(LedgerOp::AddEntity(id));
        s.wall_remainder_delta = 12345;
        s.local_tick_delta = 7;

        s.clear();

        assert!(s.state_ops.is_empty());
        assert!(s.events.is_empty());
        assert!(s.schedule_deltas.is_empty());
        assert!(s.pending_signals.is_empty());
        assert_eq!(s.id_counters.next_entity_advance, 0);
        assert_eq!(s.id_counters.next_scheduled_advance, 0);
        assert_eq!(s.id_counters.next_source_seq_advance, 0);
        assert!(s.ledger_delta.ops.is_empty());
        assert_eq!(s.wall_remainder_delta, 0);
        assert_eq!(s.local_tick_delta, 0);
        assert!(s.observer_eviction_pending.is_empty());
    }

    #[test]
    fn staged_state_delta_variants_clone() {
        let id = EntityId::new(1).unwrap();
        let meta = EntityMeta {
            owner: Principal::System,
            created: Tick(0),
        };
        let _ = StagedStateDelta::SpawnEntity { id, meta }.clone();
        let _ = StagedStateDelta::DespawnEntity { id }.clone();
        let _ = StagedStateDelta::SetComponent {
            entity: id,
            type_code: TypeCode(1),
            bytes: Bytes::from_static(b"x"),
            size: 1,
        }
        .clone();
        let _ = StagedStateDelta::RemoveComponent {
            entity: id,
            type_code: TypeCode(1),
            size: 1,
        }
        .clone();
    }

    #[test]
    fn scheduled_entry_delta_variants() {
        let entry = ScheduledEntry {
            id: ScheduledActionId::new(1).unwrap(),
            at: Tick(0),
            actor: None,
            principal: Principal::System,
            action_type_code: TypeCode(0),
            action_bytes: vec![],
            caps_ceiling: CapabilityMask::all(),
        };
        let _ = ScheduledEntryDelta::Add(entry).clone();
        let _ = ScheduledEntryDelta::Remove(ScheduledActionId::new(1).unwrap()).clone();
    }

    #[test]
    fn projected_oversized_add_saturates_no_negative_wrap() {
        // Regression: a size above i64::MAX must saturate the projection to
        // u64::MAX (not wrap negative / clamp low), so an oversized component
        // trips any budget below u64::MAX rather than bypassing the gate.
        let id = EntityId::new(1).unwrap();
        let mut stage = StepStage::default();
        stage.ledger_delta.ops.push(LedgerOp::AddComponent {
            entity: id,
            type_code: TypeCode(1),
            size: u64::MAX,
        });
        let ledger = ResourceLedger::new();
        assert_eq!(projected_component_bytes(0, &stage, &ledger), u64::MAX);
    }

    #[test]
    fn projected_remove_credits_stored_size_not_caller_size() {
        // Regression: a RemoveComponent with an inflated caller `size` must
        // NOT poison the projection — the credit is the ledger's stored size.
        let id = EntityId::new(1).unwrap();
        let mut ledger = ResourceLedger::new();
        ledger.add_entity(id);
        ledger.add_component(id, TypeCode(1), 100);
        let mut stage = StepStage::default();
        stage.ledger_delta.ops.push(LedgerOp::RemoveComponent {
            entity: id,
            type_code: TypeCode(1),
            size: u64::MAX, // bogus inflated free — must be ignored
        });
        // Baseline 100, credit the stored 100 (not u64::MAX) → 0.
        assert_eq!(projected_component_bytes(100, &stage, &ledger), 0);
    }

    #[test]
    fn projected_remove_of_unaccounted_component_credits_zero() {
        // A removal of a component the ledger does not know (e.g. added
        // earlier in the same step, not yet applied) credits 0 — conservative.
        let id = EntityId::new(1).unwrap();
        let ledger = ResourceLedger::new();
        let mut stage = StepStage::default();
        stage.ledger_delta.ops.push(LedgerOp::RemoveComponent {
            entity: id,
            type_code: TypeCode(1),
            size: 50,
        });
        assert_eq!(projected_component_bytes(0, &stage, &ledger), 0);
    }

    #[test]
    fn ledger_op_variants() {
        let id = EntityId::new(1).unwrap();
        let _ = LedgerOp::AddEntity(id).clone();
        let _ = LedgerOp::RemoveEntity(id).clone();
        let _ = LedgerOp::AddComponent {
            entity: id,
            type_code: TypeCode(1),
            size: 100,
        }
        .clone();
        let _ = LedgerOp::RemoveComponent {
            entity: id,
            type_code: TypeCode(1),
            size: 100,
        }
        .clone();
    }

    #[test]
    fn pending_signal_construction() {
        let s = PendingSignal {
            target: InstanceId::new(1).unwrap(),
            route: RouteId(1),
            payload: Bytes::from_static(b"hello"),
            principal: Principal::System,
        };
        assert_eq!(s.payload.len(), 5);
    }
}

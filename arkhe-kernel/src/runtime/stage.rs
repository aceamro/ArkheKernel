//! `StepStage` — transactional COW staging for one `step()` (10 buckets).
//!
//! Every commit-conditional write the kernel performs during a step is
//! buffered here; on commit, `Instance::apply_stage` drains in canonical
//! canonical order; on rollback, the stage is dropped without effect.
//!
//! Buckets (10):
//! 1. `state_ops` — entity/component mutations
//! 2. `events` — KernelEvent emissions (kernel-level drain)
//! 3. `schedule_deltas` — scheduler add/cancel
//! 4. `pending_signals` — outbound IPC (kernel routes post-commit)
//! 5. `id_counters` — monotonic ID counter advances
//! 6. `ledger_delta` — ResourceLedger updates
//! 7. `inflight_refs_delta` — drain-refcount per RouteId (signed delta)
//! 8. `wall_remainder_delta` — sub-tick time accumulator advance
//! 9. `local_tick_delta` — logical tick advance
//! 10. `observer_eviction_pending` — observers slated for eviction

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, InstanceId, Principal, RouteId, TypeCode};
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
    pub inflight_refs_delta: BTreeMap<RouteId, i32>,
    pub wall_remainder_delta: u128,
    pub local_tick_delta: u64,
    pub observer_eviction_pending: Vec<ObserverHandle>,
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

/// Net component-byte delta accumulated in `stage.ledger_delta` so far.
/// Used by `step()` budget enforcement to project the post-commit total
/// before each Op is dispatched. `RemoveEntity` does not carry per-entity
/// byte counts at this layer — its bytes are recovered from the ledger
/// at apply time, so this helper is conservative (under-counts freed
/// bytes within a single step), favoring false-deny over false-allow.
pub(crate) fn bytes_delta(stage: &StepStage) -> i64 {
    let mut d: i64 = 0;
    for op in &stage.ledger_delta.ops {
        match op {
            LedgerOp::AddComponent { size, .. } => {
                d = d.saturating_add(*size as i64);
            }
            LedgerOp::RemoveComponent { size, .. } => {
                d = d.saturating_sub(*size as i64);
            }
            LedgerOp::AddEntity(_) | LedgerOp::RemoveEntity(_) => {}
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Tick;

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
        assert!(s.inflight_refs_delta.is_empty());
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
        };
        let _ = ScheduledEntryDelta::Add(entry).clone();
        let _ = ScheduledEntryDelta::Remove(ScheduledActionId::new(1).unwrap()).clone();
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

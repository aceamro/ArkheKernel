//! Stage application — runtime-side `apply_stage` / `discard_stage`.
//!
//! Lives in `runtime/` so the layer DAG `abi → state → runtime → persist`
//! is preserved (R4-X) — placing it on `Instance` would force `state` to
//! import `runtime::StepStage`.
//!
//! Application is panic-free (totality contract): every operation
//! uses saturating arithmetic and `if let Some(...)` style guards.

use super::stage::{LedgerOp, ScheduledEntryDelta, StagedStateDelta, StepStage};
use crate::state::Instance;

/// Apply a `StepStage` to `instance` in canonical order:
///
/// 1. `id_counters`
/// 2. `state_ops`
/// 3. `ledger_delta`
/// 4. `inflight_refs_delta`
/// 5. `schedule_deltas`
/// 6. `wall_remainder` and `local_tick`
///
/// Kernel-level buckets `pending_signals` / `events` / `observer_eviction`
/// are drained by Kernel post-commit (chunks 3b/c) — no-op here.
pub(crate) fn apply_stage(instance: &mut Instance, stage: StepStage) {
    // 1. id_counters — monotonic; no preconditions.
    {
        let c = instance.id_counters_mut();
        c.next_entity = c
            .next_entity
            .saturating_add(stage.id_counters.next_entity_advance);
        c.next_scheduled = c
            .next_scheduled
            .saturating_add(stage.id_counters.next_scheduled_advance);
        c.next_source_seq = c
            .next_source_seq
            .saturating_add(stage.id_counters.next_source_seq_advance);
    }

    // 2. state_ops — entity/component mutation.
    for op in stage.state_ops {
        match op {
            StagedStateDelta::SpawnEntity { id, meta } => {
                instance.insert_entity(id, meta);
            }
            StagedStateDelta::DespawnEntity { id } => {
                instance.remove_entity(id);
            }
            StagedStateDelta::SetComponent {
                entity,
                type_code,
                bytes,
                ..
            } => {
                instance.insert_component((entity, type_code), bytes);
            }
            StagedStateDelta::RemoveComponent {
                entity, type_code, ..
            } => {
                instance.remove_component((entity, type_code));
            }
        }
    }

    // 3. ledger_delta — accounting follows entity/component apply.
    {
        let ledger = instance.ledger_mut();
        for lop in stage.ledger_delta.ops {
            match lop {
                LedgerOp::AddEntity(id) => {
                    let _ = ledger.add_entity(id);
                }
                LedgerOp::RemoveEntity(id) => {
                    let _ = ledger.remove_entity(id);
                }
                LedgerOp::AddComponent {
                    entity,
                    type_code,
                    size,
                } => {
                    let _ = ledger.add_component(entity, type_code, size);
                }
                LedgerOp::RemoveComponent {
                    entity,
                    type_code,
                    size,
                } => {
                    let _ = ledger.remove_component(entity, type_code, size);
                }
            }
        }
    }

    // 4. inflight_refs_delta — i32 deltas applied to u32 table.
    {
        let refs = instance.inflight_refs_mut();
        for (route_id, delta) in stage.inflight_refs_delta {
            let entry = refs.entry(route_id).or_insert(0);
            if delta >= 0 {
                *entry = entry.saturating_add(delta as u32);
            } else {
                *entry = entry.saturating_sub(delta.unsigned_abs());
            }
            if *entry == 0 {
                refs.remove(&route_id);
            }
        }
    }

    // 5. schedule_deltas — scheduler mutation. NOTE: the Add path passes
    // entry data to `Scheduler::schedule` (which assigns a fresh ID); the
    // staged `entry.id` is *not* preserved at this layer. Pre-assigned
    // scheduling is reserved (deferred) for when the stage will carry
    // the canonical ID up-front.
    {
        let scheduler = instance.scheduler_mut();
        for sd in stage.schedule_deltas {
            match sd {
                ScheduledEntryDelta::Add(entry) => {
                    let _ = scheduler.schedule(
                        entry.at,
                        entry.actor,
                        entry.principal,
                        entry.action_type_code,
                        entry.action_bytes,
                    );
                }
                ScheduledEntryDelta::Remove(id) => {
                    let _ = scheduler.cancel(id);
                }
            }
        }
    }

    // 6/7/9. pending_signals / events / observer_eviction_pending —
    // kernel-level state; Kernel drains these post-commit (chunks 3b/c).
    // Drop here so the owned stage releases the resources.
    let _ = stage.pending_signals;
    let _ = stage.events;
    let _ = stage.observer_eviction_pending;

    // 8. wall_remainder + local_tick advance.
    instance.advance_wall_remainder(stage.wall_remainder_delta);
    instance.advance_local_tick(stage.local_tick_delta);
}

/// Drop a `StepStage` without applying any of its deltas (rollback path).
/// `_instance` is taken as `&mut` to mirror `apply_stage`'s signature so
/// callers can pivot between the two without lifetime gymnastics.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn discard_stage(_instance: &mut Instance, _stage: StepStage) {
    // Owned stage drops at function exit. No mutation to instance.
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    use crate::abi::{CapabilityMask, EntityId, InstanceId, Principal, RouteId, Tick, TypeCode};
    use crate::runtime::stage::{IdCountersDelta, LedgerOp, ScheduledEntryDelta, StagedStateDelta};
    use crate::state::{
        EntityMeta, Instance, InstanceConfig, QuotaReductionPolicy, ScheduledActionId,
        ScheduledEntry,
    };

    fn id(n: u64) -> InstanceId {
        InstanceId::new(n).unwrap()
    }
    fn entity(n: u64) -> EntityId {
        EntityId::new(n).unwrap()
    }
    fn cfg() -> InstanceConfig {
        InstanceConfig {
            default_caps: CapabilityMask::default(),
            max_entities: 100,
            max_scheduled: 1000,
            memory_budget_bytes: 1 << 20,
            parent: None,
            quota_reduction: QuotaReductionPolicy::default(),
        }
    }

    #[test]
    fn apply_empty_stage_leaves_instance_untouched() {
        let mut inst = Instance::new(id(1), cfg());
        apply_stage(&mut inst, StepStage::default());
        assert_eq!(inst.entities_len(), 0);
        assert_eq!(inst.components_len(), 0);
        assert_eq!(inst.local_tick(), 0);
        assert_eq!(inst.wall_remainder(), 0);
        assert_eq!(inst.ledger().total_entities(), 0);
        assert_eq!(inst.id_counters().next_entity, 0);
    }

    #[test]
    fn apply_spawn_entity() {
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage::default();
        stage.state_ops.push(StagedStateDelta::SpawnEntity {
            id: entity(1),
            meta: EntityMeta {
                owner: Principal::System,
                created: Tick(0),
            },
        });
        apply_stage(&mut inst, stage);
        assert_eq!(inst.entities_len(), 1);
    }

    #[test]
    fn apply_despawn_entity() {
        let mut inst = Instance::new(id(1), cfg());
        let mut spawn = StepStage::default();
        spawn.state_ops.push(StagedStateDelta::SpawnEntity {
            id: entity(1),
            meta: EntityMeta {
                owner: Principal::System,
                created: Tick(0),
            },
        });
        apply_stage(&mut inst, spawn);
        assert_eq!(inst.entities_len(), 1);

        let mut despawn = StepStage::default();
        despawn
            .state_ops
            .push(StagedStateDelta::DespawnEntity { id: entity(1) });
        apply_stage(&mut inst, despawn);
        assert_eq!(inst.entities_len(), 0);
    }

    #[test]
    fn apply_set_and_remove_component() {
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage::default();
        stage.state_ops.push(StagedStateDelta::SetComponent {
            entity: entity(1),
            type_code: TypeCode(7),
            bytes: Bytes::from_static(b"data"),
            size: 4,
        });
        apply_stage(&mut inst, stage);
        assert_eq!(inst.components_len(), 1);

        let mut rm = StepStage::default();
        rm.state_ops.push(StagedStateDelta::RemoveComponent {
            entity: entity(1),
            type_code: TypeCode(7),
            size: 4,
        });
        apply_stage(&mut inst, rm);
        assert_eq!(inst.components_len(), 0);
    }

    #[test]
    fn apply_ledger_delta_balanced() {
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage::default();
        stage.ledger_delta.ops.push(LedgerOp::AddEntity(entity(1)));
        stage.ledger_delta.ops.push(LedgerOp::AddComponent {
            entity: entity(1),
            type_code: TypeCode(1),
            size: 100,
        });
        apply_stage(&mut inst, stage);
        assert_eq!(inst.ledger().total_entities(), 1);
        assert_eq!(inst.ledger().total_bytes(), 100);
        assert_eq!(inst.ledger().entity_bytes(entity(1)), 100);
    }

    #[test]
    fn apply_id_counters_advance() {
        let mut inst = Instance::new(id(1), cfg());
        let stage = StepStage {
            id_counters: IdCountersDelta {
                next_entity_advance: 5,
                next_scheduled_advance: 3,
                next_source_seq_advance: 7,
            },
            ..Default::default()
        };
        apply_stage(&mut inst, stage);
        assert_eq!(inst.id_counters().next_entity, 5);
        assert_eq!(inst.id_counters().next_scheduled, 3);
        assert_eq!(inst.id_counters().next_source_seq, 7);
    }

    #[test]
    fn apply_inflight_refs_positive_then_negative_to_zero() {
        let mut inst = Instance::new(id(1), cfg());
        let route = RouteId(42);

        let up = StepStage {
            inflight_refs_delta: [(route, 3)].into_iter().collect(),
            ..Default::default()
        };
        apply_stage(&mut inst, up);
        assert_eq!(inst.inflight_refs_for(route), 3);

        let down = StepStage {
            inflight_refs_delta: [(route, -3)].into_iter().collect(),
            ..Default::default()
        };
        apply_stage(&mut inst, down);
        assert_eq!(inst.inflight_refs_for(route), 0);
        assert_eq!(inst.inflight_refs_len(), 0);
    }

    #[test]
    fn apply_wall_and_local_tick_advance() {
        let mut inst = Instance::new(id(1), cfg());
        let stage = StepStage {
            wall_remainder_delta: 12345,
            local_tick_delta: 7,
            ..Default::default()
        };
        apply_stage(&mut inst, stage);
        assert_eq!(inst.wall_remainder(), 12345);
        assert_eq!(inst.local_tick(), 7);
    }

    #[test]
    fn apply_schedule_delta_add_inserts_into_scheduler() {
        let mut inst = Instance::new(id(1), cfg());
        let stage = StepStage {
            schedule_deltas: vec![ScheduledEntryDelta::Add(ScheduledEntry {
                id: ScheduledActionId::new(1).unwrap(),
                at: Tick(10),
                actor: None,
                principal: Principal::System,
                action_type_code: TypeCode(0),
                action_bytes: vec![1, 2, 3],
            })],
            ..Default::default()
        };
        apply_stage(&mut inst, stage);
        assert_eq!(inst.scheduler().len(), 1);
    }

    #[test]
    fn discard_stage_is_noop() {
        let mut inst = Instance::new(id(1), cfg());
        let stage = StepStage {
            state_ops: vec![StagedStateDelta::SpawnEntity {
                id: entity(1),
                meta: EntityMeta {
                    owner: Principal::System,
                    created: Tick(0),
                },
            }],
            local_tick_delta: 99,
            ..Default::default()
        };
        discard_stage(&mut inst, stage);
        assert_eq!(inst.entities_len(), 0);
        assert_eq!(inst.local_tick(), 0);
    }
}

//! Stage application — runtime-side `apply_stage`.
//!
//! Lives in `runtime/` so the layer DAG `abi → state → runtime → persist`
//! is preserved (R4-X) — placing it on `Instance` would force `state` to
//! import `runtime::StepStage`.
//!
//! `apply_stage` borrows the stage `&mut` and drains the buckets it commits,
//! so the kernel can reuse one `StepStage` scratch across actions. The
//! rollback path needs no separate function: the kernel simply skips
//! `apply_stage` and `clear()`s the scratch before the next action.
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
/// are drained by Kernel post-commit (chunks 3b/c) — left untouched here.
///
/// `stage` is borrowed `&mut` (not consumed): the kernel owns one
/// `StepStage` scratch and reuses it across actions, so this function drains
/// the buckets it applies (retaining their capacity) and leaves the
/// kernel-level buckets for the caller. The caller `clear()`s the scratch
/// before the next action.
pub(crate) fn apply_stage(instance: &mut Instance, stage: &mut StepStage) {
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
    for op in stage.state_ops.drain(..) {
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
                // Gate the component store on entity existence, mirroring
                // `ResourceLedger::add_component` (which rejects an unknown
                // entity). Without this guard the component map and the
                // ledger diverge: the bytes would be stored but unaccounted,
                // leaving them invisible to `memory_budget_bytes` and to the
                // ledger baseline (a cross-step budget bypass and unbounded
                // growth). An in-stage `SpawnEntity` for the same entity is
                // already applied earlier in this `state_ops` loop, so a
                // spawn-then-set within one step still stores correctly.
                if instance.entity_meta(entity).is_some() {
                    instance.insert_component((entity, type_code), bytes);
                }
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
        for lop in stage.ledger_delta.ops.drain(..) {
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
        // `mem::take` drains the map (retaining nothing) while preserving the
        // ascending-RouteId iteration order of a by-value walk.
        for (route_id, delta) in std::mem::take(&mut stage.inflight_refs_delta) {
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
        for sd in stage.schedule_deltas.drain(..) {
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
    // kernel-level buckets; Kernel reads/drains these post-commit and then
    // `clear()`s the whole scratch before the next action. Left untouched
    // here (no longer owned, so nothing to drop).

    // 8. wall_remainder + local_tick advance.
    instance.advance_wall_remainder(stage.wall_remainder_delta);
    instance.advance_local_tick(stage.local_tick_delta);
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
        apply_stage(&mut inst, &mut StepStage::default());
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
        apply_stage(&mut inst, &mut stage);
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
        apply_stage(&mut inst, &mut spawn);
        assert_eq!(inst.entities_len(), 1);

        let mut despawn = StepStage::default();
        despawn
            .state_ops
            .push(StagedStateDelta::DespawnEntity { id: entity(1) });
        apply_stage(&mut inst, &mut despawn);
        assert_eq!(inst.entities_len(), 0);
    }

    #[test]
    fn apply_set_and_remove_component() {
        let mut inst = Instance::new(id(1), cfg());
        // Spawn the entity first: SetComponent on a known entity is the
        // valid history (an unknown-entity set is a no-op — see
        // `apply_set_component_on_unknown_entity_is_noop`).
        let mut spawn = StepStage::default();
        spawn.state_ops.push(StagedStateDelta::SpawnEntity {
            id: entity(1),
            meta: EntityMeta {
                owner: Principal::System,
                created: Tick(0),
            },
        });
        apply_stage(&mut inst, &mut spawn);

        let mut stage = StepStage::default();
        stage.state_ops.push(StagedStateDelta::SetComponent {
            entity: entity(1),
            type_code: TypeCode(7),
            bytes: Bytes::from_static(b"data"),
            size: 4,
        });
        apply_stage(&mut inst, &mut stage);
        assert_eq!(inst.components_len(), 1);

        let mut rm = StepStage::default();
        rm.state_ops.push(StagedStateDelta::RemoveComponent {
            entity: entity(1),
            type_code: TypeCode(7),
            size: 4,
        });
        apply_stage(&mut inst, &mut rm);
        assert_eq!(inst.components_len(), 0);
    }

    #[test]
    fn apply_set_component_on_unknown_entity_is_noop() {
        // Regression: a SetComponent on an entity that was never spawned must
        // NOT store the component, so the component map and the ledger stay
        // consistent (the ledger already rejects the unknown entity). Storing
        // it would leave unaccounted bytes that bypass `memory_budget_bytes`.
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage::default();
        stage.state_ops.push(StagedStateDelta::SetComponent {
            entity: entity(999),
            type_code: TypeCode(7),
            bytes: Bytes::from_static(b"orphan"),
            size: 6,
        });
        stage.ledger_delta.ops.push(LedgerOp::AddComponent {
            entity: entity(999),
            type_code: TypeCode(7),
            size: 6,
        });
        apply_stage(&mut inst, &mut stage);
        assert_eq!(inst.components_len(), 0, "orphan component must not be stored");
        assert_eq!(
            inst.ledger().total_bytes(),
            0,
            "ledger must not account an unknown-entity component"
        );
        assert!(
            inst.component(entity(999), TypeCode(7)).is_none(),
            "InstanceView must not surface the orphan component"
        );
    }

    #[test]
    fn apply_spawn_then_set_in_same_stage_stores_component() {
        // The in-stage spawn is applied before the set in the state_ops loop,
        // so a spawn-then-set within one step stores correctly (the guard
        // sees the just-spawned entity).
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage::default();
        stage.state_ops.push(StagedStateDelta::SpawnEntity {
            id: entity(5),
            meta: EntityMeta {
                owner: Principal::System,
                created: Tick(0),
            },
        });
        stage.state_ops.push(StagedStateDelta::SetComponent {
            entity: entity(5),
            type_code: TypeCode(7),
            bytes: Bytes::from_static(b"data"),
            size: 4,
        });
        stage.ledger_delta.ops.push(LedgerOp::AddEntity(entity(5)));
        stage.ledger_delta.ops.push(LedgerOp::AddComponent {
            entity: entity(5),
            type_code: TypeCode(7),
            size: 4,
        });
        apply_stage(&mut inst, &mut stage);
        assert_eq!(inst.components_len(), 1);
        assert_eq!(inst.ledger().total_bytes(), 4);
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
        apply_stage(&mut inst, &mut stage);
        assert_eq!(inst.ledger().total_entities(), 1);
        assert_eq!(inst.ledger().total_bytes(), 100);
        assert_eq!(inst.ledger().entity_bytes(entity(1)), 100);
    }

    #[test]
    fn apply_id_counters_advance() {
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage {
            id_counters: IdCountersDelta {
                next_entity_advance: 5,
                next_scheduled_advance: 3,
                next_source_seq_advance: 7,
            },
            ..Default::default()
        };
        apply_stage(&mut inst, &mut stage);
        assert_eq!(inst.id_counters().next_entity, 5);
        assert_eq!(inst.id_counters().next_scheduled, 3);
        assert_eq!(inst.id_counters().next_source_seq, 7);
    }

    #[test]
    fn apply_inflight_refs_positive_then_negative_to_zero() {
        let mut inst = Instance::new(id(1), cfg());
        let route = RouteId(42);

        let mut up = StepStage {
            inflight_refs_delta: [(route, 3)].into_iter().collect(),
            ..Default::default()
        };
        apply_stage(&mut inst, &mut up);
        assert_eq!(inst.inflight_refs_for(route), 3);

        let mut down = StepStage {
            inflight_refs_delta: [(route, -3)].into_iter().collect(),
            ..Default::default()
        };
        apply_stage(&mut inst, &mut down);
        assert_eq!(inst.inflight_refs_for(route), 0);
        assert_eq!(inst.inflight_refs_len(), 0);
    }

    #[test]
    fn apply_wall_and_local_tick_advance() {
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage {
            wall_remainder_delta: 12345,
            local_tick_delta: 7,
            ..Default::default()
        };
        apply_stage(&mut inst, &mut stage);
        assert_eq!(inst.wall_remainder(), 12345);
        assert_eq!(inst.local_tick(), 7);
    }

    #[test]
    fn apply_schedule_delta_add_inserts_into_scheduler() {
        let mut inst = Instance::new(id(1), cfg());
        let mut stage = StepStage {
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
        apply_stage(&mut inst, &mut stage);
        assert_eq!(inst.scheduler().len(), 1);
    }

    #[test]
    fn apply_then_clear_reuse_is_state_clean() {
        // Scratch-reuse contract: applying one stage, then clear()ing it and
        // applying a second through the SAME StepStage, must commit the second
        // without any residue from the first (drains + clear leave no leak).
        let mut inst = Instance::new(id(1), cfg());
        let mut scratch = StepStage::default();
        scratch.state_ops.push(StagedStateDelta::SpawnEntity {
            id: entity(1),
            meta: EntityMeta {
                owner: Principal::System,
                created: Tick(0),
            },
        });
        scratch.ledger_delta.ops.push(LedgerOp::AddEntity(entity(1)));
        scratch.local_tick_delta = 1;
        apply_stage(&mut inst, &mut scratch);
        scratch.clear();

        scratch.state_ops.push(StagedStateDelta::SpawnEntity {
            id: entity(2),
            meta: EntityMeta {
                owner: Principal::System,
                created: Tick(0),
            },
        });
        scratch.ledger_delta.ops.push(LedgerOp::AddEntity(entity(2)));
        scratch.local_tick_delta = 1;
        apply_stage(&mut inst, &mut scratch);

        // Exactly the two spawned entities and two tick advances — no residue.
        assert_eq!(inst.entities_len(), 2);
        assert_eq!(inst.ledger().total_entities(), 2);
        assert_eq!(inst.local_tick(), 2);
    }
}

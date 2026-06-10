//! Effect dispatcher — translate an `Effect<'i, Authorized>` into
//! `StepStage` deltas.
//!
//! Inputs: an authorized Effect (Op + originating principal + branded
//! instance), the running `StepStage`, current Tick, and the kernel's
//! `next_scheduled_id` counter.
//!
//! Output: side-effect on `StepStage` only — no Instance mutation here;
//! `runtime::apply::apply_stage` commits the stage post-dispatch.

use crate::abi::{CapabilityMask, Principal, Tick};
use crate::state::{Authorized, Effect, EntityMeta, Op, ScheduledActionId, ScheduledEntry};

use super::event::KernelEvent;
use super::stage::{LedgerOp, PendingSignal, ScheduledEntryDelta, StagedStateDelta, StepStage};

/// Translate one authorized Effect into corresponding `StepStage` writes.
///
/// `next_scheduled_id` is monotonically advanced for `Op::ScheduleAction`
/// to keep `ScheduledActionId` allocation deterministic across the step
/// (id_counters tuple includes scheduled-id; staged so rollback
/// rewinds it via `id_counters.next_scheduled_advance`).
pub(crate) fn dispatch<'i>(
    effect: Effect<'i, Authorized>,
    stage: &mut StepStage,
    now: Tick,
    next_scheduled_id: &mut u64,
    parent_caps: CapabilityMask,
) {
    let instance_id = effect.instance_id;
    let effect_principal = match &effect.principal {
        Principal::Unauthenticated => Principal::Unauthenticated,
        Principal::External(e) => Principal::External(*e),
        Principal::System => Principal::System,
    };
    match effect.op {
        Op::SpawnEntity { id, owner } => {
            stage.state_ops.push(StagedStateDelta::SpawnEntity {
                id,
                meta: EntityMeta {
                    owner,
                    created: now,
                },
            });
            stage.ledger_delta.ops.push(LedgerOp::AddEntity(id));
            stage.id_counters.next_entity_advance =
                stage.id_counters.next_entity_advance.saturating_add(1);
        }
        Op::DespawnEntity { id } => {
            stage.state_ops.push(StagedStateDelta::DespawnEntity { id });
            stage.ledger_delta.ops.push(LedgerOp::RemoveEntity(id));
        }
        Op::SetComponent {
            entity,
            type_code,
            bytes,
            size,
        } => {
            stage.state_ops.push(StagedStateDelta::SetComponent {
                entity,
                type_code,
                bytes,
                size,
            });
            stage.ledger_delta.ops.push(LedgerOp::AddComponent {
                entity,
                type_code,
                size,
            });
        }
        Op::RemoveComponent {
            entity,
            type_code,
            size,
        } => {
            stage.state_ops.push(StagedStateDelta::RemoveComponent {
                entity,
                type_code,
                size,
            });
            stage.ledger_delta.ops.push(LedgerOp::RemoveComponent {
                entity,
                type_code,
                size,
            });
        }
        Op::EmitEvent {
            actor,
            event_type_code,
            event_bytes,
        } => {
            stage.events.push_back(KernelEvent::DomainEventEmitted {
                instance: instance_id,
                actor,
                event_type_code,
                bytes: event_bytes,
            });
        }
        Op::ScheduleAction {
            at,
            actor,
            action_type_code,
            action_bytes,
        } => {
            *next_scheduled_id = next_scheduled_id.saturating_add(1);
            let id = ScheduledActionId::new(*next_scheduled_id)
                .expect("next_scheduled_id incremented before use; non-zero");
            stage
                .schedule_deltas
                .push(ScheduledEntryDelta::Add(ScheduledEntry {
                    id,
                    at,
                    actor,
                    // The scheduled child inherits the scheduling action's
                    // principal and runs under a ceiling equal to the parent's
                    // effective caps — privilege can only narrow, never widen
                    // (no time-shifted escalation; action_principal is gone).
                    principal: effect_principal,
                    action_type_code,
                    action_bytes: action_bytes.to_vec(),
                    caps_ceiling: parent_caps,
                }));
            stage.id_counters.next_scheduled_advance =
                stage.id_counters.next_scheduled_advance.saturating_add(1);
        }
        Op::SendSignal {
            target,
            route,
            payload,
        } => {
            // Stage the outbound signal only. The in-flight refcount is NOT
            // incremented here — it is credited at DELIVERY time in the apply
            // router (a delivered signal increments; a dropped one does not),
            // so the refcount is a conserved quantity, never a speculative
            // dangling increment.
            stage.pending_signals.push(PendingSignal {
                target,
                route,
                payload,
                principal: effect_principal,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    use crate::abi::{CapabilityMask, EntityId, InstanceId, Principal, RouteId, Tick, TypeCode};
    use crate::state::authz::authorize;
    use crate::state::{Effect, Op, Unverified};

    fn inst() -> InstanceId {
        InstanceId::new(1).unwrap()
    }
    fn ent(n: u64) -> EntityId {
        EntityId::new(n).unwrap()
    }
    fn caps() -> CapabilityMask {
        CapabilityMask::all()
    }

    fn auth_system(op: Op) -> Effect<'static, crate::state::Authorized> {
        let e: Effect<'static, Unverified> = Effect::new(inst(), Principal::System, op);
        authorize(CapabilityMask::SYSTEM, e).expect("system always authorized")
    }

    #[test]
    fn dispatch_spawn_entity_pushes_state_op_ledger_and_advances_counter() {
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let e = auth_system(Op::SpawnEntity {
            id: ent(1),
            owner: Principal::System,
        });
        dispatch(e, &mut stage, Tick(5), &mut next_id, caps());
        assert_eq!(stage.state_ops.len(), 1);
        assert_eq!(stage.ledger_delta.ops.len(), 1);
        assert_eq!(stage.id_counters.next_entity_advance, 1);
        assert_eq!(next_id, 0); // not advanced (no schedule)
    }

    #[test]
    fn dispatch_despawn_entity_pushes_state_and_ledger_remove() {
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let e = auth_system(Op::DespawnEntity { id: ent(1) });
        dispatch(e, &mut stage, Tick(0), &mut next_id, caps());
        assert_eq!(stage.state_ops.len(), 1);
        assert_eq!(stage.ledger_delta.ops.len(), 1);
    }

    #[test]
    fn dispatch_set_component_pushes_state_and_ledger_add() {
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let e = auth_system(Op::SetComponent {
            entity: ent(1),
            type_code: TypeCode(7),
            bytes: Bytes::from_static(b"data"),
            size: 4,
        });
        dispatch(e, &mut stage, Tick(0), &mut next_id, caps());
        assert_eq!(stage.state_ops.len(), 1);
        assert_eq!(stage.ledger_delta.ops.len(), 1);
    }

    #[test]
    fn dispatch_remove_component_pushes_state_and_ledger_remove() {
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let e = auth_system(Op::RemoveComponent {
            entity: ent(1),
            type_code: TypeCode(7),
            size: 4,
        });
        dispatch(e, &mut stage, Tick(0), &mut next_id, caps());
        assert_eq!(stage.state_ops.len(), 1);
        assert_eq!(stage.ledger_delta.ops.len(), 1);
    }

    #[test]
    fn dispatch_emit_event_pushes_kernel_event() {
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let e = auth_system(Op::EmitEvent {
            actor: Some(ent(1)),
            event_type_code: TypeCode(2),
            event_bytes: Bytes::from_static(b"evt"),
        });
        dispatch(e, &mut stage, Tick(0), &mut next_id, caps());
        assert_eq!(stage.events.len(), 1);
        match stage.events.front().unwrap() {
            KernelEvent::DomainEventEmitted {
                event_type_code, ..
            } => {
                assert_eq!(*event_type_code, TypeCode(2));
            }
            _ => panic!("expected DomainEventEmitted"),
        }
    }

    #[test]
    fn dispatch_schedule_action_advances_id_and_pushes_delta() {
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let e = auth_system(Op::ScheduleAction {
            at: Tick(10),
            actor: None,
            action_type_code: TypeCode(3),
            action_bytes: Bytes::from_static(b"a"),
        });
        dispatch(e, &mut stage, Tick(0), &mut next_id, caps());
        assert_eq!(stage.schedule_deltas.len(), 1);
        assert_eq!(next_id, 1);
        assert_eq!(stage.id_counters.next_scheduled_advance, 1);
        // The scheduled child inherits the dispatching principal (System here)
        // and the parent's caps ceiling — not a domain-supplied principal.
        match &stage.schedule_deltas[0] {
            ScheduledEntryDelta::Add(entry) => {
                assert!(matches!(entry.principal, Principal::System));
                assert_eq!(entry.caps_ceiling, caps());
            }
            ScheduledEntryDelta::Remove(_) => panic!("expected Add"),
        }
    }

    #[test]
    fn dispatch_send_signal_stages_pending_without_speculative_refcount() {
        // The refcount is credited at delivery (apply router), NOT at dispatch
        // — so dispatch stages only the pending signal. There is no staged
        // refcount delta at all (the bucket was removed); a SendSignal can only
        // produce a pending_signal, which closes the dangling-increment
        // half-commit structurally.
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let route = RouteId(42);
        let e = auth_system(Op::SendSignal {
            target: inst(),
            route,
            payload: Bytes::from_static(b"hello"),
        });
        dispatch(e, &mut stage, Tick(0), &mut next_id, caps());
        assert_eq!(stage.pending_signals.len(), 1);
    }

    #[test]
    fn dispatch_send_signal_twice_stages_two_pending() {
        let mut stage = StepStage::default();
        let mut next_id: u64 = 0;
        let route = RouteId(42);
        for _ in 0..3 {
            let e = auth_system(Op::SendSignal {
                target: inst(),
                route,
                payload: Bytes::new(),
            });
            dispatch(e, &mut stage, Tick(0), &mut next_id, caps());
        }
        assert_eq!(stage.pending_signals.len(), 3);
    }
}

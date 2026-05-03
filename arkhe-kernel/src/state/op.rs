//! `Op` — kernel-level effect payload (ABI sub-enums).
//!
//! Each variant is the "what to do" intent; `Effect<S, 'i>` wraps it with
//! authorization state, instance brand, and originating principal.
//! Ships a flat enum; sub-categorization is reserved (deferred).

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, InstanceId, Principal, RouteId, Tick, TypeCode};

/// Kernel-level effect intent. Each variant is "what to do"; the
/// kernel wraps it in [`Effect`](crate::state::Effect) for
/// authorization, then dispatches into the per-step `StepStage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Op {
    /// Register a new entity with the given id and owner.
    SpawnEntity {
        /// Entity id to register.
        id: EntityId,
        /// Owning principal — recorded in `EntityMeta`.
        owner: Principal,
    },
    /// Remove an entity from the instance.
    DespawnEntity {
        /// Entity to remove.
        id: EntityId,
    },
    /// Attach (or replace) a component on `entity` under `type_code`.
    SetComponent {
        /// Entity that owns the component.
        entity: EntityId,
        /// Component type discriminant.
        type_code: TypeCode,
        /// Canonical-postcard bytes of the component value.
        bytes: Bytes,
        /// Approximate size in bytes — used by the resource ledger
        /// (memory budget enforcement).
        size: u64,
    },
    /// Detach a component from `entity`.
    RemoveComponent {
        /// Entity to detach from.
        entity: EntityId,
        /// Component type discriminant.
        type_code: TypeCode,
        /// Approximate size in bytes — must match the original
        /// `SetComponent` size for the ledger to balance.
        size: u64,
    },
    /// Emit a domain event. Surfaces as `KernelEvent::DomainEventEmitted`
    /// to observers post-commit.
    EmitEvent {
        /// Optional originating entity.
        actor: Option<EntityId>,
        /// Event type discriminant.
        event_type_code: TypeCode,
        /// Canonical-postcard bytes of the event payload.
        event_bytes: Bytes,
    },
    /// Enqueue another action for a future tick.
    ScheduleAction {
        /// Tick at which the scheduled action becomes due.
        at: Tick,
        /// Optional originating entity.
        actor: Option<EntityId>,
        /// Type code of the scheduled action.
        action_type_code: TypeCode,
        /// Canonical-postcard bytes of the scheduled action.
        action_bytes: Bytes,
        /// Principal under which the scheduled action will be authorized.
        action_principal: Principal,
    },
    /// Cross-instance signal. Routed by the kernel to the target
    /// instance's IPC queue post-commit.
    SendSignal {
        /// Receiving instance.
        target: InstanceId,
        /// Route discriminant — the receiving instance dispatches by
        /// this id.
        route: RouteId,
        /// Canonical-postcard bytes of the signal payload.
        payload: Bytes,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_variants_clone() {
        let id = EntityId::new(1).unwrap();
        let _ = Op::SpawnEntity {
            id,
            owner: Principal::System,
        }
        .clone();
        let _ = Op::DespawnEntity { id }.clone();
        let _ = Op::SetComponent {
            entity: id,
            type_code: TypeCode(1),
            bytes: Bytes::from_static(b"x"),
            size: 1,
        }
        .clone();
        let _ = Op::RemoveComponent {
            entity: id,
            type_code: TypeCode(1),
            size: 1,
        }
        .clone();
        let _ = Op::EmitEvent {
            actor: Some(id),
            event_type_code: TypeCode(2),
            event_bytes: Bytes::new(),
        }
        .clone();
        let _ = Op::ScheduleAction {
            at: Tick(0),
            actor: None,
            action_type_code: TypeCode(3),
            action_bytes: Bytes::new(),
            action_principal: Principal::System,
        }
        .clone();
        let _ = Op::SendSignal {
            target: InstanceId::new(1).unwrap(),
            route: RouteId(1),
            payload: Bytes::new(),
        }
        .clone();
    }
}

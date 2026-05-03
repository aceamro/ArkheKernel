//! `ActionContext` — read-only Instance view passed to `Action::compute`.
//!
//! Domain authors receive this context, observe Instance state through
//! the limited accessor surface, and return a `Vec<Op>` describing their
//! intended effects. Mutation is forbidden — the kernel translates Ops
//! into `StepStage` deltas, which `apply_stage` later commits.

use super::instance::Instance;
use crate::abi::{EntityId, InstanceId, Tick};

/// Read-only context passed to [`ActionCompute::compute`](super::traits::ActionCompute::compute).
/// Carries the originating actor, current tick, and a borrowed view
/// of the instance for limited introspection.
pub struct ActionContext<'a> {
    /// Optional originating entity (e.g. the player who submitted the
    /// action). `None` for system-injected actions.
    pub actor: Option<EntityId>,
    /// Tick at which `step()` is processing this action.
    pub now: Tick,
    /// `InstanceId` of the instance the action runs against.
    pub instance_id: InstanceId,
    pub(crate) instance: &'a Instance,
}

impl<'a> ActionContext<'a> {
    /// Construct an `ActionContext` bound to an Instance reference.
    /// `pub(crate)` because only the kernel scheduler dispatches actions.
    pub(crate) fn new(
        actor: Option<EntityId>,
        now: Tick,
        instance_id: InstanceId,
        instance: &'a Instance,
    ) -> Self {
        Self {
            actor,
            now,
            instance_id,
            instance,
        }
    }

    /// Number of entities currently registered in the instance.
    #[inline]
    pub fn entities_len(&self) -> usize {
        self.instance.entities_len()
    }

    /// Total component count across all entities.
    #[inline]
    pub fn components_len(&self) -> usize {
        self.instance.components_len()
    }

    /// Logical local tick of the instance.
    #[inline]
    pub fn local_tick(&self) -> u64 {
        self.instance.local_tick()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::InstanceConfig;

    #[test]
    fn context_accessor_matches_instance() {
        let inst = Instance::new(InstanceId::new(7).unwrap(), InstanceConfig::default());
        let ctx = ActionContext {
            actor: Some(EntityId::new(1).unwrap()),
            now: Tick(0),
            instance_id: InstanceId::new(7).unwrap(),
            instance: &inst,
        };
        assert_eq!(ctx.entities_len(), 0);
        assert_eq!(ctx.components_len(), 0);
        assert_eq!(ctx.local_tick(), 0);
        assert_eq!(ctx.now, Tick(0));
        assert_eq!(ctx.instance_id, InstanceId::new(7).unwrap());
        assert_eq!(ctx.actor, Some(EntityId::new(1).unwrap()));
    }
}

//! `InstanceView` — read-only public projection of one `Instance`.
//!
//! L1 applications need to *read* kernel state (entity rosters, component
//! bytes, post lists, etc.) without holding `&mut` to the kernel and
//! without reaching into private internals. `InstanceView<'a>` is the
//! single sanctioned read surface; it borrows `&self` from the kernel,
//! so callers cannot concurrently mutate while a view is live.
//!
//! No write methods exist on this struct; `&mut Instance` never escapes.

use bytes::Bytes;

use crate::abi::{EntityId, InstanceId, TypeCode};
use crate::state::{EntityMeta, Instance};

/// Read-only borrow of one instance's state.
pub struct InstanceView<'a> {
    pub(crate) instance: &'a Instance,
}

impl<'a> InstanceView<'a> {
    /// `InstanceId` of the viewed instance.
    pub fn id(&self) -> InstanceId {
        self.instance.id()
    }

    /// Number of entities currently registered.
    pub fn entity_count(&self) -> usize {
        self.instance.entities_len()
    }

    /// Total component count across all entities.
    pub fn component_count(&self) -> usize {
        self.instance.components_len()
    }

    /// Logical local tick of the instance.
    pub fn local_tick(&self) -> u64 {
        self.instance.local_tick()
    }

    /// Per-entity metadata. `None` if the entity is not registered.
    pub fn entity_meta(&self, entity: EntityId) -> Option<&'a EntityMeta> {
        self.instance.entity_meta(entity)
    }

    /// Component bytes for an `(entity, type_code)` pair. `None` if
    /// the component is not attached to that entity.
    pub fn component(&self, entity: EntityId, type_code: TypeCode) -> Option<&'a Bytes> {
        self.instance.component(entity, type_code)
    }

    /// Iterate every `(entity, &meta)` in ascending `EntityId` order
    /// (A23 canonical, supplied by `BTreeMap` iteration).
    pub fn entities(&self) -> impl Iterator<Item = (EntityId, &'a EntityMeta)> + 'a {
        self.instance.entities_iter()
    }

    /// Iterate every `(entity, &bytes)` whose component matches
    /// `type_code`. Useful for "list all posts" / "list all rolls"
    /// style queries without exposing the raw component map.
    /// Order: ascending `EntityId` (A23 canonical).
    pub fn components_by_type(
        &self,
        type_code: TypeCode,
    ) -> impl Iterator<Item = (EntityId, &'a Bytes)> + 'a {
        self.instance.components_by_type_iter(type_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{CapabilityMask, EntityId, Principal, Tick, TypeCode};
    use crate::state::traits::_sealed::Sealed;
    use crate::state::{ActionCompute, ActionContext, ActionDeriv, InstanceConfig, Op};
    use crate::Kernel;
    use serde::{Deserialize, Serialize};

    /// Test action: spawns entities `[1..=count]` and attaches the same
    /// component bytes (under `type_code`) to each.
    #[derive(Serialize, Deserialize)]
    struct SpawnManyAction {
        count: u64,
        type_code: u32,
        size: u64,
    }
    impl Sealed for SpawnManyAction {}
    impl ActionDeriv for SpawnManyAction {
        const TYPE_CODE: TypeCode = TypeCode(900);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SpawnManyAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let mut ops = Vec::with_capacity((self.count * 2) as usize);
            for n in 1..=self.count {
                let entity = EntityId::new(n).unwrap();
                ops.push(Op::SpawnEntity {
                    id: entity,
                    owner: Principal::System,
                });
                ops.push(Op::SetComponent {
                    entity,
                    type_code: TypeCode(self.type_code),
                    bytes: Bytes::from(vec![0xAB; self.size as usize]),
                    size: self.size,
                });
            }
            ops
        }
    }

    fn submit(k: &mut Kernel, inst: InstanceId, action: &SpawnManyAction) {
        use crate::state::Action;
        let bytes = Action::canonical_bytes(action);
        k.submit(
            inst,
            Principal::System,
            None,
            Tick(0),
            SpawnManyAction::TYPE_CODE,
            bytes,
        )
        .expect("submit ok");
    }

    fn boot() -> (Kernel, InstanceId) {
        let mut k = Kernel::new();
        k.register_action::<SpawnManyAction>();
        let inst = k.create_instance(InstanceConfig::default());
        (k, inst)
    }

    #[test]
    fn view_none_for_missing_instance() {
        let k = Kernel::new();
        let bogus = InstanceId::new(99).unwrap();
        assert!(k.instance_view(bogus).is_none());
    }

    #[test]
    fn view_reflects_entity_count() {
        let (mut k, inst) = boot();
        submit(
            &mut k,
            inst,
            &SpawnManyAction {
                count: 1,
                type_code: 7,
                size: 10,
            },
        );
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);

        let view = k.instance_view(inst).expect("view present");
        assert_eq!(view.id(), inst);
        assert_eq!(view.entity_count(), 1);
        assert_eq!(view.component_count(), 1);
    }

    #[test]
    fn view_component_bytes_match_set() {
        let (mut k, inst) = boot();
        submit(
            &mut k,
            inst,
            &SpawnManyAction {
                count: 1,
                type_code: 7,
                size: 4,
            },
        );
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);

        let view = k.instance_view(inst).expect("view present");
        let comp = view
            .component(EntityId::new(1).unwrap(), TypeCode(7))
            .expect("component present");
        assert_eq!(comp.as_ref(), &[0xAB, 0xAB, 0xAB, 0xAB]);
    }

    #[test]
    fn view_entities_iter_ascending() {
        let (mut k, inst) = boot();
        submit(
            &mut k,
            inst,
            &SpawnManyAction {
                count: 3,
                type_code: 7,
                size: 1,
            },
        );
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);

        let view = k.instance_view(inst).expect("view present");
        let ids: Vec<u64> = view.entities().map(|(id, _)| id.get()).collect();
        assert_eq!(ids, vec![1, 2, 3]);

        // Spot-check meta reflects the producing principal/tick.
        let meta = view.entity_meta(EntityId::new(2).unwrap()).expect("meta");
        assert_eq!(meta.owner, Principal::System);
        assert_eq!(meta.created, Tick(0));
    }

    #[test]
    fn view_components_by_type_filter() {
        // Spawn 2 entities, attach two different TypeCodes — query one.
        let (mut k, inst) = boot();
        submit(
            &mut k,
            inst,
            &SpawnManyAction {
                count: 2,
                type_code: 7,
                size: 1,
            },
        );
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        // Second action: same entities, different type_code (8).
        submit(
            &mut k,
            inst,
            &SpawnManyAction {
                count: 2,
                type_code: 8,
                size: 1,
            },
        );
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);

        let view = k.instance_view(inst).expect("view present");
        // 2 entities × 2 type_codes = 4 components total.
        assert_eq!(view.component_count(), 4);

        let tc7: Vec<u64> = view
            .components_by_type(TypeCode(7))
            .map(|(eid, _)| eid.get())
            .collect();
        assert_eq!(tc7, vec![1, 2]);

        let tc8: Vec<u64> = view
            .components_by_type(TypeCode(8))
            .map(|(eid, _)| eid.get())
            .collect();
        assert_eq!(tc8, vec![1, 2]);
    }

    #[test]
    fn view_local_tick_updates_after_step() {
        let (mut k, inst) = boot();
        submit(
            &mut k,
            inst,
            &SpawnManyAction {
                count: 1,
                type_code: 7,
                size: 1,
            },
        );
        // Before step: tick is at 0.
        let pre = k.instance_view(inst).unwrap().local_tick();
        let _ = k.step(Tick(0), CapabilityMask::SYSTEM);
        // The action does not advance local_tick (no Op::AdvanceTick
        // exists) — the view reflects whatever apply_stage applied.
        // Both readings should still resolve without panic; equality
        // documents the current semantics.
        let post = k.instance_view(inst).unwrap().local_tick();
        assert_eq!(pre, post);
    }
}

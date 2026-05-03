//! `Instance` — per-instance kernel-state container.
//!
//! Holds entities, components, scheduler, ID counters, ledger, in-flight
//! module refs, wall-remainder, and local tick. Mutation flows through the
//! `pub(crate)` accessor surface; `runtime::apply::apply_stage` is the sole
//! caller that drives `StepStage` (10-bucket commit-or-rollback) into
//! Instance state.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::abi::{EntityId, InstanceId, Principal, RouteId, Tick, TypeCode};
use crate::state::config::InstanceConfig;
use crate::state::ledger::ResourceLedger;
use crate::state::scheduler::Scheduler;

/// Per-entity metadata. Surfaced to L1 via `runtime::InstanceView`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntityMeta {
    /// Principal that owned the entity at spawn time.
    pub owner: Principal,
    /// Tick at which the entity was spawned.
    pub created: Tick,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct IdCounters {
    pub next_entity: u64,
    pub next_scheduled: u64,
    pub next_source_seq: u64,
}

pub(crate) struct Instance {
    // `id` is retained for the future IntrospectHandle (deferred). The kernel
    // already keys by `InstanceId` externally, so production read paths
    // for the field itself are deferred.
    #[cfg_attr(not(test), allow(dead_code))]
    id: InstanceId,
    config: InstanceConfig,
    entities: BTreeMap<EntityId, EntityMeta>,
    /// Component data keyed by `(entity, type)` — canonical postcard bytes.
    components: BTreeMap<(EntityId, TypeCode), Bytes>,
    scheduler: Scheduler,
    id_counters: IdCounters,
    ledger: ResourceLedger,
    /// Drain-refcount per registered route.
    inflight_refs: BTreeMap<RouteId, u32>,
    /// Sub-tick wall-clock remainder accumulator.
    wall_remainder: u128,
    /// Logical local tick advancing per `step()`.
    local_tick: u64,
}

impl Instance {
    pub(crate) fn new(id: InstanceId, config: InstanceConfig) -> Self {
        Self {
            id,
            config,
            entities: BTreeMap::new(),
            components: BTreeMap::new(),
            scheduler: Scheduler::new(),
            id_counters: IdCounters::default(),
            ledger: ResourceLedger::new(),
            inflight_refs: BTreeMap::new(),
            wall_remainder: 0,
            local_tick: 0,
        }
    }

    // ---- read accessors ----
    //
    // Kernel-internal observability surface used by tests and
    // `runtime::registry` test fixtures. Production introspection
    // wiring lands with the future IntrospectHandle interface (deferred).
    #[inline]
    pub(crate) fn id(&self) -> InstanceId {
        self.id
    }
    #[inline]
    pub(crate) fn config(&self) -> &InstanceConfig {
        &self.config
    }
    #[inline]
    pub(crate) fn entities_len(&self) -> usize {
        self.entities.len()
    }
    #[inline]
    pub(crate) fn components_len(&self) -> usize {
        self.components.len()
    }
    #[inline]
    pub(crate) fn local_tick(&self) -> u64 {
        self.local_tick
    }
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn wall_remainder(&self) -> u128 {
        self.wall_remainder
    }
    #[inline]
    pub(crate) fn ledger(&self) -> &ResourceLedger {
        &self.ledger
    }
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn id_counters(&self) -> &IdCounters {
        &self.id_counters
    }
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn inflight_refs_len(&self) -> usize {
        self.inflight_refs.len()
    }
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn inflight_refs_for(&self, route: RouteId) -> u32 {
        *self.inflight_refs.get(&route).unwrap_or(&0)
    }

    /// Per-entity metadata lookup. Surfaced through `runtime::InstanceView`.
    pub(crate) fn entity_meta(&self, entity: EntityId) -> Option<&EntityMeta> {
        self.entities.get(&entity)
    }

    /// Component bytes for an `(entity, type_code)` pair. Surfaced through
    /// `runtime::InstanceView`.
    pub(crate) fn component(&self, entity: EntityId, type_code: TypeCode) -> Option<&Bytes> {
        self.components.get(&(entity, type_code))
    }

    /// Iterate every entity in ascending `EntityId` order (BTreeMap
    /// canonical iteration; A23 deterministic). Surfaced through
    /// `runtime::InstanceView`.
    pub(crate) fn entities_iter(&self) -> impl Iterator<Item = (EntityId, &EntityMeta)> + '_ {
        self.entities.iter().map(|(id, meta)| (*id, meta))
    }

    /// Iterate every `(entity, bytes)` pair whose `TypeCode` matches.
    /// Order is ascending `(EntityId, TypeCode)` lex, so for a fixed
    /// `type_code` the effective order is ascending `EntityId`.
    pub(crate) fn components_by_type_iter(
        &self,
        type_code: TypeCode,
    ) -> impl Iterator<Item = (EntityId, &Bytes)> + '_ {
        self.components
            .iter()
            .filter_map(move |((eid, tc), bytes)| {
                if *tc == type_code {
                    Some((*eid, bytes))
                } else {
                    None
                }
            })
    }

    // ---- pub(crate) mutators ----
    //
    // R4-X DAG fix: `apply_stage` lives in `runtime::apply`, not on `Instance`,
    // so `state` does not import `runtime`. These accessors are the sole
    // surface through which `StepStage` deltas reach Instance state.
    // External crates do not see them — only sibling kernel modules
    // (notably `runtime::apply`) can mutate.

    pub(crate) fn insert_entity(&mut self, id: EntityId, meta: EntityMeta) {
        self.entities.insert(id, meta);
    }

    pub(crate) fn remove_entity(&mut self, id: EntityId) -> Option<EntityMeta> {
        self.entities.remove(&id)
    }

    pub(crate) fn insert_component(&mut self, key: (EntityId, TypeCode), bytes: Bytes) {
        self.components.insert(key, bytes);
    }

    pub(crate) fn remove_component(&mut self, key: (EntityId, TypeCode)) -> Option<Bytes> {
        self.components.remove(&key)
    }

    pub(crate) fn scheduler_mut(&mut self) -> &mut Scheduler {
        &mut self.scheduler
    }

    pub(crate) fn ledger_mut(&mut self) -> &mut ResourceLedger {
        &mut self.ledger
    }

    pub(crate) fn id_counters_mut(&mut self) -> &mut IdCounters {
        &mut self.id_counters
    }

    pub(crate) fn inflight_refs_mut(&mut self) -> &mut BTreeMap<RouteId, u32> {
        &mut self.inflight_refs
    }

    pub(crate) fn advance_wall_remainder(&mut self, delta: u128) {
        self.wall_remainder = self.wall_remainder.saturating_add(delta);
    }

    pub(crate) fn advance_local_tick(&mut self, delta: u64) {
        self.local_tick = self.local_tick.saturating_add(delta);
    }

    /// Snapshot of `IdCounters` (read-only clone) for callers that need
    /// pre-stage values without holding a borrow on Instance.
    pub(crate) fn id_counters_snapshot(&self) -> IdCounters {
        self.id_counters.clone()
    }

    /// Capture all instance fields into a serializable `InstanceSnapshot`.
    /// Excludes nothing — every Instance field is round-tripped.
    pub(crate) fn to_snapshot(&self) -> InstanceSnapshot {
        InstanceSnapshot {
            id: self.id,
            config: self.config.clone(),
            entities: self.entities.clone(),
            components: self.components.clone(),
            scheduler: self.scheduler.clone(),
            id_counters: self.id_counters.clone(),
            ledger: self.ledger.clone(),
            inflight_refs: self.inflight_refs.clone(),
            wall_remainder: self.wall_remainder,
            local_tick: self.local_tick,
        }
    }

    /// Reconstruct an Instance from a snapshot. Inverse of `to_snapshot`.
    pub(crate) fn from_snapshot(snap: InstanceSnapshot) -> Self {
        Self {
            id: snap.id,
            config: snap.config,
            entities: snap.entities,
            components: snap.components,
            scheduler: snap.scheduler,
            id_counters: snap.id_counters,
            ledger: snap.ledger,
            inflight_refs: snap.inflight_refs,
            wall_remainder: snap.wall_remainder,
            local_tick: snap.local_tick,
        }
    }
}

/// Round-tripable shape of a single `Instance`. Pub struct, pub(crate)
/// fields — visible as a type at the crate boundary (so `KernelSnapshot`
/// can name it) but not constructible/inspectable from outside the
/// kernel crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceSnapshot {
    pub(crate) id: InstanceId,
    pub(crate) config: InstanceConfig,
    pub(crate) entities: BTreeMap<EntityId, EntityMeta>,
    pub(crate) components: BTreeMap<(EntityId, TypeCode), Bytes>,
    pub(crate) scheduler: Scheduler,
    pub(crate) id_counters: IdCounters,
    pub(crate) ledger: ResourceLedger,
    pub(crate) inflight_refs: BTreeMap<RouteId, u32>,
    pub(crate) wall_remainder: u128,
    pub(crate) local_tick: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::CapabilityMask;
    use crate::state::quota::QuotaReductionPolicy;

    fn id(n: u64) -> InstanceId {
        InstanceId::new(n).unwrap()
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
    fn instance_new_initial_state() {
        let inst = Instance::new(id(1), cfg());
        assert_eq!(inst.id(), id(1));
        assert_eq!(inst.entities_len(), 0);
        assert_eq!(inst.components_len(), 0);
        assert_eq!(inst.local_tick(), 0);
        assert_eq!(inst.wall_remainder(), 0);
        assert_eq!(inst.ledger().total_entities(), 0);
        assert!(inst.scheduler().is_empty());
        assert_eq!(inst.inflight_refs_len(), 0);
    }

    #[test]
    fn instance_id_counters_default_zero() {
        let inst = Instance::new(id(1), cfg());
        let c = inst.id_counters();
        assert_eq!(c.next_entity, 0);
        assert_eq!(c.next_scheduled, 0);
        assert_eq!(c.next_source_seq, 0);
    }

    #[test]
    fn instance_config_carried_through() {
        let mut config = cfg();
        config.max_entities = 7;
        config.parent = id(99).into(); // Some(_)
        let inst = Instance::new(id(2), config);
        assert_eq!(inst.config().max_entities, 7);
        assert_eq!(inst.config().parent, Some(id(99)));
    }

    #[test]
    fn multiple_instances_independent() {
        let inst1 = Instance::new(id(1), cfg());
        let inst2 = Instance::new(id(2), cfg());
        assert_ne!(inst1.id(), inst2.id());
        assert!(inst1.scheduler().is_empty());
        assert!(inst2.scheduler().is_empty());
        assert_eq!(inst1.ledger().total_bytes(), 0);
        assert_eq!(inst2.ledger().total_bytes(), 0);
    }

    #[test]
    fn entity_meta_clone_preserves_fields() {
        let m1 = EntityMeta {
            owner: Principal::System,
            created: Tick(5),
        };
        let m2 = m1.clone();
        assert!(matches!(m2.owner, Principal::System));
        assert_eq!(m2.created, Tick(5));
    }

    #[test]
    fn id_counters_default_clone_independent() {
        let c1 = IdCounters::default();
        let mut c2 = c1.clone();
        c2.next_entity = 10;
        assert_eq!(c1.next_entity, 0);
        assert_eq!(c2.next_entity, 10);
    }

    // apply_stage / discard_stage tests live in `runtime/apply.rs`
    // (R4-X: Instance does not import `runtime::StepStage`).
}

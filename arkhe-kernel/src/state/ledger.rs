//! `ResourceLedger` — per-instance resource accounting — a StepStage bucket.
//!
//! Tracks entity count, per-entity total bytes (sum of attached components'
//! `approx_size`), per-component-type counts (observability), and global
//! totals. Production mutations flow only through `runtime::apply::apply_stage`;
//! the API is `pub(crate)` so unit tests and the apply pipeline both
//! reach it directly.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, TypeCode};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct ResourceLedger {
    /// Known entities (an entity may exist with zero attached components).
    entities: BTreeSet<EntityId>,
    /// Per-component declared `size` — the single accounting authority
    /// (A21). Keyed by `(entity, type_code)`; `total_bytes`, per-entity
    /// byte sums, and per-type counts all derive from this map, so a
    /// `SetComponent` replace adjusts by the byte delta (never double-
    /// counts) and a remove / despawn subtracts the exact stored size.
    component_sizes: BTreeMap<(EntityId, TypeCode), u64>,
    /// O(1) cache of `sum(component_sizes.values())` — hot-path read for
    /// `memory_budget_bytes` enforcement in `runtime::kernel::step()`.
    total_bytes: u64,
}

impl ResourceLedger {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Total component bytes attributed across all entities. Consumed by
    /// `runtime::kernel::step()` for `memory_budget_bytes` enforcement.
    #[inline]
    pub(crate) fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    // Test-only observability accessors below. Production introspection
    // wiring lands with the future IntrospectHandle interface (deferred).

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) fn total_entities(&self) -> u32 {
        u32::try_from(self.entities.len()).unwrap_or(u32::MAX)
    }

    /// Currently-attributed declared size of the `(entity, type_code)`
    /// component, or `None` if no such component is accounted. This is the
    /// amount a `RemoveComponent` will actually free at apply time, so the
    /// budget projection in `runtime::kernel::step()` credits removals by
    /// this stored value — never by the caller-declared `size`, which is
    /// untrusted and could otherwise poison the projection.
    pub(crate) fn component_size(&self, entity: EntityId, tc: TypeCode) -> Option<u64> {
        self.component_sizes.get(&(entity, tc)).copied()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn entity_bytes(&self, id: EntityId) -> u64 {
        self.component_sizes
            .range((id, TypeCode(0))..=(id, TypeCode(u32::MAX)))
            .fold(0u64, |acc, (_, size)| acc.saturating_add(*size))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn type_count(&self, tc: TypeCode) -> u32 {
        let n = self
            .component_sizes
            .keys()
            .filter(|(_, t)| *t == tc)
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// Register a new entity with zero attached bytes. Returns true on
    /// fresh insertion, false if the entity was already present (idempotent).
    pub(crate) fn add_entity(&mut self, id: EntityId) -> bool {
        self.entities.insert(id)
    }

    /// Remove an entity and cascade-drop every component it still held,
    /// so a despawn cannot leave orphaned byte/type accounting behind.
    /// Returns the total bytes that were attributed to the entity.
    pub(crate) fn remove_entity(&mut self, id: EntityId) -> u64 {
        if !self.entities.remove(&id) {
            return 0;
        }
        let keys: Vec<(EntityId, TypeCode)> = self
            .component_sizes
            .range((id, TypeCode(0))..=(id, TypeCode(u32::MAX)))
            .map(|(k, _)| *k)
            .collect();
        let mut freed = 0u64;
        for k in keys {
            if let Some(size) = self.component_sizes.remove(&k) {
                freed = freed.saturating_add(size);
                self.total_bytes = self.total_bytes.saturating_sub(size);
            }
        }
        freed
    }

    /// Attach (or replace) a component of `(tc, size)` on `entity`. On a
    /// replace, `total_bytes` is adjusted by the size *delta* — the prior
    /// component's size is never double-counted and the type is not
    /// re-counted. Returns false if the entity is unknown.
    pub(crate) fn add_component(&mut self, entity: EntityId, tc: TypeCode, size: u64) -> bool {
        if !self.entities.contains(&entity) {
            return false;
        }
        match self.component_sizes.insert((entity, tc), size) {
            Some(old) if size >= old => {
                self.total_bytes = self.total_bytes.saturating_add(size - old);
            }
            Some(old) => {
                self.total_bytes = self.total_bytes.saturating_sub(old - size);
            }
            None => {
                self.total_bytes = self.total_bytes.saturating_add(size);
            }
        }
        true
    }

    /// Detach a component. The size subtracted is the component's *stored*
    /// declared size — the caller-supplied `_size` is ignored, so the
    /// ledger is self-correcting and cannot be skewed by a mismatched
    /// remove size. Returns false if the entity is unknown.
    pub(crate) fn remove_component(&mut self, entity: EntityId, tc: TypeCode, _size: u64) -> bool {
        if !self.entities.contains(&entity) {
            return false;
        }
        if let Some(old) = self.component_sizes.remove(&(entity, tc)) {
            self.total_bytes = self.total_bytes.saturating_sub(old);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(n: u64) -> EntityId {
        EntityId::new(n).unwrap()
    }
    fn t(n: u32) -> TypeCode {
        TypeCode(n)
    }

    #[test]
    fn empty_ledger_zeroes() {
        let l = ResourceLedger::new();
        assert_eq!(l.total_entities(), 0);
        assert_eq!(l.total_bytes(), 0);
        assert_eq!(l.entity_bytes(e(1)), 0);
        assert_eq!(l.type_count(t(1)), 0);
    }

    #[test]
    fn add_entity_increments_total() {
        let mut l = ResourceLedger::new();
        assert!(l.add_entity(e(1)));
        assert!(l.add_entity(e(2)));
        assert_eq!(l.total_entities(), 2);
    }

    #[test]
    fn add_entity_idempotent() {
        let mut l = ResourceLedger::new();
        assert!(l.add_entity(e(1)));
        assert!(!l.add_entity(e(1)));
        assert_eq!(l.total_entities(), 1);
    }

    #[test]
    fn add_component_updates_bytes_and_count() {
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        assert!(l.add_component(e(1), t(10), 100));
        assert_eq!(l.entity_bytes(e(1)), 100);
        assert_eq!(l.total_bytes(), 100);
        assert_eq!(l.type_count(t(10)), 1);
    }

    #[test]
    fn add_component_to_unknown_entity_is_noop() {
        let mut l = ResourceLedger::new();
        assert!(!l.add_component(e(1), t(10), 100));
        assert_eq!(l.total_bytes(), 0);
        assert_eq!(l.type_count(t(10)), 0);
    }

    #[test]
    fn remove_component_balances_add() {
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        l.add_component(e(1), t(10), 100);
        l.add_component(e(1), t(20), 50);
        assert_eq!(l.total_bytes(), 150);
        l.remove_component(e(1), t(10), 100);
        assert_eq!(l.total_bytes(), 50);
        assert_eq!(l.entity_bytes(e(1)), 50);
        assert_eq!(l.type_count(t(10)), 0);
        assert_eq!(l.type_count(t(20)), 1);
    }

    #[test]
    fn remove_entity_returns_bytes_and_drops_total() {
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        l.add_component(e(1), t(10), 100);
        l.add_component(e(1), t(20), 50);
        let bytes = l.remove_entity(e(1));
        assert_eq!(bytes, 150);
        assert_eq!(l.total_entities(), 0);
        assert_eq!(l.total_bytes(), 0);
        assert_eq!(l.entity_bytes(e(1)), 0);
    }

    #[test]
    fn remove_unknown_entity_is_noop() {
        let mut l = ResourceLedger::new();
        assert_eq!(l.remove_entity(e(999)), 0);
    }

    #[test]
    fn add_remove_balanced_yields_empty() {
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        l.add_component(e(1), t(10), 100);
        l.remove_component(e(1), t(10), 100);
        l.remove_entity(e(1));
        assert_eq!(l.total_bytes(), 0);
        assert_eq!(l.total_entities(), 0);
    }

    #[test]
    fn type_count_aggregates_across_entities() {
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        l.add_entity(e(2));
        l.add_component(e(1), t(7), 10);
        l.add_component(e(2), t(7), 20);
        assert_eq!(l.type_count(t(7)), 2);
        assert_eq!(l.total_bytes(), 30);
    }

    #[test]
    fn type_count_underflow_is_saturating() {
        // Defensive: extra remove without prior add does not panic.
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        l.remove_component(e(1), t(99), 50); // count was 0
        assert_eq!(l.type_count(t(99)), 0);
    }

    #[test]
    fn set_component_replace_adjusts_by_delta_no_double_count() {
        // Regression: re-setting the same (entity, type) must adjust by the
        // size delta, not add the full size again, and must not re-count
        // the type. Larger-then-smaller exercises both delta directions.
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        assert!(l.add_component(e(1), t(7), 100));
        assert!(l.add_component(e(1), t(7), 400)); // replace, +300
        assert_eq!(l.total_bytes(), 400);
        assert_eq!(l.entity_bytes(e(1)), 400);
        assert_eq!(l.type_count(t(7)), 1);
        assert!(l.add_component(e(1), t(7), 50)); // replace, -350
        assert_eq!(l.total_bytes(), 50);
        assert_eq!(l.type_count(t(7)), 1);
    }

    #[test]
    fn remove_entity_cascades_component_accounting() {
        // Regression: despawn must drop every component's bytes AND type
        // counts — no orphaned accounting after the entity is gone.
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        l.add_component(e(1), t(7), 100);
        l.add_component(e(1), t(9), 50);
        assert_eq!(l.total_bytes(), 150);
        assert_eq!(l.type_count(t(7)), 1);
        assert_eq!(l.type_count(t(9)), 1);
        assert_eq!(l.remove_entity(e(1)), 150);
        assert_eq!(l.total_bytes(), 0);
        assert_eq!(l.total_entities(), 0);
        assert_eq!(l.type_count(t(7)), 0);
        assert_eq!(l.type_count(t(9)), 0);
    }

    #[test]
    fn remove_component_uses_stored_size_not_caller_size() {
        // Regression: a remove with a mismatched size must not skew the
        // ledger — the stored size is authoritative.
        let mut l = ResourceLedger::new();
        l.add_entity(e(1));
        l.add_component(e(1), t(7), 100);
        assert!(l.remove_component(e(1), t(7), 999_999)); // bogus size ignored
        assert_eq!(l.total_bytes(), 0);
        assert_eq!(l.entity_bytes(e(1)), 0);
    }
}

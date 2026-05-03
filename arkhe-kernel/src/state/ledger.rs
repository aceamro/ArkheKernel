//! `ResourceLedger` — per-instance resource accounting — a StepStage bucket.
//!
//! Tracks entity count, per-entity total bytes (sum of attached components'
//! `approx_size`), per-component-type counts (observability), and global
//! totals. Production mutations flow only through `runtime::apply::apply_stage`;
//! the API is `pub(crate)` so unit tests and the apply pipeline both
//! reach it directly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, TypeCode};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct ResourceLedger {
    entity_bytes: BTreeMap<EntityId, u64>,
    type_counts: BTreeMap<TypeCode, u32>,
    total_bytes: u64,
    total_entities: u32,
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
        self.total_entities
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn entity_bytes(&self, id: EntityId) -> u64 {
        *self.entity_bytes.get(&id).unwrap_or(&0)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn type_count(&self, tc: TypeCode) -> u32 {
        *self.type_counts.get(&tc).unwrap_or(&0)
    }

    /// Register a new entity with zero attached bytes. Returns true on
    /// fresh insertion, false if the entity was already present (idempotent).
    pub(crate) fn add_entity(&mut self, id: EntityId) -> bool {
        if self.entity_bytes.insert(id, 0).is_none() {
            self.total_entities = self.total_entities.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Remove an entity; returns the bytes that were attributed to it.
    /// Caller is responsible for emitting per-component `remove_component`
    /// calls in canonical apply order *before* this one if it wants
    /// `type_counts` decrements; this method is the entity-row removal
    /// (saturating-subtract from totals).
    pub(crate) fn remove_entity(&mut self, id: EntityId) -> u64 {
        if let Some(bytes) = self.entity_bytes.remove(&id) {
            self.total_bytes = self.total_bytes.saturating_sub(bytes);
            self.total_entities = self.total_entities.saturating_sub(1);
            bytes
        } else {
            0
        }
    }

    /// Attach a component of `(tc, size)` to `entity`. Returns false if the
    /// entity is unknown — apply ordering is the caller's responsibility.
    pub(crate) fn add_component(&mut self, entity: EntityId, tc: TypeCode, size: u64) -> bool {
        let Some(bytes) = self.entity_bytes.get_mut(&entity) else {
            return false;
        };
        *bytes = bytes.saturating_add(size);
        self.total_bytes = self.total_bytes.saturating_add(size);
        *self.type_counts.entry(tc).or_insert(0) += 1;
        true
    }

    /// Detach a component. Returns false if the entity is unknown.
    /// `type_counts` entry is removed when its count reaches zero.
    pub(crate) fn remove_component(&mut self, entity: EntityId, tc: TypeCode, size: u64) -> bool {
        let Some(bytes) = self.entity_bytes.get_mut(&entity) else {
            return false;
        };
        *bytes = bytes.saturating_sub(size);
        self.total_bytes = self.total_bytes.saturating_sub(size);
        if let Some(c) = self.type_counts.get_mut(&tc) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.type_counts.remove(&tc);
            }
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
}

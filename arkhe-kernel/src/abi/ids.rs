//! Identifier newtypes.
//!
//! `InstanceId` and `EntityId` wrap `NonZeroU64` — zero is structurally
//! unrepresentable, eliminating sentinel-value traps. `Tick`, `TypeCode`,
//! `RouteId` wrap plain primitives because zero is a meaningful value for
//! all three (origin tick; type/route zero is reserved for "unassigned"
//! debug placeholders only and is not a sentinel).

use core::num::NonZeroU64;
use serde::{Deserialize, Serialize};

/// Instance namespace handle. Non-zero to reject sentinel usage at the
/// type level.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InstanceId(NonZeroU64);

impl InstanceId {
    /// Returns `Some(_)` iff `v != 0`.
    #[inline]
    pub const fn new(v: u64) -> Option<Self> {
        match NonZeroU64::new(v) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// Underlying non-zero `u64`.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Per-instance entity handle. Non-zero.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityId(NonZeroU64);

impl EntityId {
    /// Returns `Some(_)` iff `v != 0`.
    #[inline]
    pub const fn new(v: u64) -> Option<Self> {
        match NonZeroU64::new(v) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// Underlying non-zero `u64`.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Deterministic logical time. Monotonic non-decreasing across `step()`
/// boundaries of an instance. Zero is the origin tick.
#[derive(
    Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Tick(pub u64);

impl Tick {
    /// Origin tick — fresh kernels and fresh instances start here.
    pub const ZERO: Tick = Tick(0);

    /// Advance by `delta` using saturating addition (no wraparound).
    #[inline]
    pub const fn advance(self, delta: u64) -> Tick {
        Tick(self.0.saturating_add(delta))
    }
}

/// Stable dispatch identifier for a registered Action/Component/Event type.
/// Assigned monotonically at `register_module` and bound to a schema_hash for
/// the lifetime of the world (TypeCode cross-restart persistence).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TypeCode(pub u32);

/// Stable dispatch identifier for an action route. Registry interns string
/// names into `RouteId` at registration; kernel internal dispatch uses
/// `RouteId` only ("string-free dispatch").
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RouteId(pub u32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_zero_is_unrepresentable() {
        assert!(InstanceId::new(0).is_none());
    }

    #[test]
    fn instance_id_nonzero_roundtrip() {
        let id = InstanceId::new(42).expect("42 is non-zero");
        assert_eq!(id.get(), 42);
    }

    #[test]
    fn entity_id_zero_is_unrepresentable() {
        assert!(EntityId::new(0).is_none());
    }

    #[test]
    fn entity_id_nonzero_roundtrip() {
        let id = EntityId::new(u64::MAX).expect("max is non-zero");
        assert_eq!(id.get(), u64::MAX);
    }

    #[test]
    fn tick_advance_saturates_without_wrapping() {
        assert_eq!(Tick::ZERO.advance(100).0, 100);
        assert_eq!(Tick(u64::MAX).advance(1).0, u64::MAX);
        assert_eq!(Tick(u64::MAX - 5).advance(10).0, u64::MAX);
    }

    #[test]
    fn type_code_and_route_id_are_totally_ordered() {
        assert!(TypeCode(1) < TypeCode(2));
        assert!(RouteId(10) > RouteId(5));
    }

    #[test]
    fn ids_are_copy_and_eq() {
        // Compile-time proof via trait bounds.
        fn assert_copy<T: Copy>() {}
        fn assert_eq<T: Eq>() {}
        fn assert_ord<T: Ord>() {}
        fn assert_hash<T: core::hash::Hash>() {}
        assert_copy::<InstanceId>();
        assert_copy::<EntityId>();
        assert_copy::<Tick>();
        assert_copy::<TypeCode>();
        assert_copy::<RouteId>();
        assert_eq::<InstanceId>();
        assert_ord::<InstanceId>();
        assert_hash::<InstanceId>();
    }
}

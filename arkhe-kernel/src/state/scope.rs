//! `InstanceScope<'i>` — invariant-lifetime-branded handle to an instance.
//!
//! GhostCell pattern (A19): the lifetime `'i` is the type-level brand
//! preventing `Effect<Authorized, 'i>` of one instance from being passed
//! to another instance's dispatcher. Production scopes are issued by an
//! HRTB-bounded `Kernel::with_instance<F>(F: for<'i> ...)` (reserved
//! / deferred); this module provides the type shape used today via the
//! skeleton constructor below.

use crate::abi::InstanceId;
use crate::state::authz::InvariantLifetime;
use core::marker::PhantomData;

/// Invariant-lifetime-branded handle to an instance (GhostCell pattern,
/// A19). The lifetime `'i` prevents an `Effect<Authorized, 'i>` of one
/// instance from being passed to another instance's dispatcher —
/// the mismatch fails lifetime unification at compile time.
pub struct InstanceScope<'i> {
    pub(crate) instance_id: InstanceId,
    _brand: InvariantLifetime<'i>,
}

impl<'i> InstanceScope<'i> {
    /// Test/skeleton constructor — production path is the deferred
    /// HRTB-bounded `Kernel::with_instance`.
    #[doc(hidden)]
    pub fn __new_for_skeleton(instance_id: InstanceId) -> Self {
        Self {
            instance_id,
            _brand: PhantomData,
        }
    }

    /// `InstanceId` this scope is branded against.
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_carries_instance_id() {
        let id = InstanceId::new(42).unwrap();
        let scope: InstanceScope<'_> = InstanceScope::__new_for_skeleton(id);
        assert_eq!(scope.instance_id().get(), 42);
    }

    #[test]
    fn scope_independent_construction_compiles() {
        // Two scopes constructed in sequence with default elision:
        // each gets its own lifetime; nothing flows between them.
        let s1 = InstanceScope::__new_for_skeleton(InstanceId::new(1).unwrap());
        let s2 = InstanceScope::__new_for_skeleton(InstanceId::new(2).unwrap());
        assert_eq!(s1.instance_id().get(), 1);
        assert_eq!(s2.instance_id().get(), 2);
        // Cross-scope rejection at the dispatcher boundary becomes
        // type-checkable when the HRTB scope guard ships (deferred).
    }
}

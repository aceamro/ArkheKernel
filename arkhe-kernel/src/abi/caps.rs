//! Capability bitmask — Mechanism/Policy boundary.
//!
//! The kernel *reserves* bit positions for its own invariants
//! (SYSTEM, ADMIN_UNLOAD, OBSERVER_REGISTER, INTROSPECT). The mapping
//! of bits to L2 roles (admin, operator, tenant) is policy owned
//! exclusively by L2. v0.13 reserves four bits; 60 more are free for
//! future kernel-reserved or L2-defined caps.

use bitflags::bitflags;

bitflags! {
    /// 64-bit capability mask. Kernel-reserved bits are documented per
    /// flag; remaining bits are available for L2 to assign semantics.
    ///
    /// Stable ABI discipline: adding a kernel-reserved bit is a schema
    /// change (version bump); repurposing an existing bit is forbidden.
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, serde::Serialize, serde::Deserialize)]
    pub struct CapabilityMask: u64 {
        /// Kernel-reserved: System-origin operations. Only `Principal::System`
        /// paths and privileged operator code should hold this bit.
        const SYSTEM = 1 << 0;

        /// Kernel-reserved: Force-unload of a module that refuses to drain
        /// (drain-refcount escape hatch).
        const ADMIN_UNLOAD = 1 << 1;

        /// Kernel-reserved: Register/remove kernel observers
        /// (observer lifecycle).
        const OBSERVER_REGISTER = 1 << 2;

        /// Kernel-reserved: Pull-side introspection access
        /// (`IntrospectHandle` grant).
        const INTROSPECT = 1 << 3;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_combine_via_bitor() {
        let c = CapabilityMask::SYSTEM | CapabilityMask::ADMIN_UNLOAD;
        assert!(c.contains(CapabilityMask::SYSTEM));
        assert!(c.contains(CapabilityMask::ADMIN_UNLOAD));
        assert!(!c.contains(CapabilityMask::INTROSPECT));
        assert!(!c.contains(CapabilityMask::OBSERVER_REGISTER));
    }

    #[test]
    fn caps_default_is_empty() {
        let empty = CapabilityMask::default();
        assert!(empty.is_empty());
        assert!(!empty.contains(CapabilityMask::SYSTEM));
    }

    #[test]
    fn caps_all_reserved_bits_have_distinct_positions() {
        let all = CapabilityMask::SYSTEM
            | CapabilityMask::ADMIN_UNLOAD
            | CapabilityMask::OBSERVER_REGISTER
            | CapabilityMask::INTROSPECT;
        assert_eq!(all.bits(), 0b1111);
    }

    #[test]
    fn caps_intersection_contains() {
        let a = CapabilityMask::SYSTEM | CapabilityMask::INTROSPECT;
        let b = CapabilityMask::INTROSPECT | CapabilityMask::OBSERVER_REGISTER;
        assert_eq!(a & b, CapabilityMask::INTROSPECT);
    }

    #[test]
    fn caps_subset_relationship() {
        let full = CapabilityMask::SYSTEM | CapabilityMask::ADMIN_UNLOAD;
        let partial = CapabilityMask::SYSTEM;
        assert!(full.contains(partial));
        assert!(!partial.contains(full));
    }
}

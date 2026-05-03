//! `InstanceConfig` — caller-supplied per-instance configuration.
//!
//! `EffectiveConfig` (parent-derived bounds, A10 — every quota = min(parent,
//! requested)) is composed at `Kernel::create_instance` time when parent ↔
//! child relationships are wired.

use serde::{Deserialize, Serialize};

use crate::abi::{CapabilityMask, InstanceId};
use crate::state::quota::QuotaReductionPolicy;

/// Per-instance configuration supplied at `Kernel::create_instance`.
/// All fields are pub — `InstanceConfig { field: ..., ..Default::default() }`
/// is the idiomatic construction pattern.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InstanceConfig {
    /// Capability mask the kernel uses when authorizing actions
    /// submitted under `Principal::System` from kernel-internal paths.
    pub default_caps: CapabilityMask,
    /// Hard upper bound on entities (0 = unlimited).
    pub max_entities: u32,
    /// Hard upper bound on scheduled actions (0 = unlimited).
    pub max_scheduled: u32,
    /// Component byte ceiling enforced per-Op in `step()`.
    /// `0` = unlimited (default). When `> 0`, an Op whose projected
    /// post-commit total exceeds this is denied per-Op (`EffectFailed`)
    /// without rolling back sibling Ops.
    pub memory_budget_bytes: u64,
    /// Parent `InstanceId` for hierarchical quota enforcement
    /// (`apply_quota_reduction`); `None` for root instances.
    pub parent: Option<InstanceId>,
    /// Policy applied when a parent's quota would drop below current
    /// child aggregate usage. See [`QuotaReductionPolicy`].
    pub quota_reduction: QuotaReductionPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_is_zero_quota_reject_policy() {
        let c = InstanceConfig::default();
        assert_eq!(c.max_entities, 0);
        assert_eq!(c.max_scheduled, 0);
        assert_eq!(c.memory_budget_bytes, 0);
        assert!(c.parent.is_none());
        assert_eq!(c.quota_reduction, QuotaReductionPolicy::Reject);
        assert!(c.default_caps.is_empty());
    }

    #[test]
    fn config_clone_eq() {
        let c1 = InstanceConfig {
            default_caps: CapabilityMask::SYSTEM,
            max_entities: 10,
            max_scheduled: 100,
            memory_budget_bytes: 1024,
            parent: InstanceId::new(7),
            quota_reduction: QuotaReductionPolicy::ThrottleProportional,
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    #[test]
    fn config_field_assignment() {
        let c = InstanceConfig {
            max_entities: 42,
            parent: InstanceId::new(3),
            quota_reduction: QuotaReductionPolicy::GrandfatherExisting,
            ..Default::default()
        };
        assert_eq!(c.max_entities, 42);
        assert_eq!(c.parent, InstanceId::new(3));
        assert_eq!(c.quota_reduction, QuotaReductionPolicy::GrandfatherExisting);
    }
}

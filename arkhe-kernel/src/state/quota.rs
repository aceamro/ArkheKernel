//! `QuotaReductionPolicy` — what to do when a parent's quota
//! reduction would drop below current child aggregate usage.
//!
//! Default `Reject` — explicit opt-in is required for destructive policies.
//! `apply_quota_reduction` is the standalone deterministic algorithm;
//! parent-child wiring at `Kernel::create_instance` time composes around it.

use serde::{Deserialize, Serialize};

use crate::abi::InstanceId;

/// What to do when a parent's quota reduction would drop below the
/// aggregate usage of its children. Default: [`Reject`](Self::Reject).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum QuotaReductionPolicy {
    /// Reject the reduction request if `new_quota < sum(child_usage)`.
    #[default]
    Reject,
    /// Existing usage retained as-is; the new quota applies only to
    /// future allocations.
    GrandfatherExisting,
    /// Existing usage proportionally scaled down; deterministic
    /// round-robin over `BTreeMap<InstanceId, _>` ascending order
    /// distributes any remainder bytes.
    ThrottleProportional,
}

/// Failure mode for [`apply_quota_reduction`] under
/// [`QuotaReductionPolicy::Reject`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuotaReductionError {
    /// `Reject` policy: the requested `new_quota` is strictly less than
    /// the aggregate `current_usage` already attributed to children.
    WouldViolateChildren {
        /// Sum of `current_usage` across the children at the time of
        /// the call.
        current_usage: u64,
        /// Requested quota that triggered the rejection.
        new_quota: u64,
    },
}

impl core::fmt::Display for QuotaReductionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WouldViolateChildren {
                current_usage,
                new_quota,
            } => write!(
                f,
                "quota reduction would violate children: current_usage={}, new_quota={}",
                current_usage, new_quota
            ),
        }
    }
}

impl std::error::Error for QuotaReductionError {}

/// Compute each child's new quota under `policy` against `new_quota`.
///
/// `children` must be sorted by `InstanceId` ascending (A23 canonical
/// order); a `debug_assert!` checks this in debug builds. The returned
/// vector preserves input order.
///
/// Algorithm by variant:
/// - `Reject`: `Err(WouldViolateChildren)` when `sum(current) > new_quota`,
///   otherwise return children unchanged.
/// - `GrandfatherExisting`: return children unchanged unconditionally —
///   the caller treats `new_quota - sum(current)` as the headroom for
///   future allocations.
/// - `ThrottleProportional`: each child gets
///   `floor(current * new_quota / total)` (u128-promoted to avoid
///   overflow); the floor remainder `new_quota - sum(scaled)` is
///   distributed as +1 per child in ascending `InstanceId` order until
///   exhausted (deterministic — A23). `total == 0` short-circuits to
///   identity.
///
/// Panic-free (A12): saturating arithmetic throughout.
#[must_use = "policy result determines whether the reduction can proceed"]
pub fn apply_quota_reduction(
    policy: QuotaReductionPolicy,
    new_quota: u64,
    children: &[(InstanceId, u64)],
) -> Result<Vec<(InstanceId, u64)>, QuotaReductionError> {
    debug_assert!(
        children.windows(2).all(|w| w[0].0 <= w[1].0),
        "apply_quota_reduction: children must be sorted by InstanceId ascending"
    );

    let current_total: u64 = children
        .iter()
        .map(|(_, u)| *u)
        .fold(0u64, u64::saturating_add);

    match policy {
        QuotaReductionPolicy::Reject => {
            if current_total > new_quota {
                Err(QuotaReductionError::WouldViolateChildren {
                    current_usage: current_total,
                    new_quota,
                })
            } else {
                Ok(children.to_vec())
            }
        }
        QuotaReductionPolicy::GrandfatherExisting => Ok(children.to_vec()),
        QuotaReductionPolicy::ThrottleProportional => {
            if children.is_empty() || current_total == 0 {
                return Ok(children.to_vec());
            }
            let total = current_total as u128;
            let target = new_quota as u128;
            let mut out: Vec<(InstanceId, u64)> = Vec::with_capacity(children.len());
            let mut allocated: u128 = 0;
            for (id, current) in children {
                let scaled = (*current as u128).saturating_mul(target) / total;
                let scaled_u64 = scaled.min(u64::MAX as u128) as u64;
                allocated = allocated.saturating_add(scaled);
                out.push((*id, scaled_u64));
            }
            let mut remainder = target.saturating_sub(allocated);
            for entry in out.iter_mut() {
                if remainder == 0 {
                    break;
                }
                entry.1 = entry.1.saturating_add(1);
                remainder -= 1;
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_default_is_reject() {
        assert_eq!(
            QuotaReductionPolicy::default(),
            QuotaReductionPolicy::Reject
        );
    }

    #[test]
    fn policy_three_distinct_variants() {
        let a = QuotaReductionPolicy::Reject;
        let b = QuotaReductionPolicy::GrandfatherExisting;
        let c = QuotaReductionPolicy::ThrottleProportional;
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn error_display_includes_numbers() {
        let e = QuotaReductionError::WouldViolateChildren {
            current_usage: 100,
            new_quota: 50,
        };
        let s = format!("{}", e);
        assert!(s.contains("current_usage=100"));
        assert!(s.contains("new_quota=50"));
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<QuotaReductionError>();
    }

    // ---- apply_quota_reduction ----

    fn id(n: u64) -> InstanceId {
        InstanceId::new(n).unwrap()
    }

    #[test]
    fn reject_allows_under_quota() {
        let cs = vec![(id(1), 25), (id(2), 25)];
        let result = apply_quota_reduction(QuotaReductionPolicy::Reject, 100, &cs).unwrap();
        assert_eq!(result, cs);
    }

    #[test]
    fn reject_denies_over_quota() {
        let cs = vec![(id(1), 100), (id(2), 100)];
        let err = apply_quota_reduction(QuotaReductionPolicy::Reject, 100, &cs).unwrap_err();
        assert_eq!(
            err,
            QuotaReductionError::WouldViolateChildren {
                current_usage: 200,
                new_quota: 100,
            }
        );
    }

    #[test]
    fn reject_at_exact_limit_allows() {
        let cs = vec![(id(1), 50), (id(2), 50)];
        let result = apply_quota_reduction(QuotaReductionPolicy::Reject, 100, &cs).unwrap();
        assert_eq!(result, cs);
    }

    #[test]
    fn grandfather_returns_children_unchanged() {
        let cs = vec![(id(1), 100), (id(2), 100)];
        let result =
            apply_quota_reduction(QuotaReductionPolicy::GrandfatherExisting, 100, &cs).unwrap();
        assert_eq!(result, cs);
    }

    #[test]
    fn throttle_basic() {
        // 100/200/300 (total 600) scaled to new_quota 300 → exact halving.
        let cs = vec![(id(1), 100), (id(2), 200), (id(3), 300)];
        let result =
            apply_quota_reduction(QuotaReductionPolicy::ThrottleProportional, 300, &cs).unwrap();
        assert_eq!(result, vec![(id(1), 50), (id(2), 100), (id(3), 150)]);
    }

    #[test]
    fn throttle_remainder_distributes_ascending() {
        // 100/100/100 (total 300) scaled to 100: each floor = 33; sum = 99;
        // remainder 1 lands on id=1 (lowest). Final: 34/33/33, sum = 100.
        let cs = vec![(id(1), 100), (id(2), 100), (id(3), 100)];
        let result =
            apply_quota_reduction(QuotaReductionPolicy::ThrottleProportional, 100, &cs).unwrap();
        assert_eq!(result, vec![(id(1), 34), (id(2), 33), (id(3), 33)]);
        let sum: u64 = result.iter().map(|(_, q)| *q).sum();
        assert_eq!(sum, 100);
    }

    #[test]
    fn throttle_zero_total_idempotent() {
        let cs = vec![(id(1), 0), (id(2), 0)];
        let result =
            apply_quota_reduction(QuotaReductionPolicy::ThrottleProportional, 100, &cs).unwrap();
        assert_eq!(result, cs);
    }

    #[test]
    fn throttle_deterministic() {
        let cs = vec![(id(1), 100), (id(2), 100), (id(3), 100)];
        let r1 =
            apply_quota_reduction(QuotaReductionPolicy::ThrottleProportional, 100, &cs).unwrap();
        let r2 =
            apply_quota_reduction(QuotaReductionPolicy::ThrottleProportional, 100, &cs).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn apply_to_empty_children_returns_empty() {
        let cs: Vec<(InstanceId, u64)> = vec![];
        for policy in [
            QuotaReductionPolicy::Reject,
            QuotaReductionPolicy::GrandfatherExisting,
            QuotaReductionPolicy::ThrottleProportional,
        ] {
            let result = apply_quota_reduction(policy, 100, &cs).unwrap();
            assert!(
                result.is_empty(),
                "policy {:?} should pass empty through",
                policy
            );
        }
    }
}

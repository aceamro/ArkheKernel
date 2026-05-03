//! Authority principal — non-optional, exhaustive enum.
//!
//! A three-variant enum forces every reader site to handle the
//! unauthenticated state explicitly. Under
//! `clippy::wildcard_enum_match_arm = deny`, a catch-all `_ =>`
//! match arm is a compile error; adding a new variant is therefore a
//! breaking change surfaced at every reader.

use serde::{Deserialize, Serialize};

/// Opaque L2-supplied external identity. Kernel does not interpret its
/// contents (`Mechanism != Policy`). The concrete byte shape is an L2
/// concern — this newtype carries a `u64` for v0.13 and reserves the
/// option to widen to a fixed-size cryptographic identifier in a future
/// approximation (deferred `[u8; 32]` option).
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExternalId(pub u64);

/// Authority principal. Three states, exhaustively type-checked.
///
/// - `Unauthenticated`: caller identity has not been verified by L2
///   (pre-auth lobby, anonymous submit path). Authorization paths must
///   treat this distinctly from `External(_)`.
/// - `External`: L2-verified external identity.
/// - `System`: kernel-internal origin (init, signal-relay, cleanup cascade,
///   replay re-injection). Ships as a payloadless variant; a `SystemOrigin`
///   payload widening is reserved (deferred).
///
/// `#[non_exhaustive]` protects the ABI: external consumers cannot match
/// exhaustively, so adding variants is not a breaking change for them.
/// Within-crate consumers see every variant and are forced by the linter
/// to match exhaustively.
#[non_exhaustive]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Principal {
    /// Caller identity has not been verified by L2 (pre-auth lobby,
    /// anonymous submit path).
    Unauthenticated,
    /// L2-verified external identity.
    External(ExternalId),
    /// Kernel-internal origin (init, signal-relay, cleanup cascade,
    /// replay re-injection).
    System,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_exhaustive_classify() {
        // Classifier uses exhaustive match — this test fails to compile if
        // a new variant is added without updating here, giving a visible
        // reminder that every reader site needs attention.
        fn classify(p: &Principal) -> &'static str {
            match p {
                Principal::Unauthenticated => "unauth",
                Principal::External(_) => "external",
                Principal::System => "system",
            }
        }
        assert_eq!(classify(&Principal::Unauthenticated), "unauth");
        assert_eq!(classify(&Principal::External(ExternalId(7))), "external");
        assert_eq!(classify(&Principal::System), "system");
    }

    #[test]
    fn external_id_is_transparent_u64() {
        let id = ExternalId(0xDEAD_BEEF);
        assert_eq!(id.0, 0xDEAD_BEEF);
    }

    #[test]
    fn external_id_is_total_ordered() {
        assert!(ExternalId(1) < ExternalId(2));
    }

    #[test]
    fn principal_equality() {
        assert_eq!(Principal::Unauthenticated, Principal::Unauthenticated);
        assert_eq!(
            Principal::External(ExternalId(3)),
            Principal::External(ExternalId(3))
        );
        assert_ne!(
            Principal::External(ExternalId(3)),
            Principal::External(ExternalId(4))
        );
        assert_ne!(Principal::System, Principal::Unauthenticated);
    }
}

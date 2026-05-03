//! Kernel-level error taxonomy.
//!
//! The `Domain` variant is opaque to the kernel — code and payload are
//! L2/L1 concerns. This prevents domain-level error paths from being
//! forced into string smuggling or `EmitEvent` side-channels.
//!
//! `#[non_exhaustive]` defends the ABI: external matchers are forbidden
//! from exhaustive-matching, so future variants are not breaking for
//! external consumers.

use bytes::Bytes;

/// Top-level kernel error.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum ArkheError {
    /// Requested `InstanceId` is not live.
    InstanceNotFound,

    /// Caller lacks one or more required capability bits.
    CapabilityDenied,

    /// Domain-level error. The kernel does not interpret `code` or
    /// `payload`; they are an L1/L2 protocol. Payload is canonical bytes
    /// (CanonicalEncode discipline) so cross-replay determinism holds.
    Domain {
        /// L1/L2-defined error code; kernel-opaque.
        code: u32,
        /// Canonical bytes carrying L1/L2-defined error payload.
        payload: Bytes,
    },
}

impl core::fmt::Display for ArkheError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InstanceNotFound => write!(f, "instance not found"),
            Self::CapabilityDenied => write!(f, "capability denied"),
            Self::Domain { code, payload } => {
                write!(
                    f,
                    "domain error: code={} payload_len={}",
                    code,
                    payload.len()
                )
            }
        }
    }
}

impl std::error::Error for ArkheError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_error_carries_code_and_payload() {
        let err = ArkheError::Domain {
            code: 42,
            payload: Bytes::from_static(b"opaque"),
        };
        match err {
            ArkheError::Domain { code, payload } => {
                assert_eq!(code, 42);
                assert_eq!(&payload[..], b"opaque");
            }
            _ => panic!("expected Domain variant"),
        }
    }

    #[test]
    fn domain_error_payload_can_be_empty() {
        let err = ArkheError::Domain {
            code: 0,
            payload: Bytes::new(),
        };
        match err {
            ArkheError::Domain { payload, .. } => assert!(payload.is_empty()),
            _ => panic!("expected Domain variant"),
        }
    }

    #[test]
    fn error_display_instance_not_found() {
        let err = ArkheError::InstanceNotFound;
        assert_eq!(format!("{}", err), "instance not found");
    }

    #[test]
    fn error_display_capability_denied() {
        let err = ArkheError::CapabilityDenied;
        assert_eq!(format!("{}", err), "capability denied");
    }

    #[test]
    fn error_display_domain_includes_code() {
        let err = ArkheError::Domain {
            code: 7,
            payload: Bytes::from_static(b"xyz"),
        };
        let s = format!("{}", err);
        assert!(s.contains("code=7"));
        assert!(s.contains("payload_len=3"));
    }

    #[test]
    fn error_implements_std_error() {
        fn assert_std_error<E: std::error::Error>() {}
        assert_std_error::<ArkheError>();
    }
}

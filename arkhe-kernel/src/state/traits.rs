//! Sealed traits for kernel-managed types.
//!
//! `Component`, `Action`, `Event` are derive-only. Domains reach `Action`
//! through `#[derive(arkhe_macros::ArkheAction)]`, which generates the
//! `_sealed::Sealed` + `ActionDeriv` impls; the kernel's blanket
//! `impl<T: ActionDeriv + ActionCompute> Action for T` then supplies the
//! postcard-canonical default methods. `Component` and `Event` keep the
//! single-trait shape until their derive macros land alongside the
//! snapshot integration.
//!
//! `_sealed::Sealed` is `#[doc(hidden)] pub`. The Rust language has no
//! true sealing primitive — this is the documented convention. Manual
//! `impl _sealed::Sealed` from outside the crate is technically possible
//! but auditable and against contract; A11 grade rests on the macro
//! being the canonical (and documented) path.

use crate::abi::TypeCode;

#[doc(hidden)]
pub mod _sealed {
    pub trait Sealed {}
}

/// Deserialization failure for canonical-bytes round-trip.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum DeserializeError {
    /// Stored bytes carry a different `SCHEMA_VERSION` than the type
    /// being decoded into.
    SchemaVersionMismatch {
        /// `SCHEMA_VERSION` declared on the target type.
        expected: u32,
        /// `version` argument supplied by the caller.
        got: u32,
    },
    /// Postcard refused to decode the bytes (truncated, invalid tag,
    /// type-shape mismatch).
    PayloadMalformed,
    /// `TypeCode` not present in the registry consulted at decode time.
    UnknownTypeCode {
        /// The unrecognized `TypeCode`.
        observed: TypeCode,
    },
    /// Encoded length exceeded the configured per-Action / per-Component
    /// byte budget.
    LengthExceedsBudget,
}

impl core::fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SchemaVersionMismatch { expected, got } => {
                write!(
                    f,
                    "schema version mismatch: expected {}, got {}",
                    expected, got
                )
            }
            Self::PayloadMalformed => write!(f, "payload malformed"),
            Self::UnknownTypeCode { observed } => {
                write!(f, "unknown type code: {:?}", observed)
            }
            Self::LengthExceedsBudget => write!(f, "deserialization length exceeds budget"),
        }
    }
}

impl std::error::Error for DeserializeError {}

/// Component — derive-only via `#[derive(arkhe_macros::ArkheComponent)]`.
/// Default methods use postcard for the canonical-bytes round trip;
/// the macro only needs to emit `Sealed` + the const declarations.
pub trait Component:
    _sealed::Sealed + serde::Serialize + serde::de::DeserializeOwned + 'static
{
    /// Stable dispatch identifier for this component type. Set by the
    /// `#[arkhe(type_code = N, ...)]` attribute on the deriving struct.
    const TYPE_CODE: TypeCode;
    /// Version tag accompanying canonical bytes. Bumping invalidates
    /// older serialized payloads at decode time.
    const SCHEMA_VERSION: u32;

    /// Postcard-canonical byte encoding. Default implementation uses
    /// `postcard::to_allocvec` against the deriving type's serde impl.
    fn canonical_bytes(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        postcard::to_allocvec(self).expect("postcard encode self for Component::canonical_bytes")
    }

    /// Inverse of [`canonical_bytes`](Component::canonical_bytes).
    /// Returns [`DeserializeError::SchemaVersionMismatch`] if `version`
    /// does not equal [`Component::SCHEMA_VERSION`].
    fn from_bytes(version: u32, bytes: &[u8]) -> Result<Box<Self>, DeserializeError>
    where
        Self: Sized,
    {
        if version != Self::SCHEMA_VERSION {
            return Err(DeserializeError::SchemaVersionMismatch {
                expected: Self::SCHEMA_VERSION,
                got: version,
            });
        }
        postcard::from_bytes::<Self>(bytes)
            .map(Box::new)
            .map_err(|_| DeserializeError::PayloadMalformed)
    }

    /// Approximate byte size — defaults to `canonical_bytes().len()`.
    /// Override only if a cheaper estimate is required.
    fn approx_size(&self) -> usize
    where
        Self: Sized,
    {
        self.canonical_bytes().len()
    }
}

/// Derive-emitted half of `Action`. Carries the constants and the
/// serde bounds that `Action`'s blanket impl needs to drive postcard.
/// `#[derive(arkhe_macros::ArkheAction)]` is the only sanctioned path.
pub trait ActionDeriv:
    _sealed::Sealed + serde::Serialize + serde::de::DeserializeOwned + 'static
{
    /// Stable dispatch identifier. Set via `#[arkhe(type_code = N, ...)]`.
    const TYPE_CODE: TypeCode;
    /// Version tag for canonical bytes. Bumping invalidates older
    /// serialized bodies.
    const SCHEMA_VERSION: u32;
}

/// User-written half of `Action`. The deterministic effect-list
/// computation is the only domain logic the kernel runs.
pub trait ActionCompute: 'static {
    /// Translate this action into a list of [`Op`](super::op::Op)s the
    /// kernel will then authorize, dispatch, and apply. **Must be
    /// pure** — A11 SOCIAL-CONTRACT until the subset-Rust checker
    /// promotes it to MACHINE-CHECKED.
    fn compute(&self, ctx: &super::context::ActionContext) -> Vec<super::op::Op>;
}

/// `Action` — kernel-facing trait. Composed automatically by the
/// blanket below: any `T: ActionDeriv + ActionCompute` is `Action`.
/// External code never implements this directly.
///
/// Default method bodies use postcard for the canonical-bytes round
/// trip (R3v3-Δ2). `approx_size` defaults to the encoded length;
/// override only if a cheaper estimate is required.
pub trait Action: ActionDeriv + ActionCompute {
    /// Postcard-canonical byte encoding. See
    /// [`Component::canonical_bytes`] for the contract; identical
    /// shape applies here.
    fn canonical_bytes(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        postcard::to_allocvec(self).expect("postcard encode self for canonical_bytes")
    }

    /// Inverse of [`canonical_bytes`](Action::canonical_bytes).
    /// `SchemaVersionMismatch` on unequal version.
    fn from_bytes(version: u32, bytes: &[u8]) -> Result<Box<Self>, DeserializeError>
    where
        Self: Sized,
    {
        if version != Self::SCHEMA_VERSION {
            return Err(DeserializeError::SchemaVersionMismatch {
                expected: Self::SCHEMA_VERSION,
                got: version,
            });
        }
        postcard::from_bytes::<Self>(bytes)
            .map(Box::new)
            .map_err(|_| DeserializeError::PayloadMalformed)
    }

    /// Approximate byte size — defaults to encoded length.
    fn approx_size(&self) -> usize
    where
        Self: Sized,
    {
        self.canonical_bytes().len()
    }
}

impl<T: ActionDeriv + ActionCompute> Action for T {}

/// Event — derive-only via `#[derive(arkhe_macros::ArkheEvent)]`. Same
/// postcard-default shape as `Component`; user types must additionally
/// `#[derive(Debug, serde::Serialize, serde::Deserialize)]`.
pub trait Event:
    _sealed::Sealed + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned + 'static
{
    /// Stable dispatch identifier. Set via `#[arkhe(type_code = N, ...)]`.
    const TYPE_CODE: TypeCode;
    /// Version tag for canonical bytes.
    const SCHEMA_VERSION: u32;

    /// Postcard-canonical byte encoding.
    fn canonical_bytes(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        postcard::to_allocvec(self).expect("postcard encode self for Event::canonical_bytes")
    }

    /// Inverse of [`canonical_bytes`](Event::canonical_bytes).
    fn from_bytes(version: u32, bytes: &[u8]) -> Result<Box<Self>, DeserializeError>
    where
        Self: Sized,
    {
        if version != Self::SCHEMA_VERSION {
            return Err(DeserializeError::SchemaVersionMismatch {
                expected: Self::SCHEMA_VERSION,
                got: version,
            });
        }
        postcard::from_bytes::<Self>(bytes)
            .map(Box::new)
            .map_err(|_| DeserializeError::PayloadMalformed)
    }

    /// Approximate byte size — defaults to encoded length.
    fn approx_size(&self) -> usize
    where
        Self: Sized,
    {
        self.canonical_bytes().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_error_display_includes_versions() {
        let e = DeserializeError::SchemaVersionMismatch {
            expected: 1,
            got: 2,
        };
        let s = format!("{}", e);
        assert!(s.contains("expected 1"));
        assert!(s.contains("got 2"));
    }

    #[test]
    fn deserialize_error_payload_malformed_displays() {
        let e = DeserializeError::PayloadMalformed;
        assert_eq!(format!("{}", e), "payload malformed");
    }

    #[test]
    fn deserialize_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<DeserializeError>();
    }

    #[test]
    fn sealed_trait_is_implementable_within_crate() {
        // Crate-internal impl is permitted; this test compiles only if the
        // seal module is reachable from this test scope.
        struct CrateInternalProof;
        impl _sealed::Sealed for CrateInternalProof {}
        let _ = CrateInternalProof;
    }
}

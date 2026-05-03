//! L0 ABI stratum.
//!
//! The outermost protocol surface of the kernel: identifiers, authority
//! principals, capability masks, top-level error type. No dependencies on
//! state / runtime / persist strata.
//!
//! Downstream layers re-export through `lib.rs`; external callers import
//! from `arkhe_kernel::abi::*`.

pub mod caps;
pub mod error;
pub mod ids;
pub mod principal;

pub use caps::CapabilityMask;
pub use error::ArkheError;
pub use ids::{EntityId, InstanceId, RouteId, Tick, TypeCode};
pub use principal::{ExternalId, Principal};

//! L0 persist stratum.
//!
//! In-memory WAL with header pinning (A14), BLAKE3-keyed chain
//! (A13), per-record `AuthDecisionAnnotation` (belt-and-suspenders),
//! and replay (A1 D1-Total bit-identical reconstruction).
//!
//! File I/O is application responsibility; this stratum produces and
//! consumes byte buffers via `Wal::serialize` / `Wal::deserialize`.

pub mod replay;
pub mod signature;
pub mod snapshot;
pub mod wal;

pub use replay::{replay_into, ReplayError, ReplayReport};
pub use signature::SignatureClass;
pub use snapshot::{KernelSnapshot, SnapshotError};
pub use wal::{
    AuthDecisionAnnotation, TypeRegistryPin, Wal, WalError, WalHeader, WalRecord, WalWriter,
};

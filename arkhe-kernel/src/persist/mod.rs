//! L0 persist stratum.
//!
//! In-memory WAL as a Canonical Input Log (CIL): each record captures only
//! a non-reproducible fact — an exogenous `Submit` (external admission) or a
//! per-pop `Step` verdict plus the full post-state digest. Every
//! deterministic effect (child schedules, signal routing, internal ids) is
//! re-derived on replay. Header pinning (A14), BLAKE3-keyed chain (A13), and
//! replay (A1 D1-Total bit-identical reconstruction).
//!
//! File I/O is application responsibility; this stratum produces and
//! consumes byte buffers via `Wal::serialize` / `Wal::deserialize`.

pub mod replay;
pub mod signature;
pub mod snapshot;
pub mod wal;

pub use replay::{replay_into, replay_into_verified, ReplayError, ReplayReport};
pub use signature::SignatureClass;
pub use snapshot::{KernelSnapshot, SnapshotError};
pub use wal::{
    SignatureTier, SkipReason, StepVerdict, TrustAnchor, TypeRegistryPin, Wal, WalError, WalHeader,
    WalRecord, WalRecordContent, WalRecordKind, WalWriter,
};

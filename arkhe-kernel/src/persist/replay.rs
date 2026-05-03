//! WAL → Kernel replay (A1 D1-Total bit-identical reconstruction).
//!
//! Replay is the from-fresh-state path: the caller re-creates the
//! instances referenced by the WAL with matching configs before calling
//! `replay_into`. The snapshot path (`KernelSnapshot` plus
//! `Kernel::from_snapshot`) is the alternative — restore from a
//! point-in-time blob without re-running history.

use crate::abi::CapabilityMask;
use crate::runtime::Kernel;

use super::wal::{Wal, WalError, WalHeader};

/// Aggregated outcome of [`replay_into`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Number of WAL records consumed.
    pub records_replayed: u32,
    /// Sum of `effects_applied` across all replayed steps.
    pub total_effects_applied: u32,
    /// Sum of `effects_denied` across all replayed steps.
    pub total_effects_denied: u32,
    /// Chain tip after the final replayed record (matches the
    /// pre-replay export when the replay is bit-identical).
    pub final_chain_tip: [u8; 32],
}

/// Failure modes for [`replay_into`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReplayError {
    /// WAL header magic doesn't match `WalHeader::MAGIC`.
    HeaderIncompatible(String),
    /// `kernel_semver` differs between WAL header and the running kernel.
    KernelSemverMismatch {
        /// Semver pinned in the WAL header.
        expected: (u16, u16, u16),
        /// Current running kernel semver.
        got: (u16, u16, u16),
    },
    /// `abi_version` differs between WAL header and the running kernel.
    AbiVersionMismatch {
        /// ABI version pinned in the WAL header.
        expected: (u16, u16),
        /// Current running kernel ABI version.
        got: (u16, u16),
    },
    /// Underlying WAL chain/signature verification failure.
    WalCorrupted(WalError),
    /// `Kernel::submit` failed during replay (carries the formatted
    /// upstream error).
    SubmitFailed(String),
}

impl From<WalError> for ReplayError {
    fn from(e: WalError) -> Self {
        Self::WalCorrupted(e)
    }
}

impl core::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HeaderIncompatible(m) => write!(f, "wal header incompatible: {}", m),
            Self::KernelSemverMismatch { expected, got } => {
                write!(
                    f,
                    "kernel semver mismatch: expected {:?}, got {:?}",
                    expected, got
                )
            }
            Self::AbiVersionMismatch { expected, got } => {
                write!(
                    f,
                    "abi version mismatch: expected {:?}, got {:?}",
                    expected, got
                )
            }
            Self::WalCorrupted(e) => write!(f, "wal corrupted: {}", e),
            Self::SubmitFailed(m) => write!(f, "submit failed: {}", m),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Replay every record into `kernel`. The caller must already have
/// created the instances referenced by the WAL; for the integrated
/// path (no manual pre-creation), use `Kernel::from_snapshot` against
/// a `KernelSnapshot` instead.
pub fn replay_into(kernel: &mut Kernel, wal: &Wal) -> Result<ReplayReport, ReplayError> {
    if wal.header.magic != WalHeader::MAGIC {
        return Err(ReplayError::HeaderIncompatible(
            "magic mismatch (expected ARKHEWAL)".to_string(),
        ));
    }
    if wal.header.kernel_semver.0 != WalHeader::CURRENT_KERNEL_SEMVER.0 {
        return Err(ReplayError::KernelSemverMismatch {
            expected: WalHeader::CURRENT_KERNEL_SEMVER,
            got: wal.header.kernel_semver,
        });
    }
    if wal.header.abi_version != WalHeader::ABI_VERSION {
        return Err(ReplayError::AbiVersionMismatch {
            expected: WalHeader::ABI_VERSION,
            got: wal.header.abi_version,
        });
    }

    wal.verify_chain(wal.header.world_id)?;

    let mut report = ReplayReport::default();
    for rec in &wal.records {
        let caps = CapabilityMask::from_bits_truncate(rec.caps_bits);
        let principal = match &rec.principal {
            crate::abi::Principal::Unauthenticated => crate::abi::Principal::Unauthenticated,
            crate::abi::Principal::External(e) => crate::abi::Principal::External(*e),
            crate::abi::Principal::System => crate::abi::Principal::System,
        };
        kernel
            .submit(
                rec.instance,
                principal,
                None,
                rec.at,
                rec.action_type_code,
                rec.action_bytes.clone(),
            )
            .map_err(|e| ReplayError::SubmitFailed(format!("{:?}", e)))?;
        let step_report = kernel.step(rec.at, caps);
        report.records_replayed = report.records_replayed.saturating_add(1);
        report.total_effects_applied = report
            .total_effects_applied
            .saturating_add(step_report.effects_applied);
        report.total_effects_denied = report
            .total_effects_denied
            .saturating_add(step_report.effects_denied);
    }
    report.final_chain_tip = wal.chain_tip();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Tick;
    use crate::persist::wal::{AuthDecisionAnnotation, Wal, WalWriter};

    fn world() -> [u8; 32] {
        [11u8; 32]
    }

    #[test]
    fn replay_empty_wal_succeeds() {
        let w = WalWriter::new(world(), [0u8; 32]);
        let wal = Wal::from_writer(w);
        let mut kernel = Kernel::new();
        let report = replay_into(&mut kernel, &wal).unwrap();
        assert_eq!(report.records_replayed, 0);
    }

    #[test]
    fn replay_rejects_wrong_magic() {
        let w = WalWriter::new(world(), [0u8; 32]);
        let mut wal = Wal::from_writer(w);
        wal.header.magic = *b"BADMAGIC";
        let mut kernel = Kernel::new();
        let result = replay_into(&mut kernel, &wal);
        assert!(matches!(result, Err(ReplayError::HeaderIncompatible(_))));
    }

    #[test]
    fn replay_rejects_kernel_semver_major_mismatch() {
        let w = WalWriter::new(world(), [0u8; 32]);
        let mut wal = Wal::from_writer(w);
        wal.header.kernel_semver = (99, 0, 0);
        let mut kernel = Kernel::new();
        let result = replay_into(&mut kernel, &wal);
        assert!(matches!(
            result,
            Err(ReplayError::KernelSemverMismatch { .. })
        ));
    }

    #[test]
    fn replay_rejects_corrupted_chain() {
        let mut w = WalWriter::new(world(), [0u8; 32]);
        w.append(
            Tick(0),
            crate::abi::InstanceId::new(1).unwrap(),
            crate::abi::Principal::System,
            crate::abi::TypeCode(100),
            vec![],
            0,
            crate::runtime::stage::StepStage::default(),
            AuthDecisionAnnotation::AllAuthorized,
        )
        .unwrap();
        let mut wal = Wal::from_writer(w);
        wal.records[0].this_chain_hash = [0xFFu8; 32];
        let mut kernel = Kernel::new();
        let result = replay_into(&mut kernel, &wal);
        assert!(matches!(result, Err(ReplayError::WalCorrupted(_))));
    }
}

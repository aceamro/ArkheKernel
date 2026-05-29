//! WAL → Kernel replay (A1 D1-Total bit-identical reconstruction).
//!
//! Replay is the from-fresh-state path: the caller re-creates the
//! instances referenced by the WAL with matching configs before calling
//! `replay_into`. The snapshot path (`KernelSnapshot` plus
//! `Kernel::from_snapshot`) is the alternative — restore from a
//! point-in-time blob without re-running history.

use crate::abi::CapabilityMask;
use crate::runtime::Kernel;

use super::wal::{TrustAnchor, Wal, WalError, WalHeader};

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
    /// `postcard_version` differs between WAL header and the running build.
    PostcardVersionMismatch {
        /// Postcard major pinned in the WAL header.
        expected: u32,
        /// Current running postcard major.
        got: u32,
    },
    /// `blake3_version` differs between WAL header and the running build.
    Blake3VersionMismatch {
        /// BLAKE3 major pinned in the WAL header.
        expected: u32,
        /// Current running BLAKE3 major.
        got: u32,
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
            Self::PostcardVersionMismatch { expected, got } => {
                write!(
                    f,
                    "postcard version mismatch: expected {}, got {}",
                    expected, got
                )
            }
            Self::Blake3VersionMismatch { expected, got } => {
                write!(f, "blake3 version mismatch: expected {}, got {}", expected, got)
            }
            Self::WalCorrupted(e) => write!(f, "wal corrupted: {}", e),
            Self::SubmitFailed(m) => write!(f, "submit failed: {}", m),
        }
    }
}

impl std::error::Error for ReplayError {}

/// Header-compatibility gates shared by [`replay_into`] and
/// [`replay_into_verified`] (A14): magic, kernel semver major, ABI
/// version, postcard / BLAKE3 major. A mismatch is a structural error.
fn check_header_gates(wal: &Wal) -> Result<(), ReplayError> {
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
    // postcard / BLAKE3 major versions are wire-format determinants (A14
    // header pinning): a mismatch means the bytes were produced under a
    // different codec/hash generation and must NOT be silently accepted.
    if wal.header.postcard_version != WalHeader::POSTCARD_MAJOR {
        return Err(ReplayError::PostcardVersionMismatch {
            expected: WalHeader::POSTCARD_MAJOR,
            got: wal.header.postcard_version,
        });
    }
    if wal.header.blake3_version != WalHeader::BLAKE3_MAJOR {
        return Err(ReplayError::Blake3VersionMismatch {
            expected: WalHeader::BLAKE3_MAJOR,
            got: wal.header.blake3_version,
        });
    }
    Ok(())
}

/// Replay the (already chain-verified) records into `kernel`.
fn replay_records(kernel: &mut Kernel, wal: &Wal) -> Result<ReplayReport, ReplayError> {
    let mut report = ReplayReport::default();
    for rec in &wal.records {
        // Preserve the EXACT recorded bits (including L2-defined high bits,
        // which `caps.rs` documents as legitimate) rather than truncating
        // to kernel-known bits. Truncation made the write side (full u64)
        // and replay side disagree, so a re-recorded `caps_bits` diverged
        // and broke A1 bit-identical chain reconstruction.
        let caps = CapabilityMask::from_bits_retain(rec.caps_bits);
        let principal = match &rec.principal {
            crate::abi::Principal::Unauthenticated => crate::abi::Principal::Unauthenticated,
            crate::abi::Principal::External(e) => crate::abi::Principal::External(*e),
            crate::abi::Principal::System => crate::abi::Principal::System,
        };
        kernel
            .submit(
                rec.instance,
                principal,
                rec.actor,
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

/// Replay every record into `kernel` (integrity-only). The caller must
/// already have created the instances referenced by the WAL; for the
/// integrated path (no manual pre-creation), use `Kernel::from_snapshot`
/// against a `KernelSnapshot` instead.
///
/// This verifies the chain's internal self-consistency but TRUSTS the
/// WAL's provenance — it derives the verification policy/keys and the
/// chain `world_id` from the (potentially attacker-controlled) header. For
/// an untrusted WAL (tampered log / peer snapshot), use
/// [`replay_into_verified`] with a [`TrustAnchor`].
pub fn replay_into(kernel: &mut Kernel, wal: &Wal) -> Result<ReplayReport, ReplayError> {
    check_header_gates(wal)?;
    wal.verify_chain(wal.header.world_id)?;
    replay_records(kernel, wal)
}

/// Replay every record into `kernel`, authenticating the WAL against a
/// caller-supplied [`TrustAnchor`] and a caller-supplied `world_id` (NOT
/// read from the untrusted header). Rejects a tier downgrade, a
/// verifying-key substitution, a manifest mismatch, and a tail truncation
/// before any record is applied. Use this for WAL bytes from an untrusted
/// source.
pub fn replay_into_verified(
    kernel: &mut Kernel,
    wal: &Wal,
    world_id: [u8; 32],
    anchor: &TrustAnchor,
) -> Result<ReplayReport, ReplayError> {
    check_header_gates(wal)?;
    wal.verify_chain_anchored(world_id, anchor)?;
    replay_records(kernel, wal)
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
    fn replay_rejects_postcard_version_mismatch() {
        let w = WalWriter::new(world(), [0u8; 32]);
        let mut wal = Wal::from_writer(w);
        wal.header.postcard_version = 999;
        let mut kernel = Kernel::new();
        assert!(matches!(
            replay_into(&mut kernel, &wal),
            Err(ReplayError::PostcardVersionMismatch { .. })
        ));
    }

    #[test]
    fn replay_rejects_corrupted_chain() {
        let mut w = WalWriter::new(world(), [0u8; 32]);
        w.append(
            Tick(0),
            crate::abi::InstanceId::new(1).unwrap(),
            crate::abi::Principal::System,
            None,
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

//! WAL → Kernel replay (A1 D1-Total bit-identical reconstruction).
//!
//! Replay is the from-fresh-state path: the caller re-creates the
//! instances referenced by the WAL with matching configs before calling
//! `replay_into`. The snapshot path (`KernelSnapshot` plus
//! `Kernel::from_snapshot`) is the alternative — restore from a
//! point-in-time blob without re-running history.

use crate::abi::{CapabilityMask, InstanceId};
use crate::runtime::Kernel;

use super::wal::{
    StepVerdict, TrustAnchor, Wal, WalError, WalHeader, WalRecordContent, WalWriter,
};

/// Aggregated outcome of [`replay_into`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReplayReport {
    /// Number of `Submit` records re-admitted.
    pub submits_replayed: u32,
    /// Number of `Step` records re-executed.
    pub steps_replayed: u32,
    /// Sum of `effects_applied` across all replayed steps.
    pub total_effects_applied: u32,
    /// Sum of `effects_denied` across all replayed steps.
    pub total_effects_denied: u32,
    /// Chain tip MEASURED by re-sealing the replayed records through a
    /// header-rebuilt writer (matches the sealed WAL's tip when the replay is
    /// bit-identical — it is a recomputed witness, never a copy of the tip).
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
    /// `Kernel::submit_with_id` failed during replay (carries the formatted
    /// upstream error).
    SubmitFailed(String),
    /// A `Step` record was reached but the instance had no due action to pop
    /// — the re-derived scheduler diverged from the recorded history.
    StepUnderflow {
        /// Instance the absent step targeted.
        instance: InstanceId,
    },
    /// A re-executed step popped a different `ScheduledActionId` than recorded
    /// — the re-derived scheduler order diverged.
    PoppedIdDivergence {
        /// Sequence of the offending `Step` record.
        seq: u64,
    },
    /// A re-executed step reached a different verdict than recorded — the
    /// re-derived authorization/budget outcome diverged.
    VerdictDivergence {
        /// Sequence of the offending `Step` record.
        seq: u64,
        /// Verdict pinned in the WAL.
        expected: StepVerdict,
        /// Verdict re-derived on replay.
        got: StepVerdict,
    },
    /// A re-executed step produced a different full-state digest than recorded
    /// — the re-derived state diverged bit-for-bit (A1 failure).
    StateDigestDivergence {
        /// Sequence of the offending `Step` record.
        seq: u64,
    },
    /// The chain tip re-measured from the replayed records does not equal the
    /// sealed WAL's tip — the replay was not bit-identical end-to-end.
    ChainTipDivergence {
        /// Tip sealed in the source WAL.
        expected: [u8; 32],
        /// Tip re-measured from the replayed records.
        measured: [u8; 32],
    },
    /// The WAL header's `manifest_digest` does not equal the replaying
    /// kernel's declared manifest (A14) — the WAL was written under a
    /// different `ModuleManifest`. Closes the otherwise-vacuous default-path
    /// manifest gate without requiring a `TrustAnchor`.
    ManifestDigestMismatch {
        /// Digest pinned in the WAL header.
        expected: [u8; 32],
        /// Digest the replaying kernel declares.
        got: [u8; 32],
    },
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
            Self::StepUnderflow { instance } => {
                write!(f, "replay step underflow: no due action for {:?}", instance)
            }
            Self::PoppedIdDivergence { seq } => {
                write!(f, "replay popped-id divergence at record {}", seq)
            }
            Self::VerdictDivergence { seq, expected, got } => write!(
                f,
                "replay verdict divergence at record {}: expected {:?}, got {:?}",
                seq, expected, got
            ),
            Self::StateDigestDivergence { seq } => {
                write!(f, "replay state-digest divergence at record {}", seq)
            }
            Self::ChainTipDivergence { expected, measured } => write!(
                f,
                "replay chain-tip divergence: expected {}, measured {}",
                blake3::Hash::from(*expected).to_hex(),
                blake3::Hash::from(*measured).to_hex()
            ),
            Self::ManifestDigestMismatch { expected, got } => write!(
                f,
                "replay manifest_digest mismatch: wal {}, kernel {}",
                blake3::Hash::from(*expected).to_hex(),
                blake3::Hash::from(*got).to_hex()
            ),
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

/// Replay the (already chain-verified) Canonical Input Log into `kernel`.
///
/// Each `Submit` is re-admitted under its exact recorded id and ceiling; each
/// `Step` is re-executed via the SAME per-instance driver the live kernel
/// uses ([`Kernel::process_instance_record`]). Replay applies NO effect from
/// the log and COPIES no hash: it re-derives every deterministic effect by
/// re-execution, asserts each step's popped-id / verdict / full-state digest
/// against the record (fail-fast tripwires), and re-seals the records through
/// a header-rebuilt writer to MEASURE the chain tip — which must equal the
/// sealed WAL's tip. This is the structural guarantee that internal
/// scheduling, signal routing, and id allocation cannot drift on replay.
fn replay_records(kernel: &mut Kernel, wal: &Wal) -> Result<ReplayReport, ReplayError> {
    let mut report = ReplayReport::default();
    // The replay-side measurement writer: same world_id-derived chain key,
    // None signing (the chain hash is over the body, which excludes
    // signatures, so an unsigned re-seal reproduces every `this_chain_hash`).
    let mut writer = WalWriter::rebuild_from_header(&wal.header);

    for rec in &wal.records {
        match &rec.content {
            WalRecordContent::Submit {
                seq: _,
                instance,
                principal,
                actor,
                caps_at_submit,
                at,
                action_type_code,
                action_bytes,
                allocated_id,
            } => {
                let caps = CapabilityMask::from_bits_retain(*caps_at_submit);
                kernel
                    .submit_with_id(
                        *instance,
                        principal.clone(),
                        *actor,
                        caps,
                        *allocated_id,
                        *at,
                        *action_type_code,
                        action_bytes.clone(),
                    )
                    .map_err(|e| ReplayError::SubmitFailed(format!("{:?}", e)))?;
                writer.append_submit(
                    *instance,
                    principal.clone(),
                    *actor,
                    *caps_at_submit,
                    *at,
                    *action_type_code,
                    action_bytes.clone(),
                    *allocated_id,
                )?;
                report.submits_replayed = report.submits_replayed.saturating_add(1);
            }
            WalRecordContent::Step {
                seq,
                instance,
                popped_id,
                now,
                session_caps,
                verdict,
                post_state_digest,
            } => {
                let session = CapabilityMask::from_bits_retain(*session_caps);
                let result = kernel
                    .process_instance_record(*instance, *now, session, true)
                    .ok_or(ReplayError::StepUnderflow {
                        instance: *instance,
                    })?;
                // Tripwires — replay must re-reach the recorded facts exactly.
                if result.popped_id != *popped_id {
                    return Err(ReplayError::PoppedIdDivergence { seq: *seq });
                }
                if result.verdict != *verdict {
                    return Err(ReplayError::VerdictDivergence {
                        seq: *seq,
                        expected: *verdict,
                        got: result.verdict,
                    });
                }
                if result.digest != *post_state_digest {
                    return Err(ReplayError::StateDigestDivergence { seq: *seq });
                }
                writer.append_step(
                    *instance,
                    *popped_id,
                    *now,
                    *session_caps,
                    *verdict,
                    *post_state_digest,
                )?;
                report.steps_replayed = report.steps_replayed.saturating_add(1);
                report.total_effects_applied = report
                    .total_effects_applied
                    .saturating_add(result.effects_applied);
                report.total_effects_denied = report
                    .total_effects_denied
                    .saturating_add(result.effects_denied);
            }
        }
    }

    // The tip is MEASURED from the re-sealed records, then checked against the
    // sealed WAL — never copied from it.
    let measured = writer.chain_tip();
    let sealed = wal.chain_tip();
    if measured != sealed {
        return Err(ReplayError::ChainTipDivergence {
            expected: sealed,
            measured,
        });
    }
    report.final_chain_tip = measured;
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
    // A14 default-path manifest gate: the WAL must have been written under the
    // same `ModuleManifest` the replaying kernel declares. This is a
    // self-consistency check (no `TrustAnchor` required) — for untrusted WAL
    // bytes, `replay_into_verified` additionally pins keys/tier/tip.
    if wal.header.manifest_digest != kernel.manifest_digest() {
        return Err(ReplayError::ManifestDigestMismatch {
            expected: wal.header.manifest_digest,
            got: kernel.manifest_digest(),
        });
    }
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
    use crate::abi::{EntityId, ExternalId, InstanceId, Principal, Tick, TypeCode};
    use crate::persist::wal::{SkipReason, Wal, WalWriter};
    use crate::runtime::Kernel;
    use crate::state::traits::_sealed::Sealed;
    use crate::state::{
        Action, ActionCompute, ActionContext, ActionDeriv, InstanceConfig, Op,
    };
    use bytes::Bytes;
    use serde::{Deserialize, Serialize};

    fn world() -> [u8; 32] {
        [11u8; 32]
    }

    /// Instance config that grants System full authority (SendSignal /
    /// ScheduleAction need SYSTEM in the resolved effective caps — there is no
    /// blanket System bypass).
    fn priv_cfg() -> InstanceConfig {
        InstanceConfig {
            default_caps: CapabilityMask::SYSTEM,
            max_entities: 1024,
            max_scheduled: 1024,
            max_inbox_per_route: 16,
            memory_budget_bytes: 1 << 20,
            ..Default::default()
        }
    }

    // ---- Test actions ----

    /// Spawns one entity with a fixed id. Basic op (no SYSTEM needed).
    #[derive(Serialize, Deserialize)]
    struct SpawnAction {
        id: u64,
    }
    impl Sealed for SpawnAction {}
    impl ActionDeriv for SpawnAction {
        const TYPE_CODE: TypeCode = TypeCode(100);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SpawnAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::SpawnEntity {
                id: EntityId::new(self.id).unwrap(),
                owner: Principal::System,
            }]
        }
    }

    /// Schedules a child `SpawnAction` for a future tick — an INTERNAL
    /// `Op::ScheduleAction` that is re-derived on replay (never logged as a
    /// Submit). The regression target for the double-execution bug.
    #[derive(Serialize, Deserialize)]
    struct ScheduleChildAction {
        child_id: u64,
        at: u64,
    }
    impl Sealed for ScheduleChildAction {}
    impl ActionDeriv for ScheduleChildAction {
        const TYPE_CODE: TypeCode = TypeCode(200);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for ScheduleChildAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let child = SpawnAction { id: self.child_id };
            vec![Op::ScheduleAction {
                at: Tick(self.at),
                actor: None,
                action_type_code: SpawnAction::TYPE_CODE,
                action_bytes: Bytes::from(Action::canonical_bytes(&child)),
            }]
        }
    }

    /// Sends a signal to `target` on a fixed route. Needs SYSTEM.
    #[derive(Serialize, Deserialize)]
    struct SignalAction {
        target: u64,
    }
    impl Sealed for SignalAction {}
    impl ActionDeriv for SignalAction {
        const TYPE_CODE: TypeCode = TypeCode(300);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for SignalAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::SendSignal {
                target: InstanceId::new(self.target).unwrap(),
                route: crate::abi::RouteId(1),
                payload: Bytes::from_static(b"ping"),
            }]
        }
    }

    /// Two SetComponents on one entity; the second can exceed a tight budget
    /// (per-Op budget skip → `BudgetPartial`).
    #[derive(Serialize, Deserialize)]
    struct TwoSetAction {
        a: u64,
        b: u64,
    }
    impl Sealed for TwoSetAction {}
    impl ActionDeriv for TwoSetAction {
        const TYPE_CODE: TypeCode = TypeCode(400);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for TwoSetAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            let e = EntityId::new(1).unwrap();
            vec![
                Op::SpawnEntity {
                    id: e,
                    owner: Principal::System,
                },
                Op::SetComponent {
                    entity: e,
                    type_code: TypeCode(7),
                    bytes: Bytes::from(vec![0u8; self.a as usize]),
                    size: self.a,
                },
                Op::SetComponent {
                    entity: e,
                    type_code: TypeCode(8),
                    bytes: Bytes::from(vec![0u8; self.b as usize]),
                    size: self.b,
                },
            ]
        }
    }

    /// Emits a single `Op::ScheduleAction` (needs SYSTEM) — used to force an
    /// AuthDenied verdict under External caps.
    #[derive(Serialize, Deserialize)]
    struct ScheduleNeedsSystemAction;
    impl Sealed for ScheduleNeedsSystemAction {}
    impl ActionDeriv for ScheduleNeedsSystemAction {
        const TYPE_CODE: TypeCode = TypeCode(500);
        const SCHEMA_VERSION: u32 = 1;
    }
    impl ActionCompute for ScheduleNeedsSystemAction {
        fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
            vec![Op::ScheduleAction {
                at: Tick(9),
                actor: None,
                action_type_code: SpawnAction::TYPE_CODE,
                action_bytes: Bytes::from_static(b""),
            }]
        }
    }

    // ---- header-gate tests (empty WAL) ----

    #[test]
    fn replay_empty_wal_succeeds() {
        let w = WalWriter::new(world(), [0u8; 32]);
        let wal = Wal::from_writer(w);
        let mut kernel = Kernel::new();
        let report = replay_into(&mut kernel, &wal).unwrap();
        assert_eq!(report.submits_replayed, 0);
        assert_eq!(report.steps_replayed, 0);
    }

    #[test]
    fn replay_rejects_wrong_magic() {
        let w = WalWriter::new(world(), [0u8; 32]);
        let mut wal = Wal::from_writer(w);
        wal.header.magic = *b"BADMAGIC";
        let mut kernel = Kernel::new();
        assert!(matches!(
            replay_into(&mut kernel, &wal),
            Err(ReplayError::HeaderIncompatible(_))
        ));
    }

    #[test]
    fn replay_rejects_kernel_semver_major_mismatch() {
        let w = WalWriter::new(world(), [0u8; 32]);
        let mut wal = Wal::from_writer(w);
        wal.header.kernel_semver = (99, 0, 0);
        let mut kernel = Kernel::new();
        assert!(matches!(
            replay_into(&mut kernel, &wal),
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
        w.append_step(
            InstanceId::new(1).unwrap(),
            crate::state::ScheduledActionId::new(1).unwrap(),
            Tick(0),
            CapabilityMask::SYSTEM.bits(),
            StepVerdict::Committed,
            [9u8; 32],
        )
        .unwrap();
        let mut wal = Wal::from_writer(w);
        wal.records[0].this_chain_hash = [0xFFu8; 32];
        let mut kernel = Kernel::new();
        assert!(matches!(
            replay_into(&mut kernel, &wal),
            Err(ReplayError::WalCorrupted(_))
        ));
    }

    // ---- CIL replay-determinism tests ----

    /// THE critical-bug regression. The original schedules a child internally;
    /// the WAL records only the parent Submit + two Step verdicts (parent and
    /// child), NOT a Submit for the child. Replay re-derives the child
    /// schedule by re-executing the parent — so the child runs exactly once,
    /// under the same id, reaching a bit-identical chain tip. A double-execution
    /// or id-drift would diverge a digest or the tip.
    #[test]
    fn replay_internal_scheduling_is_bit_identical() {
        let build = || -> Kernel {
            let mut k = Kernel::new_with_wal(world(), [0u8; 32]);
            k.register_action::<ScheduleChildAction>();
            k.register_action::<SpawnAction>();
            let inst = k.create_instance(priv_cfg());
            let parent = ScheduleChildAction {
                child_id: 77,
                at: 1,
            };
            k.submit(
                inst,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(0),
                ScheduleChildAction::TYPE_CODE,
                Action::canonical_bytes(&parent),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM); // runs parent → schedules child
            k.step(Tick(1), CapabilityMask::SYSTEM); // runs child → spawns entity 77
            k
        };
        let k1 = build();
        let original_tip = k1.wal_chain_tip().unwrap();
        let wal = k1.export_wal().unwrap();
        // The child schedule is NOT a Submit — only the parent is.
        let submit_count = wal
            .records
            .iter()
            .filter(|r| matches!(r.kind(), crate::persist::WalRecordKind::Submit))
            .count();
        let step_count = wal
            .records
            .iter()
            .filter(|r| matches!(r.kind(), crate::persist::WalRecordKind::Step))
            .count();
        assert_eq!(submit_count, 1, "only the parent is an exogenous submit");
        assert_eq!(step_count, 2, "two pops: parent then re-derived child");

        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        k2.register_action::<ScheduleChildAction>();
        k2.register_action::<SpawnAction>();
        let _ = k2.create_instance(priv_cfg());
        let report = replay_into(&mut k2, &wal).expect("bit-identical replay");
        assert_eq!(report.submits_replayed, 1);
        assert_eq!(report.steps_replayed, 2);
        assert_eq!(report.final_chain_tip, original_tip);
    }

    /// A step whose op authorize-denies (External lacking SYSTEM tries to
    /// ScheduleAction → rollback → AuthDenied) replays to the same verdict and
    /// the same (unchanged) post-state digest.
    #[test]
    fn replay_history_with_authorize_denial() {
        let build = || -> Kernel {
            let mut k = Kernel::new_with_wal(world(), [0u8; 32]);
            k.register_action::<ScheduleNeedsSystemAction>();
            k.register_action::<SpawnAction>();
            // default_caps WITHOUT system: External submission can never reach
            // SYSTEM, so ScheduleAction is denied.
            let inst = k.create_instance(InstanceConfig {
                max_scheduled: 1024,
                ..Default::default()
            });
            k.submit(
                inst,
                Principal::External(ExternalId(7)),
                None,
                CapabilityMask::empty(),
                Tick(0),
                ScheduleNeedsSystemAction::TYPE_CODE,
                Vec::new(),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM);
            k
        };
        let k1 = build();
        let original_tip = k1.wal_chain_tip().unwrap();
        let wal = k1.export_wal().unwrap();
        assert!(matches!(
            wal.records[1].content,
            WalRecordContent::Step {
                verdict: StepVerdict::AuthDenied,
                ..
            }
        ));

        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        k2.register_action::<ScheduleNeedsSystemAction>();
        k2.register_action::<SpawnAction>();
        let _ = k2.create_instance(InstanceConfig {
            max_scheduled: 1024,
            ..Default::default()
        });
        let report = replay_into(&mut k2, &wal).expect("replay ok");
        assert_eq!(report.final_chain_tip, original_tip);
    }

    /// A committed step that skips one Op on the per-Op budget gate replays to
    /// the same `BudgetPartial { denied: 1 }` verdict and digest.
    #[test]
    fn replay_history_with_budget_partial() {
        let build = || -> Kernel {
            let mut k = Kernel::new_with_wal(world(), [0u8; 32]);
            k.register_action::<TwoSetAction>();
            // budget admits the spawn + the first 40-byte component, denies the
            // second 80-byte one (40+80 > 100).
            let inst = k.create_instance(InstanceConfig {
                memory_budget_bytes: 100,
                max_entities: 1024,
                ..Default::default()
            });
            let a = TwoSetAction { a: 40, b: 80 };
            k.submit(
                inst,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(0),
                TwoSetAction::TYPE_CODE,
                Action::canonical_bytes(&a),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM);
            k
        };
        let k1 = build();
        let original_tip = k1.wal_chain_tip().unwrap();
        let wal = k1.export_wal().unwrap();
        assert!(matches!(
            wal.records[1].content,
            WalRecordContent::Step {
                verdict: StepVerdict::BudgetPartial { denied: 1 },
                ..
            }
        ));

        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        k2.register_action::<TwoSetAction>();
        let _ = k2.create_instance(InstanceConfig {
            memory_budget_bytes: 100,
            max_entities: 1024,
            ..Default::default()
        });
        let report = replay_into(&mut k2, &wal).expect("replay ok");
        assert_eq!(report.final_chain_tip, original_tip);
    }

    /// Skipped verdicts (unregistered type, undeserializable bytes) are
    /// recorded and replay re-reaches them (the kernels skip identically).
    #[test]
    fn replay_skipped_unregistered_and_deserfailed() {
        let build = || -> Kernel {
            let mut k = Kernel::new_with_wal(world(), [0u8; 32]);
            // SpawnAction registered; ScheduleChildAction (200) intentionally NOT.
            k.register_action::<SpawnAction>();
            let inst = k.create_instance(priv_cfg());
            // Unregistered type 200.
            k.submit(
                inst,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(0),
                TypeCode(200),
                vec![1, 2, 3],
            )
            .unwrap();
            // Registered type 100 but undeserializable bytes (SpawnAction needs a u64).
            k.submit(
                inst,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(1),
                SpawnAction::TYPE_CODE,
                Vec::new(),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM);
            k.step(Tick(1), CapabilityMask::SYSTEM);
            k
        };
        let k1 = build();
        let original_tip = k1.wal_chain_tip().unwrap();
        let wal = k1.export_wal().unwrap();
        let verdicts: Vec<StepVerdict> = wal
            .records
            .iter()
            .filter_map(|r| match &r.content {
                WalRecordContent::Step { verdict, .. } => Some(*verdict),
                WalRecordContent::Submit { .. } => None,
            })
            .collect();
        assert!(verdicts.contains(&StepVerdict::Skipped {
            reason: SkipReason::Unregistered
        }));
        assert!(verdicts.contains(&StepVerdict::Skipped {
            reason: SkipReason::DeserFailed
        }));

        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        k2.register_action::<SpawnAction>();
        let _ = k2.create_instance(priv_cfg());
        let report = replay_into(&mut k2, &wal).expect("replay ok");
        assert_eq!(report.final_chain_tip, original_tip);
    }

    /// The scheduler's `next_seq` tiebreak counter is not a logged fact — it is
    /// re-derived by re-execution. Two same-tick children scheduled in one step
    /// keep their FIFO-by-seq order across replay (digest pins it).
    #[test]
    fn next_seq_tiebreak_survives_replay() {
        #[derive(Serialize, Deserialize)]
        struct ScheduleTwoSameTick;
        impl Sealed for ScheduleTwoSameTick {}
        impl ActionDeriv for ScheduleTwoSameTick {
            const TYPE_CODE: TypeCode = TypeCode(600);
            const SCHEMA_VERSION: u32 = 1;
        }
        impl ActionCompute for ScheduleTwoSameTick {
            fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
                let mk = |id: u64| {
                    let child = SpawnAction { id };
                    Op::ScheduleAction {
                        at: Tick(5),
                        actor: None,
                        action_type_code: SpawnAction::TYPE_CODE,
                        action_bytes: Bytes::from(Action::canonical_bytes(&child)),
                    }
                };
                vec![mk(11), mk(22)]
            }
        }

        let build = || -> Kernel {
            let mut k = Kernel::new_with_wal(world(), [0u8; 32]);
            k.register_action::<ScheduleTwoSameTick>();
            k.register_action::<SpawnAction>();
            let inst = k.create_instance(priv_cfg());
            k.submit(
                inst,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(0),
                TypeCode(600),
                Vec::new(),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM);
            k.step(Tick(5), CapabilityMask::SYSTEM); // first same-tick child
            k.step(Tick(5), CapabilityMask::SYSTEM); // second same-tick child
            k
        };
        let k1 = build();
        let original_tip = k1.wal_chain_tip().unwrap();
        let wal = k1.export_wal().unwrap();

        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        k2.register_action::<ScheduleTwoSameTick>();
        k2.register_action::<SpawnAction>();
        let _ = k2.create_instance(priv_cfg());
        let report = replay_into(&mut k2, &wal).expect("replay ok");
        assert_eq!(report.final_chain_tip, original_tip);
    }

    /// Cross-instance signal routing (delivery into the target inbox + the
    /// delivery-time refcount) is unlogged and re-derived on replay, reaching
    /// a bit-identical tip.
    #[test]
    fn signal_routing_replays_bit_identical() {
        let build = || -> Kernel {
            let mut k = Kernel::new_with_wal(world(), [0u8; 32]);
            k.register_action::<SignalAction>();
            let a = k.create_instance(priv_cfg()); // inst 1
            let _b = k.create_instance(priv_cfg()); // inst 2 (target)
            let act = SignalAction { target: 2 };
            k.submit(
                a,
                Principal::System,
                None,
                CapabilityMask::SYSTEM,
                Tick(0),
                SignalAction::TYPE_CODE,
                Action::canonical_bytes(&act),
            )
            .unwrap();
            k.step(Tick(0), CapabilityMask::SYSTEM);
            k
        };
        let k1 = build();
        let original_tip = k1.wal_chain_tip().unwrap();
        let wal = k1.export_wal().unwrap();

        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        k2.register_action::<SignalAction>();
        let _ = k2.create_instance(priv_cfg());
        let _ = k2.create_instance(priv_cfg());
        let report = replay_into(&mut k2, &wal).expect("replay ok");
        assert_eq!(report.final_chain_tip, original_tip);
    }

    /// The default `replay_into` path validates the header `manifest_digest`
    /// against the replaying kernel's declared manifest (A14) — no `TrustAnchor`
    /// needed. A mismatch is rejected before any record is applied.
    #[test]
    fn manifest_digest_validated_on_default_path() {
        let mut k1 = Kernel::new_with_wal(world(), [0xAB; 32]);
        k1.register_action::<SpawnAction>();
        let inst = k1.create_instance(priv_cfg());
        let a = SpawnAction { id: 1 };
        k1.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            SpawnAction::TYPE_CODE,
            Action::canonical_bytes(&a),
        )
        .unwrap();
        k1.step(Tick(0), CapabilityMask::SYSTEM);
        let wal = k1.export_wal().unwrap();

        // Replaying kernel declares a DIFFERENT manifest → rejected.
        let mut k2 = Kernel::new_with_wal(world(), [0xCD; 32]);
        k2.register_action::<SpawnAction>();
        let _ = k2.create_instance(priv_cfg());
        assert!(matches!(
            replay_into(&mut k2, &wal),
            Err(ReplayError::ManifestDigestMismatch { .. })
        ));

        // Matching manifest → accepted.
        let mut k3 = Kernel::new_with_wal(world(), [0xAB; 32]);
        k3.register_action::<SpawnAction>();
        let _ = k3.create_instance(priv_cfg());
        assert!(replay_into(&mut k3, &wal).is_ok());
    }

    /// Replay MEASURES the chain tip by re-sealing the re-derived records — it
    /// does not copy the stored tip. A kernel that re-executes a step
    /// differently (here: the action is unregistered on replay, so the step
    /// Skips instead of Commits) is caught as a verdict divergence rather than
    /// silently echoing the recorded tip.
    #[test]
    fn replay_measures_not_copies_tip() {
        let mut k1 = Kernel::new_with_wal(world(), [0u8; 32]);
        k1.register_action::<SpawnAction>();
        let inst = k1.create_instance(priv_cfg());
        let a = SpawnAction { id: 5 };
        k1.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            SpawnAction::TYPE_CODE,
            Action::canonical_bytes(&a),
        )
        .unwrap();
        k1.step(Tick(0), CapabilityMask::SYSTEM);
        let wal = k1.export_wal().unwrap();

        // Replaying kernel does NOT register SpawnAction → the step Skips
        // (Unregistered) instead of Committing → VerdictDivergence, proving the
        // tip is re-derived, not copied.
        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        let _ = k2.create_instance(priv_cfg());
        assert!(matches!(
            replay_into(&mut k2, &wal),
            Err(ReplayError::VerdictDivergence { .. })
        ));
    }

    /// Replaying into a kernel that did not pre-create the referenced instance
    /// returns a graceful error — never a panic (A12 panic-free discipline
    /// holds for untrusted / malformed WAL input).
    #[test]
    fn replay_into_kernel_missing_instance_is_graceful_error() {
        let mut k1 = Kernel::new_with_wal(world(), [0u8; 32]);
        k1.register_action::<SpawnAction>();
        let inst = k1.create_instance(priv_cfg());
        let a = SpawnAction { id: 1 };
        k1.submit(
            inst,
            Principal::System,
            None,
            CapabilityMask::SYSTEM,
            Tick(0),
            SpawnAction::TYPE_CODE,
            Action::canonical_bytes(&a),
        )
        .unwrap();
        k1.step(Tick(0), CapabilityMask::SYSTEM);
        let wal = k1.export_wal().unwrap();

        // k2 registers the action but creates NO instance → the Submit cannot
        // be admitted; replay fails gracefully rather than panicking.
        let mut k2 = Kernel::new_with_wal(world(), [0u8; 32]);
        k2.register_action::<SpawnAction>();
        let result = replay_into(&mut k2, &wal);
        assert!(
            matches!(result, Err(ReplayError::SubmitFailed(_))),
            "missing instance must surface as a graceful ReplayError, got {result:?}"
        );
    }
}

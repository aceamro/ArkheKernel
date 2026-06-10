//! WAL header + records + BLAKE3-keyed chain.
//!
//! Each record's `this_chain_hash` is computed as
//! `blake3::keyed(chain_key, prev_chain_hash || canonical(body))`
//! where `chain_key = blake3::derive_key(WAL domain context, world_id)`.
//! Tampering any record's body or reordering records breaks the chain
//! at `verify_chain` time.

use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, InstanceId, Principal, Tick, TypeCode};
use crate::state::ScheduledActionId;

use super::signature::{SignatureClass, VerifierClass};

/// Pinned `(TypeCode, schema_hash)` registered for this world. v0.14 ships
/// the slot empty; the snapshot integration will populate it from
/// `ActionRegistry` (cross-restart pin set).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TypeRegistryPin {
    /// Pinned type code.
    pub type_code: TypeCode,
    /// BLAKE3 hash of the canonical schema bytes for `type_code`.
    pub schema_hash: [u8; 32],
}

/// WAL header — pinned at construction, frozen for the lifetime of
/// the WAL. Replay against an incompatible header is a structural
/// error (A14).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalHeader {
    /// Magic bytes for format identification.
    pub magic: [u8; 8],
    /// Kernel semver `(major, minor, patch)`.
    pub kernel_semver: (u16, u16, u16),
    /// Postcard major version pinned at write time.
    pub postcard_version: u32,
    /// BLAKE3 major version pinned at write time.
    pub blake3_version: u32,
    /// Raw bytes of `WalHeader::DOMAIN_CTX`. Stored as `Vec<u8>` because
    /// serde's stock array deserializer caps at 32 bytes; this slot is
    /// used only as build-time constant pinning (the chain key is
    /// derived from `DOMAIN_CTX` directly via `build_chain_key`).
    pub domain_separation_context: Vec<u8>,
    /// World identifier — fed into `blake3::derive_key` along with
    /// `DOMAIN_CTX` to produce this WAL's chain key.
    pub world_id: [u8; 32],
    /// ABI semver `(major, minor)`.
    pub abi_version: (u16, u16),
    /// BLAKE3 hash of the `ModuleManifest` that was active at write time.
    pub manifest_digest: [u8; 32],
    /// Reserved slot for snapshot-integrated TypeCode pinning.
    /// Empty (snapshot-integrated TypeCode pinning is deferred).
    pub type_registry_pins: Vec<TypeRegistryPin>,
    /// Ed25519 verifying-key bytes when the WAL was constructed with a
    /// signing class. `None` means Tier 1 (chain-only). Pinning
    /// the public key in the header makes verification self-contained.
    pub verifying_key: Option<[u8; 32]>,
    /// PQC verifying-key bytes when the WAL was constructed with a
    /// Hybrid signing class (envelope slot for ML-DSA 65 or other PQC
    /// algorithms). `None` for non-Hybrid configurations. Stored as
    /// `Vec<u8>` because PQC public keys exceed the serde 32-byte
    /// fixed-array limit (ML-DSA 65 verifying key = 1952 bytes).
    pub verifying_key_pqc: Option<Vec<u8>>,
}

impl WalHeader {
    /// Magic bytes used at the head of the encoded WAL.
    pub const MAGIC: [u8; 8] = *b"ARKHEWAL";
    /// Kernel semver pinned by [`WalWriter::new`].
    pub const CURRENT_KERNEL_SEMVER: (u16, u16, u16) = (0, 15, 0);
    /// ABI semver pinned by [`WalWriter::new`].
    pub const ABI_VERSION: (u16, u16) = (0, 15);
    /// Postcard major version pinned by [`WalWriter::new`].
    pub const POSTCARD_MAJOR: u32 = 1;
    /// BLAKE3 major version pinned by [`WalWriter::new`].
    pub const BLAKE3_MAJOR: u32 = 1;
    /// Domain-separation byte string fed into `blake3::derive_key` to
    /// produce the WAL chain key. The "v0.15" anchor pins the chain
    /// epoch; it advances with a release whose persisted wire format
    /// changes. The v0.15 epoch restructures `WalRecordBody` into the
    /// Canonical Input Log (Submit/Step records, effects re-derived on
    /// replay), so the chain key rederives and all prior-epoch (v0.14)
    /// WAL chains are not replayable under v0.15 (Layer A item 1
    /// byte-identity invariant — A1/A14; forward-only, pre-public).
    pub const DOMAIN_CTX: &'static [u8] = b"arkhe-kernel v0.15 WAL chain domain separation context";
}

/// Which fact a [`WalRecord`] captures under the Canonical Input Log
/// model: an exogenous external submission, or a per-pop step verdict.
/// The kind is the serde variant tag — the first byte of the hashed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalRecordKind {
    /// An external action was admitted into an instance's scheduler.
    Submit,
    /// One scheduled action was popped and executed (or denied/skipped).
    Step,
}

/// Outcome of a single `step_one` pop, recorded on a `Step` record. Replay
/// re-reaches the same verdict by re-execution; a mismatch fails fast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepVerdict {
    /// Every Op authorized and the stage committed.
    Committed,
    /// An Op failed authorization; the whole stage rolled back.
    AuthDenied,
    /// Authorized, but per-Op budget/quota gates skipped `denied` Ops
    /// (partial commit — the committed siblings still applied).
    BudgetPartial {
        /// Number of Ops the per-Op gates skipped this step.
        denied: u32,
    },
    /// The popped action did not run (unregistered type or undeserializable
    /// bytes). No state changed.
    Skipped {
        /// Why the action was skipped.
        reason: SkipReason,
    },
}

/// Why a popped action produced no execution (a `Skipped` verdict).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkipReason {
    /// No `ActionRegistry` entry for the action's `TypeCode`.
    Unregistered,
    /// The action bytes failed to deserialize under the registered schema.
    DeserFailed,
}

/// Kind-discriminated canonical content of a WAL record. The serde variant
/// tag is the record [`WalRecordKind`] and the first hashed body field. The
/// CIL records only non-reproducible facts: exogenous submissions and
/// per-step verdicts + post-state digest — every deterministic effect
/// (child schedules, signal routing, internal ids) is re-derived on replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalRecordContent {
    /// Exogenous admission of an external action — the only non-reproducible
    /// scheduling input (internal `Op::ScheduleAction` schedules are
    /// re-derived by re-executing the parent, never logged).
    Submit {
        /// Monotonic record sequence within this WAL.
        seq: u64,
        /// Instance the action was submitted to.
        instance: InstanceId,
        /// Principal the external caller submitted under.
        principal: Principal,
        /// Submitting entity, if any (feeds `ActionContext::actor`, so it is
        /// canonical input and chain-hashed).
        actor: Option<EntityId>,
        /// Capability ceiling granted to this submission — bounds the
        /// action's effective caps at execution (replay reconstructs it).
        caps_at_submit: u64,
        /// Tick the action is scheduled for.
        at: Tick,
        /// Type code of the submitted action.
        action_type_code: TypeCode,
        /// Canonical action bytes (replay deserializes from these).
        action_bytes: Vec<u8>,
        /// ScheduledActionId the kernel minted — replay re-injects with this
        /// exact id so the id sequence is reproduced verbatim.
        allocated_id: ScheduledActionId,
    },
    /// One `step_one` pop: which entry ran, when, under what operator session
    /// ceiling, with what verdict, and the full-state digest afterward (the
    /// bit-identity witness).
    Step {
        /// Monotonic record sequence within this WAL.
        seq: u64,
        /// Instance the step ran against.
        instance: InstanceId,
        /// ScheduledActionId popped this step (scheduler-order witness).
        popped_id: ScheduledActionId,
        /// Tick the step ran at.
        now: Tick,
        /// Operator session capability ceiling in force at step time — the
        /// final intersection applied over the action's resolved caps. It is
        /// a non-reproducible per-step operator input (like `caps_at_submit`
        /// is per submission), so it is recorded for the verdict to be
        /// re-derivable on replay.
        session_caps: u64,
        /// Step outcome — replay must re-reach this exact verdict.
        verdict: StepVerdict,
        /// BLAKE3 digest of the instance's full post-step state; replay
        /// measures the replayed instance and asserts equality (A1).
        post_state_digest: [u8; 32],
    },
}

/// Single record in the WAL chain (Canonical Input Log). Carries the
/// kind-discriminated [`WalRecordContent`] plus the chain/signature fields
/// common to both kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    /// Kind-discriminated canonical content (its variant tag is the kind).
    pub content: WalRecordContent,
    /// Previous record's `this_chain_hash` (or zero for record 0).
    pub prev_chain_hash: [u8; 32],
    /// `blake3::keyed(chain_key, prev_chain_hash || canonical(body))`.
    pub this_chain_hash: [u8; 32],
    /// Ed25519 signature over the canonical body bytes (same bytes hashed
    /// into `this_chain_hash`). `None` for Tier 1. Stored as `Vec<u8>`
    /// (64 bytes when present) per the serde 32-byte array-deserializer cap.
    pub signature: Option<Vec<u8>>,
    /// PQC signature bytes for Hybrid mode (3309 bytes for ML-DSA 65 when
    /// present); `None` otherwise.
    pub signature_pqc: Option<Vec<u8>>,
}

impl WalRecord {
    /// This record's monotonic sequence (kind-agnostic).
    pub fn seq(&self) -> u64 {
        match &self.content {
            WalRecordContent::Submit { seq, .. } | WalRecordContent::Step { seq, .. } => *seq,
        }
    }

    /// This record's [`WalRecordKind`].
    pub fn kind(&self) -> WalRecordKind {
        match &self.content {
            WalRecordContent::Submit { .. } => WalRecordKind::Submit,
            WalRecordContent::Step { .. } => WalRecordKind::Step,
        }
    }
}

/// Borrowed canonical body — the bytes hashed into `this_chain_hash` and
/// signed. The serde variant tag of `content` is the record kind (first
/// hashed field); `prev_chain_hash` is folded in so reordering records
/// breaks the chain.
#[derive(Serialize)]
struct WalRecordBody<'a> {
    content: WalRecordBodyContent<'a>,
    prev_chain_hash: [u8; 32],
}

#[derive(Serialize)]
enum WalRecordBodyContent<'a> {
    Submit {
        seq: u64,
        instance: InstanceId,
        principal: &'a Principal,
        actor: Option<EntityId>,
        caps_at_submit: u64,
        at: Tick,
        action_type_code: TypeCode,
        action_bytes: &'a [u8],
        allocated_id: ScheduledActionId,
    },
    Step {
        seq: u64,
        instance: InstanceId,
        popped_id: ScheduledActionId,
        now: Tick,
        session_caps: u64,
        verdict: StepVerdict,
        post_state_digest: [u8; 32],
    },
}

impl<'a> WalRecordBody<'a> {
    /// Reconstruct the canonical body view from a stored `WalRecord` plus
    /// the running `prev_chain_hash` (used by `verify_chain`).
    fn from_record(rec: &'a WalRecord, prev: [u8; 32]) -> Self {
        Self::from_content(&rec.content, prev)
    }

    /// Borrow a [`WalRecordContent`] as the canonical body view (the bytes
    /// hashed + signed), folding in `prev` so reordering breaks the chain.
    /// Used both on append (seal the new record) and on verify.
    fn from_content(content_ref: &'a WalRecordContent, prev: [u8; 32]) -> Self {
        let content = match content_ref {
            WalRecordContent::Submit {
                seq,
                instance,
                principal,
                actor,
                caps_at_submit,
                at,
                action_type_code,
                action_bytes,
                allocated_id,
            } => WalRecordBodyContent::Submit {
                seq: *seq,
                instance: *instance,
                principal,
                actor: *actor,
                caps_at_submit: *caps_at_submit,
                at: *at,
                action_type_code: *action_type_code,
                action_bytes,
                allocated_id: *allocated_id,
            },
            WalRecordContent::Step {
                seq,
                instance,
                popped_id,
                now,
                session_caps,
                verdict,
                post_state_digest,
            } => WalRecordBodyContent::Step {
                seq: *seq,
                instance: *instance,
                popped_id: *popped_id,
                now: *now,
                session_caps: *session_caps,
                verdict: *verdict,
                post_state_digest: *post_state_digest,
            },
        };
        Self {
            content,
            prev_chain_hash: prev,
        }
    }
}

/// Sealed WAL — the durable read-side counterpart to [`WalWriter`].
/// Produced by [`Wal::from_writer`] or [`Wal::deserialize`]; consumed
/// by [`Wal::verify_chain`] / [`replay_into`](super::replay::replay_into).
#[derive(Debug, Serialize, Deserialize)]
pub struct Wal {
    /// Header pinned at writer construction.
    pub header: WalHeader,
    /// Records in append order.
    pub records: Vec<WalRecord>,
}

/// Signature strength tier advertised by a WAL header, ordered
/// `None < Ed25519 < Hybrid`. Compared against [`TrustAnchor::min_tier`]
/// to reject a downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignatureTier {
    /// No signatures (chain integrity only).
    None,
    /// RFC 8032 Ed25519.
    Ed25519,
    /// Hybrid Ed25519 + ML-DSA 65.
    Hybrid,
}

/// Operator-supplied trust anchor for authenticated WAL verification
/// ([`Wal::verify_chain_anchored`]).
///
/// [`Wal::verify_chain`] derives its verification policy and keys from the
/// WAL header. Under the threat model where WAL bytes are attacker-
/// controlled (a tampered on-disk log or a malicious peer's snapshot),
/// that lets an attacker downgrade the tier to `None` (skipping all
/// signature checks) or substitute their own keys and re-sign the whole
/// chain. A `TrustAnchor` closes that gap: the caller pins — out-of-band —
/// the minimum tier and the exact verifying key(s) it trusts. The kernel
/// provides the MECHANISM (compare the header against the anchor; reject
/// downgrade / substitution / truncation); the caller owns the POLICY
/// (which key and tier to require). Unset (`None`) fields impose no check.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchor {
    /// Minimum acceptable signature tier. A header weaker than this is
    /// rejected with [`WalError::TierDowngrade`].
    pub min_tier: Option<SignatureTier>,
    /// Expected Ed25519 verifying-key bytes; the header's pinned key must
    /// equal this (else [`WalError::VerifyingKeyMismatch`]).
    pub ed25519_verifying_key: Option<[u8; 32]>,
    /// Expected ML-DSA 65 verifying-key bytes (Hybrid); the header's
    /// pinned PQC key must equal this.
    pub mldsa_verifying_key: Option<Vec<u8>>,
    /// Expected `manifest_digest` (A14); rejects a WAL written under a
    /// different `ModuleManifest`.
    pub expected_manifest_digest: Option<[u8; 32]>,
    /// Expected final chain tip; pins the record count so a tail
    /// truncation (a chain-consistent prefix) is detected.
    pub expected_chain_tip: Option<[u8; 32]>,
}

/// Append-only WAL writer. Each successful `Kernel::step` writes one
/// [`WalRecord`] via the kernel's internal append path.
pub struct WalWriter {
    header: WalHeader,
    records: Vec<WalRecord>,
    next_seq: u64,
    prev_hash: [u8; 32],
    chain_key: [u8; 32],
    sig_class: SignatureClass,
}

/// `seal` output: `(this_chain_hash, ed25519_signature, pqc_signature)`. The
/// two signature slots are `None` for Tier 1 (chain-only).
type SealedRecordParts = ([u8; 32], Option<Vec<u8>>, Option<Vec<u8>>);

fn build_chain_key(world_id: &[u8; 32]) -> [u8; 32] {
    let ctx = core::str::from_utf8(WalHeader::DOMAIN_CTX).expect("DOMAIN_CTX is valid UTF-8 ASCII");
    blake3::derive_key(ctx, world_id)
}

fn build_dsc() -> Vec<u8> {
    WalHeader::DOMAIN_CTX.to_vec()
}

impl WalWriter {
    /// Construct a chain-only writer (Tier 1 — no signature).
    pub fn new(world_id: [u8; 32], manifest_digest: [u8; 32]) -> Self {
        Self::with_signature(world_id, manifest_digest, SignatureClass::None)
    }

    /// Construct a writer that signs each record under `sig_class`. The
    /// verifying key is pinned in the header so post-hoc verification
    /// works against the WAL bytes alone.
    pub fn with_signature(
        world_id: [u8; 32],
        manifest_digest: [u8; 32],
        sig_class: SignatureClass,
    ) -> Self {
        let chain_key = build_chain_key(&world_id);
        let header = WalHeader {
            magic: WalHeader::MAGIC,
            kernel_semver: WalHeader::CURRENT_KERNEL_SEMVER,
            postcard_version: WalHeader::POSTCARD_MAJOR,
            blake3_version: WalHeader::BLAKE3_MAJOR,
            domain_separation_context: build_dsc(),
            world_id,
            abi_version: WalHeader::ABI_VERSION,
            manifest_digest,
            type_registry_pins: Vec::new(),
            verifying_key: sig_class.verifying_key_bytes(),
            verifying_key_pqc: sig_class.verifying_key_pqc_bytes(),
        };
        Self {
            header,
            records: Vec::new(),
            next_seq: 0,
            prev_hash: [0u8; 32],
            chain_key,
            sig_class,
        }
    }

    /// Reconstruct a measurement-only writer from a sealed header: same
    /// `world_id`-derived chain key, fresh `prev_hash`, no signing. Replay
    /// uses this to RE-MEASURE the chain tip from the same inputs/verdicts
    /// (the chain hash is over the body bytes, which exclude the signature,
    /// so a None-signing rebuild reproduces every `this_chain_hash`).
    pub(crate) fn rebuild_from_header(header: &WalHeader) -> Self {
        let chain_key = build_chain_key(&header.world_id);
        Self {
            header: header.clone(),
            records: Vec::new(),
            next_seq: 0,
            prev_hash: [0u8; 32],
            chain_key,
            sig_class: SignatureClass::None,
        }
    }

    /// Hash + sign a borrowed body, returning `(this_chain_hash, sig, pqc)`.
    /// The hash is `blake3::keyed(chain_key, prev_hash || canonical(body))`;
    /// signatures (if any) cover the same body bytes.
    fn seal(&self, body: &WalRecordBody) -> Result<SealedRecordParts, WalError> {
        let body_bytes =
            postcard::to_allocvec(body).map_err(|e| WalError::SerializeFailed(format!("{}", e)))?;
        let mut hasher = blake3::Hasher::new_keyed(&self.chain_key);
        hasher.update(&self.prev_hash);
        hasher.update(&body_bytes);
        let this_hash: [u8; 32] = *hasher.finalize().as_bytes();
        // Tier 1 (None) leaves both `None`. Hybrid emits paired
        // Ed25519 + ML-DSA 65 signatures via `sign_hybrid`.
        let (signature, signature_pqc) = match self.sig_class.sign_hybrid(&body_bytes) {
            Some(hyb) => (Some(hyb.ed25519.to_vec()), Some(hyb.pqc)),
            None => (self.sig_class.sign(&body_bytes).map(|s| s.to_vec()), None),
        };
        Ok((this_hash, signature, signature_pqc))
    }

    fn push_sealed(&mut self, content: WalRecordContent) -> Result<&WalRecord, WalError> {
        let prev = self.prev_hash;
        // Seal a borrowed body view of `content`; the borrow ends before
        // `content` is moved into the record below (NLL).
        let (this_hash, signature, signature_pqc) = {
            let body = WalRecordBody::from_content(&content, prev);
            self.seal(&body)?
        };
        let record = WalRecord {
            content,
            prev_chain_hash: prev,
            this_chain_hash: this_hash,
            signature,
            signature_pqc,
        };
        self.records.push(record);
        self.prev_hash = this_hash;
        Ok(self.records.last().expect("just pushed"))
    }

    /// Append a `Submit` record — the exogenous admission of an external
    /// action (with the ScheduledActionId the kernel minted for it).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn append_submit(
        &mut self,
        instance: InstanceId,
        principal: Principal,
        actor: Option<EntityId>,
        caps_at_submit: u64,
        at: Tick,
        action_type_code: TypeCode,
        action_bytes: Vec<u8>,
        allocated_id: ScheduledActionId,
    ) -> Result<&WalRecord, WalError> {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;
        let content = WalRecordContent::Submit {
            seq,
            instance,
            principal,
            actor,
            caps_at_submit,
            at,
            action_type_code,
            action_bytes,
            allocated_id,
        };
        self.push_sealed(content)
    }

    /// Append a `Step` record — one `step_one` pop's verdict + the full
    /// post-step state digest, under the operator session ceiling in force.
    pub(crate) fn append_step(
        &mut self,
        instance: InstanceId,
        popped_id: ScheduledActionId,
        now: Tick,
        session_caps: u64,
        verdict: StepVerdict,
        post_state_digest: [u8; 32],
    ) -> Result<&WalRecord, WalError> {
        self.next_seq = self.next_seq.saturating_add(1);
        let seq = self.next_seq;
        let content = WalRecordContent::Step {
            seq,
            instance,
            popped_id,
            now,
            session_caps,
            verdict,
            post_state_digest,
        };
        self.push_sealed(content)
    }

    /// Pinned WAL header.
    pub fn header(&self) -> &WalHeader {
        &self.header
    }
    /// All records appended so far, in append order.
    pub fn records(&self) -> &[WalRecord] {
        &self.records
    }
    /// Most recent record's `this_chain_hash`, or zero if empty.
    pub fn chain_tip(&self) -> [u8; 32] {
        self.prev_hash
    }
    /// Number of records currently buffered.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl Wal {
    /// Seal a [`WalWriter`] into a read-only [`Wal`].
    pub fn from_writer(w: WalWriter) -> Self {
        Self {
            header: w.header,
            records: w.records,
        }
    }

    /// Encode the entire WAL (header + records) as canonical postcard
    /// bytes.
    pub fn serialize(&self) -> Result<Vec<u8>, WalError> {
        postcard::to_allocvec(self).map_err(|e| WalError::SerializeFailed(format!("{}", e)))
    }

    /// Decode bytes produced by [`serialize`](Wal::serialize).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, WalError> {
        postcard::from_bytes(bytes).map_err(|e| WalError::DeserializeFailed(format!("{}", e)))
    }

    /// Most recent record's `this_chain_hash`, or zero if empty.
    pub fn chain_tip(&self) -> [u8; 32] {
        self.records
            .last()
            .map(|r| r.this_chain_hash)
            .unwrap_or([0u8; 32])
    }

    /// Verify every record's chain hash against the keyed BLAKE3 over
    /// (prev_chain_hash || canonical body). When the header pins a
    /// `verifying_key` (Tier 2 — Ed25519), each record's signature
    /// is also checked against the same body bytes. Returns `Ok` if
    /// every check passes.
    pub fn verify_chain(&self, world_id: [u8; 32]) -> Result<(), WalError> {
        let chain_key = build_chain_key(&world_id);
        let verifier = VerifierClass::from_header_bytes(
            self.header.verifying_key.as_ref(),
            self.header.verifying_key_pqc.as_deref(),
        )
        .map_err(|e| match e {
            crate::persist::signature::VerifierInitError::InvalidEd25519Key
            | crate::persist::signature::VerifierInitError::InvalidPqcKey => {
                WalError::InvalidVerifyingKey
            }
            crate::persist::signature::VerifierInitError::PqcWithoutEd25519 => {
                WalError::PqcWithoutEd25519
            }
        })?;
        let mut prev = [0u8; 32];
        for (i, rec) in self.records.iter().enumerate() {
            if blake3::Hash::from(rec.prev_chain_hash) != blake3::Hash::from(prev) {
                return Err(WalError::ChainBroken { at_record: i });
            }
            let body = WalRecordBody::from_record(rec, prev);
            let body_bytes = postcard::to_allocvec(&body)
                .map_err(|e| WalError::SerializeFailed(format!("{}", e)))?;
            let mut hasher = blake3::Hasher::new_keyed(&chain_key);
            hasher.update(&prev);
            hasher.update(&body_bytes);
            let computed: [u8; 32] = *hasher.finalize().as_bytes();
            if blake3::Hash::from(computed) != blake3::Hash::from(rec.this_chain_hash) {
                return Err(WalError::HashMismatch { at_record: i });
            }

            match &verifier {
                VerifierClass::None => {}
                VerifierClass::Ed25519(_) => {
                    let sig_vec = rec
                        .signature
                        .as_ref()
                        .ok_or(WalError::MissingSignature { at_record: i })?;
                    verifier
                        .verify(&body_bytes, sig_vec)
                        .map_err(|_| WalError::SignatureMismatch { at_record: i })?;
                }
                VerifierClass::Hybrid { .. } => {
                    let sig_vec = rec
                        .signature
                        .as_ref()
                        .ok_or(WalError::MissingSignature { at_record: i })?;
                    let sig_pqc = rec
                        .signature_pqc
                        .as_ref()
                        .ok_or(WalError::MissingPqcSignature { at_record: i })?;
                    verifier
                        .verify_hybrid(&body_bytes, sig_vec, sig_pqc)
                        .map_err(|_| WalError::PqcSignatureMismatch { at_record: i })?;
                }
            }

            prev = computed;
        }
        Ok(())
    }

    /// The signature tier the header advertises, derived from which
    /// verifying-key slots are populated. `(None, Some)` is the invalid
    /// PQC-without-Ed25519 envelope.
    fn header_tier(&self) -> Result<SignatureTier, WalError> {
        match (
            self.header.verifying_key.is_some(),
            self.header.verifying_key_pqc.is_some(),
        ) {
            (false, false) => Ok(SignatureTier::None),
            (true, false) => Ok(SignatureTier::Ed25519),
            (true, true) => Ok(SignatureTier::Hybrid),
            (false, true) => Err(WalError::PqcWithoutEd25519),
        }
    }

    /// Verify the chain AND authenticate it against a caller-supplied
    /// [`TrustAnchor`]. Use this when the WAL bytes are untrusted (a
    /// tampered log or a peer's snapshot): beyond [`Self::verify_chain`]'s
    /// integrity checks it rejects a tier downgrade below `anchor
    /// .min_tier`, a verifying-key substitution (header key != the
    /// anchored key), a `manifest_digest` mismatch, and a tail truncation
    /// (tip != the anchored `expected_chain_tip`). `world_id` is supplied
    /// by the caller out-of-band — NOT read from the (untrusted) header.
    pub fn verify_chain_anchored(
        &self,
        world_id: [u8; 32],
        anchor: &TrustAnchor,
    ) -> Result<(), WalError> {
        // (1) Tier floor — reject a downgrade (e.g. header stripped to None).
        let tier = self.header_tier()?;
        if let Some(floor) = anchor.min_tier {
            if tier < floor {
                return Err(WalError::TierDowngrade);
            }
        }
        // (2) Key pinning — the header's keys must equal the anchored keys,
        // so an attacker cannot substitute their own keypair and re-sign.
        if let Some(expected) = anchor.ed25519_verifying_key {
            match self.header.verifying_key {
                Some(k) if k == expected => {}
                _ => return Err(WalError::VerifyingKeyMismatch),
            }
        }
        if let Some(expected) = anchor.mldsa_verifying_key.as_deref() {
            match self.header.verifying_key_pqc.as_deref() {
                Some(k) if k == expected => {}
                _ => return Err(WalError::VerifyingKeyMismatch),
            }
        }
        // (3) Manifest pinning (A14).
        if let Some(expected) = anchor.expected_manifest_digest {
            if self.header.manifest_digest != expected {
                return Err(WalError::ManifestDigestMismatch);
            }
        }
        // (4) Integrity + signature verification over the caller's world_id.
        self.verify_chain(world_id)?;
        // (5) Tail-truncation — the verified tip must equal the anchored tip.
        if let Some(expected_tip) = anchor.expected_chain_tip {
            if self.chain_tip() != expected_tip {
                return Err(WalError::ChainTipMismatch);
            }
        }
        Ok(())
    }
}

/// WAL operation failures. `#[non_exhaustive]` — adding variants is
/// not a breaking change for external matchers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum WalError {
    /// Postcard refused to encode (carries the upstream message).
    SerializeFailed(String),
    /// Postcard refused to decode (carries the upstream message).
    DeserializeFailed(String),
    /// Record `at_record`'s `prev_chain_hash` doesn't match the running
    /// expected hash from the previous record.
    ChainBroken {
        /// Index of the offending record.
        at_record: usize,
    },
    /// Record `at_record`'s `this_chain_hash` doesn't match the
    /// recomputed BLAKE3 keyed hash.
    HashMismatch {
        /// Index of the offending record.
        at_record: usize,
    },
    /// Header pinning rejected (semver / abi / world / manifest mismatch).
    HeaderIncompatible(String),
    /// Header pins a `verifying_key` (Ed25519 or PQC) that fails to parse.
    InvalidVerifyingKey,
    /// Header pins a `verifying_key` but a record carries no signature.
    MissingSignature {
        /// Index of the offending record.
        at_record: usize,
    },
    /// Signature does not validate against the header's verifying key.
    SignatureMismatch {
        /// Index of the offending record.
        at_record: usize,
    },
    /// Header pins a Hybrid envelope (`verifying_key_pqc=Some`) but a
    /// record carries no PQC signature (`signature_pqc=None`).
    MissingPqcSignature {
        /// Index of the offending record.
        at_record: usize,
    },
    /// PQC signature does not validate against the header's PQC
    /// verifying key (Hybrid AND-mode failure).
    PqcSignatureMismatch {
        /// Index of the offending record.
        at_record: usize,
    },
    /// Invalid Hybrid envelope — `verifying_key_pqc=Some` without
    /// `verifying_key=Some`. Ed25519 is the chain-anchor companion;
    /// PQC-only envelope is rejected.
    PqcWithoutEd25519,
    /// The header advertises a signature tier weaker than the caller's
    /// [`TrustAnchor::min_tier`] — a downgrade attempt (e.g. a header
    /// stripped to `None` to skip all signature verification).
    TierDowngrade,
    /// The header's pinned verifying key does not equal the key the
    /// caller's [`TrustAnchor`] expects — a key-substitution attempt.
    VerifyingKeyMismatch,
    /// The header's `manifest_digest` does not equal the caller's expected
    /// digest (A14 manifest pinning under a [`TrustAnchor`]).
    ManifestDigestMismatch,
    /// The verified chain tip does not equal the caller's expected tip —
    /// a tail truncation (a chain-consistent prefix) was detected.
    ChainTipMismatch,
}

impl core::fmt::Display for WalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SerializeFailed(m) => write!(f, "wal serialize failed: {}", m),
            Self::DeserializeFailed(m) => write!(f, "wal deserialize failed: {}", m),
            Self::ChainBroken { at_record } => {
                write!(f, "wal chain broken at record {}", at_record)
            }
            Self::HashMismatch { at_record } => {
                write!(f, "wal hash mismatch at record {}", at_record)
            }
            Self::HeaderIncompatible(m) => write!(f, "wal header incompatible: {}", m),
            Self::InvalidVerifyingKey => write!(
                f,
                "wal verifying_key invalid (not a valid Ed25519 public key)"
            ),
            Self::MissingSignature { at_record } => {
                write!(f, "wal signature missing at record {}", at_record)
            }
            Self::SignatureMismatch { at_record } => {
                write!(f, "wal signature mismatch at record {}", at_record)
            }
            Self::MissingPqcSignature { at_record } => {
                write!(f, "wal PQC signature missing at record {}", at_record)
            }
            Self::PqcSignatureMismatch { at_record } => {
                write!(f, "wal PQC signature mismatch at record {}", at_record)
            }
            Self::PqcWithoutEd25519 => write!(
                f,
                "wal envelope invalid (verifying_key_pqc set without verifying_key)"
            ),
            Self::TierDowngrade => write!(
                f,
                "wal signature tier downgraded below the trust anchor's minimum"
            ),
            Self::VerifyingKeyMismatch => write!(
                f,
                "wal verifying key does not match the trust anchor's expected key"
            ),
            Self::ManifestDigestMismatch => {
                write!(f, "wal manifest_digest does not match the expected digest")
            }
            Self::ChainTipMismatch => {
                write!(f, "wal chain tip does not match the expected tip (tail truncation?)")
            }
        }
    }
}

impl std::error::Error for WalError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{EntityId, ExternalId, InstanceId, Principal, RouteId, Tick, TypeCode};
    use crate::state::ScheduledActionId;

    fn world() -> [u8; 32] {
        [7u8; 32]
    }
    fn manifest() -> [u8; 32] {
        [3u8; 32]
    }
    fn sid(n: u64) -> ScheduledActionId {
        ScheduledActionId::new(n).unwrap()
    }

    /// Append one canonical `Submit` record with fixed inputs.
    fn submit_one(w: &mut WalWriter) {
        w.append_submit(
            InstanceId::new(1).unwrap(),
            Principal::System,
            None,
            0xFF,
            Tick(0),
            TypeCode(100),
            vec![1, 2, 3],
            sid(1),
        )
        .unwrap();
    }

    /// Append one canonical `Step` record; `n` varies the body so a multi-record
    /// chain has distinct record bodies.
    fn step_n(w: &mut WalWriter, n: u8) {
        w.append_step(
            InstanceId::new(1).unwrap(),
            sid(1),
            Tick(n as u64),
            0xFF,
            StepVerdict::Committed,
            [n; 32],
        )
        .unwrap();
    }

    /// One record used by the signature tests (a `Step`).
    fn append_one(w: &mut WalWriter) {
        step_n(w, 1);
    }

    #[test]
    fn empty_writer_serializes_and_deserializes() {
        let w = WalWriter::new(world(), manifest());
        let wal = Wal::from_writer(w);
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        assert_eq!(back.header, wal.header);
        assert_eq!(back.records.len(), 0);
        assert_eq!(back.chain_tip(), [0u8; 32]);
    }

    #[test]
    fn single_step_append_produces_nonzero_chain_tip() {
        let mut w = WalWriter::new(world(), manifest());
        append_one(&mut w);
        let tip = w.chain_tip();
        assert_ne!(tip, [0u8; 32]);
        assert_eq!(w.record_count(), 1);
    }

    #[test]
    fn multi_record_chain_links_each_record() {
        let mut w = WalWriter::new(world(), manifest());
        for i in 0..5 {
            step_n(&mut w, i);
        }
        let wal = Wal::from_writer(w);
        assert_eq!(wal.records.len(), 5);
        let mut prev = [0u8; 32];
        for rec in &wal.records {
            assert_eq!(rec.prev_chain_hash, prev);
            prev = rec.this_chain_hash;
        }
        wal.verify_chain(world()).expect("clean chain");
    }

    #[test]
    fn submit_and_step_chain_verifies() {
        // A Submit followed by a Step (the canonical admission → execution
        // sequence) links and verifies.
        let mut w = WalWriter::new(world(), manifest());
        submit_one(&mut w);
        step_n(&mut w, 2);
        let wal = Wal::from_writer(w);
        assert_eq!(wal.records.len(), 2);
        assert!(matches!(wal.records[0].kind(), WalRecordKind::Submit));
        assert!(matches!(wal.records[1].kind(), WalRecordKind::Step));
        assert_eq!(wal.records[0].seq(), 1);
        assert_eq!(wal.records[1].seq(), 2);
        wal.verify_chain(world()).expect("clean chain");
    }

    #[test]
    fn tampered_step_body_breaks_verify_chain() {
        let mut w = WalWriter::new(world(), manifest());
        for i in 0..3 {
            step_n(&mut w, i);
        }
        let mut wal = Wal::from_writer(w);
        // Tamper the middle record's post_state_digest (a hashed body field).
        if let WalRecordContent::Step {
            post_state_digest, ..
        } = &mut wal.records[1].content
        {
            post_state_digest[0] ^= 0xFF;
        }
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::HashMismatch { .. })
        ));
    }

    #[test]
    fn verify_chain_detects_broken_prev_link() {
        let mut w = WalWriter::new(world(), manifest());
        for i in 0..3 {
            step_n(&mut w, i);
        }
        let mut wal = Wal::from_writer(w);
        wal.records[1].prev_chain_hash[0] ^= 1;
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::ChainBroken { at_record: 1 })
        ));
    }

    #[test]
    fn different_world_id_produces_different_chain() {
        let mut w1 = WalWriter::new([1u8; 32], manifest());
        let mut w2 = WalWriter::new([2u8; 32], manifest());
        append_one(&mut w1);
        append_one(&mut w2);
        assert_ne!(w1.chain_tip(), w2.chain_tip());
    }

    #[test]
    fn verify_chain_against_wrong_world_id_fails() {
        let mut w = WalWriter::new(world(), manifest());
        append_one(&mut w);
        let wal = Wal::from_writer(w);
        assert!(matches!(
            wal.verify_chain([99u8; 32]),
            Err(WalError::HashMismatch { .. })
        ));
    }

    #[test]
    fn step_verdict_round_trips() {
        // Replaces the old AuthDecisionAnnotation round-trip: a Step verdict
        // (here BudgetPartial) survives serialize → deserialize verbatim.
        let mut w = WalWriter::new(world(), manifest());
        w.append_step(
            InstanceId::new(1).unwrap(),
            sid(1),
            Tick(0),
            0xFF,
            StepVerdict::BudgetPartial { denied: 3 },
            [4u8; 32],
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        match &back.records[0].content {
            WalRecordContent::Step { verdict, .. } => {
                assert_eq!(*verdict, StepVerdict::BudgetPartial { denied: 3 });
            }
            WalRecordContent::Submit { .. } => panic!("expected Step"),
        }
    }

    #[test]
    fn submit_record_round_trips_inputs() {
        let actor = Some(EntityId::new(42).unwrap());
        let mut w = WalWriter::new(world(), manifest());
        w.append_submit(
            InstanceId::new(9).unwrap(),
            Principal::External(ExternalId(7)),
            actor,
            0xDEAD_BEEF,
            Tick(5),
            TypeCode(101),
            vec![9, 8, 7],
            sid(3),
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        match &back.records[0].content {
            WalRecordContent::Submit {
                instance,
                actor: a,
                caps_at_submit,
                allocated_id,
                action_bytes,
                ..
            } => {
                assert_eq!(*instance, InstanceId::new(9).unwrap());
                assert_eq!(*a, actor);
                assert_eq!(*caps_at_submit, 0xDEAD_BEEF);
                assert_eq!(*allocated_id, sid(3));
                assert_eq!(action_bytes, &vec![9, 8, 7]);
            }
            WalRecordContent::Step { .. } => panic!("expected Submit"),
        }
        assert!(back.verify_chain(world()).is_ok());
    }

    #[test]
    fn header_carries_magic_and_versions() {
        let h = WalWriter::new(world(), manifest()).header().clone();
        assert_eq!(h.magic, *b"ARKHEWAL");
        assert_eq!(h.kernel_semver, (0, 15, 0));
        assert_eq!(h.abi_version, (0, 15));
        assert_eq!(h.world_id, world());
        assert_eq!(h.manifest_digest, manifest());
        assert!(h.type_registry_pins.is_empty());
        assert!(h.verifying_key.is_none());
        let _ = RouteId(1);
    }

    // ---- Ed25519 SignatureClass (Tier 2, A16) ----

    #[test]
    fn signature_class_none_produces_no_signature() {
        let mut w = WalWriter::new(world(), manifest());
        append_one(&mut w);
        let wal = Wal::from_writer(w);
        assert!(wal.header.verifying_key.is_none());
        assert!(wal.records[0].signature.is_none());
        wal.verify_chain(world())
            .expect("Tier 1 chain still verifies");
    }

    #[test]
    fn signature_class_ed25519_signs_each_record() {
        let sig_class = SignatureClass::new_ed25519_from_secret([7u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        for _ in 0..3 {
            append_one(&mut w);
        }
        let wal = Wal::from_writer(w);
        assert!(wal.header.verifying_key.is_some());
        assert_eq!(wal.records.len(), 3);
        for rec in &wal.records {
            let sig = rec.signature.as_ref().expect("Ed25519 signs every record");
            assert_eq!(sig.len(), 64);
        }
    }

    #[test]
    fn verify_chain_validates_signatures() {
        let sig_class = SignatureClass::new_ed25519_from_secret([11u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        for _ in 0..3 {
            append_one(&mut w);
        }
        let wal = Wal::from_writer(w);
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        back.verify_chain(world()).expect("signed chain verifies");
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let sig_class = SignatureClass::new_ed25519_from_secret([13u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        if let Some(sig) = wal.records[1].signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::SignatureMismatch { at_record: 1 })
        ));
    }

    #[test]
    fn missing_signature_fails_verify_when_header_has_key() {
        let sig_class = SignatureClass::new_ed25519_from_secret([17u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        wal.records[0].signature = None;
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::MissingSignature { at_record: 0 })
        ));
    }

    #[test]
    fn wrong_key_fails_verify() {
        let sig_class = SignatureClass::new_ed25519_from_secret([19u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        let other = SignatureClass::new_ed25519_from_secret([23u8; 32])
            .verifying_key_bytes()
            .unwrap();
        wal.header.verifying_key = Some(other);
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::SignatureMismatch { at_record: 0 })
        ));
    }

    #[test]
    fn signature_deterministic_across_runs() {
        let mk = |secret: [u8; 32]| -> Vec<Vec<u8>> {
            let mut w = WalWriter::with_signature(
                world(),
                manifest(),
                SignatureClass::new_ed25519_from_secret(secret),
            );
            append_one(&mut w);
            append_one(&mut w);
            let wal = Wal::from_writer(w);
            wal.records
                .iter()
                .map(|r| r.signature.clone().unwrap())
                .collect()
        };
        let sigs1 = mk([29u8; 32]);
        let sigs2 = mk([29u8; 32]);
        assert_eq!(sigs1, sigs2);
        assert_eq!(sigs1[0].len(), 64);
    }

    #[test]
    fn domain_ctx_byte_identity_blake3() {
        // Layer A item 1 (DOMAIN_CTX literal) byte-level formal anchor. The
        // literal must remain frozen for the v0.15 epoch — every WAL chain is
        // keyed via `blake3::derive_key(DOMAIN_CTX, world_id)`; one byte change
        // rederives every chain key (A1/A14 byte-identity invariant).
        //
        // Update procedure (semver-bump escalation only): regenerate the hex via
        //   `printf '%s' "<new bytes>" | b3sum --no-names`
        // and update EXPECTED and FROZEN_HEX together. Layer A item 1
        // escalation review required.
        const EXPECTED: &[u8] = b"arkhe-kernel v0.15 WAL chain domain separation context";
        assert_eq!(WalHeader::DOMAIN_CTX, EXPECTED);
        assert_eq!(WalHeader::DOMAIN_CTX.len(), 54);

        const FROZEN_HEX: &str = "3e1aa9478e76820fbdb31ca8fdf136df81d83635e2925584934cfa110f682129";
        let actual_hex = blake3::hash(WalHeader::DOMAIN_CTX).to_hex();
        assert_eq!(
            actual_hex.as_str(),
            FROZEN_HEX,
            "DOMAIN_CTX BLAKE3 hash regression — byte-level edit detected",
        );
    }

    #[test]
    fn wal_record_persists_actor_for_replay_determinism() {
        // Regression (#1): the submit-time actor is canonical input (it feeds
        // `ctx.actor`) and must survive into the record AND the chain hash.
        let actor = Some(EntityId::new(42).unwrap());
        let mut w = WalWriter::new(world(), manifest());
        w.append_submit(
            InstanceId::new(1).unwrap(),
            Principal::System,
            actor,
            0,
            Tick(0),
            TypeCode(100),
            vec![1, 2, 3],
            sid(1),
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        match &wal.records[0].content {
            WalRecordContent::Submit { actor: a, .. } => assert_eq!(*a, actor),
            WalRecordContent::Step { .. } => panic!("expected Submit"),
        }
        assert!(wal.verify_chain(world()).is_ok());
    }

    #[test]
    fn verify_chain_anchored_rejects_downgrade_and_substitution() {
        let sig = SignatureClass::new_ed25519_from_secret([7u8; 32]);
        let vk = sig.verifying_key_bytes().unwrap();
        let mut w = WalWriter::with_signature(world(), manifest(), sig);
        append_one(&mut w);
        let wal = Wal::from_writer(w);

        let good = TrustAnchor {
            min_tier: Some(SignatureTier::Ed25519),
            ed25519_verifying_key: Some(vk),
            ..Default::default()
        };
        assert!(wal.verify_chain_anchored(world(), &good).is_ok());

        let downgrade = TrustAnchor {
            min_tier: Some(SignatureTier::Hybrid),
            ..Default::default()
        };
        assert!(matches!(
            wal.verify_chain_anchored(world(), &downgrade),
            Err(WalError::TierDowngrade)
        ));

        let wrong_key = TrustAnchor {
            min_tier: Some(SignatureTier::Ed25519),
            ed25519_verifying_key: Some([0xAB; 32]),
            ..Default::default()
        };
        assert!(matches!(
            wal.verify_chain_anchored(world(), &wrong_key),
            Err(WalError::VerifyingKeyMismatch)
        ));
    }

    // ---- frozen wire-format anchors (Layer A item 7 — CIL record shape) ----

    #[test]
    fn submit_record_postcard_layout_byte_identity() {
        // Pin the postcard byte sequence of a Tier-1 Submit record. Any silent
        // reorder / field add breaks this BLAKE3 regression.
        let mut w = WalWriter::new([7u8; 32], [3u8; 32]);
        w.append_submit(
            InstanceId::new(99).unwrap(),
            Principal::System,
            Some(EntityId::new(5).unwrap()),
            0xCAFE,
            Tick(42),
            TypeCode(0xBEEF),
            vec![0xAA, 0xBB, 0xCC],
            sid(7),
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        let encoded = postcard::to_allocvec(&wal.records[0]).expect("postcard encode");
        const FROZEN_HEX: &str = "43e10a825aa2b78cbbe59114fc546c31f64c8ffdf00dada54127bdc598967562";
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            FROZEN_HEX,
            "Submit record postcard byte sequence regression",
        );
    }

    #[test]
    fn step_record_postcard_layout_byte_identity() {
        let mut w = WalWriter::new([7u8; 32], [3u8; 32]);
        w.append_step(
            InstanceId::new(99).unwrap(),
            sid(13),
            Tick(42),
            0xC0FFEE,
            StepVerdict::BudgetPartial { denied: 2 },
            [0x5A; 32],
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        let encoded = postcard::to_allocvec(&wal.records[0]).expect("postcard encode");
        const FROZEN_HEX: &str = "44a440370648b160fa342075d77a1fd72629c1fde3467c0458c34c36d2ae4aa9";
        assert_eq!(
            blake3::hash(&encoded).to_hex().as_str(),
            FROZEN_HEX,
            "Step record postcard byte sequence regression",
        );
    }

    #[test]
    fn chain_hash_frozen_for_step_record() {
        // Pins the resulting this_chain_hash for a fixed Step body under the
        // v0.15 DOMAIN_CTX-derived chain key (DOMAIN_CTX + body field order).
        let mut w = WalWriter::new([7u8; 32], [3u8; 32]);
        w.append_step(
            InstanceId::new(1).unwrap(),
            sid(1),
            Tick(0),
            0xFF,
            StepVerdict::Committed,
            [9u8; 32],
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        const FROZEN_HEX: &str = "0627f6472e44e5af82b9019698b80adc08fe02a5ffcf081b79a3ea824556df14";
        assert_eq!(
            blake3::Hash::from(wal.records[0].this_chain_hash)
                .to_hex()
                .as_str(),
            FROZEN_HEX,
            "chain hash regression — DOMAIN_CTX or Step body field order changed",
        );
    }

    #[test]
    fn wal_record_hybrid_layout_byte_identity() {
        // Pin the postcard wire-format growth for a record's PQC signature slot
        // (ML-DSA 65 signature = 3309 bytes).
        let sig_class = SignatureClass::new_ed25519_from_secret([19u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        let baseline_encoded = postcard::to_allocvec(&wal.records[0]).expect("baseline encode");
        wal.records[0].signature_pqc = Some(vec![0xAB; 3309]);
        let with_pqc_encoded = postcard::to_allocvec(&wal.records[0]).expect("with_pqc encode");
        // None = 0x00 (1 byte); Some(vec[3309]) = 0x01 + varint(3309)=2 + 3309.
        assert_eq!(
            with_pqc_encoded.len() - baseline_encoded.len(),
            3311,
            "PQC signature envelope size mismatch — ML-DSA 65 must fit",
        );
    }

    #[test]
    fn wal_header_verifying_key_pqc_slot_pinned() {
        let h = WalWriter::new(world(), manifest()).header().clone();
        assert!(h.verifying_key.is_none());
        assert!(h.verifying_key_pqc.is_none());

        let mut h_pqc = h.clone();
        h_pqc.verifying_key_pqc = Some(vec![0xCD; 1952]);
        let baseline = postcard::to_allocvec(&h).expect("encode baseline");
        let with_pqc = postcard::to_allocvec(&h_pqc).expect("encode with pqc key");
        // None = 1 byte; Some(vec[1952]) = 0x01 + varint(1952)=2 + 1952.
        assert_eq!(
            with_pqc.len() - baseline.len(),
            1954,
            "PQC verifying-key envelope size mismatch — ML-DSA 65 must fit",
        );
    }

    // ---- PQC Hybrid (Ed25519 + ML-DSA 65) wal-side wiring ----

    #[test]
    fn hybrid_writer_emits_both_signatures() {
        let sig_class = SignatureClass::new_hybrid_from_secrets([7u8; 32], [11u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        for _ in 0..3 {
            append_one(&mut w);
        }
        let wal = Wal::from_writer(w);
        assert_eq!(wal.header.verifying_key.expect("Hybrid pins Ed25519 vk").len(), 32);
        assert_eq!(
            wal.header
                .verifying_key_pqc
                .as_ref()
                .expect("Hybrid pins PQC vk")
                .len(),
            1952
        );
        assert_eq!(wal.records.len(), 3);
        for rec in &wal.records {
            assert_eq!(
                rec.signature
                    .as_ref()
                    .expect("Hybrid signs Ed25519 every record")
                    .len(),
                64
            );
            assert_eq!(
                rec.signature_pqc
                    .as_ref()
                    .expect("Hybrid signs PQC every record")
                    .len(),
                3309
            );
        }
    }

    #[test]
    fn hybrid_verify_chain_and_mode_passes_with_both_valid() {
        let sig_class = SignatureClass::new_hybrid_from_secrets([13u8; 32], [17u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        for _ in 0..3 {
            append_one(&mut w);
        }
        let wal = Wal::from_writer(w);
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        back.verify_chain(world())
            .expect("Hybrid signed chain verifies (AND-mode pass)");
    }

    #[test]
    fn hybrid_verify_chain_rejects_missing_pqc() {
        let sig_class = SignatureClass::new_hybrid_from_secrets([19u8; 32], [23u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        wal.records[0].signature_pqc = None;
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::MissingPqcSignature { at_record: 0 })
        ));
    }

    #[test]
    fn hybrid_verify_chain_rejects_corrupt_pqc_signature() {
        let sig_class = SignatureClass::new_hybrid_from_secrets([29u8; 32], [31u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        if let Some(sig_pqc) = wal.records[1].signature_pqc.as_mut() {
            sig_pqc[0] ^= 0xFF;
        }
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::PqcSignatureMismatch { at_record: 1 })
        ));
    }

    #[test]
    fn hybrid_verify_chain_rejects_corrupt_ed25519_when_pqc_valid() {
        let sig_class = SignatureClass::new_hybrid_from_secrets([37u8; 32], [41u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        if let Some(sig) = wal.records[0].signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::PqcSignatureMismatch { at_record: 0 })
        ));
    }

    #[test]
    fn ed25519_only_wal_replays_under_hybrid_kernel() {
        let sig_class = SignatureClass::new_ed25519_from_secret([43u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        for _ in 0..3 {
            append_one(&mut w);
        }
        let wal = Wal::from_writer(w);
        assert!(wal.header.verifying_key.is_some());
        assert!(wal.header.verifying_key_pqc.is_none());
        for rec in &wal.records {
            assert!(rec.signature.is_some());
            assert!(rec.signature_pqc.is_none());
        }
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        back.verify_chain(world())
            .expect("Ed25519-only WAL replays under Hybrid-capable kernel");
    }

    #[test]
    fn pqc_without_ed25519_envelope_rejected() {
        let sig_class = SignatureClass::new_hybrid_from_secrets([47u8; 32], [53u8; 32]);
        let w = WalWriter::with_signature(world(), manifest(), sig_class);
        let mut wal = Wal::from_writer(w);
        wal.header.verifying_key = None;
        assert!(matches!(
            wal.verify_chain(world()),
            Err(WalError::PqcWithoutEd25519)
        ));
    }
}

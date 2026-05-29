//! WAL header + records + BLAKE3-keyed chain.
//!
//! Each record's `this_chain_hash` is computed as
//! `blake3::keyed(chain_key, prev_chain_hash || canonical(body))`
//! where `chain_key = blake3::derive_key(WAL domain context, world_id)`.
//! Tampering any record's body or reordering records breaks the chain
//! at `verify_chain` time.

use serde::{Deserialize, Serialize};

use crate::abi::{EntityId, InstanceId, Principal, Tick, TypeCode};
use crate::runtime::stage::StepStage;

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
    pub const CURRENT_KERNEL_SEMVER: (u16, u16, u16) = (0, 14, 0);
    /// ABI semver pinned by [`WalWriter::new`].
    pub const ABI_VERSION: (u16, u16) = (0, 14);
    /// Postcard major version pinned by [`WalWriter::new`].
    pub const POSTCARD_MAJOR: u32 = 1;
    /// BLAKE3 major version pinned by [`WalWriter::new`].
    pub const BLAKE3_MAJOR: u32 = 1;
    /// Domain-separation byte string fed into `blake3::derive_key` to
    /// produce the WAL chain key. The "v0.14" anchor pins the chain
    /// epoch; it advances with a release whose persisted wire format
    /// changes (the v0.13 → v0.14 ML-DSA stabilization being the first
    /// such advance). Any change rederives every chain key and
    /// invalidates all prior-epoch WAL chains (Layer A item 1
    /// byte-identity invariant — A1/A14).
    pub const DOMAIN_CTX: &'static [u8] = b"arkhe-kernel v0.14 WAL chain domain separation context";
}

/// One-byte annotation summarizing whether every Op in the record's
/// stage authorized cleanly. Belt-and-suspenders companion to the
/// chain hash (belt-and-suspenders companion).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthDecisionAnnotation {
    /// Every Op authorized.
    AllAuthorized = 0,
    /// At least one Op was denied.
    SomeDenied = 1,
}

/// Single committed step recorded in the WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    /// Monotonic record sequence within this WAL.
    pub seq: u64,
    /// Tick at which the producing `step()` ran.
    pub at: Tick,
    /// Instance the action ran against.
    pub instance: InstanceId,
    /// Principal under which the action was submitted.
    pub principal: Principal,
    /// Submitting entity (the `actor` passed to `submit`), if any. Part of
    /// the canonical input — it feeds `ActionContext::actor` during
    /// `compute()` — so it MUST be persisted AND chain-hashed (it is a
    /// `WalRecordBody` field) to keep replay bit-identical (A1) for any
    /// module that branches on `ctx.actor`.
    pub actor: Option<EntityId>,
    /// Type code of the executed action.
    pub action_type_code: TypeCode,
    /// Canonical action bytes (replay deserializes from these).
    pub action_bytes: Vec<u8>,
    /// `CapabilityMask` bits in effect during `step()`.
    pub caps_bits: u64,
    pub(crate) stage: StepStage,
    /// Auth-decision summary for this step's Ops.
    pub auth_decision: AuthDecisionAnnotation,
    /// Previous record's `this_chain_hash` (or zero for record 0).
    pub prev_chain_hash: [u8; 32],
    /// `blake3::keyed(chain_key, prev_chain_hash || canonical(body))`.
    pub this_chain_hash: [u8; 32],
    /// Ed25519 signature over the canonical `WalRecordBody` bytes
    /// (the same bytes hashed into `this_chain_hash`). `None` when the
    /// owning WAL was created with `SignatureClass::None`. Stored as
    /// `Vec<u8>` (always exactly 64 bytes when present) because serde's
    /// array deserializer caps at 32 — same workaround as the header's
    /// `domain_separation_context`.
    pub signature: Option<Vec<u8>>,
    /// PQC signature bytes for Hybrid signing modes (envelope slot for
    /// ML-DSA 65 or other PQC algorithms). Paired with `signature` for
    /// dual-sign verification under Hybrid policy. `None` for non-Hybrid
    /// configurations. Stored as `Vec<u8>` because PQC signatures exceed
    /// the serde 32-byte fixed-array limit (ML-DSA 65 signature = 3309
    /// bytes).
    pub signature_pqc: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct WalRecordBody<'a> {
    seq: u64,
    at: Tick,
    instance: InstanceId,
    principal: &'a Principal,
    actor: Option<EntityId>,
    action_type_code: TypeCode,
    action_bytes: &'a [u8],
    caps_bits: u64,
    stage: &'a StepStage,
    auth_decision: AuthDecisionAnnotation,
    prev_chain_hash: [u8; 32],
}

impl<'a> WalRecordBody<'a> {
    /// Reconstruct the canonical body view from a stored `WalRecord`
    /// plus the running `prev_chain_hash` (used by `verify_chain`).
    /// `append` constructs the body inline because its fields are
    /// per-field locals at that point — sharing a helper there costs
    /// readability for no LOC saved.
    fn from_record(rec: &'a WalRecord, prev: [u8; 32]) -> Self {
        Self {
            seq: rec.seq,
            at: rec.at,
            instance: rec.instance,
            principal: &rec.principal,
            actor: rec.actor,
            action_type_code: rec.action_type_code,
            action_bytes: &rec.action_bytes,
            caps_bits: rec.caps_bits,
            stage: &rec.stage,
            auth_decision: rec.auth_decision,
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn append(
        &mut self,
        at: Tick,
        instance: InstanceId,
        principal: Principal,
        actor: Option<EntityId>,
        action_type_code: TypeCode,
        action_bytes: Vec<u8>,
        caps_bits: u64,
        stage: StepStage,
        auth_decision: AuthDecisionAnnotation,
    ) -> Result<&WalRecord, WalError> {
        self.next_seq = self.next_seq.saturating_add(1);
        let body = WalRecordBody {
            seq: self.next_seq,
            at,
            instance,
            principal: &principal,
            actor,
            action_type_code,
            action_bytes: &action_bytes,
            caps_bits,
            stage: &stage,
            auth_decision,
            prev_chain_hash: self.prev_hash,
        };
        let body_bytes = postcard::to_allocvec(&body)
            .map_err(|e| WalError::SerializeFailed(format!("{}", e)))?;
        let mut hasher = blake3::Hasher::new_keyed(&self.chain_key);
        hasher.update(&self.prev_hash);
        hasher.update(&body_bytes);
        let this_hash: [u8; 32] = *hasher.finalize().as_bytes();

        // Signatures are over the same body bytes that feed the chain
        // hash. Tier 1 (None) leaves both `None`. Hybrid emits paired
        // Ed25519 + ML-DSA 65 signatures via `sign_hybrid`.
        let (signature, signature_pqc) = match self.sig_class.sign_hybrid(&body_bytes) {
            Some(hyb) => (Some(hyb.ed25519.to_vec()), Some(hyb.pqc)),
            None => (self.sig_class.sign(&body_bytes).map(|s| s.to_vec()), None),
        };

        let record = WalRecord {
            seq: self.next_seq,
            at,
            instance,
            principal,
            actor,
            action_type_code,
            action_bytes,
            caps_bits,
            stage,
            auth_decision,
            prev_chain_hash: self.prev_hash,
            this_chain_hash: this_hash,
            signature,
            signature_pqc,
        };
        self.records.push(record);
        self.prev_hash = this_hash;
        Ok(self.records.last().expect("just pushed"))
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
    /// tampered log or a peer's snapshot): beyond [`verify_chain`]'s
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
    use crate::abi::{EntityId, ExternalId, RouteId};
    use crate::runtime::stage::{LedgerOp, StagedStateDelta};
    use crate::state::EntityMeta;

    fn world() -> [u8; 32] {
        [7u8; 32]
    }
    fn manifest() -> [u8; 32] {
        [3u8; 32]
    }

    fn sample_stage() -> StepStage {
        let mut s = StepStage::default();
        s.state_ops.push(StagedStateDelta::SpawnEntity {
            id: EntityId::new(1).unwrap(),
            meta: EntityMeta {
                owner: Principal::System,
                created: Tick(0),
            },
        });
        s.ledger_delta
            .ops
            .push(LedgerOp::AddEntity(EntityId::new(1).unwrap()));
        s.id_counters.next_entity_advance = 1;
        s
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
    fn single_append_produces_nonzero_chain_tip() {
        let mut w = WalWriter::new(world(), manifest());
        w.append(
            Tick(5),
            InstanceId::new(1).unwrap(),
            Principal::System,
            None,
            TypeCode(100),
            vec![1, 2, 3],
            0,
            sample_stage(),
            AuthDecisionAnnotation::AllAuthorized,
        )
        .unwrap();
        let tip = w.chain_tip();
        assert_ne!(tip, [0u8; 32]);
        assert_eq!(w.record_count(), 1);
    }

    #[test]
    fn multi_record_chain_links_each_record() {
        let mut w = WalWriter::new(world(), manifest());
        for i in 0..5 {
            w.append(
                Tick(i),
                InstanceId::new(1).unwrap(),
                Principal::System,
                None,
                TypeCode(100),
                vec![i as u8],
                0,
                StepStage::default(),
                AuthDecisionAnnotation::AllAuthorized,
            )
            .unwrap();
        }
        let wal = Wal::from_writer(w);
        assert_eq!(wal.records.len(), 5);
        // Each record's prev_chain_hash equals previous record's this_chain_hash.
        let mut prev = [0u8; 32];
        for rec in &wal.records {
            assert_eq!(rec.prev_chain_hash, prev);
            prev = rec.this_chain_hash;
        }
        wal.verify_chain(world()).expect("clean chain");
    }

    #[test]
    fn tampered_record_breaks_verify_chain() {
        let mut w = WalWriter::new(world(), manifest());
        for i in 0..3 {
            w.append(
                Tick(i),
                InstanceId::new(1).unwrap(),
                Principal::System,
                None,
                TypeCode(100),
                vec![i as u8],
                0,
                StepStage::default(),
                AuthDecisionAnnotation::AllAuthorized,
            )
            .unwrap();
        }
        let mut wal = Wal::from_writer(w);
        // Tamper: overwrite middle record's caps_bits.
        wal.records[1].caps_bits = 0xDEAD_BEEF;
        let result = wal.verify_chain(world());
        assert!(matches!(result, Err(WalError::HashMismatch { .. })));
    }

    #[test]
    fn verify_chain_detects_broken_prev_link() {
        let mut w = WalWriter::new(world(), manifest());
        for i in 0..3 {
            w.append(
                Tick(i),
                InstanceId::new(1).unwrap(),
                Principal::System,
                None,
                TypeCode(100),
                vec![i as u8],
                0,
                StepStage::default(),
                AuthDecisionAnnotation::AllAuthorized,
            )
            .unwrap();
        }
        let mut wal = Wal::from_writer(w);
        // Tamper: break the prev_chain_hash link of record 1 without
        // touching its body. verify_chain must detect chain discontinuity
        // (ChainBroken) before reaching the body-derived hash check
        // (HashMismatch).
        wal.records[1].prev_chain_hash[0] ^= 1;
        let result = wal.verify_chain(world());
        assert!(matches!(
            result,
            Err(WalError::ChainBroken { at_record: 1 })
        ));
    }

    #[test]
    fn different_world_id_produces_different_chain() {
        let mut w1 = WalWriter::new([1u8; 32], manifest());
        let mut w2 = WalWriter::new([2u8; 32], manifest());
        for w in [&mut w1, &mut w2] {
            w.append(
                Tick(0),
                InstanceId::new(1).unwrap(),
                Principal::System,
                None,
                TypeCode(100),
                vec![],
                0,
                StepStage::default(),
                AuthDecisionAnnotation::AllAuthorized,
            )
            .unwrap();
        }
        // Domain-separation: different world_id → different keyed-hash output.
        assert_ne!(w1.chain_tip(), w2.chain_tip());
    }

    #[test]
    fn verify_chain_against_wrong_world_id_fails() {
        let mut w = WalWriter::new(world(), manifest());
        w.append(
            Tick(0),
            InstanceId::new(1).unwrap(),
            Principal::System,
            None,
            TypeCode(100),
            vec![],
            0,
            StepStage::default(),
            AuthDecisionAnnotation::AllAuthorized,
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        let result = wal.verify_chain([99u8; 32]);
        assert!(matches!(result, Err(WalError::HashMismatch { .. })));
    }

    #[test]
    fn auth_decision_annotation_round_trips() {
        let mut w = WalWriter::new(world(), manifest());
        w.append(
            Tick(0),
            InstanceId::new(1).unwrap(),
            Principal::External(ExternalId(7)),
            None,
            TypeCode(101),
            vec![],
            0,
            StepStage::default(),
            AuthDecisionAnnotation::SomeDenied,
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        assert_eq!(
            back.records[0].auth_decision,
            AuthDecisionAnnotation::SomeDenied
        );
    }

    #[test]
    fn header_carries_magic_and_versions() {
        let h = WalWriter::new(world(), manifest()).header().clone();
        assert_eq!(h.magic, *b"ARKHEWAL");
        assert_eq!(h.kernel_semver, (0, 14, 0));
        assert_eq!(h.world_id, world());
        assert_eq!(h.manifest_digest, manifest());
        assert!(h.type_registry_pins.is_empty());
        assert!(h.verifying_key.is_none());
        let _ = RouteId(1);
    }

    // ---- Ed25519 SignatureClass (Tier 2, A16) ----

    fn append_one(w: &mut WalWriter) {
        w.append(
            Tick(0),
            InstanceId::new(1).unwrap(),
            Principal::System,
            None,
            TypeCode(100),
            vec![1, 2, 3],
            0,
            sample_stage(),
            AuthDecisionAnnotation::AllAuthorized,
        )
        .unwrap();
    }

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
        // Round-trip through serialize to confirm the on-disk shape verifies.
        let bytes = wal.serialize().unwrap();
        let back = Wal::deserialize(&bytes).unwrap();
        back.verify_chain(world()).expect("signed chain verifies");
    }

    #[test]
    fn tampered_signature_fails_verify() {
        // Hash check would catch body tampering first; isolate the signature
        // path by tampering ONLY the signature field.
        let sig_class = SignatureClass::new_ed25519_from_secret([13u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        // Flip a byte inside record[1]'s signature.
        if let Some(sig) = wal.records[1].signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        let result = wal.verify_chain(world());
        assert!(matches!(
            result,
            Err(WalError::SignatureMismatch { at_record: 1 })
        ));
    }

    #[test]
    fn missing_signature_fails_verify_when_header_has_key() {
        let sig_class = SignatureClass::new_ed25519_from_secret([17u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        // Header still pins a verifying_key, but the record claims no sig.
        wal.records[0].signature = None;
        let result = wal.verify_chain(world());
        assert!(matches!(
            result,
            Err(WalError::MissingSignature { at_record: 0 })
        ));
    }

    #[test]
    fn wrong_key_fails_verify() {
        let sig_class = SignatureClass::new_ed25519_from_secret([19u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        // Replace the pinned verifying key with a different one — the records'
        // signatures stop verifying.
        let other = SignatureClass::new_ed25519_from_secret([23u8; 32])
            .verifying_key_bytes()
            .unwrap();
        wal.header.verifying_key = Some(other);
        let result = wal.verify_chain(world());
        assert!(matches!(
            result,
            Err(WalError::SignatureMismatch { at_record: 0 })
        ));
    }

    #[test]
    fn signature_deterministic_across_runs() {
        // RFC 8032 Ed25519 is deterministic — building two WALs with the
        // same key and the same append sequence yields byte-identical
        // record signatures.
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
        // Layer A item 1 (DOMAIN_CTX literal) byte-level formal anchor.
        // The literal must remain frozen across kernel semver bumps —
        // every WAL chain ever produced is keyed via
        // `blake3::derive_key(DOMAIN_CTX, world_id)`; one byte change
        // rederives every chain key (A1/A14 byte-identity invariant).
        //
        // Two complementary witnesses pin the literal:
        //   1. Byte-identity vs the canonical literal (rewrite catch).
        //   2. BLAKE3 hash regression vs a frozen hex (silent edit
        //      catch — the byte-level formal anchor of E14 / A14).
        //
        // Update procedure: if the literal must change (semver-bump
        // escalation), regenerate the hex via
        //   `printf '%s' "<new bytes>" | b3sum --no-names`
        // and update both `EXPECTED` and `FROZEN_HEX` together.
        // Layer A item 1 escalation review required.
        const EXPECTED: &[u8] = b"arkhe-kernel v0.14 WAL chain domain separation context";
        assert_eq!(WalHeader::DOMAIN_CTX, EXPECTED);
        assert_eq!(WalHeader::DOMAIN_CTX.len(), 54);

        // Frozen BLAKE3 hex of the canonical bytes (regression pin).
        const FROZEN_HEX: &str = "4c20c496b74ba868f2669cfcc1a8b6f4c2e0f122bdba5e0337eaeebe599a1fda";
        let actual_hex = blake3::hash(WalHeader::DOMAIN_CTX).to_hex();
        assert_eq!(
            actual_hex.as_str(),
            FROZEN_HEX,
            "DOMAIN_CTX BLAKE3 hash regression — byte-level edit detected",
        );
    }

    #[test]
    fn wal_record_persists_actor_for_replay_determinism() {
        // Regression (#1): the submit-time actor is canonical input (it
        // feeds `ctx.actor`) and must survive into the record AND the
        // chain hash so replay is bit-identical for modules that read it.
        let mut w = WalWriter::new(world(), manifest());
        let actor = Some(EntityId::new(42).unwrap());
        w.append(
            Tick(0),
            InstanceId::new(1).unwrap(),
            Principal::System,
            actor,
            TypeCode(100),
            vec![1, 2, 3],
            0,
            sample_stage(),
            AuthDecisionAnnotation::AllAuthorized,
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        assert_eq!(wal.records[0].actor, actor);
        assert!(wal.verify_chain(world()).is_ok());
    }

    #[test]
    fn verify_chain_anchored_rejects_downgrade_and_substitution() {
        // Regression (#1/#2 security): an anchored verify must reject a
        // tier downgrade and a verifying-key substitution.
        let sig = SignatureClass::new_ed25519_from_secret([7u8; 32]);
        let vk = sig.verifying_key_bytes().unwrap();
        let mut w = WalWriter::with_signature(world(), manifest(), sig);
        append_one(&mut w);
        let wal = Wal::from_writer(w);

        // Correct anchor (Ed25519 floor + matching key) → Ok.
        let good = TrustAnchor {
            min_tier: Some(SignatureTier::Ed25519),
            ed25519_verifying_key: Some(vk),
            ..Default::default()
        };
        assert!(wal.verify_chain_anchored(world(), &good).is_ok());

        // Downgrade: require Hybrid, WAL is only Ed25519 → reject.
        let downgrade = TrustAnchor {
            min_tier: Some(SignatureTier::Hybrid),
            ..Default::default()
        };
        assert!(matches!(
            wal.verify_chain_anchored(world(), &downgrade),
            Err(WalError::TierDowngrade)
        ));

        // Substitution: anchor expects a different key → reject.
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

    // ---- PQC envelope wire format (Layer A item 7 post-extension) ----

    #[test]
    fn wal_record_postcard_layout_byte_identity() {
        // Pin the postcard wire-format byte sequence for an Ed25519-signed
        // WalRecord via BLAKE3 frozen-hash regression. Any silent reorder
        // of WalRecord fields (or insertion of new fields without updating
        // this pin) breaks this assertion.
        let sig_class = SignatureClass::new_ed25519_from_secret([7u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let wal = Wal::from_writer(w);
        let encoded = postcard::to_allocvec(&wal.records[0]).expect("postcard encode");
        const FROZEN_HEX: &str = "170607201a4352833ebfe81a1546b4937cdafd587a3e266408b6c1a6bea16709";
        let actual = blake3::hash(&encoded);
        assert_eq!(
            actual.to_hex().as_str(),
            FROZEN_HEX,
            "WalRecord postcard byte sequence regression",
        );
    }

    #[test]
    fn wal_record_hybrid_layout_byte_identity() {
        // Pin the postcard wire-format growth for a Hybrid record's PQC
        // signature slot (envelope sized for ML-DSA 65 signature = 3309
        // bytes). Verifies the wire format slot accommodates PQC signature
        // sizes exceeding Ed25519's 64-byte fixed length.
        let sig_class = SignatureClass::new_ed25519_from_secret([19u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        // Baseline: signature_pqc=None.
        let baseline_encoded = postcard::to_allocvec(&wal.records[0]).expect("baseline encode");
        // Inject ML-DSA 65-sized placeholder signature (3309 bytes).
        wal.records[0].signature_pqc = Some(vec![0xAB; 3309]);
        let with_pqc_encoded = postcard::to_allocvec(&wal.records[0]).expect("with_pqc encode");
        // Postcard Option<Vec<u8>>: None = 0x00 (1 byte).
        // Some(vec[3309]) = 0x01 + varint(3309) + 3309 bytes.
        // varint(3309) = 0xED 0x19 (2 bytes).
        // Net growth: 1 + 2 + 3309 - 1 = 3311 bytes.
        assert_eq!(
            with_pqc_encoded.len() - baseline_encoded.len(),
            3311,
            "PQC signature envelope size mismatch — ML-DSA 65 must fit",
        );
    }

    #[test]
    fn wal_header_verifying_key_pqc_slot_pinned() {
        // Pin the WalHeader PQC verifying-key envelope slot. None for
        // non-Hybrid; Some(1952B) for Hybrid (ML-DSA 65 verifying key
        // size). Verifies the wire format slot accommodates PQC public
        // key sizes exceeding Ed25519's 32-byte fixed length.
        let h = WalWriter::new(world(), manifest()).header().clone();
        // Tier 1: both verifying keys absent.
        assert!(h.verifying_key.is_none());
        assert!(h.verifying_key_pqc.is_none());

        let mut h_pqc = h.clone();
        // Inject ML-DSA 65-sized placeholder verifying key (1952 bytes).
        h_pqc.verifying_key_pqc = Some(vec![0xCD; 1952]);
        let baseline = postcard::to_allocvec(&h).expect("encode baseline");
        let with_pqc = postcard::to_allocvec(&h_pqc).expect("encode with pqc key");
        // Postcard Option<Vec<u8>>: None = 0x00 (1 byte).
        // Some(vec[1952]) = 0x01 + varint(1952) + 1952 bytes.
        // varint(1952) = 0xA0 0x0F (2 bytes).
        // Net growth: 1 + 2 + 1952 - 1 = 1954 bytes.
        assert_eq!(
            with_pqc.len() - baseline.len(),
            1954,
            "PQC verifying-key envelope size mismatch — ML-DSA 65 must fit",
        );
    }

    #[test]
    fn chain_hash_unchanged_for_ed25519_records() {
        // Layer A item 1 (DOMAIN_CTX) byte-identity preservation under
        // the WalRecord wire format extension. WalRecordBody (10-field
        // chain hash input) UNCHANGED — chain hash for the same body
        // input is identical pre/post extension. Pins the resulting
        // this_chain_hash via BLAKE3 frozen-hex regression.
        let mut w = WalWriter::new([7u8; 32], [3u8; 32]);
        w.append(
            Tick(0),
            InstanceId::new(1).unwrap(),
            Principal::System,
            None,
            TypeCode(100),
            vec![1, 2, 3],
            0,
            sample_stage(),
            AuthDecisionAnnotation::AllAuthorized,
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        const FROZEN_HEX: &str = "4bb26e665e904314600b52b0d3bef34ee476de1c155f701fa95c8f5438140319";
        let actual_hex = blake3::Hash::from(wal.records[0].this_chain_hash).to_hex();
        assert_eq!(
            actual_hex.as_str(),
            FROZEN_HEX,
            "chain hash regression — DOMAIN_CTX or WalRecordBody field order changed",
        );
    }

    #[test]
    fn wal_record_postcard_field_order_baseline() {
        // Layer A item 7 post-extension baseline pin. Pins the WalRecord
        // postcard byte sequence for a Tier 1 (no signature) record with
        // distinctive inputs. Any silent reorder or addition of fields
        // breaks this BLAKE3 hash regression pin.
        let mut w = WalWriter::new([7u8; 32], [3u8; 32]);
        w.append(
            Tick(42),
            InstanceId::new(99).unwrap(),
            Principal::System,
            None,
            TypeCode(0xCAFE),
            vec![0xAA, 0xBB, 0xCC],
            0xFF,
            sample_stage(),
            AuthDecisionAnnotation::AllAuthorized,
        )
        .unwrap();
        let wal = Wal::from_writer(w);
        let encoded = postcard::to_allocvec(&wal.records[0]).expect("postcard encode");
        const FROZEN_HEX: &str = "ca468fac6ac1c0742c3b48e6398290630015411da040cf22c0228012b7e71cfa";
        let actual = blake3::hash(&encoded);
        assert_eq!(
            actual.to_hex().as_str(),
            FROZEN_HEX,
            "WalRecord postcard field order regression",
        );
    }

    // ---- PQC Hybrid (Ed25519 + ML-DSA 65) wal-side wiring ----

    #[test]
    fn hybrid_writer_emits_both_signatures() {
        // Hybrid sig_class populates both signature (Ed25519 64 bytes)
        // and signature_pqc (ML-DSA 65 3309 bytes) on every record.
        // Header pins both verifying_key (Ed25519 32 bytes) and
        // verifying_key_pqc (ML-DSA 65 1952 bytes).
        let sig_class = SignatureClass::new_hybrid_from_secrets([7u8; 32], [11u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        for _ in 0..3 {
            append_one(&mut w);
        }
        let wal = Wal::from_writer(w);
        assert_eq!(
            wal.header
                .verifying_key
                .expect("Hybrid pins Ed25519 vk")
                .len(),
            32
        );
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
        // AND-mode positive: both Ed25519 and ML-DSA 65 signatures
        // valid → verify_chain succeeds. Round-trip through serialize
        // confirms the on-disk shape verifies.
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
        // Strict (write-side): Hybrid envelope (header pins PQC vk) +
        // record without signature_pqc → MissingPqcSignature.
        let sig_class = SignatureClass::new_hybrid_from_secrets([19u8; 32], [23u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        // Header still pins PQC vk, but the record claims no PQC sig.
        wal.records[0].signature_pqc = None;
        let result = wal.verify_chain(world());
        assert!(matches!(
            result,
            Err(WalError::MissingPqcSignature { at_record: 0 })
        ));
    }

    #[test]
    fn hybrid_verify_chain_rejects_corrupt_pqc_signature() {
        // Hybrid with valid Ed25519 + corrupt PQC signature →
        // verify_hybrid Ed25519 phase passes, PQC phase fails →
        // PqcSignatureMismatch.
        let sig_class = SignatureClass::new_hybrid_from_secrets([29u8; 32], [31u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        // Flip a byte inside record[1]'s PQC signature.
        if let Some(sig_pqc) = wal.records[1].signature_pqc.as_mut() {
            sig_pqc[0] ^= 0xFF;
        }
        let result = wal.verify_chain(world());
        assert!(matches!(
            result,
            Err(WalError::PqcSignatureMismatch { at_record: 1 })
        ));
    }

    #[test]
    fn hybrid_verify_chain_rejects_corrupt_ed25519_when_pqc_valid() {
        // AND-mode short-circuit: corrupt Ed25519 signature with valid
        // PQC signature → verify_hybrid Ed25519 phase fails first →
        // PqcSignatureMismatch (uniform AND-mode failure error — any
        // Hybrid signature failure maps to PqcSignatureMismatch at the
        // WalError surface).
        let sig_class = SignatureClass::new_hybrid_from_secrets([37u8; 32], [41u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        append_one(&mut w);
        append_one(&mut w);
        let mut wal = Wal::from_writer(w);
        // Flip a byte inside record[0]'s Ed25519 signature; PQC stays valid.
        if let Some(sig) = wal.records[0].signature.as_mut() {
            sig[0] ^= 0xFF;
        }
        let result = wal.verify_chain(world());
        assert!(matches!(
            result,
            Err(WalError::PqcSignatureMismatch { at_record: 0 })
        ));
    }

    #[test]
    fn ed25519_only_wal_replays_under_hybrid_kernel() {
        // Backward-compat (read-side): Ed25519-only WAL bytes
        // (verifying_key_pqc=None, signature_pqc=None per record)
        // replay under a PQC-Hybrid-capable kernel via the
        // (Some, None) → VerifierClass::Ed25519 envelope-derived
        // dispatch arm. Strict mode applies write-side only.
        let sig_class = SignatureClass::new_ed25519_from_secret([43u8; 32]);
        let mut w = WalWriter::with_signature(world(), manifest(), sig_class);
        for _ in 0..3 {
            append_one(&mut w);
        }
        let wal = Wal::from_writer(w);
        // Ed25519-only envelope: Ed25519 vk pinned, no PQC vk; records
        // have signature but no signature_pqc.
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
        // Envelope-level invariant: verifying_key=None +
        // verifying_key_pqc=Some → invalid envelope. Ed25519 is the
        // chain-anchor companion; PQC-only envelope is rejected.
        // VerifierClass::from_header_bytes returns
        // VerifierInitError::PqcWithoutEd25519 → wal.rs caller maps to
        // WalError::PqcWithoutEd25519.
        let sig_class = SignatureClass::new_hybrid_from_secrets([47u8; 32], [53u8; 32]);
        let w = WalWriter::with_signature(world(), manifest(), sig_class);
        let mut wal = Wal::from_writer(w);
        // Strip the Ed25519 verifying-key while leaving PQC vk in place
        // → (None, Some) invalid envelope.
        wal.header.verifying_key = None;
        let result = wal.verify_chain(world());
        assert!(matches!(result, Err(WalError::PqcWithoutEd25519)));
    }
}

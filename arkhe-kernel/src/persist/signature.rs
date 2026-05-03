//! `SignatureClass` — Tier 1/2/3 signing configuration (A16) + PQC Hybrid (CNSA 2.0).
//!
//! Ships:
//! - `None` — no signature; chain integrity rests entirely on the
//!   BLAKE3 keyed chain (A13). Tier 1.
//! - `Ed25519` — per-record Ed25519 signature over the canonical
//!   `WalRecordBody` bytes; verifying key is pinned in the WAL header
//!   so post-hoc verification is self-contained. Tier 2.
//! - `Hybrid` — PQC dual-sign (Ed25519 + ML-DSA 65, NIST FIPS 204).
//!   Both signatures must verify (AND-mode). Forward-secure default
//!   for new WALs. CNSA 2.0 transition spec compliance.
//!
//! Tier 3 (`TransparencyLog`) is reserved (deferred).
//!
//! `SignatureClass` is **not** Serialize/Deserialize — it carries the
//! `SigningKey` which must never appear in WAL bytes. Only the
//! verifying keys (header) and per-record signatures persist.
//! `Debug` for the `Ed25519` and `Hybrid` variants redacts signing keys.

use ed25519_dalek::{
    Signer as Ed25519SignerTrait, SigningKey, Verifier as Ed25519VerifierTrait, VerifyingKey,
};
use ml_dsa::signature::{
    Keypair as MlDsaKeypairTrait, Signer as MlDsaSignerTrait, Verifier as MlDsaVerifierTrait,
};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, B32};

// Sealed-trait marker (per docs/sealing-pattern-lineage.md,
// A24 sealed-trait pattern). External crates cannot add new
// PqcSigner / PqcVerifier impls — universe is monomorphic to
// SoftwareMlDsa65Signer / SoftwareMlDsa65Verifier. HSM/KMS impls
// land via separate sealed-trait extension (deferred).
mod private_seal {
    pub trait Sealed {}
    impl Sealed for super::SoftwareMlDsa65Signer {}
    impl Sealed for super::SoftwareMlDsa65Verifier {}
}

/// Failure modes for `PqcSigner::sign` operations.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PqcSignError {
    /// PQC signing primitive returned an error (provider-specific).
    Provider(String),
}

impl core::fmt::Display for PqcSignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Provider(m) => write!(f, "PQC signer provider error: {}", m),
        }
    }
}

impl std::error::Error for PqcSignError {}

/// Failure modes for `PqcVerifier::verify` operations.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PqcVerifyError {
    /// Signature buffer was not the expected fixed length for the
    /// PQC scheme (e.g., 3309 bytes for ML-DSA 65).
    WrongLength,
    /// Signature did not validate against the message under the
    /// pinned verifying key.
    Mismatch,
}

impl core::fmt::Display for PqcVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength => write!(f, "PQC signature wrong length"),
            Self::Mismatch => write!(f, "PQC signature did not validate"),
        }
    }
}

impl std::error::Error for PqcVerifyError {}

/// Trait abstraction for PQC signers (forward-compat for HSM/KMS
/// providers, deferred). Sealed — only same-crate impls.
pub trait PqcSigner: private_seal::Sealed + Send + Sync {
    /// Sign `msg` and return the canonical encoded signature bytes.
    /// For ML-DSA 65 this is exactly 3309 bytes (FIPS 204 §4).
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, PqcSignError>;
    /// Encoded verifying-key bytes for header pinning. For ML-DSA 65
    /// this is exactly 1952 bytes (FIPS 204 §4).
    fn verifying_key_bytes(&self) -> Vec<u8>;
}

/// Trait abstraction for PQC verifiers (forward-compat for HSM/KMS
/// verify path, deferred). Sealed — only same-crate impls.
pub trait PqcVerifier: private_seal::Sealed + Send + Sync {
    /// Verify `sig` against `msg` under the pinned verifying key.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), PqcVerifyError>;
}

/// Software-only ML-DSA 65 signer (NIST FIPS 204, security category 3).
/// Wraps the `ml-dsa` crate's `SigningKey<MlDsa65>`. Debug redacts the
/// signing key — only the verifying key bytes appear in `Debug`.
///
/// Key material is in-memory only — never serialize the signing key
/// (process protection guide: `docs/pqc-software-only.md`).
pub struct SoftwareMlDsa65Signer {
    signing_key: ml_dsa::SigningKey<MlDsa65>,
    verifying_key_cache: ml_dsa::VerifyingKey<MlDsa65>,
}

impl SoftwareMlDsa65Signer {
    /// Construct a signer deterministically from a 32-byte seed.
    /// FIPS 204 ML-DSA.KeyGen_internal — same seed yields same key pair.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let xi: B32 = seed.into();
        let signing_key = MlDsa65::from_seed(&xi);
        let verifying_key_cache = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key_cache,
        }
    }
}

impl PqcSigner for SoftwareMlDsa65Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, PqcSignError> {
        // Default Signer::sign for SigningKey<P> = sign_deterministic
        // (no RNG dependency) per ml-dsa::Signer impl. Use try_sign to
        // propagate provider errors.
        let sig: ml_dsa::Signature<MlDsa65> = self
            .signing_key
            .try_sign(msg)
            .map_err(|e| PqcSignError::Provider(format!("{}", e)))?;
        Ok(sig.encode().to_vec())
    }

    fn verifying_key_bytes(&self) -> Vec<u8> {
        self.verifying_key_cache.encode().to_vec()
    }
}

impl core::fmt::Debug for SoftwareMlDsa65Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SoftwareMlDsa65Signer {{ verifying_key_bytes: <1952B>, signing_key: <redacted> }}"
        )
    }
}

/// Software-only ML-DSA 65 verifier (NIST FIPS 204, security category 3).
pub struct SoftwareMlDsa65Verifier {
    verifying_key: ml_dsa::VerifyingKey<MlDsa65>,
}

impl SoftwareMlDsa65Verifier {
    /// Reconstruct a verifier from canonical encoded verifying-key bytes
    /// (1952 bytes for ML-DSA 65 per FIPS 204).
    pub fn from_bytes(vk_bytes: &[u8]) -> Result<Self, PqcVerifyError> {
        if vk_bytes.len() != 1952 {
            return Err(PqcVerifyError::WrongLength);
        }
        let mut buf = EncodedVerifyingKey::<MlDsa65>::default();
        buf.as_mut_slice().copy_from_slice(vk_bytes);
        let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&buf);
        Ok(Self { verifying_key })
    }
}

impl PqcVerifier for SoftwareMlDsa65Verifier {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), PqcVerifyError> {
        if sig.len() != 3309 {
            return Err(PqcVerifyError::WrongLength);
        }
        let mut sig_buf = EncodedSignature::<MlDsa65>::default();
        sig_buf.as_mut_slice().copy_from_slice(sig);
        let sig_obj =
            ml_dsa::Signature::<MlDsa65>::decode(&sig_buf).ok_or(PqcVerifyError::Mismatch)?;
        self.verifying_key
            .verify(msg, &sig_obj)
            .map_err(|_| PqcVerifyError::Mismatch)
    }
}

impl core::fmt::Debug for SoftwareMlDsa65Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SoftwareMlDsa65Verifier {{ verifying_key_bytes: <1952B> }}"
        )
    }
}

/// Output of `SignatureClass::sign_hybrid` — paired Ed25519 (64 bytes)
/// and ML-DSA 65 (3309 bytes) signatures over the same body bytes.
/// Named fields prevent positional swap.
#[derive(Debug)]
pub struct HybridSignature {
    /// Ed25519 signature bytes (RFC 8032 fixed 64 bytes).
    pub ed25519: [u8; 64],
    /// ML-DSA 65 signature bytes (NIST FIPS 204 fixed 3309 bytes).
    pub pqc: Vec<u8>,
}

// Ed25519 carries 64 bytes (SigningKey 32 + VerifyingKey 32) vs None
// 0 bytes vs Hybrid much larger. SignatureClass is held exactly once
// per kernel — the size asymmetry is structurally negligible and
// boxing would cost a heap allocation for the production path.
/// Signature tier configuration for a [`WalWriter`](super::WalWriter).
/// Default: [`None`](Self::None) (Tier 1 — chain integrity only).
///
/// Adds [`Hybrid`](Self::Hybrid) for PQC dual-sign per CNSA 2.0.
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
#[derive(Default)]
pub enum SignatureClass {
    /// No signature path (chain integrity only).
    #[default]
    None,
    /// RFC 8032 Ed25519 — deterministic per-record signatures.
    Ed25519 {
        /// Private signing key. Never serialized; redacted in `Debug`.
        signing_key: SigningKey,
        /// Verifying key derived from the signing key. Pinned in the
        /// WAL header so post-hoc verification is self-contained.
        verifying_key: VerifyingKey,
    },
    /// Hybrid — Ed25519 + ML-DSA 65 dual-sign. Both signatures emitted
    /// per record. Verify path is AND-mode (both must pass).
    Hybrid {
        /// Ed25519 private signing key.
        ed25519_signing_key: SigningKey,
        /// Ed25519 verifying key (pinned in WAL header `verifying_key`).
        ed25519_verifying_key: VerifyingKey,
        /// PQC signer (trait object — currently SoftwareMlDsa65Signer;
        /// HSM/KMS providers land via PqcSigner impl, deferred).
        pqc_signer: Box<dyn PqcSigner>,
    },
}

impl SignatureClass {
    /// Construct an Ed25519 class from a 32-byte secret seed.
    /// The verifying key is derived deterministically.
    pub fn new_ed25519_from_secret(secret: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        Self::Ed25519 {
            signing_key,
            verifying_key,
        }
    }

    /// Construct a Hybrid class from independent Ed25519 and ML-DSA 65
    /// secret seeds. Both keys derived deterministically from their
    /// respective 32-byte seeds. Use independent seeds (do not reuse
    /// the same seed for both schemes).
    pub fn new_hybrid_from_secrets(ed25519_secret: [u8; 32], ml_dsa_seed: [u8; 32]) -> Self {
        let ed25519_signing_key = SigningKey::from_bytes(&ed25519_secret);
        let ed25519_verifying_key = ed25519_signing_key.verifying_key();
        let pqc_signer = Box::new(SoftwareMlDsa65Signer::from_seed(ml_dsa_seed));
        Self::Hybrid {
            ed25519_signing_key,
            ed25519_verifying_key,
            pqc_signer,
        }
    }

    /// Bytes of the Ed25519 verifying (public) key, if Ed25519/Hybrid.
    /// Returned bytes are the `[u8; 32]` form pinned in the WAL header
    /// `verifying_key` field.
    pub fn verifying_key_bytes(&self) -> Option<[u8; 32]> {
        match self {
            Self::None => None,
            Self::Ed25519 { verifying_key, .. } => Some(verifying_key.to_bytes()),
            Self::Hybrid {
                ed25519_verifying_key,
                ..
            } => Some(ed25519_verifying_key.to_bytes()),
        }
    }

    /// Bytes of the PQC verifying (public) key, if Hybrid (else None).
    /// Returned bytes are the `Vec<u8>` form (1952 bytes for ML-DSA 65)
    /// pinned in the WAL header `verifying_key_pqc` field.
    pub fn verifying_key_pqc_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Self::None | Self::Ed25519 { .. } => None,
            Self::Hybrid { pqc_signer, .. } => Some(pqc_signer.verifying_key_bytes()),
        }
    }

    /// Sign `body_bytes` and return the Ed25519 signature (if applicable).
    /// RFC 8032 deterministic. For Hybrid records this returns the
    /// Ed25519 component only — use [`sign_hybrid`](Self::sign_hybrid)
    /// to obtain both Ed25519 + ML-DSA 65 signatures together.
    pub(crate) fn sign(&self, body_bytes: &[u8]) -> Option<[u8; 64]> {
        match self {
            Self::None => None,
            Self::Ed25519 { signing_key, .. } => Some(signing_key.sign(body_bytes).to_bytes()),
            Self::Hybrid {
                ed25519_signing_key,
                ..
            } => Some(ed25519_signing_key.sign(body_bytes).to_bytes()),
        }
    }

    /// Sign `body_bytes` with both Ed25519 and ML-DSA 65 (Hybrid only).
    /// Returns paired signatures via [`HybridSignature`].
    /// Returns `None` for non-Hybrid variants.
    ///
    /// Consumed by `wal.rs` `WalWriter::append` Hybrid path.
    pub(crate) fn sign_hybrid(&self, body_bytes: &[u8]) -> Option<HybridSignature> {
        match self {
            Self::Hybrid {
                ed25519_signing_key,
                pqc_signer,
                ..
            } => {
                let ed25519 = ed25519_signing_key.sign(body_bytes).to_bytes();
                let pqc = pqc_signer.sign(body_bytes).ok()?;
                Some(HybridSignature { ed25519, pqc })
            }
            _ => None,
        }
    }
}

impl core::fmt::Debug for SignatureClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "SignatureClass::None"),
            Self::Ed25519 { verifying_key, .. } => write!(
                f,
                "SignatureClass::Ed25519 {{ verifying_key: {:?}, signing_key: <redacted> }}",
                verifying_key.to_bytes()
            ),
            Self::Hybrid {
                ed25519_verifying_key,
                ..
            } => write!(
                f,
                "SignatureClass::Hybrid {{ ed25519_verifying_key: {:?}, ed25519_signing_key: <redacted>, pqc_signer: <redacted> }}",
                ed25519_verifying_key.to_bytes()
            ),
        }
    }
}

/// Failure modes when constructing a [`VerifierClass`] from a WAL
/// header byte buffer.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum VerifierInitError {
    /// Pinned Ed25519 verifying-key bytes did not parse.
    InvalidEd25519Key,
    /// Pinned PQC verifying-key bytes did not parse (ML-DSA 65 length).
    InvalidPqcKey,
    /// `(verifying_key=None, verifying_key_pqc=Some)` envelope — PQC
    /// key without Ed25519 anchor (invalid per Hybrid spec; Ed25519 is
    /// the chain-anchor companion).
    PqcWithoutEd25519,
}

/// Failure modes when verifying a single record's signature.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum SignatureVerifyError {
    /// Signature buffer was not exactly 64 bytes (Ed25519 fixed).
    WrongLength,
    /// Signature bytes did not validate against the body under the
    /// pinned verifying key.
    Mismatch,
}

/// Verifier-side counterpart of [`SignatureClass`] — public material
/// only. Constructed once at the top of `verify_chain` from the
/// sealed WAL header and reused per record.
#[non_exhaustive]
pub(crate) enum VerifierClass {
    /// No-signature mode (chain integrity only). Calling
    /// [`Self::verify`] on this variant is a caller-guard violation;
    /// see the method doc.
    None,
    /// RFC 8032 Ed25519 — single pinned verifying key.
    Ed25519(VerifyingKey),
    /// Hybrid — Ed25519 + ML-DSA 65 dual verify (AND-mode).
    Hybrid {
        /// Ed25519 verifying key (chain-anchor).
        ed25519: VerifyingKey,
        /// PQC verifier (trait object — currently SoftwareMlDsa65Verifier).
        /// Consumed by `Self::verify_hybrid` from `wal.rs` `verify_chain`
        /// Hybrid AND-mode dispatch site.
        pqc: Box<dyn PqcVerifier>,
    },
}

impl VerifierClass {
    /// Reconstruct from the WAL header's pinned verifying-key bytes.
    /// 4-arm envelope-derived dispatch:
    /// - `(None, None)` → `None` (Tier 1 / dev mode)
    /// - `(Some, None)` → `Ed25519` (pre-Hybrid sticky + explicit Ed25519)
    /// - `(Some, Some)` → `Hybrid` (PQC dual-sign)
    /// - `(None, Some)` → invalid envelope (`PqcWithoutEd25519` reject)
    pub(crate) fn from_header_bytes(
        vk_ed25519: Option<&[u8; 32]>,
        vk_pqc: Option<&[u8]>,
    ) -> Result<Self, VerifierInitError> {
        match (vk_ed25519, vk_pqc) {
            (None, None) => Ok(Self::None),
            (Some(vk), None) => VerifyingKey::from_bytes(vk)
                .map(Self::Ed25519)
                .map_err(|_| VerifierInitError::InvalidEd25519Key),
            (Some(vk), Some(vk_p)) => {
                let ed25519 = VerifyingKey::from_bytes(vk)
                    .map_err(|_| VerifierInitError::InvalidEd25519Key)?;
                let pqc = SoftwareMlDsa65Verifier::from_bytes(vk_p)
                    .map_err(|_| VerifierInitError::InvalidPqcKey)?;
                Ok(Self::Hybrid {
                    ed25519,
                    pqc: Box::new(pqc),
                })
            }
            (None, Some(_)) => Err(VerifierInitError::PqcWithoutEd25519),
        }
    }

    /// Verify a single record's Ed25519 signature against `body_bytes`.
    /// `body_bytes` is the postcard-encoded body produced by the
    /// caller; the callee does not re-derive (preserves WAL
    /// byte-identity — derive site stays a single source of truth).
    ///
    /// `Self::None.verify(...)` panics — caller must guard with
    /// `if !matches!(verifier, VerifierClass::None)`. Failing loud
    /// beats a silent no-op on a configuration bug.
    ///
    /// For `Self::Hybrid`, this method verifies the Ed25519 component
    /// only — use [`verify_hybrid`](Self::verify_hybrid) to verify
    /// both Ed25519 and ML-DSA 65 signatures together (AND-mode).
    pub(crate) fn verify(&self, body_bytes: &[u8], sig: &[u8]) -> Result<(), SignatureVerifyError> {
        match self {
            Self::None => {
                unreachable!("VerifierClass::None.verify(): caller must guard with matches!")
            }
            Self::Ed25519(vk) => Self::verify_ed25519(vk, body_bytes, sig),
            Self::Hybrid { ed25519, .. } => Self::verify_ed25519(ed25519, body_bytes, sig),
        }
    }

    /// Verify a Hybrid record — both Ed25519 and ML-DSA 65 signatures
    /// must pass (AND-mode). Short-circuit at first failure is
    /// safe in WAL replay context (offline, not interactive sig API).
    ///
    /// `Self::Hybrid.verify_hybrid(...)` is the only valid path —
    /// other variants panic (caller must guard with
    /// `if matches!(verifier, VerifierClass::Hybrid { .. })`).
    ///
    /// Consumed by `wal.rs` `verify_chain` Hybrid AND-mode dispatch site.
    pub(crate) fn verify_hybrid(
        &self,
        body_bytes: &[u8],
        sig: &[u8],
        sig_pqc: &[u8],
    ) -> Result<(), SignatureVerifyError> {
        match self {
            Self::Hybrid { ed25519, pqc } => {
                Self::verify_ed25519(ed25519, body_bytes, sig)?;
                pqc.verify(body_bytes, sig_pqc)
                    .map_err(|_| SignatureVerifyError::Mismatch)
            }
            _ => unreachable!("VerifierClass::verify_hybrid(): caller must guard with matches!"),
        }
    }

    fn verify_ed25519(
        vk: &VerifyingKey,
        body_bytes: &[u8],
        sig: &[u8],
    ) -> Result<(), SignatureVerifyError> {
        if sig.len() != 64 {
            return Err(SignatureVerifyError::WrongLength);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig);
        let sig_obj = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verify(body_bytes, &sig_obj)
            .map_err(|_| SignatureVerifyError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_default_and_no_verifying_key() {
        let s = SignatureClass::default();
        assert!(matches!(s, SignatureClass::None));
        assert!(s.verifying_key_bytes().is_none());
        assert!(s.verifying_key_pqc_bytes().is_none());
        assert!(s.sign(b"anything").is_none());
        assert!(s.sign_hybrid(b"anything").is_none());
    }

    #[test]
    fn ed25519_from_secret_yields_verifying_key() {
        let s = SignatureClass::new_ed25519_from_secret([7u8; 32]);
        let vk = s.verifying_key_bytes().expect("Ed25519 has key");
        assert_eq!(vk.len(), 32);
        assert!(s.verifying_key_pqc_bytes().is_none());
    }

    #[test]
    fn ed25519_sign_is_deterministic() {
        // RFC 8032: same key + same body ⇒ same 64-byte signature.
        let s1 = SignatureClass::new_ed25519_from_secret([3u8; 32]);
        let s2 = SignatureClass::new_ed25519_from_secret([3u8; 32]);
        let body = b"the body bytes to sign";
        let sig1 = s1.sign(body).expect("ed25519 signs");
        let sig2 = s2.sign(body).expect("ed25519 signs");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn debug_redacts_signing_key() {
        let s = SignatureClass::new_ed25519_from_secret([42u8; 32]);
        let dbg = format!("{:?}", s);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("signing_key:") || dbg.contains("<redacted>"));
    }

    #[test]
    fn verifier_class_good_signature_validates() {
        // Sign + verify round-trip: same body, same key, signature validates.
        let sig_class = SignatureClass::new_ed25519_from_secret([29u8; 32]);
        let vk_bytes = sig_class.verifying_key_bytes().unwrap();
        let body = b"verifier round-trip body";
        let sig = sig_class.sign(body).expect("ed25519 signs");
        let verifier = VerifierClass::from_header_bytes(Some(&vk_bytes), None)
            .expect("valid Ed25519 vk parses");
        assert!(verifier.verify(body, &sig).is_ok());
    }

    #[test]
    fn verifier_class_wrong_length_signature_rejected() {
        // Distinct WrongLength variant: the centralized error type
        // separates length failures from content failures (the WAL
        // caller collapses both back to SignatureMismatch externally).
        let sig_class = SignatureClass::new_ed25519_from_secret([31u8; 32]);
        let vk_bytes = sig_class.verifying_key_bytes().unwrap();
        let verifier = VerifierClass::from_header_bytes(Some(&vk_bytes), None)
            .expect("valid Ed25519 vk parses");
        let too_short = [0u8; 63];
        assert!(matches!(
            verifier.verify(b"any body", &too_short),
            Err(SignatureVerifyError::WrongLength)
        ));
        let too_long = [0u8; 65];
        assert!(matches!(
            verifier.verify(b"any body", &too_long),
            Err(SignatureVerifyError::WrongLength)
        ));
    }

    #[test]
    fn verifier_class_wrong_sig_bytes_rejected() {
        // Correct length, wrong contents — ed25519_dalek verify fails.
        let sig_class = SignatureClass::new_ed25519_from_secret([37u8; 32]);
        let vk_bytes = sig_class.verifying_key_bytes().unwrap();
        let body = b"wrong-sig body";
        let mut sig = sig_class.sign(body).expect("ed25519 signs");
        sig[0] ^= 0xFF; // flip a byte to break the signature
        let verifier = VerifierClass::from_header_bytes(Some(&vk_bytes), None)
            .expect("valid Ed25519 vk parses");
        assert!(matches!(
            verifier.verify(body, &sig),
            Err(SignatureVerifyError::Mismatch)
        ));
    }

    // ---- PQC Hybrid (Ed25519 + ML-DSA 65) ----

    #[test]
    fn ml_dsa_65_software_signer_round_trip() {
        // Sign-then-verify positive path using SoftwareMlDsa65Signer +
        // SoftwareMlDsa65Verifier reconstructed from encoded bytes.
        let signer = SoftwareMlDsa65Signer::from_seed([11u8; 32]);
        let body = b"ml-dsa 65 round-trip body";
        let sig = signer.sign(body).expect("ml-dsa 65 signs");
        let vk_bytes = signer.verifying_key_bytes();
        let verifier = SoftwareMlDsa65Verifier::from_bytes(&vk_bytes).expect("vk bytes round-trip");
        assert!(verifier.verify(body, &sig).is_ok());
    }

    #[test]
    fn ml_dsa_65_signature_size_3309_bytes() {
        // NIST FIPS 204 ML-DSA 65 fixed signature size pin.
        let signer = SoftwareMlDsa65Signer::from_seed([13u8; 32]);
        let sig = signer.sign(b"size pin").expect("ml-dsa 65 signs");
        assert_eq!(sig.len(), 3309);
    }

    #[test]
    fn ml_dsa_65_verifying_key_size_1952_bytes() {
        // NIST FIPS 204 ML-DSA 65 fixed verifying-key size pin.
        let signer = SoftwareMlDsa65Signer::from_seed([17u8; 32]);
        let vk_bytes = signer.verifying_key_bytes();
        assert_eq!(vk_bytes.len(), 1952);
    }

    #[test]
    fn pqc_signer_trait_software_witness() {
        // Compile-time witness that SoftwareMlDsa65Signer satisfies the
        // PqcSigner sealed-trait bound. Trait-bound regression would
        // fail typeck.
        fn witness<T: PqcSigner>(_: &T) {}
        let signer = SoftwareMlDsa65Signer::from_seed([0u8; 32]);
        witness(&signer);
    }

    #[test]
    fn pqc_verifier_trait_software_witness() {
        // Compile-time witness that SoftwareMlDsa65Verifier satisfies
        // the PqcVerifier sealed-trait bound.
        fn witness<T: PqcVerifier>(_: &T) {}
        let signer = SoftwareMlDsa65Signer::from_seed([1u8; 32]);
        let verifier = SoftwareMlDsa65Verifier::from_bytes(&signer.verifying_key_bytes())
            .expect("vk bytes round-trip");
        witness(&verifier);
    }

    #[test]
    fn hybrid_signature_class_construct() {
        // Constructor smoke test — Hybrid variant constructs cleanly
        // with independent Ed25519 + ML-DSA 65 seeds.
        let s = SignatureClass::new_hybrid_from_secrets([23u8; 32], [29u8; 32]);
        assert!(matches!(s, SignatureClass::Hybrid { .. }));
        let vk_ed = s.verifying_key_bytes().expect("Hybrid has Ed25519 key");
        assert_eq!(vk_ed.len(), 32);
        let vk_pqc = s.verifying_key_pqc_bytes().expect("Hybrid has PQC key");
        assert_eq!(vk_pqc.len(), 1952);
        let body = b"hybrid construct body";
        let hyb = s.sign_hybrid(body).expect("hybrid signs");
        assert_eq!(hyb.ed25519.len(), 64);
        assert_eq!(hyb.pqc.len(), 3309);
    }
}

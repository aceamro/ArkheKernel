//! Signature pipeline benchmark — Ed25519 (Tier 2 classical) and
//! ML-DSA 65 (NIST FIPS 204) PQC sign / verify primitives.
//!
//! These are the same primitives the WAL signing path uses internally;
//! the Hybrid `SignatureClass` runs both in sequence (AND-mode verify).
//! Measuring the underlying primitives surfaces the post-quantum
//! migration cost that the kernel inherits.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::signature::{Keypair, Signer as PqcSigner, Verifier as PqcVerifier};
use ml_dsa::{KeyGen, MlDsa65, B32};

const MSG: &[u8] = b"ARKHE chain hash 32-byte tip || canonical record body";

fn ed25519_keypair() -> (SigningKey, VerifyingKey) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let vk = key.verifying_key();
    (key, vk)
}

fn mldsa65_signing_key() -> ml_dsa::SigningKey<MlDsa65> {
    let xi: B32 = [9u8; 32].into();
    MlDsa65::from_seed(&xi)
}

fn bench_ed25519_sign(c: &mut Criterion) {
    let (key, _) = ed25519_keypair();
    c.bench_function("ed25519_sign", |b| {
        b.iter(|| black_box(key.sign(black_box(MSG))));
    });
}

fn bench_ed25519_verify(c: &mut Criterion) {
    let (key, vk) = ed25519_keypair();
    let sig = key.sign(MSG);
    c.bench_function("ed25519_verify", |b| {
        b.iter(|| black_box(vk.verify(black_box(MSG), black_box(&sig)).is_ok()));
    });
}

fn bench_mldsa65_sign(c: &mut Criterion) {
    let sk = mldsa65_signing_key();
    c.bench_function("ml_dsa_65_sign", |b| {
        b.iter(|| {
            let sig: ml_dsa::Signature<MlDsa65> = sk.sign(black_box(MSG));
            black_box(sig)
        });
    });
}

fn bench_mldsa65_verify(c: &mut Criterion) {
    let sk = mldsa65_signing_key();
    let vk = sk.verifying_key();
    let sig: ml_dsa::Signature<MlDsa65> = sk.sign(MSG);
    c.bench_function("ml_dsa_65_verify", |b| {
        b.iter(|| black_box(vk.verify(black_box(MSG), black_box(&sig)).is_ok()));
    });
}

fn bench_hybrid_sign(c: &mut Criterion) {
    let (ed, _) = ed25519_keypair();
    let pqc = mldsa65_signing_key();
    c.bench_function("hybrid_sign_ed25519_plus_ml_dsa_65", |b| {
        b.iter(|| {
            let s1 = ed.sign(black_box(MSG));
            let s2: ml_dsa::Signature<MlDsa65> = pqc.sign(black_box(MSG));
            black_box((s1, s2))
        });
    });
}

fn bench_hybrid_verify_and_mode(c: &mut Criterion) {
    let (ed, ed_vk) = ed25519_keypair();
    let ed_sig = ed.sign(MSG);
    let pqc = mldsa65_signing_key();
    let pqc_vk = pqc.verifying_key();
    let pqc_sig: ml_dsa::Signature<MlDsa65> = pqc.sign(MSG);
    c.bench_function("hybrid_and_mode_verify", |b| {
        b.iter(|| {
            let ok_ed = ed_vk.verify(black_box(MSG), black_box(&ed_sig)).is_ok();
            let ok_pqc = pqc_vk.verify(black_box(MSG), black_box(&pqc_sig)).is_ok();
            black_box(ok_ed && ok_pqc)
        });
    });
}

criterion_group!(
    benches,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_mldsa65_sign,
    bench_mldsa65_verify,
    bench_hybrid_sign,
    bench_hybrid_verify_and_mode
);
criterion_main!(benches);

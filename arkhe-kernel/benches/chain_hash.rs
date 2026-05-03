//! BLAKE3-keyed WAL chain hash benchmark.
//!
//! Measures the per-record cost of the chain step: deriving the chain key
//! from the world seed under `DOMAIN_CTX`, then hashing the previous chain
//! tip concatenated with the postcard-canonical record body.
//!
//! The chain key derivation is a one-time cost per WAL; the per-record
//! `derive_key + Hasher::new_keyed + update + finalize` flow is what bounds
//! sustained throughput and is what this bench targets.

use arkhe_kernel::WalHeader;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_chain_step(c: &mut Criterion) {
    let world_seed = [0u8; 32];
    let chain_key = blake3::derive_key(
        std::str::from_utf8(WalHeader::DOMAIN_CTX).expect("DOMAIN_CTX is UTF-8"),
        &world_seed,
    );
    let prev_tip = [0u8; 32];
    // Synthetic 256-byte canonical record body (typical small action).
    let body = vec![0xABu8; 256];

    let mut group = c.benchmark_group("chain_hash");
    group.throughput(Throughput::Bytes(body.len() as u64 + prev_tip.len() as u64));
    group.bench_function("blake3_keyed_chain_step_256B", |b| {
        b.iter(|| {
            let mut h = blake3::Hasher::new_keyed(&chain_key);
            h.update(black_box(&prev_tip));
            h.update(black_box(&body));
            black_box(h.finalize());
        });
    });
    group.finish();
}

fn bench_derive_key(c: &mut Criterion) {
    let world_seed = [0u8; 32];
    let ctx = std::str::from_utf8(WalHeader::DOMAIN_CTX).expect("DOMAIN_CTX is UTF-8");
    c.bench_function("blake3_derive_chain_key", |b| {
        b.iter(|| {
            black_box(blake3::derive_key(black_box(ctx), black_box(&world_seed)));
        });
    });
}

criterion_group!(benches, bench_chain_step, bench_derive_key);
criterion_main!(benches);

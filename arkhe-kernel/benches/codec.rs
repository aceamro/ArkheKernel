//! Postcard canonical encode / decode benchmark.
//!
//! Every WAL record is postcard-canonical bytes; the encode cost bounds
//! the per-record persist-side throughput, and the decode cost bounds
//! replay throughput. This bench measures both directions on a synthetic
//! payload representative of a typical small action body.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct SamplePayload {
    instance: u64,
    tick: u64,
    type_code: u32,
    schema_version: u16,
    body: Vec<u8>,
}

fn sample() -> SamplePayload {
    SamplePayload {
        instance: 1,
        tick: 100,
        type_code: 1,
        schema_version: 1,
        body: vec![0xCDu8; 256],
    }
}

fn bench_encode(c: &mut Criterion) {
    let p = sample();
    let bytes = postcard::to_stdvec(&p).unwrap();
    let mut group = c.benchmark_group("codec");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("postcard_encode_256B_payload", |b| {
        b.iter(|| black_box(postcard::to_stdvec(black_box(&p)).unwrap()));
    });
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let p = sample();
    let bytes = postcard::to_stdvec(&p).unwrap();
    let mut group = c.benchmark_group("codec");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("postcard_decode_256B_payload", |b| {
        b.iter(|| {
            let _: SamplePayload = black_box(postcard::from_bytes(black_box(&bytes)).unwrap());
        });
    });
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);

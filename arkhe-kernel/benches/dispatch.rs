//! End-to-end action dispatch benchmark.
//!
//! Measures the full kernel step pipeline: action submission, dispatch,
//! effect application, and observer staging — exercising the same code
//! path that bit-identical replay reproduces.

use arkhe_kernel::abi::{CapabilityMask, EntityId, Principal, Tick, TypeCode};
use arkhe_kernel::state::{ActionCompute, ActionContext, InstanceConfig, Op};
use arkhe_kernel::{ArkheAction, Kernel};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 1, schema_version = 1)]
struct NoopAction;

impl ActionCompute for NoopAction {
    fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
        vec![Op::SpawnEntity {
            id: EntityId::new(1).unwrap(),
            owner: Principal::System,
        }]
    }
}

fn bench_submit_step(c: &mut Criterion) {
    c.bench_function("kernel_submit_then_step_one_action", |b| {
        b.iter_batched(
            || {
                let mut k = Kernel::new();
                k.register_action::<NoopAction>();
                let inst = k.create_instance(InstanceConfig::default());
                (k, inst)
            },
            |(mut k, inst)| {
                k.submit(
                    inst,
                    Principal::System,
                    None,
                    Tick(0),
                    TypeCode(1),
                    Vec::new(),
                )
                .unwrap();
                let report = k.step(Tick(0), CapabilityMask::SYSTEM);
                black_box(report);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_step_only(c: &mut Criterion) {
    // Pre-submit a queue of actions; bench measures the step pipeline alone.
    c.bench_function("kernel_step_with_100_pending_actions", |b| {
        b.iter_batched(
            || {
                let mut k = Kernel::new();
                k.register_action::<NoopAction>();
                let inst = k.create_instance(InstanceConfig::default());
                for i in 0..100u64 {
                    k.submit(
                        inst,
                        Principal::System,
                        None,
                        Tick(i),
                        TypeCode(1),
                        Vec::new(),
                    )
                    .unwrap();
                }
                k
            },
            |mut k| {
                for i in 0..100u64 {
                    let report = k.step(Tick(i), CapabilityMask::SYSTEM);
                    black_box(report);
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_submit_step, bench_step_only);
criterion_main!(benches);

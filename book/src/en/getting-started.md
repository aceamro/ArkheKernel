# Getting Started — 5-minute tutorial

This tutorial writes the smallest possible domain end to end. The same pattern applies
to any L1 application — BBS, games, lotteries, simulations, and so on.

## Prerequisites

- Rust **1.90+** (stable, 2021 edition).
- Add ArkheKernel as a workspace member or depend on it with
  `path = "../arkhe-kernel"`.

## Step 1 — Dependencies

`Cargo.toml`:

```toml
[package]
name = "dice-domain"
version = "0.1.0"
edition = "2021"

[dependencies]
arkhe-kernel = "0.10"
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["use-std"] }
bytes = "1"
```

## Step 2 — Define an Action

`src/main.rs`:

```rust
use arkhe_kernel::abi::{
    CapabilityMask, EntityId, Principal, Tick, TypeCode,
};
use arkhe_kernel::state::{ActionCompute, ActionContext, InstanceConfig, Op};
use arkhe_kernel::{ArkheAction, Kernel};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 7000, schema_version = 1)]
struct Greet {
    name: String,
}

impl ActionCompute for Greet {
    fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
        vec![Op::SpawnEntity {
            id: EntityId::new(1).unwrap(),
            owner: Principal::System,
        }]
    }
}
```

Key points:
- `#[derive(ArkheAction)]` — the macro generates `Sealed + ActionDeriv` automatically.
- `#[arkhe(type_code = N, schema_version = M)]` — both constants are required.
- `impl ActionCompute` — the single method you write. It **must be pure** (A11).

## Step 3 — Boot the Kernel and run

```rust
fn main() {
    let mut kernel = Kernel::new();
    kernel.register_action::<Greet>();

    let inst = kernel.create_instance(InstanceConfig::default());

    // Serialize the Action and submit it.
    use arkhe_kernel::state::Action;
    let action = Greet { name: "world".into() };
    let bytes = Action::canonical_bytes(&action);
    kernel
        .submit(inst, Principal::System, None, Tick(0), TypeCode(7000), bytes)
        .expect("submit ok");

    // step() performs dispatch + apply + WAL append (if attached) + observer drain.
    let report = kernel.step(Tick(0), CapabilityMask::SYSTEM);

    println!(
        "executed {} action(s), applied {} effect(s)",
        report.actions_executed, report.effects_applied
    );
}
```

`cargo run` output:

```text
executed 1 action(s), applied 1 effect(s)
```

## Step 4 — Verification (optional)

Attach a WAL and confirm determinism:

```rust
let mut k1 = Kernel::new_with_wal([42u8; 32], [0u8; 32]);
k1.register_action::<Greet>();
// ... (same submit + step sequence ...)
let tip1 = k1.wal_chain_tip().unwrap();

let mut k2 = Kernel::new_with_wal([42u8; 32], [0u8; 32]);
k2.register_action::<Greet>();
// ... (same submit + step sequence ...)
let tip2 = k2.wal_chain_tip().unwrap();

assert_eq!(tip1, tip2);  // bit-identical chain (A1)
```

The `examples/dice/` demo exercises the same pattern end to end, including replay:

```bash
cargo run -p dice-domain
# ✓ A1 D1-Total verified: WAL replay is bit-identical.
```

## Next steps

- **Axiom system**: [Invariants](architecture/invariants.md) — what is guaranteed and how.
- **L1 boundary contract**: [Domain Spec](architecture/domain-spec.md) — obligations that domain code must honor.
- **Threat model**: [Threat Model](architecture/threat-model.md) — adversary assumptions and defense analysis.
- **API docs**: `cargo doc --open -p arkhe-kernel` — full public rustdoc.

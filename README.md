# ArkheKernel

**Deterministic Rust microkernel with bit-identical replay and post-quantum sealed audit chains.**

[Changelog](CHANGELOG.md) · [License](#license)

Identical inputs produce bit-identical WAL bytes (BLAKE3-keyed chain) →
bit-identical state, byte-for-byte. Hybrid Ed25519 + ML-DSA 65 (NIST
FIPS 204, CNSA 2.0) is a first-class signing class — post-quantum
migration is built in, not bolted on.

## Quick start

Five-minute build, no formal-verification dependencies required:

```rust
use arkhe_kernel::abi::{CapabilityMask, EntityId, Principal, Tick, TypeCode};
use arkhe_kernel::state::{ActionCompute, ActionContext, InstanceConfig, Op};
use arkhe_kernel::{ArkheAction, Kernel};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 1, schema_version = 1)]
struct Hello;

impl ActionCompute for Hello {
    fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
        vec![Op::SpawnEntity {
            id: EntityId::new(1).unwrap(),
            owner: Principal::System,
        }]
    }
}

let mut kernel = Kernel::new();
kernel.register_action::<Hello>();
let inst = kernel.create_instance(InstanceConfig::default());
kernel.submit(inst, Principal::System, None, Tick(0), TypeCode(1), Vec::new()).unwrap();
let report = kernel.step(Tick(0), CapabilityMask::SYSTEM);
assert_eq!(report.actions_executed, 1);
assert_eq!(report.effects_applied, 1);
```

End-to-end deterministic-replay proof:

```bash
cargo run -p dice-domain
```

## Why ArkheKernel

- **Hybrid PQC baseline from day 1.** `SignatureClass` is `{None, Ed25519,
  Hybrid}` out of the box — no opt-in feature flag, no migration project.
  Hybrid mode dual-signs every WAL record (Ed25519 + ML-DSA 65, AND-mode
  verify) so audit chains stay verifiable through the post-quantum
  transition.
- **Byte-identical replay invariant.** Most event-sourcing systems
  guarantee state-equivalence under replay. ArkheKernel guarantees the
  serialized WAL bytes themselves match across runs, runtimes, and CPU
  architectures. The chain hash (BLAKE3-keyed over postcard-canonical
  records) is the public invariant.
- **Formal verification anchored.** TLA+ refinement modules cover chain
  hash determinism, state-machine refinement, replay invariance, and
  observer chain-non-affecting. Apalache typecheck is a CI gate, not a
  side project. A machine-readable axiom inventory pins every cited
  invariant to its implementation witness.

## Architecture

```text
+----------------------------------------+
|  persist  WAL chain, snapshots,        |  BLAKE3 keyed-hash, postcard
|           Hybrid PQC signatures        |  canonical bytes, replay
+------------------^---------------------+
                   |
+------------------+---------------------+
|  runtime  Kernel orchestrator,         |  step-stage commit-or-rollback,
|           observer pipeline,           |  Effect<Authorized,'i> phantom
|           InstanceView read API        |
+------------------^---------------------+
                   |
+------------------+---------------------+
|  state    Action / Component / Event   |  sealed traits, per-instance
|           types                        |  store, authorization phantoms
+------------------^---------------------+
                   |
+------------------+---------------------+
|  abi      EntityId / TypeCode /        |  identifiers, principals,
|           CapabilityMask / errors      |  capability bits
+----------------------------------------+
```

Single-direction DAG, `pub(crate)` cross-stratum edges only. The layer-DAG
CI gate catches reverse imports as a structural error before they become
a runtime bug.

## Determinism guarantees

- **A1 D1-Total** — bit-identical WAL records across runs given the same
  config + canonical input sequence + manifest digest.
- **A2 single-thread** — `Kernel: !Sync` via `PhantomData<Rc<()>>`. The
  kernel is provably single-threaded at the type level.
- **A12 panic-free** — every kernel-internal `Drop` is total; no
  reachable panic in production code paths.
- **A14 header pinning** — WAL header pins kernel semver, ABI version,
  postcard version, BLAKE3 version, world id, and manifest digest.
  Replay against an incompatible header is a structural error, not a
  silent bit-rot.

### Layer A — 8 catastrophic byte-identity invariants

A small set of byte-level guarantees where any change invalidates every
chain ever produced. Concrete examples:

- `DOMAIN_CTX` — the BLAKE3 chain key derivation literal is pinned via
  a `frozen-hex` regression test. Any edit to the literal breaks every
  pre-existing WAL chain.
- WAL postcard field order — the on-wire field layout is pinned; a
  reorder changes chain hash inputs.
- `#[derive(ArkheAction | ArkheComponent | ArkheEvent)]` byte-emission
  — derive macros pin the canonical-encoding byte sequence so a silent
  AST mutation, varint-behaviour shift, or field reorder is caught
  before it reaches the chain hash.

Escalating a Layer A invariant requires an 8-field audit-trail entry
in `formal/axiom-test-cite.toml` — date, commit hash, user consent,
rationale, literal diff, chain-invalidation status, verify-chain
reference, and spec anchor.

Full axiom catalog (A1–A24 + S1) → [`book/`](book/).

## Crypto stack (supply-chain reviewed)

| Crate            | Version       | Role                                              |
| :---             | :---          | :---                                              |
| `ed25519-dalek`  | 2.x           | RFC 8032 reference impl (Tier 2 classical sig)    |
| `ml-dsa`         | 0.1.0-rc.9    | NIST FIPS 204 ML-DSA 65 (Hybrid PQC sig)          |
| `blake3`         | 1.x           | Keyed hash for WAL chain domain separation        |
| `postcard`       | 1.x           | Canonical varint serde (deterministic encoding)   |

`#![forbid(unsafe_code)]`, no `async`, no `std::thread`, no `HashMap`
(only `BTreeMap` / `BTreeSet` for deterministic iteration).

## Crypto provider extensibility

Drop-in HSM / KMS providers without patching kernel code. The
`PqcSigner` and `PqcVerifier` traits are sealed — only same-crate impls
satisfy them — so the kernel stays sealed while the provider seam stays
open:

```rust
pub trait PqcSigner: private_seal::Sealed + Send + Sync {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, PqcSignError>;
    fn verifying_key_bytes(&self) -> Vec<u8>;
}
```

The current build ships a software-only ML-DSA 65 signer
(`SoftwareMlDsa65Signer`); HSM / KMS providers integrate by adding a
sealed-trait extension impl in the same crate without touching the
kernel surface.

## Formal verification

Optional path — required for contributors touching the formal layer,
not for first-time users.

- **5 verification tiers** — 25 invariants (24 axioms + S1) tagged as
  *machine-checked* (TLA+ + Kani, 9), *type-proven* (Rust types, 10),
  *type-adjacent* (sealed-trait shape pins, 4), *runtime-asserted*
  (observer first-panic eviction, 1), or *social-contract* (S1: clock
  monotonicity). See [`book/`](book/) for the full per-axiom
  breakdown.
- **TLA+ refinement** — four modules (`cr1` chain hash invariant,
  `cr2` state-machine refinement, `cr3` replay determinism, `cr4`
  observer capability confinement). Apalache typecheck on every push.
- **Kani harness suite** — 5 implementation-level proofs in the
  sibling ArkheForge repository (published alongside v0.13):
  `authorize`, `dispatch`, `replay`, `memory_bounds_check`, and
  `hybrid_and_mode` (PQC AND-mode verify).
- **Axiom-cite gate** — `formal/axiom-test-cite.toml` is a
  machine-readable inventory; CI verifies every cited TLA+ invariant
  name appears in its `tla_module` file and every cited impl test
  exists as `fn <name>` in some cited path. Catches inventory drift,
  not theorem soundness.
- **Process discipline** — an 8-category cosmetic-vs-semantic commit
  denylist guards security-critical, formal-artifact, timing-side-
  channel, and fuel-budget surfaces from drive-by edits. See
  [`developteamset.md`](developteamset.md).

## Performance

ArkheKernel ships three signing modes (`SignatureClass::{None, Ed25519,
Hybrid}`); throughput depends on the choice:

| Signing mode      | Throughput        | Use case                                |
| :---              |              ---: | :---                                    |
| `None`            | ~1M actions/sec   | Dev / test, deterministic replay only   |
| `Ed25519` (Tier 2)| ~35k actions/sec  | Production audit log, classical sigs    |
| `Hybrid` PQC      | ~1k actions/sec   | Long-term post-quantum audit chain      |

Numbers measured on Apple M3 Max, single-thread, via criterion (95%
confidence intervals, outlier detection, warm-up). Reproduce locally:

```bash
cargo bench -p arkhe-kernel
```

Per-primitive measurements live in [`arkhe-kernel/benches/`](arkhe-kernel/benches/)
(`chain_hash`, `signing`, `codec`, `dispatch`). HTML reports with full
distribution graphs land in `target/criterion/` after `cargo bench`.

These are honest performance disclosures, not audited industry
benchmarks — the bench code is the spec, and external readers
reproduce on their own hardware to verify.

## Stability

v0.13 — single fixed pre-public version. No version churn before
external publish; subsequent corrections land on the same v0.13 line.
Version 1.0 is intentionally never reached.

## Documentation

- Architecture book: [`book/`](book/) (`cd book && mdbook serve` for
  local preview)
- API reference: [docs.rs/arkhe-kernel](https://docs.rs/arkhe-kernel)
- Operator runbook: [`docs/runbook/`](docs/runbook/)
- Release keys + signing: [`docs/release-keys.md`](docs/release-keys.md)
- Build reproducibility: [`docs/build-reproducibility.md`](docs/build-reproducibility.md)

## License

Dual-licensed under either of:

- Apache License 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License, ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same dual-license
terms.

---
*Powered by ArkheKernel — bit-identical causality across virtual worlds.*

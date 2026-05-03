# Introduction

**ArkheKernel** is a **domain-neutral, deterministic microkernel** for virtual worlds.
It operates as a pure state machine — identical inputs always produce the same state and the same serialized bytes.
It uses no `async`, no `std::thread`, no `unsafe`, no `f32/f64`, and no `HashMap`/`HashSet`.

## Why it exists

A virtual world must **unfold according to a causal specification defined in advance**.
General-purpose operating systems (Linux and the like) abstract physical resources (CPU/RAM/Disk),
but they do not address deterministic state reproduction or quantitative control over
effect (Effect) propagation in virtual worlds. ArkheKernel fills that gap as a
**deterministic state-transition stack**.

| Aspect | General-purpose OS | ArkheKernel |
| --- | --- | --- |
| Direct target | Physical resources | State consistency (Logic Integrity) |
| Time model | Continuous flow (non-deterministic) | Discrete tick sequence |
| Isolation unit | Process / container | Causal effect quotas (Effect Quotas) |
| Reproducibility | Probabilistic | Bit-identical replay |

## Who it serves

- **MMO / multi-user simulation backend developers** — deterministic replay compresses the cost
  of debugging, load testing, and dispute resolution (tracing chaotic state).
- **Cryptographic games / verifiable execution environments** — the Ed25519 Tier 2 signature
  plus WAL chain lets external verifiers validate execution integrity without third-party trust.
- **Long-running virtual worlds** — the Snapshot + WAL split enables incremental backup and restore.

## Safety guarantees (summary)

| Axiom | Meaning | Verification tier |
| --- | --- | --- |
| A1 | Identical inputs ⇒ identical serialized bytes (bit-identical) | MACHINE-CHECKED |
| A2 | `Kernel: !Sync` (single-threaded) | TYPE-PROVEN |
| A4 | `#![forbid(unsafe_code)]` crate-wide | MACHINE-CHECKED |
| A11 | Purity of determinism-protocol functions | MACHINE-CHECKED |
| A12 | No Drop panics inside the kernel | MACHINE-CHECKED |
| A22 | Observer first-panic immediate eviction (R4-Q) | RUNTIME-ASSERTED |

The full set of 24 axioms is documented in [Invariants](architecture/invariants.md).

## Links

- **API docs (rustdoc)**: `cargo doc --open -p arkhe-kernel`
- **GitHub**: [aceamro/ArkheKernel](https://github.com/aceamro/ArkheKernel)
- **Example domains**: [`examples/dice/](https://github.com/aceamro/ArkheKernel/tree/main/examples/dice),
  [`domains/dice/`](https://github.com/aceamro/ArkheKernel/tree/main/domains/dice)

## Stability

**v0.13**. The project is finalized at v0.13; subsequent fixes remain under the v0.13 label.
**1.0 is intentionally never reached** — "no design is perfect; one only approaches it asymptotically"
is the operating principle.

## Upper layers (optional)

This L0 kernel is **usable standalone**. You can define your own `Action`/`Component` types
to build a custom domain.

An optional upper layer — **ArkheForge Runtime** (L1+L2) — is under development and promises to
absorb empirically-proven duplication. Runtime is a separate project, however; you are not required
to adopt Runtime in order to use this kernel.

- Runtime design spec: [ArkheForge Runtime Book](https://aceamro.github.io/ArkheKernel/runtime-book/en/) (separate mdBook)

Next step: [Getting Started](getting-started.md) — build your first domain in a 5-minute tutorial.

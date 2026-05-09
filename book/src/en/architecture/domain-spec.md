# Domain Spec — L1 boundary contract

This document is the interface specification for **developers working outside the kernel
(in domain space)**. It defines what you are free to do and what you must never break.

## Layer distinctions

| Layer | Responsibility | Example |
| --- | --- | --- |
| **L0 (Kernel)** | Mechanism — determinism, authorization, isolation | `arkhe-kernel` itself |
| **L1 (Runtime)** | Policy translation — translates domain rules into Op sequences | `examples/dice` |
| **L2 (Platform)** | Identity, network, multi-tenant routing | JWT verification → `Principal::External` construction |
| **L3 (Library)** | ECS modules (space, assets, matching engines, and so on) | quadtree component, order book |

**Dependency direction: L0 ← L1 ← L2 ← L3, one-way.** Upper layers may import lower layers,
but a lower layer must never be aware of an upper layer's existence.

## L1 core contract

### 1. Action / Component / Event are derive-only

```rust
use arkhe_kernel::{ArkheAction, ArkheComponent, ArkheEvent};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, ArkheAction)]
#[arkhe(type_code = 7000, schema_version = 1)]
struct Greet { name: String }

impl ActionCompute for Greet {
    fn compute(&self, ctx: &ActionContext) -> Vec<Op> { vec![] }
}

#[derive(Serialize, Deserialize, ArkheComponent)]
#[arkhe(type_code = 5001, schema_version = 1)]
struct Counter { value: u64 }

#[derive(Debug, Serialize, Deserialize, ArkheEvent)]
#[arkhe(type_code = 8001, schema_version = 1)]
struct Posted { author: u64 }
```

Manual `impl Component for ...` is forbidden — `_sealed::Sealed` is `#[doc(hidden)] pub`, but
it is not the canonical path and is audited by grep.

### 2. `compute()` bodies must be pure (A11)

APIs **forbidden** inside `Action::compute(&self, &ActionContext) -> Vec<Op>`:

| Forbidden API | Reason |
| --- | --- |
| `std::time::{Instant, SystemTime}::now` | Non-deterministic ambient state |
| `rand::*`, `thread_rng` | Non-deterministic source |
| `std::thread::*` | Violates the single-thread axiom (A2) |
| `std::env::*` | Process-global ambient state |
| `Mutex::lock`, `RwLock::*` (on non-staged state) | Hidden mutation surface |
| `HashMap` / `HashSet` / Hash* family | Non-deterministic iteration (A5) |
| External-crate `Ord` impls (non-`CanonicalOrd`) | Ordering drift between patch releases |
| `std::fs::*`, `std::net::*`, `std::process::*` | I/O — belongs to observers |

A `#[kernel_pure]` dylint that rejects the list above at compile time is a candidate hardening path.

### 3. Canonical value wrappers (reserved)

`String`, `f32`, `f64`, and `Vec<T>` (in canonical positions) are not `CanonicalEncode`. The
following wrappers are reserved for standardization:

| Wrapper | Purpose |
| --- | --- |
| `CanonicalStr` | NFC-normalized UTF-8. Mixed-form inputs are rejected |
| `CanonicalBytes` | Length-prefixed byte sequence |
| `CanonicalRational { num: i64, den: NonZeroU64 }` | Reduced fraction (gcd-normalized at construction) |
| `CanonicalDateTime` | Tick-since-origin |

The current release is satisfied by postcard + `serde::{Serialize, Deserialize}` alone.

### 4. SOCIAL-CONTRACT residual — `Clock::now()` monotonicity

`Clock::now() -> Tick` is **the one function adjacent to A11 that remains a social contract**
(S1). Implementer obligations:
1. `now()` is non-decreasing within a single kernel process.
2. It does not non-deterministically interpolate ambient sources (NTP, system-clock swing, etc.).
3. The kernel preserves forward progress using `max(observed, previous)` so a regressing clock
   cannot rewind logical time.

### 5. Pure-compute fairness (declared L2 axiom)

Purity of the `compute()` body is enforced, but **runtime termination** (preventing infinite
loops) cannot be enforced in the current release (the triangle of `#![forbid(unsafe_code)]` +
no-thread + no-async). An enclosed `loop {}` halts the kernel.

Enforcement options at the L2 layer:
1. Static analysis during code review (sufficient for first-party trusted domains)
2. `cargo-fuzz` corpus + body-bound checks
3. Future WASM sandbox + instruction counter (R4-J Subset-Rust checker)

## L2 interface (kernel invocation pattern)

- **Identity verification**: the platform verifies JWT/OAuth and then constructs
  `Principal::External(ExternalId)`. Pre-auth or anonymous traffic uses
  `Principal::Unauthenticated`. The kernel is unaware of complex authentication logic (A7).
- **Distributed IPC**: same-node traffic uses `SendSignal`. Remote-node traffic is forwarded
  by a platform observer through Redis/Kafka.
- **Process sharding**: the `InstanceId` ↔ physical-node IP mapping is a platform concern.
  Hot-swap uses `Kernel::snapshot()` + `Kernel::from_snapshot()`.

## L4 — inter-layer engagement rules

- **Access control**: L2 may read kernel events but must not arbitrarily modify them or break
  kernel integrity assumptions.
- **Dependency direction**: L0 is unaware of the existence of L1+.
- **ABI compliance**: every external request to the kernel goes through `Kernel::submit`.
  Direct memory access and raw pointer passing are strictly forbidden.
- **Isolation**: platform observer panics are caught by `catch_unwind` so the kernel stays up
  (R4-A).

## Domain authorship philosophy

> **"You should be able to build any virtual world without modifying the kernel."**

When adding a feature, ask first — **is it policy, or is it mechanism?** If it is policy, put
it in the domain. If it is mechanism, propose a new axiom for INVARIANTS / DECISIONS through
the DIP process.

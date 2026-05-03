# Threat Model — Adversary model

Operating principle: **as AI capability improves, any structural flaw can become exploitable.**
We assume adversary capability grows monotonically over the lifetime of the project.
SOCIAL-CONTRACT axioms collapse first; MACHINE-CHECKED axioms collapse only when there is a
bug in the Rust language or the compiler.

## Three adversaries

### Adversary A — AI-capable domain code (trusted today, suspect in the future)

The domain author is **currently an in-tree collaborator**, but future contributors or
LLM-assisted code generation may land code that passes review yet exploits a
SOCIAL-CONTRACT seam.

- **Tools available**: the full source, commit history, and INVARIANTS / DECISIONS.
- **Goals**: D1 violation (replay divergence), kernel-state exfiltration via covert channel,
  privilege escalation across instance boundaries.
- **L1 boundary defense**: A11 (`#[kernel_pure]` + sealed-derive), A19 (GhostCell brand),
  A8 (`Effect<Authorized, 'i>` typestate).
- **Residual surface**: the body of `Action::compute()` is SOCIAL-CONTRACT (Rust cannot forbid
  `std::time::Instant::now()` inside a trait impl body). A future WASM sandbox / Subset-Rust
  checker (R4-J) removes it.

### Adversary B — Observer code (capability-gated L2 sink)

An observer registered with the `OBSERVER_REGISTER` cap. It receives filtered KernelEvents.

- **Tools available**: every event matching `EventMask`; `panic!` to sever event delivery.
- **Goals**: exfiltrate kernel state through panic messages; DoS via repeated panics; observe
  events that depend on uncommitted state.
- **Defense**: A22 (first-panic eviction; payload-free `ObserverPanic`), A18 (post-fsync
  drain across every DurabilityClass).
- **Residual surface**: a 1-bit panic-vs-no-panic channel per event; observer side effects
  (file writes, network) are outside the kernel. A future capability-gated observer sandbox
  tightens this further.

### Adversary C — WAL offline attacker

An attacker with read/write access to the WAL file between kernel runs (a compromised storage
layer or a malicious operator).

- **Tools available**: arbitrary mutation of WAL bytes; renaming or swapping WAL files;
  replaying with a modified manifest.
- **Goals**: undetected tampering; cross-world WAL injection; type confusion through a
  re-registered TypeCode; chain replay against an incompatible kernel.
- **Defense**:
  - A13 — BLAKE3 keyed chain (domain-separation key derived from `world_id`).
  - A14 — WalHeader pin (library / ABI / world / manifest_digest).
  - A15 — TypeCode × schema_hash cross-restart pin set.
  - A16 — `SignatureClass::Ed25519` Tier 2 signing authenticates the chain head when enabled.
  - R4-G — WAL header `type_registry_pins` slot.
- **Residual surface**: `SignatureClass::None` (Tier 1) provides tamper evidence only via
  out-of-band anchor publication. If the attacker controls both the WAL and the anchor
  publication channel, a full WAL rewrite can escape detection. Enabling Tier 2 Ed25519
  provides genuine authentication.

## Attack scenarios and defenses

| Scenario | Attack | Defense | Residual |
| --- | --- | --- | --- |
| **R4-A** Observer covert channel | A malicious observer panics with a state-derived message; the payload leaks into the WAL | `ObserverPanic { observer_index: u16 }` — payload polymorphism removed | 1 bit per event; audited by R4-Q |
| **R4-B** IPC × authorize staging revoke-delay | A1 revokes P's cap; A2 (same step) sends a cross-instance signal using the stale cap | `σᵢ₋₁` snapshot — A2's auth observes A1's staged revoke; target re-auth rejects it | 0 (R4-B is the only form without a hole; every alternative leaks) |
| **R4-C** Tamper-evidence overclaim | "Cryptographic-grade" misreads as MAC; the chain is unkeyed → a rewrite goes undetected | Term renamed ("tamper-evident chained replay"); the `SignatureClass` enum forces the caller to name the tier | Tier 1 requires anchor discipline; misuse = false security |
| **R4-D** TypeCode cross-restart confusion | After restart, `TypeCode(0x4200)` is re-registered with a malicious schema_hash | The WAL header `type_registry_pins` enforces schema_hash equality | 0 |
| **R4-P** Parent-quota DoS | A parent admin reduces the quota below the sum of its children → policy-undefined → runaway destruction of children | `QuotaReductionPolicy::Reject` default — explicit `LifecycleError::QuotaReductionWouldViolateChildren`; admins opt into `Grandfather`/`ThrottleProportional` explicitly | Deterministic algorithm documented |
| **R4-Q** Observer panic DoS | A malicious observer panics on every event → DoS of the audit class | First-panic eviction; per-malicious-observer `ObserverPanic` + `ObserverEvicted` fire once each | Re-registration loops are possible (cooldown deferred); current mitigation = L2 rate-limits the `OBSERVER_REGISTER` cap |
| **R4-R** Drain-refcount indefinite hold | A module holds an inflight ref after registration and refuses to drop → kernel cannot unload | `Kernel::force_unload(route_id, ADMIN_UNLOAD)` is a cap-gated escape hatch; `KernelEvent::ModuleForceUnloaded { live_refs_at_unload }` is audited | `ADMIN_UNLOAD` cap distribution is an L2 policy (lifecycle deferred) |
| **R4-S** Domain error smuggle | Without an `ArkheError::Domain` variant, domains smuggle error info through `EmitEvent` → covert channel | The legitimate `Domain { code: u32, payload: Bytes }` path is provided | code/payload are kernel-opaque; protocols remain an L1/L2 responsibility |

## SOCIAL-CONTRACT residual — S1

`Clock::now()` monotonicity is documented as a social contract in
[Domain Spec §4](domain-spec.md). Current mitigation: emit
`KernelEvent::ClockAnomaly { previous_tick, observed_tick }` and preserve forward progress
with `max(observed, previous)`. A future typestate `impl Monotonic<Tick>` promotes this
residual away.

This is the **only** SOCIAL-CONTRACT residual. Every other A11 member is MACHINE-CHECKED via
R4-H sealed-derive + R4-T `#[kernel_pure]` dylint.

## Tier counts (summary)

| Tier | Count | Members |
| --- | --: | --- |
| MACHINE-CHECKED axioms | **9** | A1, A4, A5, A11, A12, A14, A15, A16, A17 |
| TYPE-PROVEN | **10** | A2, A3, A6, A7, A9, A10, A13, A19, A21, A23 |
| TYPE-ADJACENT | **4** | A8, A18, A20, A24 |
| RUNTIME-ASSERTED | **1** | A22 |
| SOCIAL-CONTRACT | **1** | S1 (Clock::now monotonicity) |

Subtotal: **25** (24 axioms + 1 social residual).

| Cross-cutting | Count | Members |
| --- | --: | --- |
| Machine-checked CI gates (separate from axioms) | **6** | R4-H sealed-derive proc-macro, R4-T `#[kernel_pure]` dylint, R4-W single-callsite lint, R4-X layer-DAG check, R3-H postcard-canonicality round-trip, R3-L `clippy::wildcard_enum_match_arm = deny` |
| External dependency (subset of MACHINE-CHECKED) | **2** | A17 postcard library (canonicalization correctness), A14 fsync OS semantics (durability) |

Growth in adversary capability erodes the lower three tiers (TYPE-ADJACENT,
RUNTIME-ASSERTED, SOCIAL-CONTRACT — six items) over time. Per-item promotion paths are
catalogued in the [Roadmap](../roadmap.md). CI gates and external dependencies erode only
through toolchain regressions, supply-chain compromise, or OS bugs — a distinct threat class.

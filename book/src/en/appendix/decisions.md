# Decisions — Core ADRs

This document condenses **twelve core design decisions** in ADR-lite form. Each entry follows
the same shape: problem → decision → rationale → rejected alternatives.

---

## Formalizing the A11 axiom

- **Problem**: Purity and determinism guarantees were scattered across comments and had no name.
- **Decision**: Adopt A11 — *"every function in the determinism protocol is pure in its declared
  inputs."* Members are listed in [INVARIANTS.md](../architecture/invariants.md) A11 and in
  [DOMAIN_SPEC](../architecture/domain-spec.md).
- **Rationale**: A single named axiom unifies grading and is auditable.
- **Rejected**: Per-function comments alone (rot); waiting for the R4-J checker to land (blocking).

## Removing `Event::to_json`

- **Problem**: If `Component`/`Action`/`Event` expose `to_json`, a second canonical format with no
  determinism role becomes obligatory.
- **Decision**: Remove it. Persistence uses `to_bytes` (postcard); debugging uses the `Debug` derive.
- **Rationale**: One canonical surface; sealed-derive audits a single byte path.
- **Rejected**: Keeping it as debug-only (trait surface bloat); coexisting with canonical-JSON under
  CI (two formats).

## `SCHEMA_VERSION` const + CI fingerprint

- **Problem**: Schema-version bumps relied on human discipline.
- **Decision**: Every type exposes a `SCHEMA_VERSION: u32`; CI computes the BLAKE3 fingerprint of
  the `(type_name, version, schema_hash)` triple; a fingerprint change without a version bump fails
  the PR.
- **Rationale**: RUNTIME-ASSERTED via CI — the strongest mechanism short of a formal proof.
- **Rejected**: Convention only (rot); runtime check (too late).

## Introducing the A12 totality axiom

- **Problem**: A11 covers only purity; rollback correctness also requires Drop totality (no panic
  during teardown).
- **Decision**: A12 — kernel-internal Drops carry the `no_panic` attribute (a reachable panic
  becomes a linker error).
- **Rationale**: Totality ≠ purity is a distinct axiom class; MACHINE-CHECKED for the kernel,
  SOCIAL-CONTRACT for domains.
- **Rejected**: `catch_unwind` around Drop (panic-swallowing hides bugs); Copy-only types
  (overly restrictive).

## R4-A — Observer panic payload covert channel

- **Problem**: If `PanicInfo.message: String` lives on `ObserverPanic`, the kernel leaks
  arbitrary bytes into the WAL/observer path.
- **Decision**: `ObserverPanic { observer_index: u16 }` only — payload-free. The legitimate
  control-flow side-channel is the existing `Result`-style return on `KernelObserver::on_event`.
- **Rationale**: Limits covert capacity; replaces covert reliance with an explicit channel.
- **Rejected**: Keeping `PanicInfo` (unbounded exfiltration); removing `catch_unwind` (one bug
  crashes the kernel); counter-only (hostile to debugging).

## R4-B — IPC × authorize staging snapshot ordering

- **Problem**: When an IPC is delivered, it is undefined which staged snapshot re-auth reads.
- **Decision**: `σᵢ₋₁` — action *i*'s auth observes the staged mutations of A1..Aᵢ₋₁; strict
  serializability.
- **Rationale**: The only option that preserves causality, avoids circular self-reference, and
  still reflects intra-step revokes.
- **Rejected**: `σ₀` (revoke-delay window); `σᵢ` (circular); `σ_n` (causality violation).

## R4-C — "Cryptographic-grade" terminology overclaim

- **Problem**: An unkeyed BLAKE3 chain is not a MAC, but the phrase "cryptographic-grade" implied
  authentication.
- **Decision**: Rename the term ("tamper-evident chained replay"). The `SignatureClass` enum forces
  the caller to name the tier explicitly.
- **Rationale**: The Tier 1 / 2 / 3 split aligns semantics with actual guarantees.
- **Rejected**: Keeping the term (false advertising); a single implementation without tiers (no
  room for the Ed25519 option).

## R4-N — 10-bucket StepStage commit-or-rollback

- **Problem**: Once a partial change is committed mid-`step()`, rollback is impossible.
- **Decision**: Buffer all ten commit-conditional write categories into `StepStage`; at commit,
  `apply_stage` drains them in the canonical R5-A1 order; rollback simply drops the stage.
- **Rationale**: Transactional semantics; axiomatized as A20.
- **Rejected**: Write-through (no rollback); per-op journal (more complexity).

## R4-Q — Observer first-panic eviction

- **Problem**: A malicious observer panics on every event → DoS.
- **Decision**: Evict on first panic. Emit
  `ObserverEvicted { observer_index, panic_at_seq, panic_count_before_eviction: 1 }`.
- **Rationale**: Per malicious observer, `ObserverPanic` + `ObserverEvicted` fire once each;
  re-registration requires the `OBSERVER_REGISTER` cap.
- **Rejected**: An N-panic budget (N is arbitrary whatever the choice); retry forever (DoS
  exposure).

## R4-X — Layer DAG one-way + cargo-modules CI gate

- **Problem**: Reverse imports like `state → runtime → persist` could sneak in unintentionally.
- **Decision**: A unidirectional four-stratum DAG. A `cargo-modules` + grep CI gate fails the
  build on any cycle before code review.
- **Rationale**: Structural pollution is rejected at compile time rather than at runtime.
- **Rejected**: Monolithic (test complexity grows); allowing cycles (invites design rot).

## Action decomposition + arkhe-macros

- **Problem**: A single `Action` trait lets domain authors override `canonical_bytes` /
  `from_bytes` / `approx_size`, breaking the MACHINE-CHECKED guarantee of A11.
- **Decision**: Split `Action` into `ActionDeriv` (consts + serde bounds) + `ActionCompute`
  (the compute fn), with a blanket `impl<T: ActionDeriv + ActionCompute> Action for T`.
  `#[derive(ArkheAction)]` emits only `Sealed + ActionDeriv`; the postcard default methods are
  supplied by the blanket impl, which cannot be overridden.
- **Rationale**: The blanket impl structurally seals the byte path — recovering MACHINE-CHECKED
  status for A11.
- **Rejected**: An attribute macro (excessive build cost); keeping manual impls (freezes the
  SOCIAL-CONTRACT).

## `SignatureClass::Ed25519` (A16 Tier 2)

- **Problem**: A16 declared a tier ladder, but only Tier 1 (chain only) had shipped.
- **Decision**: `persist/signature.rs` provides `SignatureClass { None, Ed25519 }`. The public
  key is pinned via `WalHeader.verifying_key`, and each record is signed via
  `WalRecord.signature` with RFC 8032. `Wal::verify_chain` checks hash first, then signature.
- **Rationale**: Header pinning keeps verification self-contained (no external key store
  required); the determinism of RFC 8032 preserves A1.
- **Rejected**: Per-record keys (key proliferation); an external key store (depends on
  out-of-band lookup).


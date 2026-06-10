# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — pre-public. The kernel epoch (minor version) advances
only when a release changes the persisted wire format; a v0.N-epoch WAL is
a distinct chain epoch that does not replay under another. Patch releases
(0.N.x) carry wire-format-neutral maintenance — dependency bumps, docs —
and hold the epoch. Version 1.0 is intentionally never reached.

## [0.14.2] — correctness hardening + step-loop optimization (wire-format-neutral)

Patch release. The persisted wire format and chain epoch are unchanged:
`WalHeader::CURRENT_KERNEL_SEMVER` `(0,14,0)`, `ABI_VERSION` `(0,14)`, and
the `DOMAIN_CTX` `v0.14` chain-separation literal all hold. No
`WalRecordBody`, header, or signature layout changed, so every 0.14-epoch
WAL replays bit-identically under 0.14.2. The fixes below alter behavior
only for inputs that were already incorrect (budget-bypassing Op sequences,
component writes to a nonexistent entity); honest histories are unaffected.

### Fixed — `memory_budget_bytes` enforcement (A21)

- **`Op::RemoveComponent` no longer poisons the budget projection.** The
  per-Op gate credited the caller-declared `size`, while the ledger frees
  only the component's *stored* size — so one phantom/oversized remove
  (e.g. `size: u64::MAX`) disabled the byte budget for the rest of the step.
  The projection now credits the ledger's stored size, never the untrusted
  caller value.
- **The projection is computed in saturating `u64`** (matching the ledger),
  replacing an `i64` round-trip. A `memory_budget_bytes` above `i64::MAX` no
  longer silently disables enforcement, and an oversized add saturates to
  `u64::MAX` rather than clamping under the gate.

### Fixed — state/ledger consistency and reporting

- **`SetComponent` on an unknown (never-spawned or despawned) entity is now
  a no-op**, mirroring the ledger's existing entity gate. Previously the
  component was stored without accounting, diverging `InstanceView` from the
  ledger and bypassing the byte budget across steps.
- **`StepReport.effects_applied` no longer counts rolled-back Ops.** On an
  authorize-deny rollback (`any_denied`) the count is now folded only on the
  commit path, so a discarded step reports zero applied effects.
- **`QuotaReductionPolicy::ThrottleProportional` no longer scales child
  quotas *up*.** A non-reducing request (`new_quota >= current_total`) now
  passes children through unchanged, matching the "scaled down" contract and
  the no-op posture of `Reject`/`GrandfatherExisting`.
- **`dispatch` increments `inflight_refs_delta` with `saturating_add`**, the
  last non-saturating arithmetic in the staged pipeline (A12 discipline).

### Security — secret scrubbing (defence-in-depth)

- **`SoftwareMlDsa65Signer::from_seed` now zeroizes the `xi` seed copy.**
  `let xi: B32 = seed.into()` produced a second in-memory copy of the 32-byte
  ML-DSA seed (`B32 = Array<u8, U32>` has no scrubbing `Drop`); only `seed`
  was scrubbed. Both transient copies are now wiped, matching the kernel's
  existing seed-scrub discipline. In-memory hygiene only — no serialized
  bytes, keys, or signatures change.

### Performance — `step()` per-instance walk + per-step staging

- `step()` destructures the kernel's fields once and iterates
  `instances.iter_mut()` directly, removing the per-step `Vec<InstanceId>`
  snapshot and the redundant `BTreeMap` re-lookups it existed to work
  around (O(n·log n) → O(n) in instance count). `BTreeMap::iter_mut` yields
  ascending `InstanceId` (A23), so WAL append order, state-mutation order,
  and observer delivery order are unchanged.
- The kernel reuses one `StepStage` scratch across actions (a private,
  non-serialized `step_scratch` field, `clear()`ed before each action)
  instead of allocating a fresh staging buffer every step. `apply_stage`
  now borrows the stage `&mut` and drains the buckets it commits (retaining
  capacity); the rollback path simply skips apply. `clear()` is exhaustive
  over all ten buckets (compile-checked via destructure), so the reused
  scratch is byte-for-byte equivalent to `StepStage::default()` — the
  frozen-hex chain-hash fixtures and the multi-record replay tests confirm
  WAL bytes are unchanged.
- Together these cut `kernel_step_with_100_pending_actions` ~16.9 µs → ~12.6 µs
  (~26%). Both wins are allocation/lookup reductions, invisible under
  Ed25519/Hybrid signing where the signing primitive (27 µs–924 µs) dominates.

## [0.14.1] — dependency maintenance (wire-format-neutral)

Patch release. The persisted wire format and chain epoch are unchanged:
`WalHeader::CURRENT_KERNEL_SEMVER` `(0,14,0)`, `ABI_VERSION` `(0,14)`, and
the `DOMAIN_CTX` `v0.14` chain-separation literal all hold, so every
0.14-epoch WAL replays bit-identically under 0.14.1. Package versions
advance to `0.14.1` (`arkhe-kernel`, `arkhe-macros`, `dice`) solely to ship
the maintenance below to crates.io.

### Dependencies

- `ml-dsa` `=0.1.0` → `=0.1.1` (RustCrypto). The sole upstream change is a
  Cargo feature-propagation fix (`module-lattice/alloc` is now forwarded
  when `alloc` is enabled); `module-lattice`'s lattice math and FIPS-204
  serialization carry no `alloc`-conditional branches, so ML-DSA
  signature/key bytes are UNCHANGED. Confirmed against the byte-shape size
  pins and the chain-hash fixtures.
- `bitflags` `2.11` → `2.13` (lockfile, within the existing `2.6` caret).
  `CapabilityMask`'s serde representation is unchanged; WAL determinism is
  preserved.
- `criterion` (dev-only) `0.5` → `0.8`. The benches migrate
  `criterion::black_box` → `std::hint::black_box` (criterion 0.8 deprecates
  its re-export). Not a published-crate dependency, so downstream MSRV is
  unaffected.
- `ed25519-dalek` held at `2.x` — `3.0` is a release candidate and is
  deliberately excluded (stable only).

## [0.14.0] — ml-dsa stabilization + audit remediation

New epoch. The kernel version advances because the persisted wire format
changed; v0.13-epoch WALs are a separate chain epoch and do not replay
under v0.14 (pre-public, forward-only). See `formal/axiom-test-cite.toml`
`item_1.escalation_event_2` + `item_7.escalation_event_2` for the Layer A
audit trail.

### Dependencies

- `ml-dsa` `=0.1.0-rc.9` → `=0.1.0` (NIST FIPS 204 final, first stable
  point release). API drift handled: the removed `KeyGen` trait → inherent
  `SigningKey::<MlDsa65>::from_seed`. ML-DSA signature/key bytes are
  UNCHANGED across the upgrade (deterministic FIPS-204 output).
- `zeroize` feature enabled on `ml-dsa` and `ed25519-dalek`; `zeroize`
  added as a direct dep — signing-key material and in-kernel seed copies
  are now scrubbed.

### Version epoch (all four axes → 0.14)

- Package versions `0.14.0` (`arkhe-kernel`, `arkhe-macros`, `dice`).
- `WalHeader::CURRENT_KERNEL_SEMVER` `(0,14,0)`, `ABI_VERSION` `(0,14)`.
- `DOMAIN_CTX` chain-separation literal → `v0.14` (new chain epoch).

### Security

- **Authenticated WAL verification** (closes a CRITICAL header-trust gap):
  `Wal::verify_chain_anchored` / `replay_into_verified` take a caller-
  supplied `TrustAnchor` (min tier + expected verifying key(s) + manifest
  digest + chain tip). Rejects signature **downgrade** (header stripped to
  `None`), verifying-key **substitution**, manifest mismatch, and **tail
  truncation**. The kernel supplies the mechanism; the caller owns the
  trust-root policy.
- Ed25519 verification now uses `verify_strict` (rejects malleable /
  non-canonical signatures).
- WAL-record signatures are domain-separated: a fixed context tag is bound
  into the signed message (`WAL_SIG_DOMAIN || body`, applied symmetrically
  on sign + verify), scoping a signature to the WAL-record domain so a key
  reused in another protocol cannot produce a cross-valid signature.
- Untrusted snapshots: `KernelSnapshot::deserialize_verified(bytes,
  &digest)` + structural validation (scheduler index consistency) on
  every decode — a corrupt/tampered snapshot is rejected up front.
- Replay A14 gate now also pins `postcard_version` / `blake3_version`.
- Per-instance quotas enforced: `max_entities`, `max_scheduled`, and
  `Kernel::submit` back-pressure (`ArkheError::QuotaExceeded`).

### Correctness

- `ResourceLedger` rebuilt around per-component sizes: replace-aware
  byte accounting (no double-count), despawn cascades component byte +
  type-count removal, remove uses the stored size, saturating throughout.
- Memory-budget projection hardened against `u64`→`i64` truncation (an
  oversized declared `size` can no longer wrap negative past the gate).
- `Scheduler` ID/seq increments saturating; replay preserves the exact
  recorded capability bits (`from_bits_retain`) for bit-identical chains.
- `WalRecord` carries the submitting `actor` (chain-hashed) so replay is
  bit-identical for modules that read `ctx.actor`.
- `ObserverHandle` widened to `u64` (monotonic, non-aliasing).

### Consistency

- Layer A catastrophic-invariant count reconciled to **7** across docs +
  `axiom-test-cite.toml` (`8` was renumber drift).
- `supply-chain/audits.toml`: dropped two orphan audits for crates not in
  this kernel's graph (`aes-gcm`, `chacha20poly1305`); `ml-dsa` audit note
  updated to `0.1.0` + feature-enabled zeroize. `deny.toml` documents the
  intentional dual RustCrypto trait-stack.

### Downstream re-verification

- The signed-message construction changed this release (the `actor` field
  is chain-hashed, and WAL-record signatures are now domain-separated), so
  the sibling ArkheForge `hybrid_and_mode` Kani harness should be re-run
  against v0.14 when ArkheForge upgrades. The AND-mode property is
  preserved by construction (both signatures cover the same domain-tagged
  message); this is a confirmation step, not a known gap.

## [0.13.0] — Initial release

ArkheKernel L0 deterministic microkernel — pure state machine with
bit-identical replay, post-quantum sealed audit chains, and formally
verified invariants.

### Workspace

Three crates:

- `arkhe-kernel` — L0 deterministic microkernel
- `arkhe-macros` — derive macros (`ArkheAction` / `ArkheComponent` / `ArkheEvent`)
- `examples/dice` — D1-Total bit-identical replay demo (`cargo run -p dice`)

### Determinism

- **A1 D1-Total** — bit-identical WAL records across runs given the
  same config + canonical input sequence + manifest digest.
- **A2 single-thread** — `Kernel: !Sync` via `PhantomData<Rc<()>>`,
  type-level enforcement.
- **A12 panic-free** — every kernel-internal `Drop` is total; no
  reachable panic in production code paths.
- **A14 header pinning** — WAL header pins kernel semver, ABI version,
  postcard version, BLAKE3 version, world id, and manifest digest.
- 4-stratum DAG: `abi` → `state` → `runtime` → `persist`. Cross-stratum
  edges are `pub(crate)` only; reverse-direction imports are caught by
  the layer-DAG CI gate.

### Layer A — 7 catastrophic byte-identity invariants

Byte-level guarantees where any change invalidates every chain ever
produced. Concrete examples include the `DOMAIN_CTX` BLAKE3 chain key
literal (frozen-hex regression test), the WAL postcard field order pin,
and the `#[derive(ArkheAction | ArkheComponent | ArkheEvent)]` byte
emission. Escalating a Layer A invariant requires an 8-field audit-trail
entry in `formal/axiom-test-cite.toml` (date, commit hash, user consent,
rationale, literal diff, chain-invalidation status, verify-chain
reference, spec anchor).

### Cryptography

- Hybrid Ed25519 + ML-DSA 65 signing (NIST FIPS 204, CNSA 2.0 transition
  spec) is a first-class signing class — `SignatureClass { None,
  Ed25519, Hybrid }`.
- Hybrid mode dual-signs every WAL record with AND-mode verify.
- BLAKE3-keyed chain hash over postcard-canonical records.
- Crypto provider extensibility via sealed `PqcSigner` / `PqcVerifier`
  traits — drop-in HSM / KMS providers without patching kernel code.
- Crypto stack (supply-chain reviewed): `ed25519-dalek` 2.x (RFC 8032),
  `ml-dsa` 0.1.0-rc.9 (NIST FIPS 204), `blake3` 1.x (keyed hash),
  `postcard` 1.x (canonical varint).

### Formal verification

- 25 invariants (24 axioms + S1) tagged across 5 enforcement tiers:
  machine-checked (TLA+ + Kani, 9), type-proven (Rust types, 10),
  type-adjacent (sealed-trait shape pins, 4), runtime-asserted
  (observer first-panic eviction, 1), social-contract (S1: clock
  monotonicity).
- TLA+ refinement modules — `cr1` chain hash invariant, `cr2`
  state-machine refinement, `cr3` replay determinism, `cr4` observer
  capability confinement, `r4_implementation_refinement` layer-DAG
  enforcement — sharing the `runtime_core` base module.
- Apalache typecheck CI gate runs on every push.
- Implementation-level Kani harness suite lives in the sibling
  [`ArkheForge`](https://github.com/aceamro/ArkheForge) repository
  (`authorize`, `dispatch`, `replay`, `memory_bounds_check`,
  `hybrid_and_mode`).
- Machine-readable axiom inventory (`formal/axiom-test-cite.toml`) +
  CI gate (`scripts/verify-axiom-cite.sh`) catches inventory drift.

### Engineering discipline

- `#![forbid(unsafe_code)]` across the entire crate.
- No `async`, no `std::thread`, no `HashMap` / `HashSet` (only
  `BTreeMap` / `BTreeSet` for deterministic iteration), no
  floating-point in canonical paths.
- L0 baseline SHA-256 protection (7 DO-NOT-TOUCH items) +
  `scripts/verify-l0-baseline.sh` CI gate.
- Linux x86_64 binary reproducibility (`SOURCE_DATE_EPOCH` +
  `--remap-path-prefix` + `--locked`) via
  `scripts/reproduce-build.sh`.
- Supply-chain governance — `cargo-deny` + `cargo-vet` (advisory).

### Documentation

- Architecture book — [`book/`](book/) (mdBook).
- API reference — [docs.rs/arkhe-kernel](https://docs.rs/arkhe-kernel).
- Operator runbook — [`docs/runbook/`](docs/runbook/).

### Sibling repository

[ArkheForge](https://github.com/aceamro/ArkheForge) ships the L1+L2
runtime substrate (action dispatch, hook host, observer pipeline,
KMS-tier crypto, sandbox safeguards) on top of this kernel.

### Licensing

Dual-licensed under Apache-2.0 OR MIT.

# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — pre-public. The kernel version advances only when a
release changes the persisted wire format; cosmetic fixes keep the
version. Version 1.0 is intentionally never reached.

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

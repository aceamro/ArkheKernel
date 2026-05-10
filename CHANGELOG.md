# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Versioning scheme — v0.13 is a single fixed pre-public version.
Subsequent corrections land on the same v0.13 line. Version 1.0 is
intentionally never reached.

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

### Layer A — 8 catastrophic byte-identity invariants

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
- L0 baseline SHA-256 protection (8 DO-NOT-TOUCH items) +
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

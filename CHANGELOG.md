# Changelog

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.0.0/) 를 따른다. Versioning scheme — v0.11 최종 완결, 이후 수정사항이 생겨도 v0.11 을 유지한다.

## [0.11.0] — 2026-04-25

ArkheKernel (L0 kernel) + ArkheForge Runtime (L1 primitives + L2 services) 초기 public release.

### Naming + structure

- **Crate rename**: L0 kernel crate is `arkhe-kernel` (folder `arkhe-kernel/`, Rust path `arkhe_kernel`). The previous in-development name `arkhe-source-kernel` / `ArkheSourceKernel` is retired before any external publish — no downstream impact, no semver-break.
- **Brand**: `ArkheKernel` (was `ArkheSourceKernel`). All committed docs / READMEs / book content reference the new brand; `tmp/dip-archive/` and git history preserve the prior name as historical record.
- **Examples relocation**: `domains/dice/` → `examples/dice/`; the legacy greeter placeholder is dropped (the dice example fully exercises the L0 Action / Op / Event surface plus the deterministic-replay axiom).

### Core

- L0 deterministic microkernel — `abi` / `state` / `runtime` / `persist` 4-strata 단방향 DAG, bit-identical WAL replay, invariant-lifetime shell brand.
- Core 5 primitives — User / Actor<'s, S> / Space / Entry / Activity (ActivityPub 하이브리드).
- 3-band determinism — Core (L0 bit-identical) / Projection (eventually consistent) / Protocol-Correctness (shell-level).
- Extension axes — Component / TypeCode / Subtype / New-Primitive gate. Runtime core 수정 없이 확장.
- Axiom catalog — L0 A1-A24 + S1 (`arkhe-kernel`), Runtime E1-E13 + 30 per-primitive invariant (`arkhe-forge-core` / `arkhe-forge-platform`).
- Sealed derive — `#[derive(ArkheAction | ArkheComponent | ArkheEvent)]` (`arkhe-macros`).

### Axiom enforcement

43 Runtime invariants are declared in spec §11.5; this release ships them at three enforcement tiers:

- **Compute-level machine-checked** — runtime rejection paths backed by an integration test under `arkhe-forge-core/tests/axioms_*.rs`. Covers depth caps (E-space-4), self-loop bans (E-act-5), the GDPR-erasure actor gate (E-user-3 C3 — `ActionContext::ensure_actor_eligible` rejecting `SubmitActivity` / `CreateSpace` with `ActionError::UserErasurePending`), the `EntityShellId` reassign gate (E-act-7 — `staged_read::<EntityShellId>` + `ActionError::EntityShellIdReassign`), the actor-handle uniqueness gate (E-actor-3 — `ActionContext::actor_by_handle` + `ActionError::ActorHandleCollision`), and the cascade-completion handshake (E-user-3 partial).
- **Type-system proven** — sealed traits, invariant-lifetime `ShellBrand<'s>`, `TypeCode` constants, and the derive-emitted `SCHEMA_VERSION` layout pin make violations impossible to express. Includes E-user-1 / E-user-2, the brand axioms, and the Action / Component / Event sealing.
- **Shape-only** — the wire `TYPE_CODE` and `SCHEMA_VERSION` are pinned, but the matching compute-level machine-checked path lands in a future release. Covers E5, E-actor-1 / -5, E-space-1 / -2 / -5 / -7, E-entry-2..-4 / -6 / -7, and E-act-1 / -4. Each test file's module rustdoc enumerates the shape-only entries and the future-release path.

### Security

- WAL chain — `blake3::keyed(chain_key, prev_hash ‖ canonical_body)` + `SignatureClass { None, Ed25519 }` Tier 1 / Tier 2.
- Crypto-erasure — HSM-generated DEK + envelope encryption + tombstone semantics (XChaCha20-Poly1305 default, AEAD AAD 19B).
- Compliance tier 3-level — Tier-0 software-kek (dev) / Tier-1 KMS free-tier / Tier-2 production Multi-KMS + threshold HSM (t-of-n Shamir).
- Post-quantum migration path — `RuntimeSignatureClass { None, Ed25519, MlDsa65, Hybrid }` + runtime_max gate.
- Process protection — `trait ProcessProtection` (Linux `mlock_all` + `PR_SET_DUMPABLE` + ptrace / macOS `PT_DENY_ATTACH` / Windows `SetProcessMitigationPolicy`).
- Multi-region 2PC atomic shred — per-region `PerRegionErasureProgress` event + restore refuse.
- HF2 Auto Promote Trust Model — multi-channel health check (DoH / alternate region / static-IP) + threshold HSM.

### Operations

- Prometheus SLO metrics + alert policy table + Alertmanager inhibit rule.
- Active-passive L2 single-active model + SLO suspension 규약.
- Binary reproducibility — same machine Linux x86_64, `SOURCE_DATE_EPOCH` + `--remap-path-prefix` + `--locked`.
- Supply chain security — `cargo-audit` + `cargo-deny` + `cargo-vet` + Sigstore keyless cosign release 서명 (dice 바이너리 + 7 crate tarball, release tag CI job `release-sign`).
- L0 baseline CI gate — `arkhe-kernel/src/**/*.rs` SHA-256 hash list + DO NOT TOUCH 8건 invariance.
- Layer independence CI — `cargo-depgraph` 가 Runtime crate → Shell crate 의존 금지 enforce.

### Documentation

- L0 kernel book — `book/` (mdBook, 한국어).
- Runtime book — `runtime-book/` (mdBook, 한국어).
- Rustdoc — `cargo doc --no-deps --workspace`, `RUSTDOCFLAGS=-D warnings`.
- Operator runbook + Shell 저자 guide + 법률 근거 (`docs/`).

### Examples

- `examples/dice` — L0 deterministic 3D6 roll (A1 D1-Total bit-identical replay 증명).

### Licensing

- Dual license — MIT OR Apache-2.0.

### Known limitations

- Band 3 protocol-correctness = shell-level (core scope 거부, §1.2).
- Real-time tick-synchronized state (MMORPG / FPS) = Runtime scope 밖, 별 game-kernel overlay.
- Cross-platform binary reproducibility = stretch goal, 현 scope 는 Linux x86_64 same-machine.
- Federation content pull = 향후 확장 후보.
- `arkhe-forge-platform::observer` — skeleton surface only; the L0 `OBSERVER_REGISTER` bridge that turns kernel events into projection dispatches is reserved for the next release.
- `arkhe-forge-platform::verifier` — skeleton surface only; direct WAL chain-tip re-verification (HF3 fail-close path) and the Sigstore Rekor inclusion-proof check land alongside the verifier wiring in the next release.
- `arkhe-forge-platform::hf2_kms::journal` — in-memory `ConsumedTokenJournal` is the dev impl; production deployments plug a chain-signed persistent backend that satisfies the `PersistentJournal` trait.
- `arkhe-forge-platform::projection::evaluate_auto_promote` — `threshold_hsm` policy honours the `threshold_ready` boolean parameter, but the share-collection workflow that actually flips it lives outside the runtime in this release.

### Spec drift candidates for next round

Four implementation-ahead drifts surface for the next spec patch round
(`docs/spec-drift-candidates.md`). None affect the wire
contract / axioms / user surface — all are wire-equivalent or
spec-incomplete:

- AES-GCM invocation field — `replica_id: u32` shape (federation-ready).
- BLAKE3 domain `arkhe-runtime-doctor-journal-chain` (chain hash for `runtime_doctor_journal`).
- `UserSalt` typed anchor (Zeroize + non-Clone, single-owner-per-fetch).
- `TIER0_DEV_DIGEST_V0_11` manifest-digest regression sentinel (toml crate stability invariant).

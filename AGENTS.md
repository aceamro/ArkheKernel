# AGENTS.md — ArkheKernel

> **What this is:** an orientation map for AI agents (and new humans) working in this repo.
> It is the entry point: read it before reading code, and **read §3 before editing anything**.
> **🇰🇷 한 줄:** AI 에이전트용 길잡이 — 코드보다 이 파일을 먼저, **수정 전엔 반드시 §3 먼저** 읽으세요.

ArkheKernel is a **deterministic Rust microkernel**: identical inputs always produce
identical state *and* identical persisted bytes (a BLAKE3-keyed Write-Ahead-Log chain),
verifiable across runs, machines, and CPU architectures, with a built-in post-quantum
(Hybrid Ed25519 + ML-DSA 65) signing path.

This file is **navigation metadata only** — it lives outside the kernel source on purpose
(see §3: touching kernel source is gated). It does not change any behavior.

---

## 0. How to use this file (agent prime directive)

> **🇰🇷 한 줄:** 길 찾기는 §4, 수정 금지선은 §3, 커밋 전엔 §6 — 이 순서가 안전합니다.

1. **Orient** — read §1 (what it is) and §2 (the layer DAG mental model).
2. **Locate** — use §4 (file → role map) to find where a thing lives. Don't grep blindly.
3. **Before editing** — read §3 (DO NOT TOUCH). Most of this kernel is byte-frozen; an
   innocent edit (even adding a comment to an L0 file) breaks a CI gate or invalidates
   every audit chain ever produced.
4. **Understand the flow** — §5 traces one action from submission to verified replay.
5. **Before committing** — run the §6 gate checklist. CI runs the same gates.
6. **Stuck on a word?** — §7 is a glossary of ~60 project terms.

**Hard rules for any change:** no `unsafe` (`#![forbid(unsafe_code)]`), no `async`, no
`std::thread`, no floating-point in canonical paths, no `HashMap`/`HashSet`
(only `BTreeMap`/`BTreeSet`, for deterministic iteration). These four disciplines are
*why* replay is bit-identical — they are not stylistic preferences.

---

## 1. What ArkheKernel is

> **🇰🇷 한 줄:** 결정론적 상태기계 — 같은 입력 → 같은 상태 + **같은 바이트** WAL, PQC 봉인 감사체인.

- **Pure state machine.** `Kernel::step()` applies scheduled actions; given the same config
  + canonical input sequence + manifest digest, the serialized WAL bytes are identical
  (axiom **A1 / D1-Total**).
- **Tamper-evident chain.** Each WAL record's hash is
  `blake3::keyed(chain_key, prev_hash ‖ postcard(body))`. A single-byte tamper is caught by
  chain verification.
- **Post-quantum from day one.** `SignatureClass` is `{None, Ed25519, Hybrid}`. Hybrid
  dual-signs every record (Ed25519 + ML-DSA 65, **AND-mode** verify).
- **Trust-anchored verification.** A caller supplies a `TrustAnchor` (min signature tier,
  pinned verifying keys, expected chain tip) — rejecting downgrade, key substitution, and
  tail truncation. The kernel supplies the mechanism; the caller owns the policy.
- **Single crate, four strata** (`arkhe-kernel`) + one proc-macro crate (`arkhe-macros`).
  ~9,000 lines of Rust across 31 source files.

---

## 2. Layer DAG & mental model

> **🇰🇷 한 줄:** `abi → state → runtime → persist` 단방향 DAG. 역방향 import = 빌드 실패(R4-X).

```text
abi  ───►  state  ───►  runtime  ───►  persist
  │          │            │              │
  └─── unidirectional, pub(crate) edges only. No back-edges. ───┘
```

| Stratum | Responsibility | Core types |
| --- | --- | --- |
| **abi** | identifiers, principals, capability bits, error taxonomy | `EntityId`, `InstanceId`, `Tick`, `TypeCode`, `RouteId`, `Principal`, `CapabilityMask`, `ArkheError` |
| **state** | sealed domain traits, per-instance state, authorization phantoms | `Action`/`Component`/`Event`, `Op`, `Effect<'i, S>`, `InstanceConfig`, `ActionContext`, `Scheduler`, `ResourceLedger` |
| **runtime** | orchestrator, commit-or-rollback step, observer pipeline, read view | `Kernel`, `StepReport`, `Stats`, `KernelObserver`, `EventMask`, `InstanceView` |
| **persist** | WAL chain, snapshot, Ed25519/Hybrid signing, replay | `Wal`, `WalHeader`, `WalRecord`, `SignatureClass`, `KernelSnapshot`, `replay_into` |

The DAG is enforced **structurally** by Rust's `pub(crate)` module boundaries and the
**R4-X** layer-DAG CI gate. A reverse import (e.g. `state` importing `runtime`) does not
compile — that is why `apply_stage`/`discard_stage` live in `runtime/apply.rs`, not on
`Instance` in `state/`.

---

## 3. ⛔ DO NOT TOUCH — editing hazards (READ BEFORE ANY EDIT)

> **🇰🇷 한 줄:** L0 소스는 SHA-256으로 봉인됨 — 주석 한 줄도 게이트를 깨고, byte-identity 표면은 모든 과거 체인을 무효화합니다.

This kernel is mostly **frozen at the byte level**. The hazards below are not advice; they
are gates that fail your build or, worse, silently invalidate existing audit chains.

### 3.1 L0 baseline seal (the broadest gate)

All **32 L0 source files** (the 31 under `arkhe-kernel/src/` — including `lib.rs` — plus
`arkhe-macros/src/lib.rs`) are pinned by SHA-256 in `ci/l0-baseline-hashes.txt`. **Any**
modification — including adding a doc comment or reformatting — changes a hash and fails
`scripts/verify-l0-baseline.sh`.

→ This is precisely **why orientation lives in this AGENTS.md, not in code comments.**
Changing L0 requires a formal escalation: an L0-specific change proposal (`l0-dip` label) +
auditor approval + a baseline-regeneration PR. Do not edit L0 to "improve readability."

### 3.2 Byte-identity surfaces (changing these invalidates every chain ever produced)

| Surface | Location | Why it is frozen |
| --- | --- | --- |
| `DOMAIN_CTX` literal (54 bytes) | `persist/wal.rs:85` | feeds `blake3::derive_key(DOMAIN_CTX, world_id)`; any byte change rederives every chain key (Layer A item 1) |
| `WalRecordBody` 10-field order | `persist/wal.rs:146-159` | postcard wire layout feeds both chain hash and signature; reorder/insert breaks A1 (Layer A item 7) |
| `WAL_SIG_DOMAIN` literal (47 bytes) | `persist/signature.rs:247` | domain-separation prefix on every signature |
| Header version pins | `persist/wal.rs:71-75` | `CURRENT_KERNEL_SEMVER`, `ABI_VERSION=(0,14)`, `POSTCARD_MAJOR=1`, `BLAKE3_MAJOR=1`; replay rejects mismatch (A14) |
| Derive byte-emission | `arkhe-macros/src/lib.rs:129-192` | `#[derive(ArkheAction/Component/Event)]` pins canonical encoding via `TYPE_CODE`/`SCHEMA_VERSION` |
| `Tick::advance` (saturating) | `abi/ids.rs:71-73` | switching to wrapping changes tick sequences post-restart |
| `CapabilityMask` reserved bits 0–3 | `abi/caps.rs:21-33` | SYSTEM / ADMIN_UNLOAD / OBSERVER_REGISTER / INTROSPECT are fixed; repurposing is forbidden |
| `EventMask` bit allocation | `runtime/event.rs:140-173` | observer filter compatibility (Layer A item 6) |
| `StepStage` 10-bucket order + derives | `runtime/stage.rs:1-17, 119-133` | cloned for WAL; `bytes_delta()` must clamp to `i64::MAX` to stop budget-bypass overflow |

**Frozen-hex regression tests** in `persist/wal.rs` (lines ~1018–1246) pin BLAKE3 hashes of
the above. If you change a frozen surface, these tests fail loudly — that is the design.

### 3.3 Sealed traits (the universe of impls is intentionally finite)

- `Action` / `Component` / `Event` — sealed via `state::traits::_sealed::Sealed`
  (`state/traits.rs`). The **only** sanctioned impl path is the derive macro; manual impls
  are contract violations. `Action` is a blanket `impl<T: ActionDeriv + ActionCompute>`.
- `AuthState` (`Unverified`/`Authorized`) — sealed in `state/authz.rs:38-40`. `authorize()`
  is the **sole** constructor of `Effect<'i, Authorized>`; fields are `pub(crate)`.
- `PqcSigner` / `PqcVerifier` — sealed in `persist/signature.rs:32-36`. The seam is open for
  HSM/KMS providers (same-crate sealed-extension impls) while the kernel stays sealed.

### 3.4 Type-level invariants you can break by accident

- **`Kernel: !Sync`** (`runtime/kernel.rs:35-41`) via `PhantomData<Rc<()>>` — single-thread
  is proven at the type level (A2). Do not add `Send`/`Sync` to make something compile.
- **GhostCell brand** — `InvariantLifetime = PhantomData<fn(&'i ()) -> &'i ()>`
  (`state/authz.rs:20`, `state/scope.rs:20`) prevents reusing an `Effect` across instances
  at compile time (A19).
- **No panic (A12)** — every kernel-internal `Drop` is total; canonical paths use saturating
  arithmetic and `if let` guards, never `unwrap`/`expect`/`panic` (the few `expect!`s mark
  "impossible" invariant violations, e.g. `scheduler.rs:170`).
- **Determinism** — iterate `BTreeMap`/`BTreeSet` only; replay preserves recorded
  `caps_bits` via `CapabilityMask::from_bits_retain` (`persist/replay.rs:159`) — never
  truncate to kernel-known bits.

### 3.5 Layer A & escalation

There are **7 catastrophic byte-identity invariants** ("Layer A") inventoried in
`formal/axiom-test-cite.toml`. Escalating one is a one-time, audited event requiring an
**8-field record** (date, commit hash, consent, rationale, literal diff, chain-invalidation
status, verify-chain reference, spec anchor). A new format = a new **epoch**; old-epoch WALs
are not replayable under a new-epoch kernel.

---

## 4. File → role map (31 kernel files + the macros crate)

> **🇰🇷 한 줄:** "X가 어디 있나" — grep 전에 이 표. 각 파일 한 줄 역할.

### crate root
| File | Role |
| --- | --- |
| `arkhe-kernel/src/lib.rs` | crate root: `#![forbid(unsafe_code)]`, module docs, the layered-DAG diagram, re-exports, and the quick-start doctest |

### abi/ — protocol surface (no deps on other strata)
| File | Role |
| --- | --- |
| `abi/mod.rs` | re-export hub for the ABI stratum |
| `abi/ids.rs` | identifier newtypes: `InstanceId`/`EntityId` (`NonZeroU64`), `Tick`, `TypeCode`, `RouteId` |
| `abi/principal.rs` | `Principal` enum: `Unauthenticated` / `External(ExternalId)` / `System` |
| `abi/caps.rs` | `CapabilityMask` — 64-bit, kernel reserves bits 0–3, 60 free for L2 |
| `abi/error.rs` | `ArkheError` taxonomy (`InstanceNotFound`, `CapabilityDenied`, `QuotaExceeded`, `Domain`) |

### state/ — sealed traits, per-instance state, authorization
| File | Role |
| --- | --- |
| `state/mod.rs` | re-export hub |
| `state/traits.rs` | sealed `Component` / `ActionDeriv` / `ActionCompute` / `Action` / `Event` |
| `state/op.rs` | `Op` enum — kernel-level effect intents (Spawn/Despawn/SetComponent/EmitEvent/Schedule/Signal) |
| `state/context.rs` | `ActionContext` — read-only instance view passed to `compute()` |
| `state/instance.rs` | `Instance` — per-instance state container (entities, components, scheduler, ledger) |
| `state/ledger.rs` | `ResourceLedger` — the single accounting authority (entity/byte/type counts) (A21) |
| `state/authz.rs` | `Effect<'i, S>` phantom typestate + `authorize()` gate + `DenyReason` |
| `state/quota.rs` | `QuotaReductionPolicy` + `apply_quota_reduction` (Reject / Grandfather / ThrottleProportional) |
| `state/scheduler.rs` | `Scheduler` — three BTreeMaps (ready/by_id/by_actor) in lockstep; `validate()` checks bijection |
| `state/scope.rs` | `InstanceScope<'i>` — invariant-lifetime brand (GhostCell) |
| `state/config.rs` | `InstanceConfig` — caller-supplied caps/quotas/memory budget/parent |

### runtime/ — orchestrator, step pipeline, observers, read view
| File | Role |
| --- | --- |
| `runtime/mod.rs` | re-export hub |
| `runtime/kernel.rs` | `Kernel` orchestrator: constructors, `submit`, `step` (commit-or-rollback), `force_unload`, `snapshot` |
| `runtime/dispatch.rs` | `dispatch()` — translate an authorized `Effect` into `StepStage` deltas (no `Instance` mutation) |
| `runtime/apply.rs` | `apply_stage` / `discard_stage` — commit (10 buckets, strict order) or rollback |
| `runtime/stage.rs` | `StepStage` — 10-bucket transactional staging buffer (COW) |
| `runtime/event.rs` | `KernelEvent` enum + `EventMask` bitflags + `ObserverHandle` |
| `runtime/observer.rs` | `KernelObserver` trait + panic-resilient registry (first-panic eviction, A22) |
| `runtime/registry.rs` | `ActionRegistry` — `TypeCode` → deserializer fn-pointer table |
| `runtime/view.rs` | `InstanceView<'a>` — read-only borrowed projection (no write methods) |

### persist/ — WAL chain, signing, snapshot, replay (byte-identity epicenter)
| File | Role |
| --- | --- |
| `persist/mod.rs` | re-export hub |
| `persist/wal.rs` | `Wal`/`WalHeader`/`WalRecord`/`WalWriter`, BLAKE3 chain, `verify_chain`/`verify_chain_anchored`, `TrustAnchor` |
| `persist/signature.rs` | `SignatureClass` {None/Ed25519/Hybrid}, `SoftwareMlDsa65Signer/Verifier`, AND-mode verify |
| `persist/snapshot.rs` | `KernelSnapshot` — postcard point-in-time state, `deserialize_verified` (BLAKE3 digest gate) |
| `persist/replay.rs` | `replay_into` / `replay_into_verified` — header gating + chain verify + bit-identical reconstruction |

### arkhe-macros/ (separate crate, L0)
| File | Role |
| --- | --- |
| `arkhe-macros/src/lib.rs` | `#[derive(ArkheAction/ArkheComponent/ArkheEvent)]` + `#[arkhe(type_code, schema_version)]` |

---

## 5. Action lifecycle (submit → verified replay)

> **🇰🇷 한 줄:** 액션 하나가 제출→스케줄→인가→예산검사→스테이지 적용→WAL 체인해시·서명→검증/리플레이까지 18단계.

| # | Step | Where |
| --- | --- | --- |
| 1 | `Kernel::submit(...)` validates instance + `max_scheduled` quota, enqueues into scheduler | `kernel.rs:285-317` |
| 2 | `Kernel::step(now, caps)` pops one due action per instance, **ascending `InstanceId`** (A23) | `kernel.rs:321-333` |
| 3 | look up `TypeCode` in `ActionRegistry`, deserialize action bytes | `kernel.rs:336-344` |
| 4 | build `ActionContext` (actor, tick, instance) | `kernel.rs:346-348` |
| 5 | `action.compute_dyn(&ctx)` → `Vec<Op>` (pure, deterministic) | `kernel.rs:348` |
| 6 | wrap each `Op` in `Effect<Unverified>`, call `authorize(caps, eff)` | `kernel.rs:356-363` |
| 7 | enforce memory budget (per-Op projection) | `kernel.rs:365-393` |
| 8 | enforce entity quota (per-Op) | `kernel.rs:394-412` |
| 9 | enforce scheduled-action quota (per-Op) | `kernel.rs:413-430` |
| 10 | `dispatch(authorized_effect, &mut stage, ...)` → `StepStage` deltas | `kernel.rs:431` |
| 11 | if any **capability** deny → `discard_stage` (full rollback), next instance | `kernel.rs:441-445` |
| 12 | if WAL attached, clone stage for the WAL snapshot | `kernel.rs:459-464` |
| 13 | `apply_stage` commits 10 buckets in canonical order | `kernel.rs:474-475` |
| 14 | `wal.append(...)`: build `WalRecordBody`, postcard-encode, `blake3::keyed` chain hash, optionally sign | `wal.rs:299-359` |
| 15 | deliver staged `KernelEvent`s to observers (panic → evict) | `kernel.rs:491-506` |
| 16 | (caller) `verify_chain(world_id)` re-derives key, recomputes every hash, verifies signatures | `wal.rs:412-472` |
| 17 | (caller) `replay_into(&mut fresh_kernel, &wal)` re-submits & re-steps each record | `replay.rs:150-186` |
| 18 | assert `report.final_chain_tip == original.chain_tip()` → **A1 bit-identical proof** | `replay.rs:184` |

> **Authorize-deny vs budget-deny:** a capability denial rolls back the *whole* stage; a
> per-Op budget/quota denial *skips that one Op* (emits `EffectFailed`) without rollback.

Run the end-to-end proof: `cargo run -p dice` (prints `✓ A1 D1-Total verified`).

---

## 6. ✅ Verify before you commit

> **🇰🇷 한 줄:** CI가 돌리는 5게이트를 로컬에서 그대로 — `scripts/pre-publish-verify.sh` 하나로 전부.

CI enforces five gates in this order (mirrored by `scripts/pre-publish-verify.sh`):

```bash
# 1/5  tests (baseline: 241 default / 241 all-features — drift fails CI)
cargo test --workspace --all-features --no-fail-fast

# 2/5  lints (deny all warnings)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 3/5  L0 baseline seal (fails if any L0 source byte changed)
scripts/verify-l0-baseline.sh

# 4/5  axiom-cite: every cited TLA+ INV + impl test exists
scripts/verify-axiom-cite.sh

# 5/5  TLA+ typecheck (CI is authoritative; skipped locally if apalache-mc absent)
apalache-mc typecheck formal/tla-plus/*.tla

# …or just run all five at once:
scripts/pre-publish-verify.sh
```

If gate 3 fails because you *intentionally* changed L0, stop — that needs the §3.5
escalation, not a baseline bump. `ci/scripts-baseline-hashes.txt` also pins the verify
scripts themselves against tampering. Dependency policy is in `deny.toml` (crates.io only,
license allowlist, CVE deny).

---

## 7. Glossary (~60 terms)

> **🇰🇷 한 줄:** 모르는 용어가 막히는 1순위 원인 — 한 줄 정의 모음.

**Layers & structure**
- **L0** — the kernel foundation: `arkhe-kernel/src/**` + `arkhe-macros/src/lib.rs`; baseline-sealed, lint-exempt.
- **Layer DAG (R4-X)** — `abi → state → runtime → persist`, unidirectional; reverse imports don't compile.
- **Layer A** — the 7 catastrophic byte-identity invariants; editing one needs an 8-field escalation record.
- **Stratum** — one of the four layers above.
- **Mechanism vs policy** — kernel enforces isolation (mechanism); L2 maps capabilities to roles (policy).

**Identity & ABI**
- **InstanceId / EntityId** — `NonZeroU64` handles (an instance namespace / a per-instance entity).
- **Tick** — deterministic logical clock; starts at `Tick::ZERO`, advances by saturating add.
- **TypeCode** — stable `u32` dispatch id bound to a schema, assigned at registration.
- **RouteId** — interned `u32` for action routes (string-free internal dispatch).
- **ExternalId** — opaque L2-supplied identity the kernel does not interpret.
- **Principal** — caller authority: `Unauthenticated` / `External` / `System`.
- **CapabilityMask** — 64-bit permission bits; bits 0–3 kernel-reserved (SYSTEM, ADMIN_UNLOAD, OBSERVER_REGISTER, INTROSPECT).
- **Sentinel** — a reserved "absent" value; `NonZeroU64` makes `0` unrepresentable to avoid sentinels.

**State & authorization**
- **Sealed trait** — a trait only crate-internal/derive code may implement (`_sealed::Sealed` super-trait).
- **ActionDeriv** — macro-emitted half of `Action` (carries `TYPE_CODE`/`SCHEMA_VERSION`).
- **ActionCompute** — user-written half: `compute(&ctx) -> Vec<Op>`, must be pure (A11).
- **Op** — a kernel effect intent (SpawnEntity, SetComponent, ScheduleAction, EmitEvent, SendSignal…).
- **Effect<'i, S>** — an `Op` branded with instance + principal + an `AuthState` tag.
- **AuthState** — sealed typestate tag: `Unverified` or `Authorized`.
- **authorize()** — the *sole* gate producing `Effect<Authorized>`; the single audited permission check.
- **DenyReason** — why authorization failed (CapabilityDenied / InstanceMismatch / OperationRestricted / NotImplemented).
- **GhostCell brand** — invariant-lifetime phantom preventing cross-instance `Effect` reuse at compile time (ICFP 2021).
- **InstanceScope<'i>** — the branded handle carrying that lifetime.
- **ResourceLedger** — single source of truth for entity/byte/type accounting (A21).
- **Scheduler three-table lockstep** — ready/by_id/by_actor BTreeMaps kept in sync; `validate()` checks the bijection.
- **QuotaReductionPolicy** — how a parent quota cut below child usage is handled (Reject / GrandfatherExisting / ThrottleProportional).
- **EntityMeta** — per-entity metadata (owner principal at spawn + created tick).
- **InstanceConfig** — caller config: capabilities, quotas, memory budget, parent, reduction policy.

**Runtime**
- **Kernel** — the `!Sync` single-thread orchestrator.
- **StepStage** — 10-bucket transactional buffer; committed by `apply_stage` or dropped on rollback.
- **dispatch** — turns an authorized `Effect` into `StepStage` deltas (no direct `Instance` mutation).
- **Commit-or-rollback** — capability deny → full rollback; budget/quota deny → per-Op skip.
- **KernelObserver / first-panic eviction (A22)** — observers receive events; a panicking observer is caught and evicted permanently.
- **EventMask** — bitflag filter, one bit per `KernelEvent` variant.
- **ObserverHandle** — monotonic registration ticket (never reused).
- **InstanceView** — read-only borrowed projection of an `Instance`.
- **A23 deterministic order** — per-tick instances are processed in ascending `InstanceId`.

**Persist & crypto**
- **WAL (Write-Ahead Log)** — the chain-linked record store enabling durability + replay.
- **DOMAIN_CTX** — frozen 54-byte literal feeding `blake3::derive_key` to make the per-world chain key.
- **WalRecordBody** — the 10-field struct that is postcard-encoded for *both* chain hashing and signing.
- **BLAKE3-keyed chain** — `hash = blake3::keyed(chain_key, prev_hash ‖ postcard(body))`.
- **Postcard canonical encoding** — deterministic varint serde; field order must stay stable.
- **SignatureClass / VerifierClass** — write-side / read-side signing config: None / Ed25519 / Hybrid.
- **Hybrid signing** — Ed25519 (64 B) + ML-DSA 65 (3309 B) over the same domain-separated body.
- **ML-DSA 65** — NIST FIPS 204 PQC; 1952-byte verifying key, 3309-byte signature.
- **AND-mode verification** — Hybrid requires *both* signatures to pass.
- **WAL_SIG_DOMAIN** — 47-byte prefix scoping signatures to the WAL-record domain.
- **TrustAnchor** — caller-supplied policy (min tier, pinned keys, manifest digest, expected chain tip) for `verify_chain_anchored`.
- **verify_strict** — RFC 8032 strict Ed25519 path (rejects non-canonical / small-order).
- **Tail-truncation detection** — `expected_chain_tip` check defeating chain-consistent prefix attacks.
- **Key-substitution prevention** — pinned verifying keys must match the header's.
- **KernelSnapshot** — opaque point-in-time state; `deserialize_verified` gates on a BLAKE3 digest.
- **Frozen-hex regression test** — pins a BLAKE3 hash of a constant so silent edits fail the test.

**Determinism, formal & process**
- **A1 / D1-Total** — bit-identical WAL bytes across runs given the same config + canonical inputs + manifest digest.
- **Manifest digest** — keyed hash of the runtime manifest, pinned in the WAL header (A14) to detect schema drift.
- **Epoch** — a distinct chain identity created when a Layer A escalation changes the wire format; old epochs are not cross-replayable.
- **Escalation event** — the audited, one-time 8-field record permitting a Layer A change.
- **Axiom-cite** — machine-checked 1:1 link between an axiom, its TLA+ INV/lemma, and a Rust witness test.
- **Verification tiers** — MACHINE-CHECKED / TYPE-PROVEN / TYPE-ADJACENT / RUNTIME-ASSERTED / SOCIAL-CONTRACT.
- **Tier 0 / 1 / 2** — signing strength: none / chain-only (BLAKE3, tamper-evident) / Ed25519 cryptographic.
- **L0 DO-NOT-TOUCH** — the baseline-hash boundary forbidding L0 edits without escalation.

---

## 8. Where else to look

> **🇰🇷 한 줄:** 더 깊이 — README(개요), book/(공리·위협모델), docs/(정책·런북), docs.rs(API).

- `README.md` — project overview, quick start, performance, crypto stack.
- `book/` — the architecture book (axioms A1–A24 + S1, threat model, domain spec, decisions). `cd book && mdbook serve`.
- `docs/` — policy & ops: `msrv-policy.md`, `ABI-versioning.md`, `sealing-pattern-lineage.md`, `axiom-test-cite-guide.md`, `pqc-software-only.md`, `build-reproducibility.md`, `runbook/`.
- `formal/` — `axiom-test-cite.toml` (axiom inventory) + `tla-plus/` (refinement modules).
- API reference — <https://docs.rs/arkhe-kernel>.
- `arkhe-macros/README.md` — derive-macro usage for L1 domains.

> ArkheForge (the L1+L2 runtime that depends on this kernel) is a **separate repo** with its
> own `AGENTS.md`. The Shell layer (e.g. BBS) is yet another separate repo. Layer
> independence is a hard directive — this kernel never depends upward.

# ArkheForge Runtime — Implementation Plan

**Spec status** — entered implementation after the four-person cold-read
absorbed Major 3 (§5 two-stage freeze / §17 scale-aware SLA / §14 crypto
primitives + KMS integration milestone split + crypto surface enumeration)
plus selected minor spec clarifications, classification corrections, and
§5 wording adjustments inherited from internal review. 14 entry
checkpoints were added at the same time. The spec body itself remained
unchanged.

**Shell split** (2026-04-24): the BBS repo split is **complete** —
`arkhe-shell-bbs` lives in a separate repository. References to BBS in
this plan (§1 workspace / §15 shell example / alpha-blocker §BBS telnet
TLS / Exit criteria) reflect the "BBS lives in another repo" reality.
No structural change — wording / row ownership only.

**Role**: this is a planning document — a navigation aid for translating
the spec (`runtime-book/src/architecture/runtime-spec.md`, 3,182 lines,
frozen) into code. Implementation agents consult it when deciding
**what to build and which constraints to honour**. It is not the spec —
spec edits go through an emergency patch round or a future-extension DIP.

**Format convention**: every item carries the **decision + rationale +
how-to-verify** triple.

---

## Foreword — spec → code translation principles

The spec DIP froze on design convergence. The implementation DIP is a
spec-to-code translation — design re-discovery (iteration) is forbidden.
When drift surfaces, route it via §11 Spec drift policy.

**L0 boundary**: ArkheKernel v0.11 is tagged with 205/205 tests passing.
The current release window holds L0 at zero edits (§10 L0-frozen
inheritance). If a change becomes necessary, split it into a separate
L0 DIP immediately.

**Layer independence (2026-04-24 directive, emphasised)**: dependencies
are one-way — L0 ← Runtime ← Shell. A Runtime crate must never depend
on a shell crate (§2 CI gate). Each layer must be independently usable —
a third party should be able to take just L0 and build a different
domain on top.

**Completeness over speed**: prefer completeness to development pace.
The spec DIP's 8 rounds + the closing patch trace this principle —
implementation follows the same line.

---

## 11 durable user directives (catalogued from session state, applied throughout)

1. **Completeness first** — choose the more complete approach over the
   faster one (emphasised twice).
2. **Layer independence** — L0 ↔ Runtime ↔ Shell one-way deps; each
   layer independently usable.
3. **"Validated repetition only"** — refuse speculative abstraction. No
   Room / Session / MMORPG primitive in this release (§15.5 spec
   roadmap).
4. **Linus kernel discipline** — stability / no regressions /
   mechanism-not-policy / structural over convenient.
5. **"Later releases must not destabilise earlier ones"** —
   `#[non_exhaustive]` / trait defaults / optional fields / append-only
   schemas / public API freeze.
6. **AI-capable future-adversary threat model** — cryptographer focus,
   PQC migration ready.
7. **Six-month-future-reader baseline** — no useless comments or
   placeholders.
8. **Korean responses, English identifiers / code**.
9. **Versioning**: 0.11 → 0.12 → … → 0.99 → 0.100 (integer increments,
   1.0 is intentionally never reached).
10. **Leader proactivity** — the user cannot decide everything; the
    leader recommends what the user might overlook.
11. **Terse reporting** — no detailed mid-agent summaries, only final
    synthesis + decision points.

---

## Six-phase decomposition

Implementation runs sequentially. Phase N+1 cannot start until Phase N
completes — each phase has a review gate enforcing the dependency.

| Phase | Scope | Main gate | Dependency |
|-------|-------|-----------|------------|
| **1 — Infrastructure** | Workspace + CI gate + test-harness skeleton + axiom-harness skeleton | `cargo build` green, CI gate installed, ready to spawn the Core primitives milestone | — |
| **2 — Core 5 + Band 1** | User / Actor / Space / Entry / Activity impl + `ActionContext` + `ArkheComponent` / `ArkheAction` derive + L1 compute pipeline | E1-E11 + the 30 per-primitive (E-user / actor / space / entry / act) harnesses green, L0 integration tests pass | Infrastructure milestone |
| **3 — L2 skeleton** | Projection observer + manifest loader + idempotency dedup (PG UNIQUE INDEX, L1 WAL-scan stub) | L2 projection-writer tick-atomic test green, manifest strict-parse test green | Core primitives milestone |
| **4 — BBS dogfood (overlap with the L2 services milestone allowed)** | BBS Core 5 usage + telnet-over-TLS adapter + 1 board + 1 chat room + nicknames + post passwords | BBS write/read happy-path E2E green, Runtime polish feedback applied | L2 services milestone (skeleton complete; can predate L2 completion) |
| **5 — L2 complete** | Crypto-erasure + KMS integration + HF1 platform abstraction + HF4 credential rotation + HF2 threshold HSM + multi-region 2PC + E12 `RuntimeBootstrap` + E13 `SignatureClassPolicy` emission | E12 / E13 + cryptographer review green, Tier-1 KMS free-tier connection verified | Shell-dogfood milestone (can run in parallel with BBS dogfood) |
| **6 — Freeze → Alpha** | Public API freeze → pre-freeze 4-person review → BBS complete → 6 alpha-blocker docs merged → release-gate pass → `current-release alpha` tag | All 9 §13 release criteria pass | L2-complete milestone |

**Parallel paths**: the shell-dogfood milestone (BBS) starts as soon as
the L2-skeleton stage of the L2-services milestone is finished —
Runtime Band 1 + L2 skeleton is enough for a minimal BBS. The
L2-completion stage of the L2-services milestone overlaps with BBS
dogfood (crypto-erasure can land up to the alpha cut).

**Strict serial paths**: the L2-services milestone cannot start without
the Core primitives milestone (L1 primitives feed L2 projections).
Release-freeze cannot start without the L2-complete milestone (KMS /
PQC / multi-region interfaces are part of the public API).

---

## Entry checkpoint (14 items, new)

At the start of the Infrastructure milestone the implementation agent
**commits each item as its own PR + reviewer approval**. All 14 must
land before the Core-primitives milestone may begin. PR → designated
reviewer approval → merge — three steps.

| # | Item | Owner / reviewer | Deliverable |
|---|------|------------------|-------------|
| 1 | **`arkhe-runtime-testkit` crate + custom Arbitrary + shrinker** | implementer / theorist | `crates/arkhe-runtime-testkit/` — proptest `Arbitrary` impls (shell_id / TypeCode / Action / Component) + shrinker (auto-minimises regression cases). |
| 2 | **`test-corpus/` policy + CI fixed seed** | implementer / theorist | `test-corpus/README.md` — convention for storing regression cases (filenames / git LFS or inline / fixed CI seed). |
| 3 | **`arkhe-trait-default-check` custom lint** | implementer / theorist | Custom dylint — detects semantic changes to `#[derive(ArkheComponent)]` / `ArkheAction` / `ArkheEvent` default-method bodies (the breaking-change rule for default-method body semantics). |
| 4 | **`ci/l0-baseline-hashes.txt` + L0-tag commit** | implementer / auditor | SHA-256 list for `arkhe-kernel/src/**/*.rs` at the L0 v0.11 tag. Baseline for the §10 L0-frozen CI gate. |
| 5 | **`cargo-vet` trust-base config** | implementer / cryptographer | `supply-chain/config.toml` — trusted crate authors + audit delegation. After `cargo vet init`, add the major trust bases (rust-lang / dtolnay / BurntSushi …). |
| 6 | **`runtime_doctor_journal` signing key + HW storage** | implementer / cryptographer | Generate Ed25519 key pair + store on a **hardware security key** (YubiKey / NitroKey). Pin the public key in `docs/release-keys.md`. Document private-key custodians (≥ 2-person co-custody). |
| 7 | **`trait ProcessProtection` Linux / macOS / Windows skeleton** | implementer / cryptographer | `crates/arkhe-forge-platform/src/process_protection/{linux,macos,windows}.rs` — Linux `mlockall()` + `prctl(PR_SET_DUMPABLE, 0)` + ptrace protection / macOS `PT_DENY_ATTACH` + `VM_MAKE_NOMAP` / Windows `SetProcessMitigationPolicy` + `DebugSetProcessKillOnExit`. Skeleton stage (full impl by L2-complete). HF1 carryover from §15.5. |
| 8 | **HF2 library PoC (health check + Shamir threshold)** | implementer / cryptographer | `crates/arkhe-forge-platform/src/hf2_kms/` — multi-channel health check (DoH / alternate region / static IP) PoC + `shamir-secret-sharing` integration (`t = 2 of 3` authorisation token). Kept until KMS-integration milestone closes. |
| 9 | **AEAD AAD 19-byte composition + DEK rotation metric skeleton** | implementer / cryptographer | `crates/arkhe-forge-core/src/pii.rs` — `compute_aad(dek_id, pii_code, aead_kind) -> [u8; 19]` helper + `arkhe_runtime_dek_message_count` counter skeleton. Filled in during the crypto-primitives milestone. |
| 10 | **Binary reproducibility scope (same machine Linux x86_64)** | implementer / veteran | `scripts/reproduce-build.sh` + `docs/build-reproducibility.md` — defines scope (same machine, same toolchain, same `CARGO_TARGET_DIR`, Linux x86_64 primary). Cross-machine / cross-platform reproducibility is a future-extension stretch. |
| 11 | **Docs workload distribution (6 alpha-blocker docs × phase mapping)** | implementer / veteran | `docs/alpha-release-schedule.md` — owners / deadlines / phases for the 6 docs. Workstream that runs parallel to Runtime implementation. |
| 12 | **Single-active L2 SLO suspension policy** | implementer / veteran | `docs/runbook/l2-single-active-operations.md` — convention for temporarily suspending the SLO (p99 projection_lag) during active-passive failover; pin the alert-policy lockout window. |
| 13 | **`gdpr-crypto-erasure.md` external legal review — 8-week buffer** | implementer / veteran + legal | Lock `docs/Legal/gdpr-crypto-erasure.md` draft completion + 8-week external legal-review window. Milestone fixed at pre-freeze. |
| 14 | **Future-extension MSRV bump policy** | implementer / theorist | `docs/msrv-policy.md` — re-confirm MSRV 1.80+ pin + future bump conditions (upstream toolchain security patch / crate ecosystem dependence …) + obligation to assess major-version impact at bump time. |

**Completion criterion**: all 14 must land via **PR merge + reviewer
approval** before the Core-primitives milestone is allowed to begin. If
anything is missing, team-lead blocks the milestone start. Each PR
references the matching Item / Owner / Deliverable columns in its
commit message (trace-back).


**Rationale**: the Infrastructure milestone is the "before-coding"
stage. Without the CI gates / test harness / process-protection
skeleton, the Core-primitives milestone keeps churning back to fill
infrastructure gaps. Gating on these 14 entry checkpoints lets later
phases focus on implementation.

---

# 19 detailed items

## Structure (§1 – §4)

### §1. Crate split + cargo workspace

**Decision**: a **3-crate Runtime** workspace + separate-repo shells.

```
[workspace]
members = [
    "arkhe-forge-core",         # L1 primitives (User/Actor/Space/Entry/Activity + derive)
    "arkhe-forge-platform",     # L2 services (projection / manifest / crypto-erasure)
    "arkhe-forge",              # umbrella re-export (public surface)
    # Shells (BBS …) live in **separate repos** — Layer-independence directive (2026-04-24).
]
exclude = ["arkhe-kernel"]      # L0 in its own repo eventually; currently a path dep
```

**Rationale**: layer independence — L0 ← Runtime ← Shell, one-way.
`arkhe-forge-core` carries L1 primitive types and traits only;
`arkhe-forge-platform` carries L2 services only. The `arkhe-forge`
umbrella is the **public API surface** — most shells import only this
one. The reference shell (BBS) lives in its own repo so a shell crate
cannot accidentally re-enter the Runtime workspace's dep graph.

**Repo split status**:

- ✅ **BBS split complete (2026-04-24, Task #31)** — `arkhe-shell-bbs`
  moved to its own repo. Removed from this workspace's `members`.
- `arkhe-kernel` / `arkhe-forge` independent-repo split planned for
  **immediately after the current-release alpha tag**.

**How to verify**:

- `cargo build -p arkhe-forge-core` compiles without `arkhe-forge-platform`.
- `cargo build -p arkhe-forge` compiles without any shell crate (trivially true — separate repo).
- A shell (separate repo) reaches the Runtime only via `arkhe-forge = { path = "../ArkheKernel/arkhe-forge" }` or a published crate.

### §2. One-way dep CI gate

**Decision**: `cargo-deny` + a workspace-metadata rule prevents
accidental Runtime → Shell dep.

```toml
# deny.toml
[bans]
multiple-versions = "warn"
[[bans.deny]]
name = "arkhe-shell-*"
use-in = ["arkhe-forge-core", "arkhe-forge-platform", "arkhe-forge"]
```

**Rationale**: layer-independence CI enforcement. Install during the
Infrastructure milestone — installing later means an entangled
dependency may already have crept in. Only a CI gate can prevent the
regression (human discipline alone won't).

**Additional gates**:

- **Workspace rule**: a CI step parses `cargo metadata`, builds the dep
  graph, and asserts zero `arkhe-forge-*` → `arkhe-shell-*` edges.
- **Internal Runtime graph**: zero `arkhe-forge-core` → `arkhe-forge-platform`
  edges (L1 → L2 import forbidden, spec §5.4).

**How to verify**:

- `cargo deny check bans` CI step green.
- `cargo-depgraph --all-deps` shows shell → runtime only, no reverse.
- An intentional-violation PR (test) is rejected by CI.

### §3. Dependency version pinning

**Decision**: minor-version pin, `^` on patch.

Major crates:

| Crate | Min version | Use | Rationale |
|-------|-------------|-----|-----------|
| `ed25519-dalek` | `^2.1` | L0 SignatureClass Ed25519 + L2 audit receipt | L0 compatibility required |
| `ml-dsa` | `^0.1` | MlDsa65 / Hybrid (§14.7) | PQC crate is early-stage; minor breaks possible |
| `postcard` | `^1.0` | Canonical bytes (A17) | L0 compatibility |
| `argon2` | `^0.5` | AuthCredential KDF (§4.1 S2) | OWASP 2024 baseline |
| `chacha20poly1305` | `^0.10` | XChaCha20-Poly1305 default AEAD (§14.9.1) | C-R5-1 |
| `aes-gcm-siv` | `^0.11` | AES-GCM-SIV (§14.9.1 AeadKind) | RFC 8452 |
| `serde` | `^1.0` | — | stable |
| `arrayvec` | `^0.7` | BoundedString (§3.4, bounded-string-analysis) | bounded-stack pattern |
| `blake3` | `^1.5` | Chain domain separation + verb allocation | L0 compatibility |

**Rationale**: minor-version breaks are within the Rust crate
ecosystem's semver-minor allowance — pin so we detect them. Patch
(`^`) is bug-fix-only, allowed. The PQC crate (`ml-dsa`) is early-stage
so we pin extra strictly.

**cargo-vet approval chain**: see §18 Supply-chain security. Each
dep's prior → current version transition must be reviewed.

**How to verify**:

- `Cargo.lock` is committed and reviewed in CI.
- `cargo vet check` CI green.
- `cargo audit` reports zero known vulnerabilities (or any whitelist
  entry must include a justification).

### §4. Feature-flag boundary

**Decision**: four primary features — `tier-1-kms` /
`tier-2-multi-kms` / `pqc-hybrid` / `unstable`.

```toml
[features]
default = []                                  # Tier-0 dev only
tier-1-kms = ["dep:aws-kms", "dep:gcp-kms"]   # Tier-1 KMS free-tier (AWS / GCP)
tier-2-multi-kms = ["tier-1-kms", "dep:vault", "dep:threshold-hsm"]
pqc-hybrid = ["dep:ml-dsa"]                   # MlDsa65 + Hybrid
unstable = []                                 # unstable feature opt-in
```

**Rationale**: aligns with compliance tiers (§14.9.1 §§12). Tier-0 is
default (software-KEK, minimal deps). Tier-1+ is explicit opt-in —
operators consciously pick a KMS. `unstable` is for pre-freeze API
verification — **forbidden inside BBS dogfood** (using `unstable` from
BBS would break BBS on every API change, which violates "do not depend
on `unstable`").

**How to verify**:

- `cargo build --no-default-features` green (Tier-0 minimal).
- `cargo build --features tier-1-kms` green.
- `cargo build --features unstable` warning or `cfg`-attribute-emitted
  "unstable warning".
- BBS `Cargo.toml` uses `arkhe-forge = { features = ["tier-1-kms"] }`
  with `unstable` absent.

---

## Stability (§5 – §9)

### §5. Public API freeze (two-stage) + deprecation policy

**Decision**: **two-stage freeze**.

- **Soft freeze — at the Core-primitives milestone close (Core 5 + Band 1
  pipeline)**: API surface fixed. Subsequent changes require
  reviewer-approved PRs. **Additive changes (new method / new struct /
  new enum variant appended) are allowed based on dogfood feedback**;
  breaking changes are rejected by reviewers as "soft-freeze
  violations". The shell-dogfood milestone (BBS) supplies real-world
  feedback during this window.
- **Hard freeze — release-freeze pre-alpha**: at the moment BBS dogfood
  closes and the four-person review passes. From this point all
  breaking changes go to a future-extension DIP. Even additive changes
  are now bound by current-release alpha stability guarantees.

**Why two stages**: a single freeze either misses dogfood feedback
(too early — no realistic feedback yet) or has nowhere to apply it
(too late — already shipped). Soft freeze freezes the surface while
allowing fine-tuning; hard freeze guarantees alpha stability. This
reconciles "later releases must not destabilise earlier ones" with
dogfood-driven feedback.

**Deprecation policy**:

- `#[deprecated(since = "0.13.0", note = "use X instead")]`.
- Minimum two-version grace (deprecated in one minor → removed two minors later).
- Removal is a separate intentional DIP-round decision (no silent
  removals).

**Rationale**: the core of "later releases must not destabilise earlier
ones". A breaking change after freeze breaks the shell ecosystem —
must always go through a separate future-extension DIP.

**Freeze scope** (API surface, identical for soft and hard):

- `arkhe-forge` umbrella re-exports.
- L1 primitive public types: `User` / `Actor<'s, S>` / `Space` /
  `Entry<'s>` / `Activity<'s>`.
- Derive macros: `#[derive(ArkheComponent, ArkheAction, ArkheEvent)]` +
  attributes.
- Manifest schema (§5.6 canonical structure).
- WAL event TypeCode allocation (§3.2).

**Outside freeze scope (breaking allowed within the current release)**:

- L2 internal observer impl details.
- `runtime-doctor` CLI subcommand names (re-organisable until
  stabilisation).

**How to verify**:

- API-surface diff tool (`cargo public-api`) CI step. Save the
  soft-freeze baseline at Core-primitives close. During the soft-freeze
  window, diffs must be additive or opt-in features — reviewer
  confirms. After hard freeze (release freeze), all diffs are rejected
  (deferred to future-extension).
- Deprecation use cases — importing a deprecated symbol requires
  `#[allow(deprecated)]`.

### §6. Universal extension points

**Decision**: every public enum is `#[non_exhaustive]`, every trait
method has a default impl, manifest fields are optional + default,
TypeCode ranges remain partitioned.

**Enums**:

- All `#[non_exhaustive]` + `#[repr(u8)]` with explicit indices.
- Compute paths reject by default (`_ => return reject` — spec §3.4 NC5).
- Existing variants must not be reordered or removed (append-only).

**Traits**:

- Extension traits (e.g. L2 hooks) provide default impls. Shells
  override selectively.
- Breaking changes go through a new trait + blanket impl migration.
- **Default-method body semantics**: **changing the semantics of a
  default-method body is also a breaking change** (observable behaviour
  shift = downstream behaviour shift). New semantics → new method, keep
  the old default. After hard freeze, default-body changes are rejected.

**Manifest (serde convention)**:

- Every field that can be optional is optional + default. Required
  fields carry a rationale comment.
- Each optional field uses **`#[serde(default)]` +
  `#[serde(skip_serializing_if = "Option::is_none")]`** (or the
  matching default predicate). A manifest that omits the field
  round-trips through default without canonical-digest drift.
- Unknown top-level keys reject (strict parse); unknown sub-keys warn
  + skip.

**TypeCode ranges**:

- Component `0x0003_0000..0x0003_0EFF` / core Event
  `0x0003_0F00..0x0003_FFFF` / shell-free `0x0100_0000..` (spec §3.2)
  preserved.
- New core Events allocate within the Event subrange.
- TypeCode reclamation is forbidden absolutely (spec §14.7
  forward-compat).

**Rationale**: if implementation drift breaks the spec's extension
paths, every future-extension feature becomes a breaking change.
Extension points are the **L0 / spec-DIP compatibility contract** —
the implementation enforces them automatically.

**How to verify**:

- Macro enforcement: `#[derive(ArkheEnum)]` checks `#[non_exhaustive]`
  presence at compile time.
- Test: codify the TypeCode allocation table as a fixture; PRs adding
  allocations must update the table.
- `cargo public-api` flags reordered / removed enum variants as
  breaking.

### §7. Schema-evolution rule + Runtime version-upgrade path

**Decision**: WAL postcard is append-only (L0 DO-NOT-TOUCH item #8
inheritance). Older Runtime versions must read newer WALs.

**Schema evolution**:

- Components / Actions / Events allow field **append only**
  (`#[serde(default)]` required).
- Removing fields, reordering, or changing types is forbidden.
- Bump `schema_version` for the affected TypeCode pin (A15).
- Older `schema_version` records are **always** replayable
  (read-forward).
- **`schema_version` first field**: every Component / Action / Event
  struct's **first field is `schema_version: u32`**.
  The first 4 bytes of the postcard canonical encoding are the version
  tag — a forward-compat parser reads the version first and branches.
  The `#[derive(...)]` macros validate the first field's name/type at
  compile time and emit
  ``error: first field must be `schema_version: u32` `` on violation.

**Runtime version upgrade (current → future-extension)**:

```
(a) Process graceful drain (reject new requests, finish current ticks)
(b) Binary swap (current → future-extension)
(c) WAL replay (bit-identical, L0 A1)
(d) Projection rebuild (reset kernel_projection_state, restart observer)
```

**Downtime SLA**: (a) drain ~ seconds; (b) swap ~ seconds; (c) replay ~
ticks × ~ms, proportional to WAL size; (d) projection rebuild ~
projection rows × insert time. **~5-10 min target** for a 10k-user
shell on alpha.

**Rollback (future-extension → current)**:

- Binary downgrade + WAL replay back to the previous chain tip →
  projection rebuild.
- TypeCodes added in the future-extension are recorded in the current
  release's `unknown_variants` staging — no data loss on rollback.

**Detail**: see §17 Runtime version upgrade path.

**Rationale**: L0 A1 bit-identical replay closes the data-corruption
path during version transitions. The downtime SLA is the operator's
expectation — "recoverable in minutes" is the current-release alpha's
operational promise.

**How to verify**:

- Test: a current-release binary replaying a future-extension WAL
  (with future TypeCodes) records into `unknown_variants` and proceeds.
- Test: a future-extension binary replaying a current-release WAL
  reproduces the bit-identical state.
- CI: an upgrade / rollback simulator runs end-to-end with real WAL
  files.

### §8. Dogfooding schedule

**Decision**: the BBS minimal shell starts after Runtime Band 1 + L2
skeleton (L2-services milestone). BBS basics complete before
crypto-erasure (L2-completion stage). BBS feedback converges before
public API freeze.

**Timeline**:

| Week | Runtime | BBS |
|------|---------|-----|
| 1-2 | Infrastructure milestone | — |
| 3-5 | Core-primitives milestone (Core 5 + Band 1) | — |
| 6-7 | L2-services milestone, L2 skeleton | BBS shell-dogfood milestone start (Core 5 usage + telnet adapter) |
| 8-9 | L2-completion stage (parallel) | BBS basics complete, Runtime polish feedback delivered |
| 10 | Release-freeze | BBS complete, alpha-blocker docs merged |

**Rationale**: starting BBS **before** Runtime API freeze is the heart
of "dogfooding" — finding API problems after freeze is too late.
During the Runtime skeleton stage, BBS's "validated repetition" reveals
gaps / overreach in Core 5 → Runtime polish → freeze.

**Churn-avoidance timing**: starting BBS before Core-primitives close
forces BBS through L1 churn — the optimal window is Core-primitives
done → L2-skeleton starting.

**How to verify**:

- BBS `cargo check` is green from L2-services milestone close onward.
- Count Runtime issues (rate limit / TLS adapter / telnet session
  state) found by BBS and applied to Runtime polish (target ≥ 3).
- BBS write/read happy-path E2E test (telnet login → post → read →
  logout) is green before Runtime freeze.

### §9. Test harness as spec enforcement

**Decision**: axiom (E1-E13 + per-primitive 30) property-based
verification + machine-checked-invariant auto-verification +
accumulating regression corpus.

**Test layers**:

| Layer | Target | Tool | Run time |
|-------|--------|------|----------|
| Unit | individual functions / trait methods | `#[test]` | < 10 s |
| Property | all axioms (43 items) | `proptest` | < 2 min |
| Invariant | E-series MC auto-verification | custom harness | < 3 min |
| Integration | L0 + Runtime combined | `tokio-test` + in-memory `Kernel` | < 5 min |
| **Formal** | selected MC invariants | `kani` or `creusot` | separate nightly |

**CI budget**:

- **Smoke** (every PR): unit + property subset + invariant subset, < 5 min.
- **Nightly**: full property + integration + formal, < 30 min.

**Property-test corpus**:

- Fixed CI seed (reproducibility).
- Every failure is added to the **regression corpus** so the same case
  cannot break again.
- Corpus stored in git LFS or a separate `test-corpus/` directory.

**Formal-verification scope**:

- E1 / E2 / E3 / E12 / E13 (chain-anchored MC axioms) prioritised.
- Per-primitive: E-act-1 (idempotent) / E-user-3 (GDPR) emphasised.
- Kani bounded model checking — proofs constrained by tick depth.

**Rationale**: with 43 axioms across 45 slots, you cannot tell which
axiom drift breaks something unless tests automate the check. The
harness is automated spec enforcement.

**How to verify**:

- `cargo test` smoke green.
- `cargo test --release --features nightly` full green.
- Axiom coverage table: each E-axiom + per-primitive axiom maps to a
  property test, zero uncovered axioms (CI check).
- A failure case landing → mandatory regression-corpus PR.

---

## Process (§10 – §12)

### §10. L0 frozen — inheritance

**Decision**: spec-DIP L0 v0.11 freeze inherited through the entire
implementation DIP. If an L0 change becomes necessary, **stop
immediately and split into a separate L0 DIP**.

**L0 DO-NOT-TOUCH (8 items, spec §16)**:

1. `DOMAIN_CTX` literal (`persist/wal.rs`).
2. InvariantLifetime variance (`state/authz.rs`).
3. `Principal` / `KernelEvent` / `StepStage` derives.
4. A11 MACHINE-CHECKED tag.
5. Deferred section (future-extension candidates) of the roadmap.
6. R4-X DAG.
7. EventMask bit allocation.
8. `WalRecord` postcard field order.

**Runtime-side workarounds, in order of preference**:

- In-band event pattern (E12 `RuntimeBootstrap` / E13 `SignatureClassPolicy`)
  is the standard sidecar-metadata avoidance.
- Runtime-owned enums (`RuntimeSignatureClass` vs L0 `SignatureClass`)
  are the standard avoidance for L0 enum changes.
- Trait layering (`PiiType` sealed / `ShellPiiType` wrapper) is the
  standard avoidance for L0 trait changes.
- Derive attribute opt-ins (`#[arkhe(canonical_sort)]` /
  `#[arkhe(idempotent)]`) are the standard avoidance for L0 trait-method
  additions.

**Rationale**: L0 is the stability foundation. The spec DIP held L0 at
zero edits for the entire run — implementation inherits the same
posture. If a Runtime extension forced an L0 DIP, the L0 DIP cycle
would also have to spin up, and development speed would crater.

**How to verify**:

- CI gate: any PR touching `arkhe-kernel/` requires an **explicit
  reviewer assignment** (declares an accompanying L0 DIP).
- File-hash check: SHA-256 list of `arkhe-kernel/src/**/*.rs` saved as
  CI baseline; any drift triggers "L0 modification detected — L0 DIP
  required".

### §11. Spec drift policy

**Decision**: classify spec issues found during implementation, then
route each by class.

| Class | Route |
|-------|-------|
| **Critical** | Immediate patch (emergency micro-patch round) — leader decision. Architect dispatch. |
| **Major** | Defer to future-extension DIP — workaround within the current release if possible; otherwise temporary fix + future-extension proper resolution. |
| **Minor** | Absorb into the implementation (team judgement). No patch needed. |

**Patches are not new DIP rounds** — emergency patches are
housekeeping-level (same scope as the spec-finalisation patch).
Four-person clean rounds are not re-run; the leader self-reviews.

**Already deferred to the current release** (spec §15.5
current-release tracking):

- HF1 platform abstraction (Linux / macOS / Windows
  `trait ProcessProtection`).
- HF4 manifest-bypass audit (`alpha_credential_rotation_required = false`
  WARN + journal).
- `EncryptedPii<T>::decrypt()` record-time manifest resolution
  (tick-anchored).

**Rationale**: spec freeze means "no design re-discovery". Issues found
during implementation are either a design flaw (→ patch /
future-extension) or an implementation detail (→ absorb). Critical is
the only fast path; Major waits for the future extension — concrete
operationalisation of "completeness first".

**How to verify**:

- `docs/drift-log.md` (created at the start of the implementation DIP)
  records discovered cases × class × route. Reviewed at release-freeze.
- The next future-extension DIP uses this log as its initial-findings
  input.

### §12. Current scope boundary + telemetry privacy

**Decision**: full Tier-0 / Tier-1 / Tier-2 implementation. Tier-2 HW
verification is partially restricted.

**Scope**:

- **Tier-0** (software-KEK dev/alpha): full functionality, BBS alpha
  deployment path.
- **Tier-1** (AWS KMS / GCP Cloud KMS free-tier): full functionality,
  BBS realistic-beta path.
- **Tier-2** (Multi-KMS + threshold HSM + transparency log): code
  shipped, **physical-HW verification partially restricted**. Where
  real HSM access is unavailable, mock substitution; HF1 / HF2
  integration tests defer to the future extension.

**Telemetry privacy**:

- The Prometheus metric endpoint requires authentication (HTTP Basic /
  JWT minimum). Public endpoint forbidden.
- **Drop user_id labels after GDPR crypto-erasure** — scrub
  `user_id=<hashed-id>` labels from erased users' metrics. Metric
  retention nullifies / removes `user_id` labels post
  `UserErasureCompleted`.
- **Region labels not in public deployments** — regional data-residency
  exposure can leak infrastructure topology. Internal dashboards only.

**Unstable features**: gated by `cfg(feature = "unstable")` + emit a
runtime warning log.

**Rationale**: full scope was confirmed by team-lead (2026-04-24).
Tier-2 HW verification is the only restriction — alpha runs Tier-1, so
not a blocker. Telemetry privacy must extend GDPR crypto-erasure to
the metric layer; otherwise Art. 17 has a side channel.

**How to verify**:

- Integration test: Tier-1 AWS KMS free-tier per-user DEK
  generation + shred happy path green.
- Metric scrub test: zero metric series carrying the erased user's
  `user_id` post `UserErasureCompleted` (Prometheus query).
- Endpoint-auth test: unauthenticated requests rejected (HTTP 401).

---

## Gates (§13 – §14)

### §13. Release criteria + supply-chain security

**Decision**: all 9 release-gate items must pass.

**Release criteria**:

1. **Axiom harness 100 %** — E1-E13 + per-primitive 30 — every
   property / invariant test green.
2. **6 alpha-blocker docs complete** — see the dedicated section.
3. **BBS minimal dogfood complete** — happy path + edge cases (GDPR
   erasure / session timeout / TLS wrap) green.
4. **Zero breaking changes after public API freeze** — `cargo public-api`
   diff shows zero breaking entries.
5. **L0 v0.11 unmodified, automatically verified** — §10 file-hash
   baseline check green.
6. **Supply-chain security** — `cargo-audit` / `cargo-deny` /
   `cargo-vet` all pass.
7. **Binary reproducibility** — same source → same hash; two
   independent CI builds compare equal.
8. **Signed release** — `current-release alpha` tag carries an Ed25519
   signature (Hybrid is future-extension PQC).
9. **Sigstore / Rekor transparency log entry** — release artifact +
   signature published to Sigstore (§15.4 future-extension preview
   pre-shipped).

**Detail**: see §18 Supply-chain security.

**Rationale**: makes "completeness first" concrete at the release
gate. Each gate is independently verifiable by operator / user /
auditor. Especially (7) binary reproducibility externally proves
"this binary is the translation of this source".

**How to verify**:

- Release-gate checklist `docs/release-gate.md` — checked off
  at release-freeze close.
- Release-automation script (`scripts/release.sh`) runs the 9 gates
  sequentially.

### §14. Implementation review rounds + threat model + audit log + review SLA

**Decision**: 4 review checkpoints + a 4-person pre-freeze final.

**Review checkpoints** (Crypto-primitives / 5b split — see rationale below):

| Checkpoint | Target | Primary reviewer | Goal | SLA |
|------------|--------|------------------|------|-----|
| **Core-primitives close** | Core 5 + Band 1 code | auditor | structure / type safety / axiom coverage | 1 week |
| **L2-services close** | L2 skeleton | veteran | operations / SLO / observability | 1 week |
| **Crypto-primitives close** | crypto-erasure primitives (AEAD / PiiType / DEK envelope / AAD) | cryptographer | security surface 1-8 | **1 week** |
| **KMS-integration close** | KMS integration + HF1/2/4 + multi-region 2PC + transparency log | cryptographer | security surface 9-15 | **1 week** |
| **Release-freeze pre-freeze** | whole codebase | **4-person final** | verify release-gate pass, Go / No-Go | 2 weeks |

**Why split crypto-primitives / 5b**: a single review for all of
L2-completion crypto would (a) overload one cryptographer iteration
and (b) primitive-layer feedback could force KMS-integration rework.
Splitting gives a serial cryptographer review on primitives → feedback
applied → KMS-integration starts.

**L2-completion crypto security surface (15-item enumeration, scope
of cryptographer review)**:

| # | Surface | Stage | Spec ref |
|---|---------|-------|----------|
| 1 | `EncryptedPii<T>` wire format + `PII_CODE: u16` | 5a | §14.9.1 §§1 / C-R5-4 |
| 2 | AEAD AAD composition (`dek_id || pii_code || aead_kind`) | 5a | §14.9.1 NR6-1 |
| 3 | `AeadKind` default XChaCha20-Poly1305 + AES-GCM counter nonce | 5a | §14.9.1 §§3 / C-R5-1 |
| 4 | DEK envelope (HSM-generated random + wrap) | 5a | §14.9.1 §§2 / C-R5-3 |
| 5 | `PiiType` sealed + shell-PII range separation | 5a | §14.9.1 §§1 / NR6-7 |
| 6 | `body_hash` per-user salt + per-record nonce immutability | 5a | §14.9.1 §§4 / NF8 / mNF-C |
| 7 | `AeadKind` downgrade check (manifest-anchored) | 5a | §14.9.1 §§1 / GF2 |
| 8 | `RuntimeSignatureClass` + `SignatureClassPolicy` chain-anchored | 5a | §14.7 / E13 / FG5 |
| 9 | HSM health threshold (5 timeouts / 60 s 50 % errors) + degraded mode | 5b | §14.9.1 §§6 / M-R6-2 |
| 10 | Multi-KMS primary/secondary + 60 min operator SLA + auto_promote trust model | 5b | §14.11.2 / HF2 |
| 11 | Multi-region atomic-shred 2PC (`PerRegionErasureProgress` + `scope` enum) | 5b | §14.9.1 §§13 / GF4 |
| 12 | HSM attestation transparency log (Sigstore / Rekor or in-house Merkle) | 5b | §14.11.3 / FG3 |
| 13 | Public `/erasure-receipt/{user_id}` endpoint + WAL chain-tip re-verify | 5b | §14.11.4 / HF3 |
| 14 | `software-kek` binary version cross-check + process protection | 5b | §5.6 GF1 / §14.7 HF1 / §14.9.1 §§12 |
| 15 | `runtime_doctor_journal` chain-signed + admin-DB-tamper detection | 5b | §14 audit-log tamper-resistance |
| 16 | `hf2_kms::journal::ConsumedTokenJournal` — append-only + `runtime_doctor_journal` chain-signed integration | 5b | §14.11.2.1 HF2 + §14 threat model actor 5 |

**Review SLA**:

- Each checkpoint 1 week (release-freeze pre-freeze 2 weeks — 4-person
  parallel + Go / No-Go meeting).
- A critical regression triggers immediate report → freeze deferral.
- Disagreements among reviewers → team-lead mediation.

**Threat model catalog** (see §19 detail):

1. Malicious shell developer.
2. Malicious runtime operator (insider).
3. Malicious user.
4. Network MITM.
5. HSM operator collusion (threshold-HSM breach).
6. L0 kernel bug exploitation.

**Audit-log tamper resistance**:

- `runtime_doctor_journal` is implemented as a WAL-like chain-signed
  structure.
- An admin running `UPDATE runtime_doctor_journal SET ...` directly
  mismatches the chain hash.
- Chain tip published periodically (GitHub release or internal
  transparency log).

**Rationale**: the spec DIP showed (R4 course correction) that a
single agent's iteration has limits — the implementation follows the
same pattern. A specialty reviewer at each checkpoint provides
orthogonal coverage. The threat-model catalog declares "what attacks
we model"; anything outside is explicitly future-scope.

**How to verify**:

- Save each checkpoint review as
  `docs/Review/implementation-phase-N-review-2026-MM-DD.md`.
- Write the threat-model catalog
  `docs/threat-model-catalog.md` mapping each actor to its
  defenses.
- Audit-log chain-verification test included in CI.

---

## Discipline (§15 – §16)

### §15. Concurrency + multi-shell interaction

**Decision**: shell isolation absolute. Inter-shell direct calls
forbidden.

**Shell isolation rules**:

- Two shells (e.g. BBS / Casino) may run inside the same Runtime
  process simultaneously (spec §13 multi-shell hybrid proof).
- State / memory completely separated — `ShellBrand<'s>` invariant
  lifetime + L1 compute MC `shell_id` double-check.
- Inter-shell direct calls **forbidden** — Rust's type system rejects
  cross-shell lifetime unification (spec §3.7).

**Cross-shell notification**:

- `CrossShellActivity` event (TypeCode `0x0003_0F07`) — read-only.
  Shell B's observer subscribes to Shell A's `CrossShellActivity` for
  notification only.
- Event emission stays Band 1 deterministic (L0 observer convention
  inheritance).

**Federation** (future extension):

- Cross-shell interactivity → ActivityPub federation. Out of scope here.

**Rationale**: applies "validated repetition" + "layer independence"
at the shell level. Coupling between shells entangles each shell's
independent dev / deployment / erasure paths and breaks "third
parties can extract and run a single shell". The 2026-04-24 BBS repo
split is the practical evidence.

**How to verify**:

- Compile test: passing `Actor<'shell_a, _>` to
  `Activity<'shell_b>` is a compile error (lifetime unification fails).
- Integration test: Shell A reading Shell B's internal state results
  in a `TypeError` or compile-fail.
- L1 compute MC: an adversarial WAL (shell_id mismatch) produces a
  `CrossShellActivity` event with zero `Op`s.

### §16. Implementation discipline (panic / MSRV / target matrix)

**Decision**:

**Panic policy**:

- `unreachable!()` allowed — match arms unreachable by L0 / Runtime
  invariants.
- `debug_assert!` allowed — disabled in release, enabled in CI smoke.
- `panic!()` / `unwrap()` / `expect()` **forbidden** — compute paths
  require totality (L0 A12 inheritance).
- `Result<T, E>` / `Option<T>` exhaustively handled.
- **Clippy deny CI gate**:
  `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`
  on the workspace root.

**MSRV**: Rust stable **1.80+** (matches L0). No MSRV bump within the
current release.

**Build target matrix** (HF1 platform-abstraction influence):

- `x86_64-unknown-linux-gnu` (primary — production Linux servers).
- `aarch64-unknown-linux-gnu` (ARM Linux servers).
- `x86_64-apple-darwin` (Intel dev laptops).
- `aarch64-apple-darwin` (M-series dev laptops).
- `x86_64-pc-windows-msvc` (Windows dev).

CI: build + unit-test all 5 targets. Integration tests run on Linux
primary only.

**Rationale**: a panic in the Runtime hits the L0 A22 (observer-panic
quarantine) path and risks projection-stuck. Totality (L0 A12) is the
contract; the bits the Rust type system cannot enforce (`unwrap`) are
covered by discipline + CI lint. MSRV pinning pushes "later releases
must not destabilise earlier ones" down to the toolchain layer.

**How to verify**:

- `cargo clippy --all-targets --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic` CI green.
- `cargo build --target <each>` 5-target CI green.
- `rust-toolchain.toml` pinned `channel = "1.80"` (or higher but
  pinned).

---

## Deep dives (§17 – §19)

### §17. Runtime version-upgrade path (detail, expansion of §7)

**Operator-perspective procedure**:

```
# current → future-extension upgrade (staging example)

# 1. Pre-upgrade verification
$ arkhe-runtime-doctor upgrade-precheck --target 0.13
  - WAL integrity OK
  - Projection lag < 5s
  - Active session count < 100

# 2. Drain
$ arkhe-runtime-doctor drain --timeout 60s
  # reject new requests, wait for tick completion

# 3. Binary swap
$ systemctl stop arkhe-forge-platform
$ ln -sf /opt/arkhe/<future-extension>/arkhe-forge-platform /opt/arkhe/current
$ systemctl start arkhe-forge-platform

# 4. Replay + rebuild
# (automatic on start — WAL replay + projection rebuild)

# 5. Verification
$ arkhe-runtime-doctor upgrade-verify
  - Chain tip match
  - Axiom harness pass
  - L2 projection resume
```

**WAL continuity**:

- L0 A1 bit-identical replay guarantee.
- Future-extension TypeCodes are recorded in `unknown_variants` staging
  by current binaries.
- A future-extension `schema_version` bump re-emits `RuntimeBootstrap`
  (§14.7 E12).

**Projection rebuild**:

- `kernel_projection_state` reset (`observer_state = 'replaying'`).
- L2 serving fully disabled during replay (false-negative protection,
  §14.7 m3).
- At replay completion, the `RuntimeBootstrap` event matches the
  current manifest digest (MC check).
- Mismatch → `ReplayError::ManifestDrift` + rollback.

**Rollback path**:

- `arkhe-runtime-doctor rollback --to 0.12`.
- Binary downgrade + `kernel_projection_state` reset.
- Future-extension TypeCodes preserved in current binary's
  `unknown_variants` staging (zero data loss).
- Projection rebuild.

**Downtime SLA (scale-aware)**:

| Scale | Total downtime target | L2-completion measurement |
|-------|-----------------------|---------------------------|
| Alpha (≤ 1 k user) | **~10 min** (drain ~1 min + swap ~30 s + replay ~3-5 min + rebuild ~3-5 min) | BBS dogfood measurement |
| Beta (1-10 k user) | **~30 min** (replay ~10 min + rebuild ~15 min + buffer ~5 min) | Tier-1 measurement (proportional to WAL size) |
| Production (100 k+ user) | **separate roadmap** — replay / rebuild parallelisation required (future-extension research item) | Out of current scope |

**Rollback triggers**:

- **Automatic rollback**: during upgrade — `ReplayError::ManifestDrift`
  / chain-tip mismatch / projection rebuild failure.
- **Operator-judgment rollback**: when **upgrade time > 2 ×
  tier SLA**, the operator manually rolls back (alpha 20 min / beta
  60 min) — partial-apply state must not persist; at 10 k users a
  60-min rollback is cheaper than a fresh restart (operational
  measurement target).
- Rollback itself consumes downtime. `arkhe-runtime-doctor rollback`
  requires an operator Ed25519 signature + `runtime_doctor_journal`
  append.

**L2-completion-stage dogfood measurement requirements**:

- At L2-completion close, BBS dogfood measures upgrade / rollback on
  alpha-tier WAL (~1 k user equivalent).
- Record results in `docs/runbook/upgrade-downtime-measured.md` —
  deviation from this SLA target.
- If > 2 × SLA, reopen the L2-completion review (cryptographer +
  veteran joint).

### §18. Supply-chain security (detail, expansion of §13)

**cargo-vet approval chain**:

- Every transitive dep version change is recorded with a reviewer
  approval chain.
- Approval = reviewer attests they reviewed the source diff.
- `cargo vet diff old new` extracts the change set; the reviewer
  signs it.

**cargo-deny**:

- License: MIT / Apache-2.0 / BSD-3 whitelist. GPL family rejected
  (avoid forced-disclosure obligation).
- Vulnerability: integrate `cargo-audit`, block known CVEs.
- Multi-version: warn (multiple versions of the same crate = bloat).
- Deprecated: warn.

**Binary reproducibility**:

- Same source → same hash.
- Two independent builds (e.g. CI machine × 2, Linux x86_64) produce
  identical SHA-256.
- Reproducibility-breakers: timestamp embedding / path embedding /
  parallel-build non-determinism.
- Mitigation: pin `RUSTFLAGS="--remap-path-prefix"` +
  `SOURCE_DATE_EPOCH` + `CARGO_TARGET_DIR`.
- CI: "rebuild and compare" step.

**Signed release key management**:

- Current: Ed25519 signing key.
- Future-extension PQC: Hybrid (Ed25519 + MlDsa65, §14.7 PQC timeline).
- Storage: **hardware security key** (YubiKey / NitroKey) — software
  storage forbidden.
- Rotation: 90 d + grace window (spec §14.7 FG8 inheritance).
- Public-key pinning in `README.md` + a separate `arkhe-release-keys`
  repo.

**Sigstore integration scope**:

- Release artifact (`current-release-tar.gz`) + signature → Sigstore
  transparency log.
- Rekor entry index committed to `docs/release-log.md`.
- BBS shell deployment lets operators verify artifact authenticity
  via Rekor.

**How to verify**:

- CI step: `cargo vet check` + `cargo deny check` + rebuild compare +
  Sigstore publish.
- Third-party verification: external auditors confirm artifact
  authenticity from the Rekor entry.

### §19. Threat model catalog (detail, expansion of §14)

Six actors × defense posture.

| Actor | Motive | Primary attack path | Defense | Mapped axiom / invariant |
|-------|--------|---------------------|---------|--------------------------|
| **1. Malicious shell developer** | Plant a backdoor in a shell | Shell crate impls L0 trait manually | `ActionCompute sealed + derive only` (spec §3.3), cargo-deny CI | spec §3.3 / C2 sealed-trait |
| **2. Malicious runtime operator (insider)** | PII theft / audit tampering | Direct DB manipulation / journal rewrite | `chain_tip_signature` Ed25519 (C3), `runtime_doctor_journal` append-only + chain-signed (§14), multi-party threshold HSM (FG3) | E12 / E13 / S5 |
| **3. Malicious user** | Compromise the shell via the L4 API | Idempotency collision, GDPR bypass, rate-limit evasion | PG UNIQUE INDEX dedup (§14.8), L1 compute gdpr_status MC (B3 / C3), 3-axis rate limit (§5.2.1) | E-user-3, C3 gate |
| **4. Network MITM** | L4 traffic theft | Plaintext-Telnet credential sniffing | TLS 1.3+ mandatory (§5.2 GF3), telnet-over-TLS (RFC 2946), WebSocket-over-TLS | GF3 |
| **5. HSM operator collusion** | Reconstruct DEK (bypass erasure) | t operators collude → master-key export | Threshold HSM (t-of-n Shamir, t = 3 of 5), public transparency log (Sigstore / Rekor), tamper-evident counter | FG3 |
| **6. L0 kernel bug exploitation** | Trigger an L0 defect via the Runtime | Malformed Extension bytes → panic, WAL chain manipulation | Per-tick atomicity, Extension TypeCode validator log+skip (no panic, §5.5), L0 DO-NOT-TOUCH 8 items (immutable) | §10 |

**Out of scope**:

- **Nation-state-level supply-chain attack** — cargo ecosystem
  compromise. Outside the defense boundary; partial mitigation when
  Sigstore lands fully.
- **Zero-day in the Rust compiler** — compiler backdoor. Cannot be
  defended; reproducible builds are partial mitigation.
- **Physical HSM extraction** — FIPS 140-3 HSM physical destruction.
  Out of current scope.

**Defense-posture log**: future extensions amend this document
(append, with a separate DIP round) when a defense improves.

---

## Side sections

### Known limitations catalog (current release)

Boundary disclosures so implementation agents / operators / alpha
users do not misuse the system. **These remain after the current-release
alpha tag and are part of the long-term scope boundary**.

| Limitation | Scope | Workaround / future response |
|------------|-------|------------------------------|
| **Tier-2 HW verification partially restricted** | §12 | Real HSM access → manual integration test; future extension automates in CI |
| **Band 3 unsupported** (shell-level) | §9.3 spec, option B | Casino and similar Band-3 shells own their FSM + audit tooling. Future-extension DIP candidate (§15.4) |
| **Multi-region 2PC partial** | §14.9.1 §§13 | Up to 3 regions on alpha; production after future-extension HW verification |
| **BBS minimal scope** | team-lead directive 2026-04-24 | Fixed at 1 board + 1 chat room; additional boards / HTTP support → future extension |
| **Single-active L2** | §14.8 | Multi-active is a separate DIP (v0.15+ §15.5 roadmap) |
| **L0 single-thread throughput** | §10.4 | ~200 Action/s/instance; 10 k+ users → §14.10 Option C read-replica |
| **Federation unsupported** | §14.10 Option A | Future extension — `SignedArkheUri` + protocol spec + identity federation |

### Implementation TODOs

Items inside the current scope that **must complete** — not Known
Limitations (resolved before alpha). Aligned with spec §15.5
"current-release implementation tracking".

| TODO | Origin | Owner | Goal |
|------|--------|-------|------|
| **`EncryptedPii<T>::decrypt()` tick-anchored manifest resolution** | spec-finalisation patch carryover | cryptographer | Resolve cipher from the **manifest at record-creation tick**, not the current manifest. Old ciphertexts still decode under their old cipher even when the shell manifest changes. Manifest-history table or a `SignatureClassPolicy`-style `PiiCipherPolicy` event chain-anchor. |
| **HF1 process-protection platform abstraction** | spec §15.5 | cryptographer + veteran | `trait ProcessProtection` + Linux / macOS / Windows impls. See entry-checkpoint item 7 in §10. |
| **HF4 manifest-bypass audit** | spec §15.5 | cryptographer | When `alpha_credential_rotation_required = false` + `runtime_max ≥ "0.16"`, emit WARN + `runtime_doctor_journal` append. |
| **`DekMigrationCompleted` event struct formal definition** | spec §14.7 (Option 2) | cryptographer | TypeCode `0x0003_0F09` already reserved. The struct stabilises when the current-release Option 2 offline batch tool ships. |

### 6 alpha-blocker docs — parallel workstream

Independent of Runtime implementation; runs throughout the phases and
must be draft-complete before release-freeze. See
`docs/alpha-release-schedule.md` for owners / deadlines /
phase mapping (replaces the old `alpha-blocker-docs-schedule.md` and
folds in `gdpr-legal-review-schedule.md`).

---

## Exit criteria + next steps

**Conditions for the current-release alpha tag**:

- All milestones complete.
- All 9 §13 release criteria pass.
- **5 alpha-blocker docs** (Runtime repo) + the **BBS telnet TLS matrix
  (BBS repo deliverable)** complete.
- BBS minimal-shell dogfood + E2E verification (BBS repo).
- Team-lead approval.

**Next (future-extension DIP candidates)**:

| Candidate | Gate criteria | Target semver |
|-----------|---------------|---------------|
| Room primitive promotion | 2+ shell evidence among BBS chatroom / GuildChat / TubeLike live | future extension |
| Band 3 primitive (`BandThreePhase`) | 1+ additional evidence among Casino / E2E DM / threshold vote | future extension |
| `SpaceMembership` primitive | 3-shell evidence (BBS / Guild / DM) | v0.14 |
| Active-multi L2 | Production 10 k+ user evidence | v0.15+ |
| `ComplianceTierChange` event | future-extension DIP candidate | future extension |
| `DekMigrationCompleted` event | formalise once Option 2 implementation lands | end of current release |

**Repo split**:

- ✅ **`arkhe-shell-bbs` independent repo done** (BBS reference shell,
  Task #31, 2026-04-24).
- ⏳ `arkhe-kernel` independent repo (L0 kernel) — target immediately
  after the current-release alpha tag.
- ⏳ `arkhe-forge` independent repo (Runtime L1 + L2) — target
  immediately after the current-release alpha tag.
- Each has its own release cycle, CI, issue tracker, and LICENSE.

---

**End of Implementation Plan.**

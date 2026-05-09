# `formal/tla-plus/` — ArkheKernel Runtime TLA+ refinement specs

**Apalache** primary tooling (type-checker + bounded model checker,
SMT-backed). **TLC** documented fallback for large-state explicit-state
MC where Apalache's bounded search times out (CR-3 replay determinism
over WAL records is the expected first call site).

Anchored to the E1-E15 Runtime axiom set.

## Modules

| Module | Anchor axiom(s) | Adversary closure | Primary tool |
|---|---|---|---|
| `runtime_core.tla` | E1 + E10 (foundation, base module) | — | Apalache typecheck |
| `cr1_chain_hash_invariant.tla` | **E14 ⇒ A1** | **Adversary A** (compute non-determinism) | Apalache |
| `cr2_state_machine_refinement.tla` | E4 + E5 + E6 + E7 | (multi-shell isolation) | Apalache |
| `cr3_replay_determinism.tla` | E11 + E12 + E13 | (replay determinism + PQC downgrade) | Apalache primary, TLC fallback |
| `r4_implementation_refinement.tla` | E3 + E8 + E9 | (L1↔L0 layering + DAG integrity) | Apalache primary, TLC fallback |
| `cr4_observer_capability_confinement.tla` | **E15** (4-clause) | **Adversary B** (observer mutation bypass) | Apalache |

`runtime_core.tla` is the base module; the five CR-* / R4-I files
EXTEND it and add module-specific INVs.

## E1-E15 ↔ TLA+ INV mapping

The "Impl test anchor" column gives a short cite per axiom. The
machine-readable 1:1 mapping (full impl test names + paths, including
Kani harness anchors and Layer A item 3 inheritance) lives in
`formal/axiom-test-cite.toml` — `scripts/verify-axiom-cite.sh`
is the CI grep gate that enforces it.

| Axiom | Statement (1-line) | Tier | TLA+ INV name | Module | Impl test anchor |
|---|---|---|---|---|---|
| **E1** | Runtime primitive set = {User, Actor, Space, Entry, Activity} | MC | `CONSTANTS PrimitiveSet` (definitional) | (foundation) | `axioms_e_series.rs:72` |
| **E2** | `Action::compute` pure (A11 inheritance) | MC | subsumed by E14 `ChainHashDeterministic` | CR-1 | `axioms_e_series.rs:85,261` |
| **E3** | Runtime → L0 strictly downward, L1 → L2 forbidden | MC | `LayerImportStrictlyDownward` + `ImportDirectionMonotone` (L1+ runtime sub-DAG boundary→runtime; formal companion to the CI grep gate) | R4-I | `axioms_e_series.rs:107` + sibling ArkheForge: `arkhe-forge-platform/src/wasm_runtime_common/mod.rs` |
| **E4** | `UserId` globally unique / `ActorId` shell-unique | TP | `UserIdGloballyUnique` + `ActorIdShellUnique` | CR-2 | `axioms_e_series.rs:122` |
| **E5** | `Actor.user_id` + `shell_id` immutable post-creation | MC | `ActorIdentityImmutable` | CR-2 | `axioms_e_series.rs:133` |
| **E6** | `Actor<_, Authenticated>` requires `UserBinding` (typestate) | TP | `AuthenticatedActorHasUserBinding` | CR-2 | `axioms_e_series.rs:145` + Kani `kani_authorize_property` |
| **E7** | Shell isolation submit (TP) + replay (RA) dual-tier | TP+RA | `ShellBrandConsistent` (submit) + `ShellIsolationOnReplay` (replay) | CR-2 | `axioms_e_series.rs:165` + Kani `kani_authorize_property` |
| **E8** | Entry/Space DAG cycle-free + depth ≤ 64 | MC | `EntryParentDagDepthBounded` + `EntryParentDagAcyclic` | R4-I | `axioms_e_series.rs:180` |
| **E9** | Activity self-loop blocked + meta-verb depth ≤ 8 | MC | `ActivitySelfLoopBlocked` + `MetaVerbDepthBounded` | R4-I | `axioms_e_series.rs:189` |
| **E10** | `ArkheUri` 3-tuple `(instance, shell, local)` | TA | (no TLA+ INV — type-system level) | skip | `axioms_e_series.rs:199` |
| **E11** | Cascade re-submit `Op::ScheduleAction Tick(t+1)`, deterministic order | MC | `CascadeOpDeterministicTickPlacement` | CR-3 | `axioms_e_series.rs:211` |
| **E12** | `RuntimeBootstrap` chain-anchored, manifest-drift rejected on replay | MC | `RuntimeBootstrapChainAnchored` + `ManifestDriftReplayRejected` | CR-3 | `axioms_e_series.rs:224` |
| **E13** | `SignatureClassPolicy` chain-anchored, PQC downgrade rejected | MC | `NoSignatureDowngradeAfterPolicy` + `PolicyMonotonic_Derivable` (theorem) | CR-3 | `axioms_e_series.rs:248` |
| **E14** | Compute Determinism Closure: L1 deny-list (build) + L2 allow-list (runtime) ⇒ A1 bit-identical replay | MC | `ChainHashDeterministic` + `HostImportSealed` + `Adversary_A_ResidualReduction` (lemma) + `SealedHostLinker_implies_4_set` (lemma) | CR-1 | `subset-rust-check/src/lib.rs:366,635` + `pure_*` UI + `hook_host/capability_linker.rs` (22 tests) + `wasm_runtime_common/mod.rs` (4 EngineProfile + 2 SealedHostImport witness tests) + Kani `kani_dispatch_property` + `kani_replay_property` + `kani_memory_bounds_check_property` |
| **E15** | Observer Capability Confinement, chain-non-affecting (4-clause) | MC | `ObserverChainNonAffecting` + `ObserverCapabilityConfined` + `QuarantineHostSupervised` + `CapTokenSealed` + `Adversary_B_ResidualReduction` (lemma) + `SealedTrait_implies_E15.b` (lemma) | CR-4 | `observer_host/{mod,capability_linker,wasmtime_observer}.rs` (10 tests) + `wasm_runtime_common/mod.rs` (2 SealedCapToken witness tests) |

Tier legend: **MC** = MACHINE-CHECKED, **TP** = TYPE-PROVEN, **TA** = TYPE-ADJACENT, **RA** = RUNTIME-ASSERTED. Module proof skeletons (concrete TLA+ formulations per INV) live in the per-module `.tla` file headers.

E2 is subsumed by E14 (compute purity is the input-level guarantee A1
bit-identical replay requires). E10 is TYPE-ADJACENT — the 3-tuple
shape is enforced at the Rust type level, no runtime invariant.

**E13 PolicyMonotonic — sticky-Hybrid semantic.** `ShellPolicySnapshot(wal, shell_id)` returns `Hybrid` if any prior `SignatureClassPolicy` event with `declared_class = Hybrid` exists in `wal`, else `Ed25519Only`. `PolicyMonotonic_Derivable` is then a theorem from A14 WAL append-only, not a separate INV. The E13 axiom describes the snapshot as sticky/latching, consistent with this derivation.

## Tooling

### Apalache (CI primary)

CI runs `apalache-mc typecheck` per `.tla` file via the `tla-plus-check`
job in `.github/workflows/ci.yml`. Apalache **0.57.0** jar pinned by
SHA-256 hash from the official `sha256sum.txt` release artefact.

Local run:

```bash
# Java 17 prerequisite. Apalache jar download:
wget https://github.com/apalache-mc/apalache/releases/download/v0.57.0/apalache-0.57.0.tgz
echo "b0eab09c832750cb731786480c48a2768a48d77016b48475fb3945166e350244  apalache-0.57.0.tgz" | sha256sum -c -
tar xzf apalache-0.57.0.tgz

# Type-check any module:
./apalache-0.57.0/bin/apalache-mc typecheck formal/tla-plus/runtime_core.tla

# Bounded MC of an INV:
./apalache-0.57.0/bin/apalache-mc check --inv=ChainHashDeterministic formal/tla-plus/cr1_chain_hash_invariant.tla
```

### TLC (fallback)

Manual fallback for modules where Apalache's SMT-bounded MC is
expected to time out (CR-3 large WAL state). Annotated per-module in
the relevant `.tla` header comment when a module declares TLC fallback.

## Refinement Map convention

Each refinement module includes a `(* --- Refinement Map --- *)`
section with three sub-sections:

1. **Abstract Vars ↔ Concrete Vars** — explicit variable mapping from
   `runtime_core.tla` to the module's concrete state vector.
2. **Abstract step ↔ Concrete step** — refinement predicate
   establishing that any concrete step projects to a valid abstract
   step.
3. **Module-specific INVs** — sealed-completeness chain anchors with
   explicit axiom references (E14, E15, etc.).

Apalache type-checker verifies the mapping's type-soundness
automatically at `apalache-mc typecheck` time.

## Adversary residual reduction lemmas

- **CR-1** anchors **Adversary A** (chain-affecting compute
  determinism) residual reduction. E14.L1-Deny + E14.L2-Allow combined
  reduce the residual surface to (i) host-import allow-list compromise
  and (ii) wasmtime engine zero-day, both out-of-scope per
  `docs/implementation-plan.md` §19.

- **CR-4** anchors **Adversary B** (chain-non-affecting observer
  mutation bypass) residual reduction. E15.a panic close + E15.b
  capability-token confinement reduce the residual surface to (i)
  host-call API implementation defects and (ii) wasmtime engine
  zero-day (same out-of-scope exclusion).

Together CR-1 + CR-4 close the chain-affecting compute axis (Adversary
A) and the chain-non-affecting observer axis (Adversary B) at the
sealing cut.

## Layer A non-violation anchor (sealing constraint)

- **L0 unchanged**: TLA+ specs do NOT modify `arkhe-kernel/src/**` or
  `arkhe-macros/src/**`. `verify-l0-baseline.sh` enforces the 31-files
  SHA-256 baseline.
- **Path placement**: `formal/tla-plus/` is workspace-root sibling to
  `arkhe-kernel/`, NOT inside L0 source tree. The companion Kani
  harness suite (`arkhe-runtime-proofs/`) lives in sibling ArkheForge
  under the same workspace-root parallel convention.
- **Module-tool annotation**: Apalache primary across all 5 modules.
  CR-3 + R4-I have TLC fallback documented when Apalache SMT bounded
  trace > 8 ticks times out.

## Axiom evidence summary

### Phase closure status

| Phase | Deliverable | Status |
|---|---|---|
| Phase 1 (Foundation) | `runtime_core.tla` base module + Apalache CI + Kani scaffold | ✅ closed |
| Phase 2 (TLA+ refinement) | 5 modules: CR-1 + CR-2 + CR-3 + R4-I + CR-4 | ✅ closed |
| Phase 3 (Kani implementation proofs) | 4-property suite | ✅ closed |
| Phase 4 (Cycle close) | this section + Layer A verbatim verify + baseline preservation | ✅ closed |

**Repo-split history note (transparency):** the v0.13 ArkheSourceKernel→ArkheKernel split (initial-commit `eefc929`, 2026-05-03) carried `cr1`/`cr2`/`cr3`/`cr4_*.tla` but transiently dropped two orphan modules — `runtime_core.tla` and `r4_implementation_refinement.tla`. Both were restored in the post-publish CI recovery on 2026-05-04: `a246754` (runtime_core.tla restore + `ci/l0-baseline-hashes.txt` regen for the new repo path) and `ee2687b` (r4_implementation_refinement.tla restore). The Phase 1 + Phase 2 closure claims above describe the substantive verification state — once again backed by every cited module being present in this working tree. See `CHANGELOG.md` and `git log a246754..ee2687b` for the recovery audit trail.

### Kani 4-property suite ↔ axiom mapping

In sibling ArkheForge, `arkhe-runtime-proofs/src/lib.rs`:

| Kani property | Axiom anchor | Tier | Verification target |
|---|---|---|---|
| `kani_authorize_property` | E6 + E7 (typestate + dual-tier shell brand) | TYPE-PROVEN (Rust) + MC (Kani) | Authorization invariant — 32 symbolic cases bounded |
| `kani_dispatch_property` | E14 (Compute Determinism Closure) | MC (build-time L1 + runtime L2) | Twice-dispatch determinism — pure function |
| `kani_replay_property` | A1 (L0 bit-identical replay) via E14 closure | MC (inherited from L0) | Twice-fold determinism — abstract fold |
| `kani_memory_bounds_check_property` | E14.L2 (firm contract anchor) | MC (runtime sandbox) | Pre-deref bounds check — 3-branch exhaustive (Overflow branch structurally unreachable under bounded MC; the verification scope is the in-bounds + OOB partition) |

### Cumulative formal-method coverage

- **TLA+ refinement**: 20 INVs + 2 theorems + 2 lemmas across 5 modules
  - CR-1: 2 INVs (`ChainHashDeterministic` + `ComputePurityHonored`) + 1 lemma (Adversary A residual)
  - CR-2: 5 INVs (`UserIdGloballyUnique` + `ActorIdentityImmutable` + `AuthenticatedActorHasUserBinding` + `ShellBrandConsistent` + `ShellIsolationOnReplay`)
  - CR-3: 5 INVs (`RuntimeBootstrapChainAnchored` + `ManifestDriftReplayRejected` + `CascadeOpDeterministicTickPlacement` + `NoSignatureDowngradeAfterPolicy` + `NoPqcDowngradeAttack`) + 1 theorem (`PolicyMonotonic_Derivable`)
  - R4-I: 5 INVs (`LayerImportStrictlyDownward` + `EntryParentDagDepthBounded` + `EntryParentDagAcyclic` + `ActivitySelfLoopBlocked` + `MetaVerbDepthBounded`)
  - CR-4: 3 INVs (`ObserverChainNonAffecting` + `ObserverCapabilityConfined` + `QuarantineHostSupervised`) + 1 theorem (`ChainProgressionUnaffectedByObserver`) + 1 lemma (Adversary B residual)
- **Kani implementation proofs**: 4 properties (impl-level, complement TLA+ refinement)
- **Axiom coverage**: E3 + E4 + E5 + E6 + E7 + E8 + E9 + E11 + E12 + E13 + E14 + E15 + A1 (12 of 15 E-axioms + L0 A1 inheritance; E1 + E2 + E10 not requiring TLA+ refinement per `runtime_core.tla` foundation)

### Sealing chain — formal-method level closure

**Adversary axis closures**:
- **CR-1 (E14, Adversary A)** — chain-affecting compute determinism. Pre-E14 surface (clock/RNG/I/O/FFI/non-canonical NaN/SIMD/threading) closed by L1-Deny + L2-Allow dual realisation. Residual: (i) host-import allow-list compromise + (ii) wasmtime engine zero-day, both out-of-scope per `docs/implementation-plan.md` §19.
- **CR-3 (E13, PQC downgrade adversary)** — chain-anchored signature class policy. Pre-E13 surface (verifier trusts message-tag without chain anchor) closed by sticky-Hybrid `ShellPolicySnapshotAtTick` + `NoPqcDowngradeAttack` + `NoSignatureDowngradeAfterPolicy`. Residual: (i) WAL forge before chain-anchored detection + (ii) BLAKE3 collision, both out-of-scope.
- **CR-4 (E15, Adversary B)** — chain-non-affecting observer mutation bypass. Pre-E15 surface (native panic propagation + uncontrolled syscall egress) closed by E15.a sandbox boundary catch (atomic ObserverPanic + ObserverQuarantine emission with `emitter="HOST"`) + E15.b capability-token confinement (`{PgWrite}`). Residual: (i) host-call API impl defects (complemented by `kani_memory_bounds_check_property` at impl level) + (ii) wasmtime zero-day, both out-of-scope (symmetric with E14.L2 exclusion).

**Together CR-1 + CR-3 + CR-4 close the sealing chain at the formal-method level**: chain integrity (compute) + chain anchoring (policy) + chain isolation (observer).

### Linker hook-fn 1:1 mapping

In sibling ArkheForge, `arkhe-forge-platform/src/hook_host/capability_linker.rs` enumerates 4 host-fns under `arkhe:hook/*` namespace (cited at lines 22-26 of that file):
- `arkhe:hook/state.read` ↔ TLA+ `"hook.state.read"` (CR-1 `HostImports`)
- `arkhe:hook/state.write` ↔ TLA+ `"hook.state.write"` (CR-1 `HostImports`)
- `arkhe:hook/emit.extra_bytes` ↔ TLA+ `"hook.emit.extra_bytes"` (CR-1 `HostImports`)
- `arkhe:hook/fuel.consumed` ↔ TLA+ `"hook.fuel.consumed"` (CR-1 `HostImports`)

**1:1 mapping ✓** between concrete Linker host-fns and abstract `HostImports` set in CR-1's `ComputePurityHonored` INV.

### Layer A non-violation anchor

**Layer A 8 items verbatim** (canonical ordering):
1. `DOMAIN_CTX` literal
2. `InvariantLifetime` variance
3. `Principal` / `KernelEvent` / `StepStage` derives
4. A11 MACHINE-CHECKED tag
5. ROADMAP Deferred section
6. R4-X DAG (Layer DAG one-way + cargo-modules CI gate)
7. `EventMask` bit allocation
8. `WalRecord` postcard field order

`verify-l0-baseline.sh` enforces the 31-files SHA-256 baseline; the formal/ tree lives outside `arkhe-kernel/src` and `arkhe-macros/src`, so these specs cannot mutate Layer A by construction.

### Test count baseline

7-config workspace baseline: default 540 / federation-archive 543 / audit-receipt 544 / both 548 / tier-2-hook 611 / tier-2-observer 585 / all-features 695. The Kani crate is workspace-excluded via an empty `[workspace]` table and is invisible to `cargo test --workspace`.

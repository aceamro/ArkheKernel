# Invariants — Axiom system

Every guarantee in ArkheKernel reduces to 24 axioms (A1–A24) plus a single
social-contract residual (S1). The tier tags (MACHINE-CHECKED / TYPE-PROVEN /
TYPE-ADJACENT / RUNTIME-ASSERTED / SOCIAL-CONTRACT) indicate how the axiom is
verified — by the compiler, the type system, a runtime assert, or (as a last resort)
documentation and convention.

## Foundation

| ID | Axiom | Tier |
| --- | --- | --- |
| **A1** | Identical config + postcard-canonical input sequence + `ModuleManifest::schema_hash` ⇒ all serialized bytes (WAL records + BLAKE3 chain, snapshot) are bit-identical | MACHINE-CHECKED |
| **A2** | The Kernel is single-threaded. `Kernel: !Sync` (`PhantomData<Rc<()>>`) | TYPE-PROVEN |
| **A3** | Instance independence. Effect reuse across instances is a compile error (A19 GhostCell brand) | TYPE-PROVEN |
| **A4** | `#![forbid(unsafe_code)]` across the entire crate | MACHINE-CHECKED |
| **A5** | Only `BTreeMap`/`BTreeSet` are used. The `HashMap`/`HashSet` family is forbidden (deterministic iteration) | MACHINE-CHECKED |

## State and identity

| ID | Axiom | Tier |
| --- | --- | --- |
| **A6** | `InstanceId` and `EntityId` wrap `NonZeroU64`. Zero is structurally unrepresentable (sentinel-free) | TYPE-PROVEN |
| **A7** | `Principal { Unauthenticated, External(ExternalId), System }` is an exhaustive enum. `Option<Principal>` is forbidden at every auth site | TYPE-PROVEN |
| **A8** | `Effect<S: AuthState, 'i>` is phantom-typed. `authorize()` is the sole `Authorized` constructor | TYPE-ADJACENT |
| **A9** | `CapabilityMask: u64` flows through every `submit`/`authorize`/dispatch path. Kernel-reserved bits are separated from L2-defined bits | TYPE-PROVEN |
| **A10** | Parent quotas strictly bound children. `EffectiveConfig::derive(parent, request) = min(...)` is enforced at compile time | TYPE-PROVEN |

## Purity and totality

| ID | Axiom | Tier |
| --- | --- | --- |
| **A11** | Every function in the determinism protocol (`authorize`, `Action::compute`, `Component::{to_bytes,from_bytes,approx_size,canonical_bytes}`, `AuthInputs::project`) is pure in its declared inputs. Enforced by the `#[kernel_pure]` dylint + sealed-derive proc-macro + the `Effect::<Authorized>::__new` single-callsite lint | MACHINE-CHECKED |
| **A12** | Every kernel-internal Drop impl is total (no panic along any reachable path). The `no_panic` attribute turns a reachable panic into a linker error | MACHINE-CHECKED |

## Cryptographic discipline

| ID | Axiom | Tier |
| --- | --- | --- |
| **A13** | The WAL chain hash uses `blake3::derive_key(WAL_CHAIN_CONTEXT, world_seed)` + `Hasher::new_keyed`. Cross-domain hash collisions are structurally impossible | TYPE-PROVEN |
| **A14** | The WAL header pins kernel semver, postcard version, blake3 version, world_id, abi_version, manifest_digest, and type_registry_pins. Replay against an incompatible header returns `ReplayError::WalHeaderIncompatible` | MACHINE-CHECKED |
| **A15** | `TypeCode × schema_hash` is append-only within a `world_id` across every kernel restart. Re-registering a mismatching schema_hash returns `RegistryError::TypeCodeDrift` | MACHINE-CHECKED |
| **A16** | `SignatureClass { None, Ed25519 }` is declared at builder time. The tier semantics ("tamper-evident chained replay" — not "cryptographic-grade") are explicit | MACHINE-CHECKED |
| **A17** | Persistence is postcard-canonical. The `CanonicalEncode` sealed trait + derive-only pathway forbids `String`, floats, and foreign `Ord` in canonical positions | MACHINE-CHECKED |
| **A18** | Observer emissions are staged in `StepStage`. Draining happens only after WAL fsync completes (Durable: per-step, GroupCommit: per-N, BestEffort: per-app-barrier) | TYPE-ADJACENT |

## Extension axioms

| ID | Axiom | Tier |
| --- | --- | --- |
| **A19** | `Effect<S, 'i>` brand: invariant lifetime (GhostCell pattern, Yanovski et al. ICFP 2021). Cross-instance reuse fails lifetime unification at compile time | TYPE-PROVEN |
| **A20** | `StepStage` captures all ten commit-conditional writes (state_ops, events, schedule_deltas, id_counters, ledger_delta, inflight_refs_delta, wall_remainder_delta, local_tick_delta, pending_signals, observer_eviction_pending). `Instance` is mutated only through `apply_stage` | TYPE-ADJACENT |
| **A21** | `InstanceConfig::quota_reduction: QuotaReductionPolicy { Reject, GrandfatherExisting, ThrottleProportional }`. The default is Reject. Each variant has a deterministic algorithm | TYPE-PROVEN |
| **A22** | Observers are evicted on first panic. `ObserverEvicted { observer_index, panic_at_seq, panic_count_before_eviction: 1 }` is emitted. Re-registration requires the `OBSERVER_REGISTER` cap | RUNTIME-ASSERTED |
| **A23** | Per-tick instance step order is ascending `InstanceId` (NonZeroU64 lex). `BTreeMap` iteration supplies this for free | TYPE-PROVEN |
| **A24** | `AuthInputs` has private fields and a single constructor, the sealed `pub(crate) fn project()`. Canonical projection operates on `InstanceScope<'i>` + `StagedStateAtIndex` | TYPE-ADJACENT |

## Social-contract residual

| ID | Residual | Tier |
| --- | --- | --- |
| **S1** | `Clock::now()` monotonicity is documented in [Domain Spec](domain-spec.md). It is not type-enforced; the kernel preserves forward progress with `max(observed, previous)` | SOCIAL-CONTRACT |

## Counts by verification tier

| Tier | Count | Members |
| --- | --: | --- |
| MACHINE-CHECKED | **9** | A1, A4, A5, A11, A12, A14, A15, A16, A17 |
| TYPE-PROVEN | **10** | A2, A3, A6, A7, A9, A10, A13, A19, A21, A23 |
| TYPE-ADJACENT | **4** | A8, A18, A20, A24 |
| RUNTIME-ASSERTED | **1** | A22 |
| SOCIAL-CONTRACT | **1** | S1 |

Total: 25 (24 axioms + 1 social residual). Growth in AI-adversary capability applies
pressure incrementally to the lower three tiers (TYPE-ADJACENT, RUNTIME-ASSERTED,
SOCIAL-CONTRACT — six items combined). Per-item promotion paths are catalogued in the
[Threat Model](threat-model.md).

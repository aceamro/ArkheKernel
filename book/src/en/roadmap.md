# Roadmap

This document records the closing scope of ArkheKernel v0.11 and candidate extensions
for subsequent work.

## Closing scope — v0.11

| Scope | Status | Detail |
| --- | --- | --- |
| **ABI foundation** | Done | `abi/` stratum: ids, principal, caps, error |
| **State sealed traits** | Done | `state/` sealed traits via `arkhe-macros` (`ArkheAction`/`ArkheComponent`/`ArkheEvent`); A11 MACHINE-CHECKED recovery; `apply_quota_reduction` algorithm; BTreeMap immediate-cancel scheduler; ResourceLedger always on |
| **Runtime orchestrator** | Done | `runtime/`: dispatch + StepStage commit-or-rollback; EventMask-filtered observer pipeline; `force_unload` (R4-R drain hatch); `instance_view` read API; `stats` aggregate observability. `Kernel: !Sync` preserved |
| **ADMIN_UNLOAD cap path** | Done | `ADMIN_UNLOAD` cap path complete. `IntrospectHandle` grant-once API + ModuleManifest TypeCodePin deferred to future extensions |
| **Persistence** | Done | `persist/`: WalHeader + BLAKE3 keyed chain (R4-F); WAL replay (`replay_into`); `KernelSnapshot` point-in-time blob (orthogonal to WAL); `SignatureClass { None, Ed25519 }` (Tier 1 + 2) |
| **Determinism proof** | Done | The dice-domain demo reports `✓ A1 D1-Total verified` (WAL chain bit-identical) and passes the snapshot byte-identical determinism test |

## Deferred extensions

Items **excluded** from v0.11. Each item retains a named promotion path.

- **R4-J Subset-Rust pure L1 checker** — statically blocks non-A11 APIs from domain crates;
  promotes `ActionCompute::compute()` purity from SOCIAL-CONTRACT (declaration) to MACHINE-CHECKED.
- **WASM sandbox option for L1** — alternative to Subset-Rust; instruction counter for runtime
  fairness; complementary to R4-J.
- **Per-step cycle-budget watchdog** — refuses further Op dispatch inside `step()` when the
  cycle count exceeds a per-instance ceiling. Runtime counterpart of the memory budget.
- **TLA+ formal specs CR-1/2/3 + R4-I** — composed model checking of StepStage rollback,
  cross-instance IPC re-auth, refcount oracle, and σᵢ₋₁ snapshot ordering.
- **Implementation-level proofs (Kani / Creusot)** — beyond TLA+ specifications; machine-checked
  Rust property proofs for authorize, dispatch, and replay.
- **WAL streaming export** — incremental fsync as each record arrives (the current release is
  buffer-then-export).
- **Snapshot + WAL hybrid replay** — start from a snapshot and apply tail WAL records.
  The current release keeps the two mechanisms independent.
- **Per-entity authority granularity** — `Effect<AuthorizedFor<EntityId>>` finer than
  whole-Effect authorization.
- **`Clock::now()` typestate `impl Monotonic<Tick>`** — removes the last SOCIAL-CONTRACT
  residual (S1).
- **`Kernel<NotStepping>` live-registration retrofit** — threads the register_module fence
  through a trait parameter (currently a runtime check).
- **Capability-based revocation** — seL4-style `Kernel::revoke(&handle)`.
- **`SignatureClass::TransparencyLog`** — Tier 3 CT-style append-only Merkle log (deferred
  above R4-C Tier 2).
- **`IntrospectHandle<Scoped<InstanceId>>`** — const-generic activation once `adt_const_params`
  stabilizes; finer than the current `InstanceView` read surface.
- **`ModuleManifest::TypeCodePin` set populated from `ActionRegistry` snapshot** — the current
  release ships an empty WAL header `type_registry_pins` slot; snapshot integration will fill
  it (R4-D cross-restart pin set).
- **`WalRecord` recorded `AuthDecision` full enum** — the current release records a 1-byte
  annotation; the schema slot is reserved for the full enum as a forensic trail.
- **Component / Event WAL replay integration** — the `ArkheComponent`/`ArkheEvent` derive
  surfaces ship; first-class WAL paths (parallel to Action) are deferred.
- **Observer readmission cooldown / ADMIN_UNLOAD cap lifecycle** — remaining backlog.

Every item retains cross-references to [INVARIANTS](architecture/invariants.md) and
[Decisions](appendix/decisions.md).

This document tracks technical completeness only; it does not include business milestones.

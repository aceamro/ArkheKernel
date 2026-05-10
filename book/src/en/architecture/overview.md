# Overview

ArkheKernel is a single crate split into four strata. Dependencies flow **strictly
downward** (R4-X) — reverse imports fail the CI gate at build time.

## Layer DAG

```text
   abi  ───►  state  ───►  runtime  ───►  persist
   │           │            │              │
   └─── unidirectional, pub(crate) edges. No back-edges.
```

| Stratum | Responsibility | Core types |
| --- | --- | --- |
| [`abi`](https://docs.rs/arkhe-kernel/latest/arkhe_kernel/abi/) | Identifiers, principals, capability bits, error taxonomy | `InstanceId`, `EntityId`, `Tick`, `TypeCode`, `Principal`, `CapabilityMask`, `ArkheError` |
| [`state`](https://docs.rs/arkhe-kernel/latest/arkhe_kernel/state/) | Sealed traits, instance state, authorization phantom types | `Action`/`Component`/`Event`, `Op`, `Effect<'i, S>`, `InstanceConfig`, `ActionContext` |
| [`runtime`](https://docs.rs/arkhe-kernel/latest/arkhe_kernel/runtime/) | Orchestrator, step-stage commit, observer pipeline, read view | `Kernel`, `StepReport`, `Stats`, `KernelObserver`, `EventMask`, `InstanceView` |
| [`persist`](https://docs.rs/arkhe-kernel/latest/arkhe_kernel/persist/) | WAL chain, snapshot blob, Ed25519 signing, replay | `Wal`, `WalHeader`, `WalRecord`, `KernelSnapshot`, `SignatureClass`, `replay_into` |

## Public API summary

`Kernel` constructors:
- `Kernel::new()` — bare kernel
- `Kernel::new_with_wal(world_id, manifest_digest)` — Tier 1 (chain only)
- `Kernel::new_with_wal_signed(world_id, manifest_digest, SignatureClass)` — Tier 2 Ed25519
- `Kernel::from_snapshot(KernelSnapshot)` — restore from a serialized point-in-time state

Read operations:
- `instance_view(id) -> Option<InstanceView<'_>>` — read-only borrow
- `stats() -> Stats` — aggregate counters across all instances
- `wal_chain_tip()`, `wal_record_count()`, `export_wal()`
- `snapshot() -> KernelSnapshot`

Write operations:
- `register_action::<A>()`, `register_observer(...)`,
  `register_observer_filtered(..., EventMask)`
- `create_instance(InstanceConfig) -> InstanceId`
- `submit(...) -> Result<ScheduledActionId, ArkheError>`
- `step(Tick, CapabilityMask) -> StepReport`
- `force_unload(RouteId, CapabilityMask) -> Result<usize, ArkheError>` (R4-R, requires ADMIN_UNLOAD)

Derive macros used by L1 domains:
- `#[derive(ArkheAction)]` + `impl ActionCompute`
- `#[derive(ArkheComponent)]`
- `#[derive(ArkheEvent)]`

All three derives accept `#[arkhe(type_code = N, schema_version = M)]`.

## Determinism guarantee (three lines)

1. **WAL chain** — `blake3::keyed(chain_key, prev_hash || canonical_body)`. A single-byte
   tamper is detected immediately by chain verification.
2. **Snapshot** — `BTreeMap` iteration + postcard canonical encoding ⇒ the same state produces
   the same bytes.
3. **Replay** — replaying WAL records from the beginning reaches a chain tip bit-identical to
   the original (A1 D1-Total).

The dice demo exercises all three at once:

```bash
cargo run -p dice
# ✓ A1 D1-Total verified: WAL replay is bit-identical.
```

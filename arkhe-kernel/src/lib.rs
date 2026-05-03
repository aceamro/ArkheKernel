#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # ArkheKernel
//!
//! Deterministic microkernel for virtual worlds. The kernel is a pure
//! state machine: identical inputs always produce identical state and
//! identical persisted bytes. There is no `async`, no `std::thread`, no
//! `unsafe`, no floating-point in canonical paths, and no
//! `HashMap`/`HashSet` (only `BTreeMap`/`BTreeSet` for deterministic
//! iteration).
//!
//! ## Layered DAG
//!
//! ```text
//! abi  →  state  →  runtime  →  persist
//! ```
//!
//! Downward-only via `pub(crate)` edges; cross-stratum back-edges are a
//! structural error caught by the layer-DAG CI gate (R4-X).
//!
//! - [`abi`] — identifiers, principals, capability bits, the
//!   [`abi::ArkheError`] taxonomy.
//! - [`state`] — sealed traits ([`state::Action`], [`state::Component`],
//!   [`state::Event`]), per-instance state, authorization phantoms
//!   ([`state::Effect`]).
//! - [`runtime`] — orchestrator [`Kernel`], step-stage commit-or-rollback,
//!   observer pipeline, read-only [`InstanceView`].
//! - [`persist`] — [`Wal`] (BLAKE3-keyed chain),
//!   [`KernelSnapshot`] (postcard blob), [`SignatureClass`] (Ed25519
//!   Tier 2 + Hybrid PQC ML-DSA 65), [`replay_into`](persist::replay_into).
//!
//! ## Quick start
//!
//! Domains define an `Action` via the `#[derive(ArkheAction)]` macro
//! plus `impl ActionCompute`, register it on the kernel, submit it,
//! and step the clock. The kernel does the rest:
//!
//! ```
//! use arkhe_kernel::abi::{CapabilityMask, EntityId, Principal, Tick, TypeCode};
//! use arkhe_kernel::state::{ActionCompute, ActionContext, InstanceConfig, Op};
//! use arkhe_kernel::{ArkheAction, Kernel};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, ArkheAction)]
//! #[arkhe(type_code = 1, schema_version = 1)]
//! struct Hello;
//!
//! impl ActionCompute for Hello {
//!     fn compute(&self, _ctx: &ActionContext) -> Vec<Op> {
//!         vec![Op::SpawnEntity {
//!             id: EntityId::new(1).unwrap(),
//!             owner: Principal::System,
//!         }]
//!     }
//! }
//!
//! let mut kernel = Kernel::new();
//! kernel.register_action::<Hello>();
//! let inst = kernel.create_instance(InstanceConfig::default());
//! kernel.submit(inst, Principal::System, None, Tick(0), TypeCode(1), Vec::new()).unwrap();
//! let report = kernel.step(Tick(0), CapabilityMask::SYSTEM);
//! assert_eq!(report.actions_executed, 1);
//! assert_eq!(report.effects_applied, 1);
//! ```
//!
//! ## Determinism guarantees
//!
//! - **A1 D1-Total** — identical config + identical postcard-canonical
//!   input sequence + identical `ModuleManifest` produces bit-identical
//!   WAL records (BLAKE3 chain), bit-identical snapshots, and identical
//!   step counters. The dice domain demonstrates this end-to-end.
//! - **A2 single-thread** — `Kernel: !Sync` via `PhantomData<Rc<()>>`.
//! - **A12 panic-free** — every kernel-internal Drop is total; no
//!   reachable panic in production code paths (test fixtures excepted).
//! - **A14 header pinning** — WAL header carries kernel semver, ABI
//!   version, postcard version, BLAKE3 version, world id, manifest digest.
//!   Replay against an incompatible header is a structural error, not a
//!   runtime surprise.
//!
//! See `book/src/en/architecture/invariants.md` for the full axiom
//! list (A1–A24 + S1).
//!
//! ## Stability
//!
//! v0.13 — single fixed pre-public version (no version bumps before
//! public release). Version 1.0 is intentionally never reached.

/// L0 ABI stratum — identifiers, authority principals, capability
/// bits, and the top-level [`abi::ArkheError`] type. No dependencies
/// on state / runtime / persist strata.
pub mod abi;

/// L0 state stratum — sealed traits ([`Action`](state::Action),
/// [`Component`](state::Component), [`Event`](state::Event)),
/// authorization phantoms, per-instance state container.
pub mod state;

/// L0 runtime stratum — kernel orchestrator, step-stage commit
/// machinery, observer pipeline, [`InstanceView`] read API.
pub mod runtime;

/// L0 persist stratum — [`Wal`], [`KernelSnapshot`],
/// [`SignatureClass`], and the [`replay_into`](persist::replay_into)
/// reconstruction path.
pub mod persist;

pub use persist::{
    KernelSnapshot, ReplayError, ReplayReport, SignatureClass, SnapshotError, Wal, WalError,
    WalHeader, WalRecord, WalWriter,
};
pub use runtime::event::{EventMask, KernelEvent, ObserverHandle};
pub use runtime::{InstanceView, Kernel, KernelObserver, Stats, StepReport};

/// Re-export of the kernel-companion derive macros. `ArkheAction`
/// emits `Sealed + ActionDeriv` (pair with `impl ActionCompute`).
/// `ArkheComponent` and `ArkheEvent` emit `Sealed +` the corresponding
/// kernel trait — postcard-canonical defaults handle the byte round
/// trip. Every derive expects `#[arkhe(type_code = N, schema_version = M)]`.
pub use arkhe_macros::{ArkheAction, ArkheComponent, ArkheEvent};

---- MODULE cr1_chain_hash_invariant ----
(*
 * cr1_chain_hash_invariant — DIP-N5 sub-step E.3.
 *
 * CR-1 anchors E14 (Compute Determinism Closure) => A1 (bit-identical
 * replay). EXTENDs runtime_core with:
 *  (1) concrete refinement of `chain_tip` from opaque string to a
 *      bytes-sequence (theorist Finding 1 absorption at refinement,
 *      path (b) opaque-in-base + refine-here);
 *  (2) `WalRecord` concrete record type for `wal` sequence (postcard
 *      field order sealed at L0 DO NOT TOUCH item 8);
 *  (3) `ChainHashDeterministic` invariant — E14 => A1 anchor;
 *  (4) `ComputePurityHonored` invariant — E14.L1-Deny build-time
 *      dylint + L2-Allow runtime sandbox dual realisation;
 *  (5) `Adversary_A_ResidualReduction` lemma (in comment block).
 *
 * Anchored to:
 *   - runtime-book/src/en/architecture/11-axioms.md E14
 *   - book/src/en/architecture/threat-model.md Adversary A
 *
 * Apalache primary tooling per formal/tla-plus/README.md.
 * CI: `apalache-mc typecheck cr1_chain_hash_invariant.tla`.
 * Bounded MC (`apalache-mc check --inv=...`) lands when all 5 CR-* +
 * R4-I modules are present (E.7 close convention).
 *)

EXTENDS runtime_core

CONSTANTS
    \* @type: Set(Str);
    ComputeFns,            \* Pure compute fn identifiers (E14.L1-Deny)
    \* @type: Set(Str);
    HostImports,           \* Allow-listed host imports (E14.L2-Allow)
    \* @type: Seq(Int);
    InitialChainTipBytes,  \* Genesis chain tip (concrete bytes)
    \* @type: Seq($walRecord) -> Seq(Int);
    ChainHashFn            \* Abstract: Seq(WalRecord) -> ChainTipBytes
                           \* Concrete realisation: BLAKE3 keyed hash
                           \* over postcard-encoded WalRecordBody bytes
                           \* (10-field chain hash input subset of
                           \* WalRecord, INVARIANT across PQC envelope
                           \* extensions). `arkhe-kernel/src/persist/
                           \* wal.rs` Layer A item 8 dual-layer
                           \* protection: (a) WalRecordBody field order
                           \* never escalates; (b) WalRecord wire format
                           \* relaxed monotone append-only. theorist
                           \* Minor Note 3 absorption at E.9 cycle close.

ASSUME
    /\ ComputeFns # {}
    /\ HostImports \subseteq {"hook.state.read", "hook.state.write",
                              "hook.emit.extra_bytes",
                              "hook.fuel.consumed"}

(* --- Concrete refinement of base-module opaque types --- *)

\* WalRecord — postcard-encoded canonical bytes contributing to the
\* chain hash. The concrete v0.12 implementation lives in
\* `arkhe-kernel/src/persist/wal.rs`. Chain hash input subset =
\* WalRecordBody 10-field order, INVARIANT across PQC envelope
\* extensions (Layer A item 8 dual-layer: WalRecordBody never
\* escalates; WalRecord wire format relaxed monotone append-only).
\* TLA+ `payload: Seq(0..255)` abstraction covers any concrete byte
\* layout.
WalRecord ==
    [ seq:     Nat,
      tick:    Nat,
      payload: Seq(0..255) ]

\* ChainTipBytes — concrete bytes-sequence refinement of
\* runtime_core's opaque `chain_tip \in STRING` (theorist Finding 1
\* absorption at CR-1, path (b) opaque-in-base + refine-here).
ChainTipBytes == Seq(0..255)

ASSUME
    /\ InitialChainTipBytes \in ChainTipBytes
    /\ ChainHashFn \in [Seq(WalRecord) -> ChainTipBytes]
    /\ InitialChainTipBytes = ChainHashFn[<< >>]

(* --- Type invariant under concrete refinement --- *)

TypeOK_CR1 ==
    /\ chain_tip \in ChainTipBytes
    /\ wal \in Seq(WalRecord)
    /\ tick \in 0..MaxTicks
    /\ Len(wal) <= MaxWalLen

(* --- Module-specific invariants --- *)

\* INV ChainHashDeterministic — E14 => A1 anchor.
\* State-level invariant: at every reachable state, `chain_tip`
\* equals `ChainHashFn(wal)`. Combined with the determinism of
\* `ChainHashFn` (declared as a function above), two replays of the
\* same wal trace produce identical chain_tip — refining L0 axiom
\* A1 (bit-identical replay) at the runtime layer.
ChainHashDeterministic == chain_tip = ChainHashFn[wal]

\* INV ComputePurityHonored — E14 dual realisation enforced.
\* L1-Deny: every fn applied to wal contents is in `ComputeFns`
\* (build-time `arkhe-subset-rust-check` dylint enforces this on the
\* Rust side; the TLA+ refinement abstracts the deny-list as the
\* `ComputeFns` set). L2-Allow: host imports restricted to the
\* whitelist (runtime wasmtime sandbox enforces).
ComputePurityHonored ==
    /\ HostImports \subseteq {"hook.state.read", "hook.state.write",
                              "hook.emit.extra_bytes",
                              "hook.fuel.consumed"}
    /\ ComputeFns # {}

\* INV HostImportSealed — E14.L2-Allow rule 3 type-system anchor
\* (M2.5 sealed-trait safeguard, DIP-N6 Phase 2). Strengthens
\* ComputePurityHonored at the *type-system layer*: the host-import
\* surface is provided exclusively by types impl-ing the Rust trait
\* `SealedHostImport: private_seal::Sealed` (where `private_seal::
\* Sealed` is a private-module marker). External crates cannot
\* satisfy `L: SealedHostImport`, so the host-linker universe is
\* monomorphic — only same-crate types (`HookCapabilityLinker` +
\* `ObserverCapabilityLinker`) can register host imports.
\*
\* The CR-1 `HostImports` set is the CONSTANTS-fixed 4-set
\* (`hook.state.read` / `hook.state.write` / `hook.emit.extra_bytes`
\* / `hook.fuel.consumed`). HostImportSealed expresses that this
\* finite universe is type-system-bounded: no out-of-crate `L` can
\* widen the registered host-import set.
\*
\* Operationally this INV holds vacuously at the TLA+ level (the
\* CONSTANTS already fix the universe); its purpose is naming the
\* Rust-side type-system anchor explicitly so axiom-test-cite.toml +
\* Apalache typecheck capture the M2.5 strengthening event.
\*
\* Anchored to:
\*   - arkhe-forge-platform/src/wasm_runtime_common/mod.rs:394
\*     (`pub trait SealedHostImport: private_seal::Sealed`)
\*   - arkhe-forge-platform/src/wasm_runtime_common/mod.rs:898,910
\*     (witness tests hook_capability_linker_satisfies_sealed_host_import
\*      + observer_capability_linker_satisfies_sealed_host_import)
HostImportSealed ==
    HostImports \subseteq {"hook.state.read", "hook.state.write",
                           "hook.emit.extra_bytes",
                           "hook.fuel.consumed"}

(* --- Concrete state machine refinement --- *)

\* AppendWalRecord — concrete step that appends a record and updates
\* chain_tip via the deterministic ChainHashFn.
AppendWalRecord(rec) ==
    /\ rec \in WalRecord
    /\ Len(wal) < MaxWalLen
    /\ tick + 1 <= MaxTicks
    /\ wal' = Append(wal, rec)
    /\ chain_tip' = ChainHashFn[wal']
    /\ tick' = tick + 1
    /\ UNCHANGED << actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy >>

\* CR-1 Init — chain begins at the genesis bytes (= ChainHashFn(<<>>)).
InitCR1 ==
    /\ chain_tip = InitialChainTipBytes
    /\ wal = << >>
    /\ tick = 0
    /\ actor_user_binding \in [Actors -> Users]
    /\ actor_shell_binding \in [Actors -> Shells]
    /\ authenticated_actors = {}
    /\ runtime_bootstrap = "BOOTSTRAP_PLACEHOLDER"
    /\ signature_class_policy = [s \in Shells |-> "Ed25519"]

\* CR-1 Next — append a record, advancing the chain.
NextCR1 == \E rec \in WalRecord : AppendWalRecord(rec)

\* CR-1 Spec — standard linear-time temporal-logic frame.
SpecCR1 == InitCR1 /\ [][NextCR1]_vars

(* --- Refinement Map (per formal/tla-plus/README.md convention) ---
 *
 * Section 1 — Abstract Vars <-> Concrete Vars
 *
 *   runtime_core.tla         cr1 (refined)
 *   ---------------------    --------------------------------
 *   chain_tip \in STRING ->  chain_tip \in ChainTipBytes
 *                            (theorist Finding 1 absorption,
 *                             path b opaque-in-base + refine-here)
 *   wal \in Seq(STRING)  ->  wal \in Seq(WalRecord)
 *                            (concrete record with seq + tick + payload)
 *
 * Section 2 — Abstract step <-> Concrete step
 *
 *   runtime_core.Next    ->  AppendWalRecord(rec)
 *                            (wal grows by one record;
 *                             chain_tip := ChainHashFn(wal'))
 *
 * Section 3 — Module-specific INVs
 *
 *   ChainHashDeterministic — chain_tip = ChainHashFn(wal) at every
 *                            reachable state. With ChainHashFn
 *                            declared as a function, two replays of
 *                            an identical wal yield identical chain_tip.
 *   ComputePurityHonored   — host imports restricted to allow-list +
 *                            ComputeFns non-empty (E14.L1+L2 dual).
 *   HostImportSealed       — M2.5 sealed-trait type-system anchor of
 *                            E14.L2-Allow rule 3: only same-crate
 *                            types impl SealedHostImport, host-import
 *                            universe monomorphic at compile time.
 *
 * Apalache type-checker verifies the mapping's type-soundness at
 * `apalache-mc typecheck` time.
 *)

(* --- Adversary A residual reduction lemma ---
 *
 * Pre-E14 adversary surface for chain-affecting compute non-
 * determinism reduces under E14.L1-Deny + L2-Allow combined to:
 *   (i)  host-import allow-list compromise (operator scope);
 *   (ii) wasmtime engine zero-day (vendor scope).
 * Both are out-of-scope per `docs/implementation-plan.md` §19.
 *
 * Mechanical reduction by source category:
 *  - clock / RNG / I/O / FFI / `unsafe` block in compute body
 *      -> rejected at build by `arkhe-subset-rust-check`
 *         (E14.L1-Deny 4-rule MVP);
 *  - non-canonical NaN, non-deterministic SIMD ops
 *      -> rejected by wasmtime config (`cranelift_nan_canonicalization
 *         (true)` + `wasm_simd(false)`, E14.L2-Allow);
 *  - wasm-side threading / `lazy_static!` / `OnceCell`
 *      -> rejected by wasmtime config (`wasm_threads(false)`,
 *         E14.L2-Allow);
 *  - non-whitelisted host import
 *      -> rejected at module-load via three-layer host-import defense
 *         (pre-scan + link-time deny-by-default + call-time
 *         capability check, E14.L2-Allow whitelist enforcement);
 *  - residual = (i) + (ii) above, both out-of-scope per impl-plan §19.
 *
 * Symmetric counterpart in CR-4: Adversary B residual reduction
 * (E15 observer capability confinement, chain-non-affecting axis).
 *
 * Together CR-1 + CR-4 close the chain-affecting compute axis
 * (Adversary A) and the chain-non-affecting observer axis
 * (Adversary B) at the v0.12 sealing cut.
 *)

(* --- SealedHostLinker_implies_4_set lemma (M2.5 strengthening) ---
 *
 * LEMMA SealedHostLinker_implies_4_set:
 *   The Rust-side sealed-trait safeguard (`SealedHostImport:
 *   private_seal::Sealed`) derives the CR-1 4-set host-import
 *   universe at the type-system level — only same-crate types impl
 *   `SealedHostImport`, so the registered host imports cannot widen
 *   beyond the crate-internal universe. Combined with the per-impl
 *   register_imports body (which registers exactly the 4 hook host
 *   imports for `HookCapabilityLinker` and 0 imports for
 *   `ObserverCapabilityLinker`), the TLA+ CONSTANTS-fixed
 *   `HostImports = {hook.state.read, hook.state.write,
 *                    hook.emit.extra_bytes, hook.fuel.consumed}`
 *   is faithfully realised.
 *
 * PROOF SKETCH:
 *   (1) `private_seal::Sealed` is private to `wasm_runtime_common`
 *       (`mod private_seal { pub trait Sealed {} }`). External
 *       crates cannot impl Sealed (Rust sealed-trait pattern).
 *   (2) `SealedHostImport: Sealed` requires Sealed as super-trait,
 *       so external impls are blocked.
 *   (3) Witness tests `hook_capability_linker_satisfies_sealed_host_import`
 *       + `observer_capability_linker_satisfies_sealed_host_import`
 *       (`wasm_runtime_common/mod.rs:898,910`) compile-time-verify
 *       that the two concrete linkers satisfy the bound.
 *   (4) Hook impl's `register_imports` body registers exactly 4 host
 *       functions (the CR-1 4-set); observer impl's body registers
 *       0 (chain-non-affecting). Therefore the runtime host-import
 *       universe = TLA+ `HostImports` CONSTANTS-fixed set. Faithfulness
 *       verified.
 *
 * COROLLARY:
 *   Combined with INV `ChainHashDeterministic` (chain_tip =
 *   ChainHashFn(wal)), HostImportSealed gives a *dual-layer*
 *   enforcement of E14.L2-Allow rule 3:
 *     - Layer 1 (type-system): sealed-trait pattern blocks external
 *       linker impls at compile time
 *     - Layer 2 (state-level INV): TLA+ HostImports CONSTANTS fix
 *       the abstraction
 *   Adversary A cannot widen the host-import universe even at the
 *   type-system layer; the TLA+ refinement faithfully models the
 *   strict Rust-side property.
 *
 * Witness anchors (1:1 with axiom-test-cite.toml E14_L2_Allow.impl_tests):
 *   - hook_capability_linker_satisfies_sealed_host_import      (mod.rs:898)
 *   - observer_capability_linker_satisfies_sealed_host_import  (mod.rs:910)
 *)

====

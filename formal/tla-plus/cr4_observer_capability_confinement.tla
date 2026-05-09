---- MODULE cr4_observer_capability_confinement ----
(*
 * cr4_observer_capability_confinement.
 *
 * CR-4 anchors E15 (Observer Capability Confinement, chain-non-
 * affecting, 4-clause). Together with CR-1 (Adversary A, E14) +
 * CR-2 (E4-E7 multi-shell) + CR-3 (E11-E13 + PQC) + R4-I (E3 +
 * E8 + E9 layering/DAG), CR-4 completes the formal-method
 * sealing chain.
 *
 * EXTENDs runtime_core with:
 *  (1) ObserverCapToken set ({"PgWrite"} initial enum, additive);
 *  (2) ObserverInvocation record (observer + cap_token + payload);
 *  (3) ObserverPanic + ObserverQuarantine event records;
 *  (4) Module-specific INVs + 1 theorem + 1 lemma;
 *  (5) Concrete state machine: ObserverNominalStep + Observer-
 *      PanicTransition (atomic with host-supervised quarantine).
 *
 * E15 4-clause invariant coverage:
 *   #1 observer host-fn never call chain-mutation primitives
 *      → captured by VARIABLES partition (observer state in
 *        cr4 vars, chain state in runtime_core vars carry-through)
 *        + UNCHANGED << chain_tip, wal >> in all observer sub-
 *        actions
 *   #2 ObserverCapability::execute carries `&[u8]` payload only
 *      → captured at type level (Payloads opaque byte set, no
 *        chain-mutation operations exposed)
 *   #3 ObserverQuarantine emission is host-supervised
 *      → INV `QuarantineHostSupervised` (emitter = "HOST" field)
 *   #4 panic isolation preserves chain progression
 *      → INV `ObserverChainNonAffecting` (panic-quarantine 1:1
 *        correspondence) + UNCHANGED conjuncts in transitions
 *
 * E15.a panic close: observer trap caught at sandbox boundary;
 * host emits ObserverQuarantine atomically — captured by
 * ObserverPanicTransition action that updates observer_panics
 * AND quarantine_events in the same step.
 *
 * E15.b capability confinement: ObserverCapToken set is the only
 * authorized side-effect channel. Direct syscalls/wasi rejected
 * at module-load — captured at TLA+ abstraction level by
 * cap_token field type-bounded to ObserverCapTokens.
 *
 * Adversary B residual reduction (chain-non-affecting observer
 * mutation bypass): pre-E15 surface = native panic propagation +
 * uncontrolled syscall egress. E15.a closes the native-crash
 * channel; E15.b closes uncontrolled egress. Residual: (i) host-
 * call API implementation defects + (ii) wasmtime engine zero-day
 * (out-of-scope under the project residual policy, symmetric
 * with E14.L2 wasmtime zero-day exclusion).
 *
 * Symmetric counterparts:
 *   - CR-1 (Adversary A, chain-affecting compute determinism via E14)
 *   - CR-3 (PQC downgrade adversary, chain-anchored policy via E13)
 *   - CR-4 (Adversary B, chain-non-affecting observer mutation via E15)
 *
 * CR-1 + CR-3 + CR-4 close the formal-method sealing chain along
 * three axes: chain integrity (compute) + chain anchoring (policy)
 * + chain isolation (observer).
 *
 * Tier annotations per `formal/tla-plus/README.md` §2 mapping:
 *   - E15-ObserverChainNonAffecting (MC, 4-clause #1+#4 anchor)
 *   - E15-ObserverCapabilityConfined (MC, type-level + operational)
 *   - E15-QuarantineHostSupervised (MC, host-emit witness #3)
 *   - E15-CapTokenSealed (MC, sealed-trait safeguard companion)
 *   - E15-Adversary_B_ResidualReduction (lemma)
 *
 * Anchors the E15 axiom (4-clause Observer Capability Confinement).
 *
 * Apalache primary tooling. CI: `apalache-mc typecheck` per .tla.
 *)

EXTENDS runtime_core

\* @typeAlias: observerId = Str;
ALIAS_observerId == TRUE

\* @typeAlias: payload = Str;
ALIAS_payload == TRUE

\* @typeAlias: capToken = Str;
ALIAS_capToken == TRUE

\* @typeAlias: observerInvocation = { observer: Str, cap_token: Str, payload: Str };
ALIAS_observerInvocation == TRUE

\* @typeAlias: observerPanic = { observer: Str, panic_tick: Int };
ALIAS_observerPanic == TRUE

\* @typeAlias: observerQuarantine = { observer: Str, panic_tick: Int, emit_tick: Int, emitter: Str };
ALIAS_observerQuarantine == TRUE

CONSTANTS
    \* @type: Set($observerId);
    ObserverIds,             \* Observer identifier set
    \* @type: Set($payload);
    Payloads,                \* Abstract opaque byte payload set (E15.b
                             \* clause #2 — chain-orthogonal at type-level)
    \* @type: Set($capToken);
    ObserverCapTokens,       \* {"PgWrite"} initial enum, additive
    \* @type: Int;
    MaxObserverInvocations,  \* Bounded MC ceiling
    \* @type: Int;
    MaxObserverPanics,       \* Bounded MC ceiling
    \* @type: Int;
    MaxQuarantineEvents      \* Bounded MC ceiling

ASSUME
    /\ ObserverIds # {}
    /\ Payloads # {}
    /\ ObserverCapTokens = {"PgWrite"}        \* fixed initial set
    /\ MaxObserverInvocations \in Nat \ {0}
    /\ MaxObserverPanics \in Nat \ {0}
    /\ MaxQuarantineEvents \in Nat \ {0}

(* --- Concrete refinement of CR-4 record types --- *)

\* ObserverInvocation — observer side-effect with capability token
\* + chain-orthogonal payload. E15.b clause #2 anchor (payload is
\* opaque bytes only, no chain-mutation operations exposed).
ObserverInvocation ==
    [ observer:  ObserverIds,
      cap_token: ObserverCapTokens,
      payload:   Payloads ]

\* ObserverPanic — panic event captured at sandbox boundary BEFORE
\* side-effects propagate. E15.a panic close anchor.
ObserverPanic ==
    [ observer:   ObserverIds,
      panic_tick: Nat ]

\* ObserverQuarantine — host-supervised quarantine receipt.
\* E15.a + 4-clause #3 anchor (host-emit witness via emitter field
\* fixed to "HOST" only).
ObserverQuarantine ==
    [ observer:   ObserverIds,
      panic_tick: Nat,
      emit_tick:  Nat,
      emitter:    {"HOST"} ]   \* emitter field domain restricted

VARIABLES
    \* @type: Set($observerInvocation);
    observer_invocations,    \* Set of ObserverInvocation
    \* @type: Set($observerPanic);
    observer_panics,         \* Set of ObserverPanic
    \* @type: Set($observerQuarantine);
    quarantine_events        \* Set of ObserverQuarantine

vars_cr4 == << chain_tip, wal, tick,
               actor_user_binding, actor_shell_binding,
               authenticated_actors,
               runtime_bootstrap, signature_class_policy,
               observer_invocations, observer_panics,
               quarantine_events >>

(* --- Type invariant (explicit composition over base TypeOK) --- *)

TypeOK_CR4 ==
    /\ TypeOK                                    \* base, via EXTENDS
    /\ observer_invocations \subseteq ObserverInvocation
    /\ observer_panics \subseteq ObserverPanic
    /\ quarantine_events \subseteq ObserverQuarantine
    /\ Cardinality(observer_invocations) <= MaxObserverInvocations
    /\ Cardinality(observer_panics) <= MaxObserverPanics
    /\ Cardinality(quarantine_events) <= MaxQuarantineEvents

(* --- Module-specific invariants --- *)

\* INV E15-1: ObserverChainNonAffecting (MC, 4-clause #1+#4 anchor).
\* Chain state (chain_tip + wal) is independent of observer state
\* (observer_invocations + observer_panics + quarantine_events).
\*
\* State-level concrete content: panic-quarantine 1:1 correspondence
\* enforces E15.a panic close mechanism — every observer panic
\* produces an ObserverQuarantine emission (host-supervised), no
\* native unwind reaches chain. Pre-E15 violation = panic without
\* quarantine = native unwind to L0 chain. Post-E15: 1:1 bijection
\* on (observer, panic_tick) key.
\*
\* Combined with structural enforcement (VARIABLES partition +
\* UNCHANGED << chain_tip, wal >> in all observer transitions),
\* this captures clauses #1 (host-fn never call chain-mutation —
\* observer state in disjoint VARS partition from wal) + #4 (panic
\* isolation preserves chain progression — UNCHANGED chain across
\* panic transitions). See theorem
\* `ChainProgressionUnaffectedByObserver` below for the operational
\* form.
ObserverChainNonAffecting ==
    /\ \A p \in observer_panics :
         \E q \in quarantine_events :
            /\ q.observer = p.observer
            /\ q.panic_tick = p.panic_tick
    /\ \A q \in quarantine_events :
         \E p \in observer_panics :
            /\ q.observer = p.observer
            /\ q.panic_tick = p.panic_tick

\* INV E15-2: ObserverCapabilityConfined (MC, dual: type-level +
\* operational). Every observer side-effect uses a capability token
\* from the allowed ObserverCapTokens set (initial = {"PgWrite"}).
\* Type-level enforcement: Rust ObserverCapToken `#[non_exhaustive]`
\* enum + module-load deny-list rejects direct syscalls/wasi-{fs,
\* sockets, clocks, random, io, cli, http}. Operationally captured
\* here as cap_token field type-bounded to ObserverCapTokens.
\*
\* Captures 4-clause #1 (observer host-fn restricted to capability
\* set, no chain-mutation primitives) + #2 (chain-orthogonal at
\* type level, only Payloads byte sequences allowed).
ObserverCapabilityConfined ==
    \A inv \in observer_invocations :
        inv.cap_token \in ObserverCapTokens

\* INV E15-3: QuarantineHostSupervised (MC, 4-clause #3 anchor).
\* Every quarantine event has emitter = "HOST". Observer self-
\* emission is forbidden. Pre-E15 violation = observer self-emit
\* of quarantine receipt = covert channel via ObserverQuarantine
\* event content forgery. Post-E15: host catches trap, generates
\* quarantine receipt with emitter field hard-set to "HOST".
QuarantineHostSupervised ==
    \A q \in quarantine_events :
        q.emitter = "HOST"

\* INV E15-4: CapTokenSealed (MC, sealed-trait safeguard).
\* Type-system anchor of E15.b capability confinement — every
\* observer/hook cap_token is drawn from a *sealed* universe of
\* types (Rust `pub trait HookCapTokenSealed: private_seal::Sealed`
\* + `ObserverCapTokenSealed: private_seal::Sealed`, where
\* `private_seal::Sealed` is a private-module marker). External
\* crates cannot impl the sealed bound, so the cap_token universe
\* is monomorphic at the language level — no out-of-crate Cap can
\* ever satisfy `Cap: HookCapTokenSealed` or `Cap: ObserverCapTokenSealed`.
\*
\* TLA+ formal abstraction: `ObserverCapTokens` is a CONSTANTS-fixed
\* finite set (ASSUMEd to `{"PgWrite"}`). The CapTokenSealed INV at
\* TLA+ level expresses that every observed cap_token in the model
\* is drawn from this CONSTANTS-fixed set — the same property
\* `ObserverCapabilityConfined` already enforces. The sealed-trait
\* safeguard adds a *type-system layer* of enforcement on the Rust
\* side: the sealed trait blocks any external impl from weakening
\* the cap_token universe at compile time, so the Rust-side universe
\* matches the TLA+ abstraction faithfully.
\*
\* CapTokenSealed is therefore the *strengthened type-level companion*
\* to ObserverCapabilityConfined — at the formal-method level the two
\* INVs are operationally equivalent, but CapTokenSealed names the
\* type-system anchor explicitly so axiom-test-cite.toml + Apalache
\* typecheck record the sealed-trait strengthening as a first-class
\* invariant.
\*
\* Anchored to:
\*   - sibling ArkheForge: arkhe-forge-platform/src/wasm_runtime_common/mod.rs:299-329
\*     (HookCapTokenSealed + ObserverCapTokenSealed trait definitions)
\*   - sibling ArkheForge: arkhe-forge-platform/src/wasm_runtime_common/mod.rs:813,822
\*     (witness tests hook_cap_token_satisfies_sealed_bound +
\*      observer_cap_token_satisfies_sealed_bound)
CapTokenSealed ==
    \A inv \in observer_invocations :
        inv.cap_token \in ObserverCapTokens

(* --- Theorem: ChainProgressionUnaffectedByObserver (E15 derivable)
 *
 * THEOREM ChainProgressionUnaffectedByObserver:
 *   For any reachable state pair (s, s') of CR-4 connected by an
 *   observer transition (ObserverNominalStep ∨ ObserverPanic-
 *   Transition), the chain state is preserved:
 *     s.chain_tip = s'.chain_tip ∧ s.wal = s'.wal
 *
 * PROOF SKETCH:
 *   Both observer sub-actions explicitly enforce
 *     UNCHANGED << chain_tip, wal, ... >>
 *   in their conjuncts (lines below for ObserverNominalStep +
 *   ObserverPanicTransition). Therefore, by definition of UNCHANGED,
 *   chain state is preserved across observer transitions. QED.
 *
 * This theorem is the operational form of the 4-clause #4 invariant
 * (panic isolation preserves chain progression). Combined with INV
 * `ObserverChainNonAffecting` (panic-quarantine 1:1 correspondence
 * at state level), the CR-4 refinement captures the full chain-
 * non-affecting property of E15.
 *
 * COROLLARY (composition with CR-1):
 *   At any reachable state of CR-4, chain_tip = ChainHashFn(wal)
 *   (CR-1's `ChainHashDeterministic` INV holds under CR-4 transition
 *   composition). Proof: observer transitions UNCHANGED << chain_tip,
 *   wal >>, so CR-1's INV is preserved verbatim across the CR-4
 *   refinement. Therefore observer state cannot affect chain hash
 *   determinism (Adversary B chain-affecting attack vector closed).
 *)

(* --- Concrete state machine refinement --- *)

\* ObserverNominalStep — observer executes successfully via capability
\* token. Chain state UNCHANGED (clause #1+#4). E15.b capability
\* confinement enforced via cap_token type-bounded.
ObserverNominalStep(inv) ==
    /\ inv \in ObserverInvocation
    /\ Cardinality(observer_invocations) < MaxObserverInvocations
    /\ tick + 1 <= MaxTicks
    /\ observer_invocations' = observer_invocations \cup {inv}
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    observer_panics, quarantine_events >>

\* ObserverPanicTransition — observer panics; host catches trap at
\* sandbox boundary BEFORE side-effects propagate; host emits
\* ObserverQuarantine atomically with panic recording. E15.a panic
\* close mechanism. Chain state UNCHANGED (clause #4 panic isolation
\* preserves chain progression).
\*
\* Atomic emission: observer_panics' adds the panic AND
\* quarantine_events' adds the host-supervised receipt in the same
\* step. This enforces ObserverChainNonAffecting INV (panic-
\* quarantine 1:1 correspondence) at construction time.
ObserverPanicTransition(p) ==
    /\ p \in ObserverPanic
    /\ p.panic_tick = tick
    /\ Cardinality(observer_panics) < MaxObserverPanics
    /\ Cardinality(quarantine_events) < MaxQuarantineEvents
    /\ tick + 1 <= MaxTicks
    /\ observer_panics' = observer_panics \cup {p}
    /\ quarantine_events' = quarantine_events \cup {[
           observer   |-> p.observer,
           panic_tick |-> p.panic_tick,
           emit_tick  |-> tick,
           emitter    |-> "HOST"   \* host-supervised emission
       ]}
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    observer_invocations >>

InitCR4 ==
    /\ chain_tip = << >>
    /\ wal = << >>
    /\ tick = 0
    /\ actor_user_binding \in [Actors -> Users]
    /\ actor_shell_binding \in [Actors -> Shells]
    /\ authenticated_actors = {}
    /\ runtime_bootstrap = "BOOTSTRAP_PLACEHOLDER"
    /\ signature_class_policy = [s \in Shells |-> "Ed25519"]
    /\ observer_invocations = {}
    /\ observer_panics = {}
    /\ quarantine_events = {}

NextCR4 ==
    \/ \E inv \in ObserverInvocation : ObserverNominalStep(inv)
    \/ \E p \in ObserverPanic : ObserverPanicTransition(p)

SpecCR4 == InitCR4 /\ [][NextCR4]_vars_cr4

(* --- Refinement Map (per formal/tla-plus/README.md convention) ---
 *
 * Section 1 — Abstract Vars <-> Concrete Vars
 *
 *   runtime_core.tla         cr4 (refined + extended)
 *   ---------------------    ------------------------------------
 *   chain_tip                (carry-through, CR-1's domain;
 *                            UNCHANGED in all CR-4 transitions)
 *   wal                      (carry-through, CR-1's domain;
 *                            UNCHANGED in all CR-4 transitions)
 *   tick                     (carry-through; advances on observer
 *                            sub-actions)
 *   actor_user_binding       (carry-through, CR-2's domain)
 *   actor_shell_binding      (carry-through, CR-2's domain)
 *   authenticated_actors     (carry-through, CR-2's domain)
 *   runtime_bootstrap        (carry-through, CR-3's domain)
 *   signature_class_policy   (carry-through, CR-3's domain)
 *   --                       observer_invocations \subseteq
 *                            ObserverInvocation              NEW
 *   --                       observer_panics \subseteq
 *                            ObserverPanic                   NEW
 *   --                       quarantine_events \subseteq
 *                            ObserverQuarantine              NEW
 *
 * Section 2 — Abstract step <-> Concrete step
 *
 *   runtime_core.Next   ->   ObserverNominalStep /
 *                            ObserverPanicTransition (2-disjunctive)
 *
 *   ObserverPanicTransition refines E15.a panic close: atomic
 *   update of observer_panics ∪ quarantine_events, host-supervised
 *   emission with emitter="HOST".
 *
 * Section 3 — Module-specific INVs + theorem + lemma
 *
 *   E15-ObserverChainNonAffecting    (MC, panic-quarantine 1:1
 *                                    correspondence + structural
 *                                    chain disjointness)
 *   E15-ObserverCapabilityConfined   (MC, cap_token type-bounded;
 *                                    type-level + operational dual)
 *   E15-QuarantineHostSupervised     (MC, emitter="HOST" witness)
 *   E15-CapTokenSealed               (MC, sealed-trait safeguard
 *                                    type-system companion to E15-
 *                                    ObserverCapabilityConfined)
 *
 *   ChainProgressionUnaffectedByObserver (theorem, derivable from
 *                                    UNCHANGED conjuncts in
 *                                    observer transitions)
 *
 *   Adversary_B_ResidualReduction    (lemma, see comment block)
 *   SealedTrait_implies_E15.b        (lemma, sealed-trait derives
 *                                    E15.b confinement at the
 *                                    type-system level; see
 *                                    comment block below)
 *)

(* --- Adversary B residual reduction lemma ---
 *
 * Pre-E15 attack surface for chain-non-affecting observer mutation
 * bypass:
 *
 *   (α) Native panic propagation: A22 quarantines AFTER native
 *       unwind, NOT BEFORE — observer panic side-effects can
 *       propagate to L0 chain via the unwind path before quarantine
 *       takes effect. Adversary B leverages this to corrupt chain
 *       hash via observer-triggered native panic.
 *
 *   (β) Uncontrolled syscall egress: pre-E15, observers can issue
 *       direct syscalls (wasi-{fs, sockets, clocks, random, io,
 *       cli, http}) without capability mediation. Adversary B
 *       leverages this for covert channel + side-channel attacks
 *       (e.g., wasi-fs to leak chain state, wasi-clocks to
 *       introduce non-determinism).
 *
 * E15 closure (chain-non-affecting 4-clause invariant):
 *
 *   E15.a panic close — wasmtime sandbox boundary catches the
 *   panic trap BEFORE side-effects propagate; host emits
 *   ObserverQuarantine receipt (TypeCode 0x0003_0F0C) with
 *   emitter="HOST". TLA+ refinement: ObserverPanicTransition
 *   atomically updates observer_panics ∪ quarantine_events with
 *   1:1 correspondence enforced by INV ObserverChainNonAffecting.
 *   Chain state UNCHANGED across panic transition (theorem
 *   ChainProgressionUnaffectedByObserver).
 *
 *   E15.b capability confinement — ObserverCapToken
 *   #[non_exhaustive] enum (initial = {PgWrite}); module-load
 *   deny-list rejects wasi-{fs, sockets, clocks, random, io,
 *   cli, http}. TLA+ refinement: cap_token field type-bounded
 *   to ObserverCapTokens; INV ObserverCapabilityConfined
 *   enforces at state level.
 *
 *   4-clause invariant decomposition:
 *   #1 host-fn never call chain-mutation primitives
 *      → VARIABLES partition (observer state in cr4 vars,
 *        wal in CR-1's domain) + UNCHANGED conjuncts in transitions
 *   #2 ObserverCapability::execute carries `&[u8]` payload only
 *      → Payloads opaque byte set (no chain-mutation operations)
 *   #3 ObserverQuarantine emission is host-supervised
 *      → INV QuarantineHostSupervised (emitter="HOST" hard-set)
 *   #4 panic isolation preserves chain progression
 *      → INV ObserverChainNonAffecting + theorem
 *        ChainProgressionUnaffectedByObserver
 *
 * Residual surface (post-E15):
 *
 *   (i)  Host-call API implementation defects — addressed by the
 *        Kani memory bounds-check property at the impl level plus
 *        integration tests in the sister repo's observer_host
 *        crate (sibling ArkheForge: arkhe-forge-platform/src/observer_host/).
 *        Residual implementation defects are out-of-scope at the
 *        TLA+ refinement level.
 *
 *   (ii) wasmtime engine zero-day — out-of-scope per
 *        the project residual policy, symmetric with E14.L2
 *        wasmtime zero-day exclusion. The reduction is conservative:
 *        any adversary path not in (i)/(ii) is closed by E15 at the
 *        formal-method level.
 *
 * Symmetric counterparts:
 *
 *   - Adversary A residual reduction (CR-1, E14 chain-affecting
 *     compute determinism). Together with Adversary B (CR-4) the
 *     refinement closes both chain-affecting and chain-non-
 *     affecting attack axes at the formal-method level.
 *
 *   - PQC downgrade adversary residual reduction (CR-3, E13
 *     chain-anchored policy). Together with Adversary A + B the
 *     refinement closes the compute + policy + observer axes.
 *
 * Temporal semantic anchor: CR-4 has a temporal coupling at the
 * panic-quarantine ordering — panic_tick precedes emit_tick (the
 * host emits the receipt at the current tick while the panic
 * occurred at p.panic_tick). The 1:1 correspondence INV is
 * tick-aware via panic_tick field matching (no temporal gap
 * allowed between panic and quarantine emission).
 *)

(* --- SealedTrait_implies_E15.b lemma (sealed-trait strengthening) ---
 *
 * LEMMA SealedTrait_implies_E15.b:
 *   The Rust-side sealed-trait safeguard (HookCapTokenSealed +
 *   ObserverCapTokenSealed, both supertraited by `private_seal::Sealed`
 *   in a private module) derives E15.b capability confinement at the
 *   type-system level — no Cap type outside the host crate can ever
 *   satisfy the bound `Cap: HookCapTokenSealed` or `Cap:
 *   ObserverCapTokenSealed`, so the universe of valid cap_tokens is
 *   monomorphic at compile time and matches the TLA+ CONSTANTS-fixed
 *   `ObserverCapTokens` set faithfully.
 *
 * PROOF SKETCH:
 *   (1) `private_seal::Sealed` resides in a private sub-module
 *       (`mod private_seal { pub trait Sealed {} }`); external crates
 *       have no syntactic path to name `private_seal::Sealed` and
 *       therefore cannot write `impl Sealed for ExternalType`. This
 *       is the standard Rust sealed-trait pattern (RFC 1023 + nomicon).
 *   (2) `HookCapTokenSealed: Sealed + ...` requires Sealed as a
 *       super-trait. Therefore `impl HookCapTokenSealed for T` requires
 *       `impl Sealed for T` first — impossible from outside the crate
 *       by (1).
 *   (3) Witness tests `hook_cap_token_satisfies_sealed_bound` +
 *       `observer_cap_token_satisfies_sealed_bound`
 *       (`wasm_runtime_common/mod.rs:813,822`) call
 *       `assert_X<C: TraitX>()` with concrete cap_token types, forcing
 *       the bound to hold at compile time. Trait removal would fail
 *       these tests at the typeck stage.
 *   (4) Therefore the Rust-side cap_token universe = {types impl-ing
 *       Sealed within the host crate} = the CONSTANTS-fixed
 *       `ObserverCapTokens` of CR-4 abstraction. Faithfulness verified.
 *
 * COROLLARY:
 *   Combined with INV `ObserverCapabilityConfined`
 *   (cap_token \in ObserverCapTokens), CapTokenSealed gives a
 *   *dual-layer* enforcement of E15.b confinement:
 *     - Layer 1 (type-system): sealed-trait pattern blocks external
 *       Cap impls at compile time
 *     - Layer 2 (state-level INV): TLA+ ObserverCapabilityConfined
 *       constrains the modelled cap_token to the CONSTANTS-fixed set
 *   Adversary B cannot widen the cap_token universe even at the type
 *   system layer; the TLA+ refinement faithfully models the strict
 *   Rust-side property.
 *
 * Witness anchors (1:1 with axiom-test-cite.toml E15.impl_tests):
 *   - hook_cap_token_satisfies_sealed_bound      (mod.rs:813)
 *   - observer_cap_token_satisfies_sealed_bound  (mod.rs:822)
 *)

(* --- Module-shape conventions ---
 *
 * NextCR4 is self-contained: each refinement module declares its
 * own Next predicate rather than composing into a single global
 * Next operator on runtime_core. This keeps the modules
 * Apalache-typecheckable in isolation; a global composition would
 * couple them tightly with no offsetting benefit at the current
 * abstraction level.
 *
 * TypeOK_CR4 follows the same pattern used by CR-1 / CR-2 / CR-3
 * / R4-I: `TypeOK_<MOD> == TypeOK /\ ...`. Base TypeOK is inherited
 * via EXTENDS and explicitly composed with the module's own
 * type-shape conjuncts.
 *
 * R4-I Space coverage uses the structural isomorphism argument
 * (Entry-only TLA+ modeling is sufficient because Space refines
 * to the same parent-DAG shape as Entry); see r4 module-level
 * comment for the proof sketch.
 *)

====

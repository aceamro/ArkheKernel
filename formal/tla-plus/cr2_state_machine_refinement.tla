---- MODULE cr2_state_machine_refinement ----
(*
 * cr2_state_machine_refinement — DIP-N5 sub-step E.4.
 *
 * CR-2 anchors E5 (Actor immutability) + E6 (Authenticated typestate)
 * + E7 (dual-tier shell brand) + E4 (UserId uniqueness). EXTENDs
 * runtime_core with:
 *  (1) Activity record type (actor + target + verb tuple);
 *  (2) UserBinding record (actor_id -> user_id);
 *  (3) 5 module-specific INVs;
 *  (4) Concrete state machine: AddActor / AuthenticateActor /
 *      SubmitActivity transitions.
 *
 * Tier annotations per `formal/tla-plus/README.md` Section 2 mapping:
 *   - E4-UserIdGloballyUnique (TP)
 *   - E4-ActorIdShellUnique   (TP, vacuous at TLA+ abstraction;
 *                              captured by Actors set + function
 *                              semantics, see Module-level note)
 *   - E5-ActorIdentityImmutable (MC)
 *   - E6-AuthenticatedActorHasUserBinding (TP at submit, MC at replay)
 *   - E7-ShellBrandConsistent (TP at submit-site)
 *   - E7-ShellIsolationOnReplay (RA fallback at replay)
 *
 * Module-level note on E4-ActorIdShellUnique: the underlying Rust
 * property (NonZeroU64 ActorId per shell, A6 + A19 anchors) is
 * TYPE-PROVEN in the Rust type system. In the TLA+ refinement,
 * Actors is modelled as an opaque set + actor_shell_binding as a
 * total function — distinct Actor identifiers remain distinct by
 * set semantics, which captures the property at the abstraction
 * level. No explicit state-level invariant is added; this comment
 * serves as the axiom-mapping anchor.
 *
 * Anchored to:
 *   - runtime-book/src/en/architecture/11-axioms.md E4-E7
 *
 * Apalache primary tooling. CI: `apalache-mc typecheck` per .tla.
 * Bounded MC `apalache-mc check --inv=...` lands at E.7 close.
 *)

EXTENDS runtime_core

\* @typeAlias: verb = Str;
ALIAS_verb == TRUE

\* @typeAlias: userBinding = { actor_id: Str, user_id: Str };
ALIAS_userBinding == TRUE

\* @typeAlias: activity = { actor: Str, target: Str, verb: Str };
ALIAS_activity == TRUE

CONSTANTS
    \* @type: Set($verb);
    Verbs,            \* Verb identifier set (used by Activity)
    \* @type: Set($userBinding);
    UserBindings,     \* Set of all admissible UserBinding records
    \* @type: Int;
    MaxActivities     \* Bounded MC ceiling for activities sequence

ASSUME
    /\ Verbs # {}
    /\ UserBindings \subseteq [actor_id: Actors, user_id: Users]
    /\ MaxActivities \in Nat \ {0}

(* --- Concrete refinement of CR-2 state vector --- *)

\* Activity record — actor submits a verb against a target. E7
\* requires actor and target to share a shell at submit-site.
Activity == [ actor: Actors, target: Actors, verb: Verbs ]

VARIABLES
    \* @type: Seq($activity);
    activities,           \* Seq(Activity), append-only at submit
    \* @type: Set($userBinding);
    user_bindings_state,  \* Subset of UserBindings (E6 anchor)
    \* @type: Set($actor);
    pending_actors        \* Actors awaiting AuthenticateActor

vars_cr2 == << chain_tip, wal, tick,
               actor_user_binding, actor_shell_binding,
               authenticated_actors,
               runtime_bootstrap, signature_class_policy,
               activities, user_bindings_state, pending_actors >>

(* --- Type invariant (theorist Minor Note 2 absorption — explicit
 *     composition with base TypeOK via EXTENDS) --- *)

TypeOK_CR2 ==
    /\ TypeOK                                       \* base, via EXTENDS
    /\ activities \in Seq(Activity)
    /\ user_bindings_state \subseteq UserBindings
    /\ pending_actors \subseteq Actors
    /\ Len(activities) <= MaxActivities

(* --- Module-specific invariants --- *)

\* INV E4-UserIdGloballyUnique (TYPE-PROVEN tier; meaningful at
\* user_bindings_state level — no actor double-bound to multiple
\* user identities).
UserIdGloballyUnique ==
    \A b1, b2 \in user_bindings_state :
        b1.actor_id = b2.actor_id => b1.user_id = b2.user_id

\* INV E5-ActorIdentityImmutable (MACHINE-CHECKED). Bindings remain
\* well-defined functions throughout; no transition rebinds an
\* existing actor's user_id or shell_id. Captured at state level by
\* the absence of any Next sub-action that updates
\* actor_user_binding or actor_shell_binding (UNCHANGED in all 3
\* CR-2 sub-actions below).
ActorIdentityImmutable ==
    /\ DOMAIN actor_user_binding = Actors
    /\ DOMAIN actor_shell_binding = Actors

\* INV E6-AuthenticatedActorHasUserBinding (TP at submit-site,
\* MC at replay). Every authenticated actor has a corresponding
\* UserBinding entry in user_bindings_state.
AuthenticatedActorHasUserBinding ==
    \A a \in authenticated_actors :
        \E b \in user_bindings_state : b.actor_id = a

\* INV E7-ShellBrandConsistent (TYPE-PROVEN at submit-site via Rust
\* `ShellBrand<'s>` phantom-lifetime branding). Every submitted
\* activity has actor and target in the same shell.
ShellBrandConsistent ==
    \A i \in DOMAIN activities :
        actor_shell_binding[activities[i].actor]
            = actor_shell_binding[activities[i].target]

\* INV E7-ShellIsolationOnReplay (RUNTIME-ASSERTED fallback at
\* replay). On replay, the canonical shell of the authenticated
\* actor must match the shell of the activity's target.
ShellIsolationOnReplay ==
    \A i \in DOMAIN activities :
        activities[i].actor \in authenticated_actors
            => actor_shell_binding[activities[i].actor]
               = actor_shell_binding[activities[i].target]

(* --- Concrete state machine refinement --- *)

\* AddActor — register a fresh Actor identifier into pending_actors.
\* Pre: actor not yet known to authentication state.
AddActor(a) ==
    /\ a \in Actors
    /\ a \notin pending_actors
    /\ a \notin authenticated_actors
    /\ pending_actors' = pending_actors \cup {a}
    /\ tick' = tick + 1
    /\ tick + 1 <= MaxTicks
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    activities, user_bindings_state >>

\* AuthenticateActor — promote a pending actor to authenticated
\* state with a UserBinding (E6 typestate transition).
AuthenticateActor(a, b) ==
    /\ a \in pending_actors
    /\ b \in UserBindings
    /\ b.actor_id = a
    /\ user_bindings_state' = user_bindings_state \cup {b}
    /\ authenticated_actors' = authenticated_actors \cup {a}
    /\ pending_actors' = pending_actors \ {a}
    /\ tick' = tick + 1
    /\ tick + 1 <= MaxTicks
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    runtime_bootstrap, signature_class_policy,
                    activities >>

\* SubmitActivity — append an Activity to the activities sequence.
\* Pre-conditions enforce E6 (actor authenticated) and E7 (shell
\* brand consistent at submit-site).
SubmitActivity(act) ==
    /\ act \in Activity
    /\ act.actor \in authenticated_actors
    /\ actor_shell_binding[act.actor] = actor_shell_binding[act.target]
    /\ Len(activities) < MaxActivities
    /\ activities' = Append(activities, act)
    /\ tick' = tick + 1
    /\ tick + 1 <= MaxTicks
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    user_bindings_state, pending_actors >>

InitCR2 ==
    /\ chain_tip = << >>
    /\ wal = << >>
    /\ tick = 0
    /\ actor_user_binding \in [Actors -> Users]
    /\ actor_shell_binding \in [Actors -> Shells]
    /\ authenticated_actors = {}
    /\ runtime_bootstrap = "BOOTSTRAP_PLACEHOLDER"
    /\ signature_class_policy = [s \in Shells |-> "Ed25519"]
    /\ activities = << >>
    /\ user_bindings_state = {}
    /\ pending_actors = {}

NextCR2 ==
    \/ \E a \in Actors : AddActor(a)
    \/ \E a \in Actors, b \in UserBindings : AuthenticateActor(a, b)
    \/ \E act \in Activity : SubmitActivity(act)

SpecCR2 == InitCR2 /\ [][NextCR2]_vars_cr2

(* --- Refinement Map (per formal/tla-plus/README.md convention) ---
 *
 * Section 1 — Abstract Vars <-> Concrete Vars
 *
 *   runtime_core.tla         cr2 (refined + extended)
 *   --------------------     --------------------------------
 *   chain_tip                (carry-through, no CR-2 refinement)
 *   wal                      (carry-through)
 *   tick                     (carry-through)
 *   actor_user_binding       (carry, [Actors -> Users] base type)
 *   actor_shell_binding      (carry, [Actors -> Shells] base type)
 *   authenticated_actors     (carry, subset of Actors)
 *   --                       activities \in Seq(Activity)        NEW
 *   --                       user_bindings_state                 NEW
 *   --                       pending_actors \subseteq Actors     NEW
 *
 * Section 2 — Abstract step <-> Concrete step
 *
 *   runtime_core.Next   ->   AddActor / AuthenticateActor /
 *                            SubmitActivity (3 disjunctive cases)
 *
 * Section 3 — Module-specific INVs
 *
 *   E4-UserIdGloballyUnique          (TP, user_bindings_state)
 *   E5-ActorIdentityImmutable        (MC, function domain)
 *   E6-AuthenticatedActorHasUserBinding (TP at submit, MC at replay)
 *   E7-ShellBrandConsistent          (TP at submit-site)
 *   E7-ShellIsolationOnReplay        (RA fallback at replay)
 *
 *   E4-ActorIdShellUnique captured at TLA+ abstraction by Actors
 *   set + actor_shell_binding function semantics (Module-level
 *   note above).
 *)

(* --- Rust typestate refinement note ---
 *
 * Rust typestate `Actor<S, Authenticated>` <-> TLA+ membership in
 * `authenticated_actors`. Transition `Actor<S, Anonymous>` ->
 * `Actor<S, Authenticated>` is enforced by Rust at the type level
 * (consume + return new typed value with `UserBinding`); the TLA+
 * refinement captures this as `AuthenticateActor` adding to
 * `authenticated_actors` and `user_bindings_state` in lockstep.
 *
 * The `<'s>` ShellBrand lifetime in Rust (TYPE-PROVEN at
 * submit-site via phantom lifetime branding) <-> TLA+
 * shell-brand consistency invariant `ShellBrandConsistent`. The
 * Rust compiler refuses any submit where actor and target carry
 * different `'s` lifetimes; the TLA+ refinement captures this as
 * a precondition on `SubmitActivity` plus the
 * `ShellBrandConsistent` state-level invariant.
 *)

====

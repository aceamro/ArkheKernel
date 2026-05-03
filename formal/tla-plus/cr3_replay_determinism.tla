---- MODULE cr3_replay_determinism ----
(*
 * cr3_replay_determinism.
 *
 * CR-3 anchors E11 (cascade re-submit deterministic tick) + E12
 * (RuntimeBootstrap chain-anchored) + E13 (SignatureClassPolicy
 * chain-anchored, PQC downgrade rejected). EXTENDs runtime_core
 * with:
 *  (1) RuntimeBootstrapEvent record refinement;
 *  (2) SignatureClassPolicyEvent + AuditReceipt + CascadeOp
 *      record types;
 *  (3) Sticky-Hybrid policy snapshot helpers (sticky-by-construction
 *      under WAL append-only, so PolicyMonotonic is a derivable
 *      theorem rather than a separate state-level INV);
 *  (4) Module-specific INVs + 1 derivable theorem;
 *  (5) Concrete state machine: DeclareSignatureClassPolicy /
 *      IssueAuditReceipt / ScheduleCascadeOp transitions.
 *
 * Tier annotations per `formal/tla-plus/README.md` Section 2 mapping:
 *   - E11-CascadeOpDeterministicTickPlacement (MC)
 *   - E12-RuntimeBootstrapChainAnchored (MC)
 *   - E12-ManifestDriftReplayRejected (MC, fail-secure)
 *   - E13-NoSignatureDowngradeAfterPolicy (MC, sticky-derived)
 *   - E13-NoPqcDowngradeAttack (MC, explicit attack-form)
 *   - E13-HybridDualSignBoth (MC, AND-mode positive form)
 *   - E13-PolicyMonotonic_Derivable (theorem from A14)
 *
 * Spec body sticky semantic anchor:
 * `runtime-book/src/en/architecture/11-axioms.md` E13 phrasing
 * "after the tick at which a given shell declared Hybrid ...
 *  shell-per-tick sticky snapshot of SignatureClassPolicy ...
 *  monotone: once a shell declares Hybrid at tick T, all receipts
 *  at ticks >= T must be Hybrid-signed; the snapshot never
 *  reverts". The latching semantic is captured by tick-filtered
 *  ShellPolicySnapshotAtTick: receipts are evaluated against the
 *  snapshot of policy events with effective_tick <= issued_tick,
 *  so a pre-Hybrid Ed25519 receipt is not retroactively invalidated
 *  by a later Hybrid declaration.
 *
 * PQC envelope dependency: WalRecord wire format provides
 * signature_pqc (field 13) and verifying_key_pqc (field 11) slots.
 * E13 NoPqcDowngradeAttack is type-system anchored at the wire
 * format level by these slots — any post-Hybrid receipt must
 * populate signature_pqc=Some, any Hybrid policy event implicitly
 * references the envelope slot. The Hybrid signature class enum
 * variant and dual-sign verify path land in the impl side under
 * persist/{signature,wal}.rs; the cr3 INV growth point sits in
 * this module (signature class policy axis), with cr1 carrying
 * the chain-hash determinism axis.
 *
 * Anchored to:
 *   - runtime-book/src/en/architecture/11-axioms.md E11-E13
 *
 * Apalache primary tooling. CI: `apalache-mc typecheck` per .tla.
 *)

EXTENDS runtime_core

\* @typeAlias: manifest = Str;
ALIAS_manifest == TRUE

\* @typeAlias: runtimeBootstrapEvent = { shell: Str, manifest_digest: Str, effective_tick: Int };
ALIAS_runtimeBootstrapEvent == TRUE

\* @typeAlias: policyEvent = { shell: Str, declared_class: Str, effective_tick: Int };
ALIAS_policyEvent == TRUE

\* @typeAlias: auditReceipt = { shell: Str, issued_tick: Int, signature_class: Str, ed25519_verify: Bool, mldsa65_verify: Bool };
ALIAS_auditReceipt == TRUE

\* @typeAlias: cascadeOp = { original_tick: Int, scheduled_at: Int };
ALIAS_cascadeOp == TRUE

CONSTANTS
    \* @type: Set($manifest);
    Manifests,                  \* Set of manifest digest values
    \* @type: $manifest;
    BootstrapManifestDigest,    \* Genesis manifest digest
    \* @type: Int;
    InitialBootstrapTick,       \* Genesis bootstrap event tick
    \* @type: Int;
    MaxPolicyEvents,            \* Bounded MC ceiling: policy events
    \* @type: Int;
    MaxAuditReceipts,           \* Bounded MC ceiling: audit receipts
    \* @type: Int;
    MaxCascadeOps               \* Bounded MC ceiling: cascade ops

ASSUME
    /\ Manifests # {}
    /\ BootstrapManifestDigest \in Manifests
    /\ InitialBootstrapTick \in Nat
    /\ MaxPolicyEvents \in Nat \ {0}
    /\ MaxAuditReceipts \in Nat \ {0}
    /\ MaxCascadeOps \in Nat \ {0}

(* --- Concrete refinement of CR-3 chain-anchored event types --- *)

\* RuntimeBootstrapEvent — chain-anchored manifest digest pin (E12).
\* Refines runtime_core's opaque `runtime_bootstrap` to a concrete
\* record type at the CR-3 abstraction level.
RuntimeBootstrapEvent ==
    [ shell:           Shells,
      manifest_digest: Manifests,
      effective_tick:  Nat ]

\* SignatureClassPolicyEvent — chain-anchored signature class
\* declaration per shell (E13). Append-only sequence in WAL.
SignatureClassPolicyEvent ==
    [ shell:          Shells,
      declared_class: SignatureClasses,
      effective_tick: Nat ]

\* AuditReceipt — receipt with signature class tag (E13 verifier
\* check anchor). The ed25519_verify and mldsa65_verify abstract
\* BOOLEAN fields capture per-receipt dual-sign verification state;
\* under a Hybrid policy snapshot both must hold (HybridDualSignBoth).
AuditReceipt ==
    [ shell:           Shells,
      issued_tick:     Nat,
      signature_class: SignatureClasses,
      ed25519_verify:  BOOLEAN,
      mldsa65_verify:  BOOLEAN ]

\* CascadeOp — scheduled action with deterministic tick placement
\* (E11). `scheduled_at` MUST equal `original_tick + 1`.
CascadeOp ==
    [ original_tick: Nat,
      scheduled_at:  Nat ]

VARIABLES
    \* @type: $runtimeBootstrapEvent;
    bootstrap_event,    \* Concrete refinement of runtime_bootstrap
    \* @type: Seq($policyEvent);
    policy_events,      \* Seq(SignatureClassPolicyEvent), append-only
    \* @type: Seq($auditReceipt);
    audit_receipts,     \* Seq(AuditReceipt), append-only
    \* @type: Seq($cascadeOp);
    cascade_ops         \* Seq(CascadeOp), append-only

vars_cr3 == << chain_tip, wal, tick,
               actor_user_binding, actor_shell_binding,
               authenticated_actors,
               runtime_bootstrap, signature_class_policy,
               bootstrap_event, policy_events,
               audit_receipts, cascade_ops >>

(* --- Type invariant (explicit composition over base TypeOK) --- *)

TypeOK_CR3 ==
    /\ TypeOK                                    \* base, via EXTENDS
    /\ bootstrap_event \in RuntimeBootstrapEvent
    /\ policy_events \in Seq(SignatureClassPolicyEvent)
    /\ audit_receipts \in Seq(AuditReceipt)
    /\ cascade_ops \in Seq(CascadeOp)
    /\ Len(policy_events) <= MaxPolicyEvents
    /\ Len(audit_receipts) <= MaxAuditReceipts
    /\ Len(cascade_ops) <= MaxCascadeOps

(* --- Sticky-Hybrid snapshot helper ---
 *
 * ShellPolicySnapshot returns "Hybrid" if any prior policy event
 * for the shell declared "Hybrid"; else "Ed25519". This captures
 * the sticky-latching semantic from `11-axioms.md` E13 ("after
 * the tick at which a given shell declared Hybrid ... shell-per-
 * tick snapshot ... trust only the chain-anchored policy").
 *
 * Mathematical property: sticky under WAL append-only (A14).
 * Once a Hybrid policy event lands, it persists in subsequent
 * snapshots — the existential is monotone under set extension.
 * Because the property is derivable from A14 + the existential
 * structure, PolicyMonotonic is carried as a derivable theorem
 * (see `PolicyMonotonic_Derivable` below) rather than as a
 * separate state-level invariant.
 *)
\* @type: (Seq($policyEvent), $shell) => $signatureClass;
ShellPolicySnapshot(events, shell_id) ==
    IF \E i \in DOMAIN events :
         /\ events[i].shell = shell_id
         /\ events[i].declared_class = "Hybrid"
    THEN "Hybrid"
    ELSE "Ed25519"

(* --- Tick-filtered ShellPolicySnapshotAtTick helper ---
 *
 * Returns the shell-per-tick snapshot of SignatureClassPolicy as
 * of tick `t` — filters policy events to those with effective_tick
 * <= t. Used by NoSignatureDowngradeAfterPolicy to capture the
 * E13 "after the tick at which a given shell declared Hybrid"
 * semantic. The unfiltered ShellPolicySnapshot would retroactively
 * invalidate pre-Hybrid Ed25519 receipts (a receipt at tick 0
 * combined with a Hybrid policy at tick 1 would violate the spec
 * body's "after" temporal ordering); the tick-filtered variant
 * aligns the INV with the IssueAuditReceipt precondition (issue-
 * time check at the receipt's own tick).
 *)
\* @type: (Seq($policyEvent), $shell, Int) => $signatureClass;
ShellPolicySnapshotAtTick(events, shell_id, t) ==
    IF \E i \in DOMAIN events :
         /\ events[i].shell = shell_id
         /\ events[i].declared_class = "Hybrid"
         /\ events[i].effective_tick <= t
    THEN "Hybrid"
    ELSE "Ed25519"

(* --- Module-specific invariants --- *)

\* INV E12-1: RuntimeBootstrap chain-anchored. The bootstrap event
\* manifest digest must equal the genesis configuration anchor at
\* the genesis tick (refinement of E12 in-band recording).
RuntimeBootstrapChainAnchored ==
    /\ bootstrap_event.effective_tick = InitialBootstrapTick
    /\ bootstrap_event.manifest_digest = BootstrapManifestDigest

\* INV E12-2: ManifestDriftReplayRejected (fail-secure). On replay,
\* a manifest mismatch between the loaded runtime and the
\* chain-anchored bootstrap must be rejected. Captured as a
\* state-level invariant: bootstrap_event.manifest_digest is
\* immutable post-Init (no transition rebinds).
ManifestDriftReplayRejected ==
    bootstrap_event.manifest_digest = BootstrapManifestDigest

\* INV E11: cascade Op::ScheduleAction Tick(t+1) deterministic
\* placement. Every cascade op's scheduled_at is exactly its
\* original_tick + 1 — no scheduler non-determinism.
CascadeOpDeterministicTickPlacement ==
    \A i \in DOMAIN cascade_ops :
        cascade_ops[i].scheduled_at = cascade_ops[i].original_tick + 1

\* INV E13-1: NoSignatureDowngradeAfterPolicy. Receipts issued for
\* a shell that has previously declared "Hybrid" (with
\* effective_tick <= issued_tick) must themselves be "Hybrid"-signed.
\* Uses ShellPolicySnapshotAtTick (tick-filtered) to capture E13
\* "after the tick at which a given shell declared Hybrid" semantic
\* per spec body. Contrapositive equivalent of NoPqcDowngradeAttack
\* — both INVs preserved for positive + negative form documentation.
NoSignatureDowngradeAfterPolicy ==
    \A i \in DOMAIN audit_receipts :
        LET r        == audit_receipts[i]
            snapshot == ShellPolicySnapshotAtTick(policy_events,
                                                  r.shell,
                                                  r.issued_tick)
        IN snapshot = "Hybrid" => r.signature_class = "Hybrid"

\* INV E13-2: NoPqcDowngradeAttack (explicit attack-form). No
\* receipt is "Ed25519" while a prior "Hybrid" policy event exists
\* for the same shell at or before the receipt's issued tick.
NoPqcDowngradeAttack ==
    ~ \E i \in DOMAIN audit_receipts, j \in DOMAIN policy_events :
        /\ policy_events[j].shell = audit_receipts[i].shell
        /\ policy_events[j].declared_class = "Hybrid"
        /\ policy_events[j].effective_tick <= audit_receipts[i].issued_tick
        /\ audit_receipts[i].signature_class = "Ed25519"

\* INV E13-3: HybridDualSignBoth_implies_AND_verify (Hybrid AND-mode
\* safety net, positive enforcement-form sibling of E13-2 attack-form).
\* Under a Hybrid shell-policy snapshot at the receipt's issued tick,
\* the receipt's signature_class must be "Hybrid" AND both the
\* Ed25519 and ML-DSA 65 abstract verify flags must hold. This
\* refines the runtime requirement that a Hybrid policy mandates
\* both classical and post-quantum signatures to validate (AND, not
\* OR) before a receipt is accepted.
HybridDualSignBoth ==
    \A i \in DOMAIN audit_receipts :
        LET r        == audit_receipts[i]
            snapshot == ShellPolicySnapshotAtTick(policy_events,
                                                  r.shell,
                                                  r.issued_tick)
        IN snapshot = "Hybrid" =>
              /\ r.signature_class = "Hybrid"
              /\ r.ed25519_verify = TRUE
              /\ r.mldsa65_verify = TRUE

(* --- Theorem: PolicyMonotonic_Derivable (sticky-Hybrid from A14) ---
 *
 * THEOREM PolicyMonotonic_Derivable (tick-monotonicity form):
 *   For any shell s, policy_events sequence p, and times t1 <= t2,
 *   if ShellPolicySnapshotAtTick(p, s, t1) = "Hybrid", then
 *   ShellPolicySnapshotAtTick(p, s, t2) = "Hybrid".
 *
 * PROOF SKETCH:
 *   ShellPolicySnapshotAtTick existentially quantifies over policy
 *   events with effective_tick <= t. For t1 <= t2, the predicate
 *   "effective_tick <= t1" implies "effective_tick <= t2" (integer
 *   monotonicity). Therefore any witness Hybrid event satisfying
 *   the t1 predicate also satisfies the t2 predicate. The
 *   existential is monotone under predicate weakening, so
 *   "Hybrid" at t1 implies "Hybrid" at t2. QED.
 *
 * COROLLARY (state-evolution form): By A14 (WAL append-only),
 * policy_events at state s1 is a prefix of policy_events at state
 * s2 for s1 reached before s2. ShellPolicySnapshot (without tick
 * filter) is monotone under this prefix extension — any prior
 * "Hybrid" witness persists.
 *
 * This theorem stands in for an explicit PolicyMonotonic state-
 * level invariant: it is a derivable consequence of integer
 * monotonicity + the tick-filtered helper definition, and the
 * corollary additionally requires A14 append-only. The spec body
 * sticky/latching wording at `runtime-book/src/en/architecture/
 * 11-axioms.md` E13 + §14.11 supplies the source-of-truth
 * narrative anchor.
 *)

(* --- Concrete state machine refinement --- *)

\* DeclareSignatureClassPolicy — shell declares its signature
\* class (typically "Hybrid"). The event lands in the WAL-anchored
\* policy_events sequence (E13 in-band chain anchoring).
DeclareSignatureClassPolicy(shell_id, cls) ==
    /\ shell_id \in Shells
    /\ cls \in SignatureClasses
    /\ Len(policy_events) < MaxPolicyEvents
    /\ tick + 1 <= MaxTicks
    /\ policy_events' = Append(policy_events,
         [shell           |-> shell_id,
          declared_class  |-> cls,
          effective_tick  |-> tick])
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    bootstrap_event,
                    audit_receipts, cascade_ops >>

\* IssueAuditReceipt — audit receipt issued for a shell. The
\* signature_class must respect the sticky-Hybrid policy snapshot
\* enforced as a precondition (E13 verifier-side check).
IssueAuditReceipt(shell_id, cls) ==
    /\ shell_id \in Shells
    /\ cls \in SignatureClasses
    /\ Len(audit_receipts) < MaxAuditReceipts
    /\ tick + 1 <= MaxTicks
    \* E13 sticky-Hybrid enforcement at issue time:
    /\ ShellPolicySnapshot(policy_events, shell_id) = "Hybrid"
         => cls = "Hybrid"
    \* Receipts under a Hybrid signature class carry both Ed25519 and
    \* ML-DSA 65 verify flags (HybridDualSignBoth AND-mode); receipts
    \* under Ed25519 carry only the Ed25519 flag.
    /\ audit_receipts' = Append(audit_receipts,
         [shell           |-> shell_id,
          issued_tick     |-> tick,
          signature_class |-> cls,
          ed25519_verify  |-> TRUE,
          mldsa65_verify  |-> (cls = "Hybrid")])
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    bootstrap_event, policy_events,
                    cascade_ops >>

\* ScheduleCascadeOp — append a cascade op with deterministic
\* tick placement (E11): `scheduled_at = original_tick + 1`.
ScheduleCascadeOp(orig_tick) ==
    /\ orig_tick \in 0..(MaxTicks - 1)
    /\ Len(cascade_ops) < MaxCascadeOps
    /\ tick + 1 <= MaxTicks
    /\ cascade_ops' = Append(cascade_ops,
         [original_tick |-> orig_tick,
          scheduled_at  |-> orig_tick + 1])
    /\ tick' = tick + 1
    /\ UNCHANGED << chain_tip, wal,
                    actor_user_binding, actor_shell_binding,
                    authenticated_actors,
                    runtime_bootstrap, signature_class_policy,
                    bootstrap_event, policy_events,
                    audit_receipts >>

InitCR3 ==
    /\ chain_tip = << >>
    /\ wal = << >>
    /\ tick = 0
    /\ actor_user_binding \in [Actors -> Users]
    /\ actor_shell_binding \in [Actors -> Shells]
    /\ authenticated_actors = {}
    /\ runtime_bootstrap = "BOOTSTRAP_PLACEHOLDER"
    /\ signature_class_policy = [s \in Shells |-> "Ed25519"]
    /\ bootstrap_event =
         [shell           |-> CHOOSE s \in Shells : TRUE,
          manifest_digest |-> BootstrapManifestDigest,
          effective_tick  |-> InitialBootstrapTick]
    /\ policy_events = << >>
    /\ audit_receipts = << >>
    /\ cascade_ops = << >>

NextCR3 ==
    \/ \E s \in Shells, c \in SignatureClasses :
         DeclareSignatureClassPolicy(s, c)
    \/ \E s \in Shells, c \in SignatureClasses :
         IssueAuditReceipt(s, c)
    \/ \E t \in 0..(MaxTicks - 1) : ScheduleCascadeOp(t)

SpecCR3 == InitCR3 /\ [][NextCR3]_vars_cr3

(* --- Refinement Map (per formal/tla-plus/README.md convention) ---
 *
 * Section 1 — Abstract Vars <-> Concrete Vars
 *
 *   runtime_core.tla         cr3 (refined + extended)
 *   ---------------------    ------------------------------------
 *   chain_tip                (carry-through, CR-1's domain)
 *   wal                      (carry-through, CR-1's domain)
 *   tick                     (carry-through)
 *   actor_user_binding       (carry-through, CR-2's domain)
 *   actor_shell_binding      (carry-through, CR-2's domain)
 *   authenticated_actors     (carry-through, CR-2's domain)
 *   runtime_bootstrap        (carry-through opaque base; refined by
 *                            bootstrap_event below per Finding 1
 *                            absorption pattern)
 *   signature_class_policy   (carry-through; refined by sticky-
 *                            Hybrid ShellPolicySnapshot derived
 *                            from policy_events sequence)
 *   --                       bootstrap_event \in
 *                            RuntimeBootstrapEvent           NEW
 *   --                       policy_events \in
 *                            Seq(SignatureClassPolicyEvent)  NEW
 *   --                       audit_receipts \in
 *                            Seq(AuditReceipt)               NEW
 *   --                       cascade_ops \in Seq(CascadeOp)  NEW
 *
 * Section 2 — Abstract step <-> Concrete step
 *
 *   runtime_core.Next   ->   DeclareSignatureClassPolicy /
 *                            IssueAuditReceipt /
 *                            ScheduleCascadeOp (3-disjunctive)
 *
 * Section 3 — Module-specific INVs + theorem
 *
 *   E12-RuntimeBootstrapChainAnchored      (MC, genesis pin)
 *   E12-ManifestDriftReplayRejected        (MC, fail-secure)
 *   E11-CascadeOpDeterministicTickPlacement (MC)
 *   E13-NoSignatureDowngradeAfterPolicy    (MC, sticky-derived)
 *   E13-NoPqcDowngradeAttack               (MC, attack-form)
 *   E13-HybridDualSignBoth                 (MC, AND-mode positive form)
 *   E13-PolicyMonotonic_Derivable          (theorem from A14)
 *)

(* --- Adversary "PQC downgrade" residual reduction lemma ---
 *
 * Pre-E13 surface for PQC downgrade attack:
 *   - Verifier trusts message-tag signature_class without chain
 *     anchor → adversary tampers a post-Hybrid receipt to claim
 *     Ed25519 signing → bypasses Hybrid quantum-security.
 *
 * E13 closure under the sticky-Hybrid semantic:
 *   - SignatureClassPolicy events chain-anchored in WAL via A14
 *     append-only.
 *   - Verifier reconstructs ShellPolicySnapshot from WAL prefix.
 *   - Sticky-Hybrid: once "Hybrid" declared, all subsequent
 *     receipts must be "Hybrid"-signed (PolicyMonotonic_Derivable
 *     is a theorem from A14 — no separate state-level INV
 *     required).
 *   - Ed25519 receipt after a "Hybrid" declaration is rejected
 *     (NoSignatureDowngradeAfterPolicy + NoPqcDowngradeAttack);
 *     a Hybrid receipt's both Ed25519 and ML-DSA legs must verify
 *     (HybridDualSignBoth, AND-mode).
 *
 * Residual surface:
 *   (i)  WAL forge before chain-anchored detection (A14 append-
 *        only invariant breach, out-of-scope per L0 sealing
 *        guarantees);
 *   (ii) Cryptographic collision in BLAKE3 chain hash
 *        (cryptographic primitive failure, out-of-scope per
 *        `docs/implementation-plan.md` §19, symmetric with
 *        E14.L2 wasmtime zero-day exclusion).
 *
 * Symmetric counterpart: CR-1 Adversary A residual reduction
 * (E14 compute determinism). Together CR-1 + CR-3 close the
 * chain-affecting compute axis (Adversary A) + chain-anchored
 * policy axis (PQC downgrade). CR-4 closes the chain-non-
 * affecting observer axis (Adversary B, E15).
 *)

====

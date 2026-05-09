# Sealing pattern lineage — A24 ↔ SealedCapToken ↔ SealedHostImport

This document anchors the **sealed-trait pattern** as an architectural
invariant spanning L0 → L1+ runtime. The same Rust idiom (private-module
marker + super-traited public trait) is used at three axioms, and the
consistency itself is part of the sealing chain.

## Pattern statement

```rust
mod private_marker {
    pub trait Sealed {}
}

pub trait PublicSealedTrait: private_marker::Sealed + /* additional bounds */ {}

// Same-crate impls only — external crates cannot name `private_marker::Sealed`
// (it lives behind a private path), so external `impl Sealed for T` is
// syntactically impossible. By transitivity, external `impl PublicSealedTrait
// for T` is impossible.
impl private_marker::Sealed for ConcreteType {}
impl PublicSealedTrait for ConcreteType {}
```

The pattern is a standard Rust technique (RFC 1023; Rustonomicon "sealed
traits") and gives a **type-system-level** monomorphic guarantee: the
universe of types satisfying `PublicSealedTrait` is the finite set of impls
declared inside the host crate.

## Three anchors

### A24 (L0 — `arkhe-kernel`)

**`AuthInputs` sealed projection** (`book/src/en/architecture/invariants.md`
line 56, classified TYPE-ADJACENT in the threat-model count). The
`AuthInputs` struct has private fields and a single constructor — a sealed
`pub(crate) fn project()` that operates on `InstanceScope<'i>` +
`StagedStateAtIndex`.

This is the **L0 origin** of the sealed pattern: the canonical projection
that produces authorization inputs cannot be constructed from outside the
kernel's privacy boundary, so any caller wishing to feed inputs into the
authorize/dispatch path must traverse the sealed constructor. External
forgery of `AuthInputs` is type-syntactically impossible.

### SealedCapToken (L1+ runtime, sibling ArkheForge: `arkhe-forge-platform`)

**E15.b cap_token confinement strengthening.**

In sibling ArkheForge, `arkhe-forge-platform/src/wasm_runtime_common/mod.rs:262-329` declares:

- `mod private_seal { pub trait Sealed {} }` (single private marker shared
  across cap-token and host-import bounds)
- `pub trait HookCapTokenSealed: private_seal::Sealed + Ord + Copy + Clone +
  Debug + Hash + 'static {}`
- `pub trait ObserverCapTokenSealed: private_seal::Sealed + Ord + Copy + ...`

Hook + observer host crates each impl `Sealed` + the matching public sealed
trait for their concrete cap-token enums. External crates cannot widen the
cap-token universe — the runtime invariant `ObserverCapabilityConfined`
(CR-4 INV) is mirrored at the type-system level by INV `CapTokenSealed`
(also CR-4) plus lemma `SealedTrait_implies_E15.b` (CR-4 comment block).

Witness tests at `mod.rs:813,822` (`hook_cap_token_satisfies_sealed_bound`,
`observer_cap_token_satisfies_sealed_bound`) compile-time-verify that the
concrete cap-token types satisfy the sealed bound; trait-bound regression
would fail typeck.

### SealedHostImport (L1+ runtime, sibling ArkheForge: `arkhe-forge-platform`)

**E14.L2-Allow rule 3 host-import allow-list strengthening.**

In sibling ArkheForge, `arkhe-forge-platform/src/wasm_runtime_common/mod.rs:361-394` declares:

- `mod private_seal { pub trait Sealed {} }` (same private marker as the
  cap-token bound — single source of seal authority)
- `pub trait SealedHostImport: private_seal::Sealed {}`

Hook's `CapabilityLinker` and observer's `ObserverCapabilityLinker` are the
only same-crate types impl-ing `SealedHostImport`. External crates cannot
synthesize a new host-linker type that registers a different host-import
set — the CR-1 4-set `HostImports` invariant
(`hook.state.read` + `hook.state.write` + `hook.emit.extra_bytes` +
`hook.fuel.consumed`) is mirrored at the type-system level by INV
`HostImportSealed` (CR-1) plus lemma `SealedHostLinker_implies_4_set`
(CR-1 comment block).

Witness tests at `mod.rs:898,910`
(`hook_capability_linker_satisfies_sealed_host_import`,
`observer_capability_linker_satisfies_sealed_host_import`) compile-time-
verify the bound.

## Why this lineage matters

The three anchors form a **vertical pattern axis**:

```
L0 axiom layer:   A24 sealed projection (AuthInputs)
                  └─ private fields + sealed pub(crate) constructor

Runtime CR layer: SealedHostImport (CR-1, hook-side host-import 4-set)
                  └─ private_seal::Sealed marker + SealedHostImport trait

Runtime CR layer: SealedCapToken (CR-4, observer/hook cap-tokens)
                  └─ private_seal::Sealed marker + Hook/ObserverCapTokenSealed
```

Three properties make this a meaningful architectural lineage rather than
incidental code reuse:

1. **Same Rust idiom at every level** — the `private_marker::Sealed +
   super-traited public trait` pattern is verbatim across L0 and runtime.
   Future audits can apply one pattern check uniformly.

2. **Same enforcement mechanism** — type-system monomorphism. None of the
   anchors rely on runtime checks for the sealing property; the universe of
   inhabiting types is fixed at compile time by the host crate's privacy
   boundary.

3. **Same threat-model role** — closing a "type universe expansion" attack
   vector. Pre-sealing, an external crate could theoretically synthesize a
   new type satisfying the trait bound; post-sealing, this is
   syntactically impossible. The TLA+ refinements (`CapTokenSealed`,
   `HostImportSealed`) capture the post-sealing invariant; the lemmas
   (`SealedTrait_implies_E15.b`, `SealedHostLinker_implies_4_set`) make the
   reduction explicit.

## Verification anchors

For each row, the cite triplet (spec body / TLA+ INV+lemma / Rust witness)
is captured in the canonical inventory:

| Anchor | Spec body | TLA+ refinement | Rust witness |
| --- | --- | --- | --- |
| A24 | `book/src/en/architecture/invariants.md:56` | (no TLA+ — type-adjacent at L0 axiom layer) | sealed `pub(crate) fn project()` constructor + private fields |
| SealedCapToken | E15.b axiom | `cr4_observer_capability_confinement.tla` INV `CapTokenSealed` + lemma `SealedTrait_implies_E15.b` | `hook_cap_token_satisfies_sealed_bound`, `observer_cap_token_satisfies_sealed_bound` |
| SealedHostImport | E14 axiom | `cr1_chain_hash_invariant.tla` INV `HostImportSealed` + lemma `SealedHostLinker_implies_4_set` | `hook_capability_linker_satisfies_sealed_host_import`, `observer_capability_linker_satisfies_sealed_host_import` |

The axiom-test-cite inventory (`formal/axiom-test-cite.toml`) is the
machine-readable form; this document is the human-readable narrative
companion.

## Adding a new sealed-pattern anchor

Adding a new sealed-pattern anchor (e.g., a hypothetical
`SealedSignatureInputs` strengthening on the cryptography surface) follows
the same triplet:

1. Add a Rust `mod private_X { pub trait Sealed {} }` + super-traited public
   trait + concrete impls inside the host crate.
2. Add a compile-time witness test
   (`<concrete_type>_satisfies_sealed_<bound>`) at the module's `tests`
   sub-module.
3. Add a TLA+ INV (`<Concept>Sealed`) and a lemma
   (`SealedX_implies_<axiom>`) to the relevant `cr*.tla` module's
   refinement section, paired with the Rust commit.
4. Update `formal/axiom-test-cite.toml` (`tla_invs` += INV; `tla_lemma` +=
   lemma; `impl_tests` += witness tests) and re-extend this lineage table
   with a fourth row.

The pattern is intentionally additive — sealed traits compose by stacking
super-trait bounds, so the lineage grows without retraction.

## References

- `book/src/en/architecture/invariants.md:56` — A24 statement (L0 source).
- `formal/tla-plus/cr1_chain_hash_invariant.tla` — `HostImportSealed` INV +
  `SealedHostLinker_implies_4_set` lemma comment block.
- `formal/tla-plus/cr4_observer_capability_confinement.tla` —
  `CapTokenSealed` INV + `SealedTrait_implies_E15.b` lemma comment block.
- `formal/axiom-test-cite.toml` — machine-readable cite inventory.
- `formal/tla-plus/README.md` — E1-E15 ↔ TLA+ INV mapping table (this
  document supplements the table with the cross-row sealing lineage).
- RFC 1023 + Rustonomicon — sealed-traits idiom reference.

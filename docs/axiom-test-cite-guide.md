# Axiom Test Cite — Author + Operator Guide

This guide explains how the **`formal/axiom-test-cite.toml` ↔ TLA+ INV ↔ Rust impl
test** triple-link works, and what an author must do when adding or modifying an
axiom. It is the companion document to the four-piece axiom-cite mechanism: the
7-config CI test matrix, the inventory file, the grep gate, and this guide.

## Purpose

The Runtime axiom set (E1–E15) has
three independent enforcement layers:

1. **TLA+ refinement** — formal proof of the abstract invariant
   (`formal/tla-plus/<module>.tla`).
2. **Rust impl test** — concrete check at the implementation level
   (in sibling ArkheForge: `arkhe-forge-core/tests/axioms_e_series.rs` and
   domain-specific test files).
3. **Inventory cite** — machine-readable mapping that links the abstract proof to
   the concrete check (`formal/axiom-test-cite.toml`).

The CI grep gate (`scripts/verify-axiom-cite.sh`) verifies that every cited TLA+
identifier and impl test name actually exists, so silent regressions —
*"axiom defined but test missing"* or *"test renamed but inventory not updated"* —
fail the build.

## Quick reference

| Action | Local command | Exit code |
| --- | --- | --- |
| Run the grep gate locally | `bash scripts/verify-axiom-cite.sh` | 0 pass / 1 mismatch / 2 env |
| Inventory file | `formal/axiom-test-cite.toml` | — |
| Inventory schema version | `[meta] schema_version` | currently `1` |
| CI step | `lint` job → "Verify axiom-test cite mapping" | — |

## Adding a new axiom

When a new MACHINE-CHECKED axiom (e.g., `E16`) is introduced, the author must
update **all three layers** plus the inventory in a single coherent change.
The CI grep gate makes the inventory the single source of truth — get the
inventory right and everything else falls into place.

**Step 1 — spec body**. Add the axiom row to the canonical axiom inventory
(statement, L0 lineage, tier).

**Step 2 — TLA+ refinement**. Add an INV (or theorem) capturing the axiom in the
appropriate `formal/tla-plus/<module>.tla` file. Use PascalCase identifier names
that read at the call site (e.g., `LayerImportStrictlyDownward` rather than
`E3_INV`). If the axiom doesn't fit into any of the existing CR-1/CR-2/CR-3/R4-I/
CR-4 modules, add a new module (`crX_*.tla`) and update the README.md mapping
table at `formal/tla-plus/README.md`.

**Step 3 — Rust impl test**. Add a test that exercises the runtime contract. Place
it in sibling ArkheForge: `arkhe-forge-core/tests/axioms_e_series.rs` for E-series
axioms, or in the domain-specific test file when the axiom is realised in another
crate (e.g., `arkhe-subset-rust-check` for E14.L1 deny-list,
`arkhe-forge-platform/src/hook_host/capability_linker.rs` for E14.L2). Test names
must be unique and greppable as `fn <name>` (one identifier per axiom slot,
multiple tests allowed when an axiom has multiple invariants).

**Step 4 — inventory entry**. Add an `[E<N>]` section to
`formal/axiom-test-cite.toml`. The minimum fields are:

```toml
[E16]
tier = "MC"
axiom = "<one-line restatement of the axiom>"
spec_section = "§<section>"
tla_inv = "<single INV name>"           # or `tla_invs = [...]` when ≥ 2
tla_module = "formal/tla-plus/<module>.tla"
impl_tests = ["<test_name>"]
impl_paths = ["<crate>/tests/<file>.rs:<line>"]
```

When the axiom has more than one invariant or theorem:

```toml
tla_invs = ["FirstInvariant", "SecondInvariant"]
tla_theorem = "DerivableTheorem"           # optional
```

Multiple impl tests work the same way:

```toml
impl_tests = ["test_one", "test_two", "test_three"]
impl_paths = ["crateA/tests/x.rs:10", "crateB/src/lib.rs:200"]
```

The grep gate looks for each `impl_test` in **any** of the cited `impl_paths`, so
the array doesn't need to be aligned 1:1.

**Step 5 — verify locally**. Run the gate before pushing:

```bash
bash scripts/verify-axiom-cite.sh
```

The expected output ends with `OK: all axiom cites verified`. A mismatch means
one of the four pieces (spec, TLA+, Rust test, inventory) is out of step with
the others — fix the cite, not the gate.

## Modifying an existing axiom's test

The most common change is renaming a Rust impl test or restructuring a TLA+
module. Either change requires an inventory update in the same commit.

- **Rename a Rust impl test**: update `impl_tests` in the matching axiom section.
  If the line moved, update the `:line` suffix in `impl_paths` for archival
  accuracy (the gate ignores the suffix; humans read it).
- **Rename a TLA+ INV**: update `tla_inv` (or the matching entry in `tla_invs`).
  Cite drift across `formal/tla-plus/README.md` is **not** caught by this gate —
  update the README mapping table by hand.
- **Move an impl test to a different crate**: update both `impl_tests` (if the
  function was renamed) and `impl_paths` (the new crate path).

Run `bash scripts/verify-axiom-cite.sh` after every change.

## Renaming a TLA+ INV without updating the inventory — what happens

The grep gate fails with a clear message:

```
FAIL E13: tla_invs 'NoSignatureDowngradeAfterPolicy' NOT FOUND in formal/tla-plus/cr3_replay_determinism.tla
```

This is the intended catch — the gate refuses the change until the inventory
matches reality. Update `tla_invs` in `[E13]` and re-run.

## Skip patterns (descriptive names)

Some axioms use composite names rather than literal TLA+ identifiers and are
skipped by the gate on purpose:

- **E1** `CONSTANTS_PrimitiveSet` — definitional foundation (the primitive set
  is a CONSTANTS declaration, not a state-level INV). Verified by the impl test
  `e1_core_5_type_code_ranges_pinned` only.
- **E2** `ChainHashDeterministic_via_E14_subsumption` — E2 is documented as
  subsumed by E14, so the inventory points at E14's INV with a name that
  signals the subsumption. Verified by the deterministic-compute impl tests.
- **`tla_lemma` entries** (e.g., `SealedHostLinker_implies_4_set`,
  `SealedTrait_implies_E15.b`) — lemmas are documented in TLA+ comment
  blocks (proof sketches with anchors) rather than declared as theorem
  entities. Names follow `<premise>_implies_<conclusion>` convention; the
  comment block carries the formal content. Verified by inspecting the
  lemma section of the cited `tla_module` plus the witness impl tests
  cited via `impl_tests` (e.g., the sealed-trait pattern anchors —
  `hook_cap_token_satisfies_sealed_bound` etc.).

The gate's skip rule is purely lexical: names containing `_via_` or
`_implies_`, or starting with `CONSTANTS_`, are not searched for in the TLA+
module. New descriptive names should follow the same convention; everything
else is treated as a literal identifier.

**Per-key-type cite handling**: the gate accepts four TOML key types under
each axiom section — `tla_inv` (single literal name), `tla_invs` (list of
literal names), `tla_theorem` (single literal name), and `tla_lemma` (single
descriptive name, expected to match a skip pattern). The first three are
grep-verified verbatim; the fourth is documented-only (verified via the
human-readable comment block + paired witness tests).

## Running the CI grep gate locally

The script lives at `scripts/verify-axiom-cite.sh`. It is a thin bash wrapper
around an inline Python program (Python 3.11+ for `tomllib`, with a `tomli`
fallback for older interpreters). The script does:

1. Resolve the repo root via `git rev-parse --show-toplevel`.
2. Load `formal/axiom-test-cite.toml`.
3. For each MC axiom and non-MC axiom section, grep the cited TLA+ identifier in
   the cited TLA+ module and grep `fn <test_name>` in the cited impl path.
4. Exit 0 if every cite resolves, 1 on the first mismatch, 2 if Python or
   `tomllib` is missing.

The CI runs the same script in the `lint` job; failure surfaces as a normal
GitHub Actions error annotation.

## Script integrity baseline

The grep gate is itself a sealing artifact — silent edits to
`scripts/verify-axiom-cite.sh` could weaken the gate (e.g., loosening the
word-boundary regex, adding a permissive skip pattern, short-circuiting
exit codes). To prevent silent regressions of the verifier itself, the
script's SHA-256 hash is pinned in a baseline file and the CI re-checks it
on every push.

- **Baseline file**: `ci/scripts-baseline-hashes.txt` (sibling of
  `ci/l0-baseline-hashes.txt`, separate from the L0 source-file baseline).
- **CI step**: `lint` job, sibling of the `Verify axiom-test cite mapping`
  step. Hash drift fails the build with the same fail-secure semantics as
  the L0 baseline.
- **Update procedure**: any intentional change to
  `scripts/verify-axiom-cite.sh` must regenerate the baseline in the same
  commit:

  ```bash
  shasum -a 256 scripts/verify-axiom-cite.sh > ci/scripts-baseline-hashes.txt
  ```

  The PR diff then shows both the script change and the hash update — a
  reviewer can confirm intent at a glance.

The script integrity baseline is symmetric with `verify-l0-baseline.sh`
(L0 source-file baseline) and is part of the sealing chain for the
script-side verification surface.

## CI gate failure — how to debug

The failure log lists the offending axiom, the missing identifier, and the
expected location. Three common causes:

- **Test was renamed**, inventory not updated — update `impl_tests`.
- **TLA+ INV was renamed**, inventory not updated — update `tla_inv` /
  `tla_invs` / `tla_theorem`.
- **Inventory entry has a typo** — re-check against the actual file. The grep
  is case-sensitive and uses word boundaries, so `MyInv` does not match
  `MyInvariant`.

If the gate flags a name that looks correct, run the same regex by hand to
confirm:

```bash
grep -nE "\bMyInv\b" formal/tla-plus/cr3_replay_determinism.tla
# in sibling ArkheForge:
grep -nE "\bfn\s+my_test\b" arkhe-forge-core/tests/axioms_e_series.rs
```

The exit code from `verify-axiom-cite.sh` reflects the first mismatch — if you
see 1, fix it and run again to surface any further issues.

## Architecture notes

- **The inventory is the truth source for the gate, not the spec.** When the
  spec changes, the inventory must change to match; the gate then verifies the
  TLA+ + Rust pair against the inventory.
- **The gate is one-sided.** It checks that every inventoried cite resolves; it
  does **not** check that every TLA+ INV or every Rust test name has an
  inventory entry. Adding a new TLA+ INV or impl test without an inventory
  entry is silent — the inventory is the discoverability layer.
- **Word-boundary grep is intentional.** Substring matches would let
  `ChainHashDeterministic` mistakenly satisfy a cite for a hypothetical
  `ChainHashDeterministic2`. Word boundaries align with TLA+ identifier rules
  and Rust function names.
- **Composite names are documentation, not enforcement.** The skip rule keeps
  E1 and E2 visible in the inventory without forcing a fictional TLA+ symbol.

## References

- `formal/axiom-test-cite.toml` — inventory file.
- `scripts/verify-axiom-cite.sh` — grep gate script.
- `.github/workflows/ci.yml` `lint` job — CI gate integration.
- `formal/tla-plus/README.md` — TLA+ refinement narrative + E1-E15 ↔ INV table.
- Runtime axiom set (E1-E15) — canonical narrative carried by the inventory + this guide.
- Sibling ArkheForge: `arkhe-forge-core/tests/axioms_e_series.rs` — E1-E13 impl tests.
- Sibling ArkheForge: `arkhe-runtime-proofs/src/lib.rs` — Kani 5-property suite.

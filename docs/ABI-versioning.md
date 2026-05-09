# ABI Versioning

ArkheKernel has **two independent version coordinate systems**. They are intentionally separated, and it is normal for their values not to match. This document specifies the meaning, relationship, and change policy of the two coordinate systems.

## Two coordinate systems

### 1. Project release tag (`v0.13`)

- **Location**: release marker across the repo. Each crate's `Cargo.toml` `[package] version` (`0.13.0`), git tag (`v0.13`), `CHANGELOG.md` entry.
- **Audience**: project users — "which release am I using at this point in time".
- **Bump condition**: when there is a public change and the team-lead declares a release.
- **Policy**: this project aims for a single final release at v0.13. Even if fixes are introduced later, the same version is retained. v1.0 is intentionally never reached.

### 2. L0 kernel ABI snapshot (`(0, 13)` / `(0, 13, 0)`)

- **Location**: `arkhe-kernel/src/persist/wal.rs`
  ```rust
  pub const CURRENT_KERNEL_SEMVER: (u16, u16, u16) = (0, 13, 0);
  pub const ABI_VERSION:           (u16, u16)      = (0, 13);
  ```
- **Audience**: binary compatibility verifiers of WAL / snapshot / event bytes (the replay path, external verifiers).
- **Meaning**: a marker indicating which snapshot the **serialized ABI** of the L0 kernel corresponds to. `(0, 13)` means "L0 ABI snapshot 0.13" — it identifies the set of byte formats including the WAL header, record layout, and `StepStage` discriminant.
- **Bump condition**: when L0 makes a breaking change to its own WAL / event byte layout. That is, bump only under the single condition where replay incompatibility occurs.
- **Policy**: one of the core protected targets of L0 DO NOT TOUCH. It moves **independently** of project release bumps.

## Why they are separated

This project includes L0 ABI snapshot `(0, 13)` in the `v0.13` release. The reasons the two values can in general differ are as follows.

- **Different boundaries**: the project release is a repo-level public marker, and the ABI snapshot is a record-level marker of the kernel byte format. Since the meanings differ, there is no basis for the values to match.
- **Different bump conditions**: the project release may be bumped frequently per unit of public change, but the L0 ABI is bumped only when there is a WAL / snapshot breaking change.
- **L0 DO NOT TOUCH protection**: the L0 kernel source is protected by baseline hashing (`ci/l0-baseline-hashes.txt`) so that it is not modified without re-review. If L0 source were modified on every project release bump, this protection would lose meaning.

As a result, the two coordinate systems are independent. The fact that project `v0.13` happens to carry L0 ABI `(0, 13)` at this release point is the official combination for v0.13; future releases may carry an unchanged ABI tag.

## What external consumers should look at

| Purpose | Location to check |
|---|---|
| Which repo release | `Cargo.toml` package version / git tag |
| WAL / snapshot byte compatibility | `WalHeader::ABI_VERSION` or, at replay time, header.abi_version |
| Kernel semver string | `WalHeader::CURRENT_KERNEL_SEMVER` |

Those reading WAL or building external verifiers judge based on the **ABI snapshot**. Execution environments / deployment pipelines judge based on the project release.

## Policy for L0 ABI bump timing

The L0 ABI snapshot is bumped only when the WAL / event byte format undergoes a breaking change. The procedure for that:

1. **Dedicated L0 DIP first** — since changes to serialization paths such as WAL / snapshot / `StepStage` imply replay incompatibility, cold-read by auditor + theorist + cryptographer is mandatory.
2. **DO NOT TOUCH exception record** — attach the DIP document link to the `ci/l0-baseline-hashes.txt` update PR, with auditor approval.
3. **ABI bump record** — explicitly note "L0 ABI snapshot `(0, N)` → `(0, N+1)`" as a separate entry in `CHANGELOG.md`. Separated from project release changes.
4. **Backward path** — so that WAL recorded under the previous ABI snapshot can also be read, the replay header check logic in the next snapshot must handle the previous snapshot either as a compatibility reject or an upgrade path.

L0 source modifications without this procedure are a violation of L0 DO NOT TOUCH, and the CI `l0-baseline` job blocks them.

## Summary

- `v0.13` is the repo release, `(0, 13)` is the L0 ABI snapshot — the two are different axes that simply happen to align at this release point.
- Even when the values differ, the state is intended; if the project release is bumped without an ABI break, the L0 ABI is held constant.
- External consumers use the coordinate system that matches their purpose: release tag for deployment, ABI snapshot for WAL compatibility.
- An L0 ABI bump is permitted only through a dedicated DIP path, and requires an exemption record in the DO NOT TOUCH baseline and auditor approval.

## Hash-based wire invariants

Beyond the ABI snapshot, the repo has two **hash-pinned wire invariants**. They require a spec drift correction even when the schema itself does not change, if reproducibility breaks.

### Manifest canonical digest (sibling ArkheForge: `arkhe-forge-platform::manifest`)

`canonical_digest = blake3::keyed_hash(derive_key("arkhe-forge-manifest-digest", &[]), toml::to_string(snapshot))`

- Input is the `toml` crate's serialise output — sensitive to `BTreeMap` ordering, key spacing, and string quoting.
- Within the frozen `Cargo.lock` window the `toml` minor version is pinned, so the emitted bytes are stable.
- A future `toml` **major** version bump (e.g. `1.x → 2.x`) may rewrite the BTreeMap traversal / whitespace canonicalisation and therefore drift the digest.

**Drift response procedure** (Option C):
1. The regression test in sibling ArkheForge — `arkhe-forge-platform/src/manifest.rs::digest_invariant::TIER0_DEV_DIGEST_V0_11` — surfaces the drift on the first failing build.
2. The operator updates the sentinel bytes to the new value.
3. **Companion micro-patch in the canonical ABI policy notes** — the schema itself did not change, so manifest `schema_version` stays put; the patch records the toml-crate bump as the explicit contract change.
4. Manifest `schema_version` is **not** bumped — Option C avoids the contract ambiguity of "schema_version bump without schema change".

Rejected alternatives: Option B (mix `toml` version into the digest input) leaks a build-dep into the audit log; Option A (bump `schema_version` for non-schema reasons) muddies the contract.

### WAL chain digest

L0's WAL chain BLAKE3 hash is bound to §1's ABI snapshot `(0, 13)`. The WAL record `postcard` field order is DO NOT TOUCH #8 — Runtime-side changes can never disturb it.

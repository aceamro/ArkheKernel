# docs/

Top-level documentation index for **ArkheKernel** (L0 kernel library).
Specs build via mdBook; operational and planning documents live as flat
Markdown here.

## Canonical specifications

| Spec | Path | Renders to |
|------|------|------------|
| L0 Kernel design + axioms (A1-A24, S1) | `book/` (mdBook) | `https://aceamro.github.io/ArkheKernel/book/` |
| Public API reference | `cargo doc --no-deps --workspace` | `https://aceamro.github.io/ArkheKernel/api/arkhe_kernel/` |

Layer independence is one-way: L0 ← Runtime ← Shell. Shell repositories
(e.g., `arkhe-shell-bbs`) are external to this repo.

## Planning + policy

| Document | Purpose |
|----------|---------|
| [`msrv-policy.md`](msrv-policy.md) | MSRV 1.80+ pin + future bump conditions. |
| [`sealing-pattern-lineage.md`](sealing-pattern-lineage.md) | Sealed-trait lineage — A24 ↔ SealedCapToken ↔ SealedHostImport, the architectural anchor of the type-system sealing chain. |
| [`axiom-test-cite-guide.md`](axiom-test-cite-guide.md) | Author + operator guide for the axiom-cite triple-link (TLA+ INV ↔ Rust impl test ↔ inventory). |
| [`pqc-software-only.md`](pqc-software-only.md) | PQC software-only signer caveat — Tier 0/1/2 deployment matrix, key handling guide. |

## Build, ABI, release

| Document | Purpose |
|----------|---------|
| [`build-reproducibility.md`](build-reproducibility.md) | Same-machine Linux x86_64 reproducibility scope + procedure. |
| [`ABI-versioning.md`](ABI-versioning.md) | Schema evolution + WAL ABI stability rules. |

## Operator runbooks (`runbook/`)

| Document | Purpose |
|----------|---------|
| [`runbook/tier-0-limitations.md`](runbook/tier-0-limitations.md) | Tier-0 (software-KEK dev) deployment boundary + limits. |

---

*Repo-level entry points: [`README.md`](../README.md), [`CHANGELOG.md`](../CHANGELOG.md).*

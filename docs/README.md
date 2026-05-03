# docs/

Top-level documentation index for **ArkheKernel + ArkheForge Runtime**
(L0 + L1 + L2). Specs build via mdBook; operational and planning documents
live as flat Markdown here.

## Canonical specifications

| Spec | Path | Renders to |
|------|------|------------|
| L0 Kernel design + axioms (A1-A24, S1) | `book/` (mdBook) | `https://aceamro.github.io/ArkheKernel/book/` |
| ArkheForge Runtime — L1 + L2 design | `runtime-book/` (mdBook) | `https://aceamro.github.io/ArkheKernel/runtime-book/` |
| Public API reference | `cargo doc --no-deps --workspace` | `https://aceamro.github.io/ArkheKernel/api/arkhe_kernel/` |

Layer independence is one-way: L0 ← Runtime ← Shell. Shell repositories
(e.g., `arkhe-shell-bbs`) are external to this repo.

## Planning + policy

| Document | Purpose |
|----------|---------|
| [`implementation-plan.md`](implementation-plan.md) | Runtime implementation plan — 19 items + milestones + entry-checkpoint conditions. |
| [`alpha-release-schedule.md`](alpha-release-schedule.md) | Alpha-release blocker docs (5 Runtime + 1 BBS) and external-legal review buffer. |
| [`msrv-policy.md`](msrv-policy.md) | MSRV 1.80+ pin + future bump conditions. |
| [`spec-drift-candidates.md`](spec-drift-candidates.md) | Implementation-ahead drifts queued for the next spec patch round. |
| [`runtime-sealing-plan.md`](runtime-sealing-plan.md) | v0.12 Runtime sealing plan — 8 work tracks (A-H), axioms E14 / E15, decision register. |

## Build, ABI, release

| Document | Purpose |
|----------|---------|
| [`build-reproducibility.md`](build-reproducibility.md) | Same-machine Linux x86_64 reproducibility scope + procedure. |
| [`ABI-versioning.md`](ABI-versioning.md) | Schema evolution + WAL ABI stability rules. |
| [`release-keys.md`](release-keys.md) | Sigstore keyless cosign release-signing policy + verification commands. |

## Operator runbooks (`runbook/`)

| Document | Purpose |
|----------|---------|
| [`runbook/tier-0-limitations.md`](runbook/tier-0-limitations.md) | Tier-0 (software-KEK dev) deployment boundary + limits. |
| [`runbook/l2-single-active-operations.md`](runbook/l2-single-active-operations.md) | Active-passive L2 single-active model + SLO suspension protocol. |

Additional alpha-blocker runbooks (`crypto-erasure.md`, `hsm-degraded-mode.md`,
`alpha-to-beta-promote.md`) and the legal-basis note (`Legal/gdpr-crypto-erasure.md`)
land during the matching milestones — see
[`alpha-release-schedule.md`](alpha-release-schedule.md).

---

*Repo-level entry points: [`README.md`](../README.md) (English),
[`README.ko.md`](../README.ko.md) (Korean), [`CHANGELOG.md`](../CHANGELOG.md).*

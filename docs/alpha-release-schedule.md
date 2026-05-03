# Alpha Release Schedule

**Purpose**: pin the owner / milestone / deadline matrix for the documents
that must be in place before the alpha tag ships, and reserve an 8-week
external-legal-review buffer for the GDPR crypto-erasure note inside the
same plan.

This document supersedes the prior `alpha-blocker-docs-schedule.md` and
`gdpr-legal-review-schedule.md`; the GDPR review is folded in as §4.

---

## 1. Six alpha-blocker docs

| # | Document | Path | Phase deadline | Primary owner | Secondary (review / split) |
|---|----------|------|----------------|---------------|----------------------------|
| 1 | Operator runbook — crypto-erasure | `docs/runbook/crypto-erasure.md` | Crypto primitives milestone complete | veteran | cryptographer |
| 2 | GDPR legal basis | `docs/Legal/gdpr-crypto-erasure.md` | Pre-freeze (8-week buffer, §4) | external legal reviewer | cryptographer |
| 3 | AWS KMS free-tier guide | `docs/guide/kms-free-tier.md` | KMS integration milestone start | veteran | cryptographer |
| 4 | HSM degraded-mode runbook | `docs/runbook/hsm-degraded-mode.md` | Crypto primitives milestone complete | veteran | cryptographer |
| ~~5~~ | ~~BBS telnet TLS wrap matrix~~ | **BBS repo deliverable** — managed in `arkhe-shell-bbs` (split 2026-04-24) | BBS repo maintainer | — |
| 6 | Alpha → beta promote runbook | `docs/runbook/alpha-to-beta-promote.md` | Pre-freeze | veteran | cryptographer |

**Runtime repo scope**: 5 docs (#1, #2, #3, #4, #6). The BBS repo carries
its own workstream; only the cross-reference is tracked here.

---

## 2. Workload distribution — relieve the veteran bottleneck

5 of the 6 docs originally landed on `veteran` as primary owner. Parallel
authoring across the crypto-primitives → pre-freeze window is a single-
person bottleneck and a delivery risk; the load is split along three axes:

### 2.1 SRE / DevOps split (crypto-primitives → pre-freeze, parallel)

When an SRE / DevOps participant joins the alpha team, the following
splits apply:

- `docs/runbook/crypto-erasure.md` — veteran outline + cryptographer
  fill-in + SRE operator-perspective review.
- `docs/runbook/hsm-degraded-mode.md` — veteran outline + SRE on-call
  perspective review.

### 2.2 BBS repo delegation (post-split)

- BBS telnet TLS wrap matrix — deliverable of the `arkhe-shell-bbs`
  repository. Outside this Runtime schedule; only the cross-repo
  reference is tracked above (row 5, struck through).
- `docs/runbook/alpha-to-beta-promote.md` — **stays in the Runtime repo**.
  AuthCredential rotation / session invalidation / login-block
  protocols sit on the Runtime L2 surface, so the BBS repo references
  this runbook as the deployment runbook.

### 2.3 External legal-reviewer dependency

- `docs/Legal/gdpr-crypto-erasure.md` is owned by an external legal
  reviewer (counsel / compliance consultant). The internal team
  provides technical context and accepts review feedback.
- The 8-week buffer schedule lives in §4 below.

---

## 3. Per-milestone gates

Each milestone gate requires the matching docs to be in **draft-complete**
state.

| Milestone | Gate condition |
|-----------|----------------|
| Shell-dogfood (BBS dogfood start) | BBS repo deliverable (TLS wrap matrix) tracked separately in the BBS repo. No Runtime gate. |
| Crypto-primitives complete | #1 crypto-erasure runbook + #4 HSM degraded-mode runbook draft. #3 KMS free-tier outline. |
| KMS-integration start | #3 AWS KMS free-tier guide draft. |
| Pre-freeze | #2 GDPR legal external sign-off + #6 alpha → beta promote runbook draft. |
| Release-freeze gate | All 5 Runtime docs complete + cross-review passed + BBS repo deliverable confirmed (cross-repo). |

---

## 4. GDPR legal review — 8-week buffer schedule

`docs/Legal/gdpr-crypto-erasure.md` (alpha blocker #2) is the spec
§14.9.1 §§9 EDPB / Article 29 WP / ICO / UK DPA citation document. The
external legal reviewer (lawyer / compliance consultant) is the primary
owner; the internal team supplies technical context and integrates
review feedback.

### 4.1 Schedule overview

```
Crypto-primitives mid-milestone (W-8) → external legal review (W-8 → W-2) → sign-off (W0)
                              ≈ 8-week buffer
```

`W0` = **release-freeze pre-freeze deadline** (alpha-blocker completion
mandate, §15.5 of the implementation plan).

### 4.2 Week-by-week

| Week | Date range (example) | Action | Owner |
|------|----------------------|--------|-------|
| **W-8** | Crypto-primitives mid-milestone | Internal draft v1 complete (§14.9.1 §§9 framework: 5 case-law / regulatory citations) + legal-reviewer contract / NDA signed + draft sent | cryptographer (draft), veteran (contract) |
| W-7 | W-8 + 1 week | Initial legal kick-off + clarifying questions (terminology / scope) returned | legal + team-lead |
| **W-6** | W-8 + 2 weeks | Legal first feedback received (strengths / weaknesses) | legal |
| W-5 | W-8 + 3 weeks | Internal revision v2 (first feedback applied) | cryptographer + veteran |
| **W-4** | W-8 + 4 weeks | Revised draft → second legal review submission | cryptographer |
| W-3 | W-8 + 5 weeks | Legal second review | legal |
| **W-2** | W-8 + 6 weeks | Legal final review + clarification call | legal + veteran |
| W-1 | W-8 + 7 weeks | Final revision v3 (minor edits) + proof-read | cryptographer + veteran |
| **W0** | Pre-freeze | Sign-off + commit `docs/Legal/gdpr-crypto-erasure.md` | legal (sign), veteran (commit) |

### 4.3 Draft scope at W-8

Internal draft v1 (W-8 baseline) covers:

1. **Framework introduction** — crypto-erasure satisfies the
   "effective erasure" requirement of GDPR Art. 17.
2. **Five case-law / regulatory citations** (spec §14.9.1 §§9):
   - EDPB Guidelines 04/2019 on Controller / Processor.
   - EDPB Opinion 04/2022 on Transfers.
   - Article 29 WP Opinion 05/2014 on Anonymisation Techniques.
   - ICO Anonymisation guidance (2023).
   - UK DPA 2018 Schedule 3.
3. **Technical architecture** — envelope encryption + HSM DEK shred
   (spec §14.9.1 §§2). The legal reviewer must understand why
   plaintext recovery is impossible.
4. **Multi-region 2PC** (spec §14.9.1 §§13) — per-region tombstone +
   restore-refuse semantics.
5. **Limitations disclosure** — backup-retention ciphertext residue
   (§14.11.1 BackupErasurePropagated SLA p99 < 7 days) + Tier-0
   software-KEK does not provide compliance-grade guarantees.
6. **Cross-references** — spec §14.9.1 §§9, runbook
   `docs/runbook/crypto-erasure.md`.

### 4.4 Risk mitigation

#### Legal reviewer delay (> 1 week)

**Trigger**: legal misses a weekly delivery by more than 7 days.

**Action**:
1. Team-lead immediate escalation.
2. Option A — accept release-freeze deadline slip (alpha + 1 week).
3. Option B — narrow legal scope (e.g. drop UK DPA Schedule 3
   citation, defer to a future expansion) and continue with the
   simplified document.
4. Option C — alternate legal reviewer (replaceable within 2 weeks).

#### Internal draft delay

**Trigger**: W-8 draft v1 not complete.

**Action**:
1. Slip crypto-primitives mid-milestone → late-milestone by 1 week.
2. Adopt compressed W-7 / W-6 schedule (legal first-feedback → second-
   revision window shortened by 1 week).
3. Continued slip → alpha delay (team-lead decision).

#### Critical legal finding

**Trigger**: legal determines the crypto-erasure approach is
**fundamentally insufficient** under GDPR Art. 17.

**Action**:
1. **Immediate team-lead escalation** → spec drift policy
   (implementation plan §11).
2. Critical classification → emergency micro-patch or spec DIP
   re-open (severity-dependent).
3. Alpha delivery **fully reconsidered** — alternate strategy review
   (e.g. WAL ciphertext TTL + auto-destruction).

### 4.5 Deliverable checklist (W0)

```
- [ ] Legal-reviewer formal sign-off (signature + date)
- [ ] All 5 case-law / regulatory citations verified (URL + retrieval date + quote)
- [ ] Technical section accuracy confirmed (cryptographer + legal cross-check)
- [ ] Limitations section includes "Tier-0 compliance not guaranteed"
- [ ] Cross-reference complete — spec §14.9.1 §§9 / runbook / alpha-to-beta-promote
- [ ] PDF / HTML render verified (mdBook or external converter)
- [ ] GitHub commit `docs/Legal/gdpr-crypto-erasure.md` + legal email archive
```

---

## 5. Tracking

Per-doc status tracked in
`docs/alpha-blocker-status.md` (created at the start of the
shell-dogfood milestone) with weekly updates. Status values:

- `pending` — not started.
- `drafting` — in progress.
- `internal-review` — team cross-review.
- `external-review` — external (legal / SRE third-party) review.
- `complete` — final approval + commit.

Release-freeze gate checklist (Runtime repo scope):

```
- [ ] #1 crypto-erasure runbook — complete
- [ ] #2 GDPR legal — complete (external sign-off)
- [ ] #3 KMS free-tier guide — complete
- [ ] #4 HSM degraded-mode — complete
- [ ] #6 alpha → beta promote — complete
- [ ] BBS TLS wrap matrix — BBS repo deliverable confirmed (cross-repo)
```

---

## 6. References

- Implementation plan §15.5 — alpha-blocker docs table.
- Implementation plan §13 release-criteria #2 — "alpha-blocker docs (6 items) complete".
- Spec §14.9.1 §§9 — GDPR case-law / regulatory citation framework.

---

*Repo baseline schedule. Actual document drafts are produced as parallel
workstreams during the matching milestones.*

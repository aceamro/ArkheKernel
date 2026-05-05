# Release Keys

**Scope**: `runtime_doctor_journal` Ed25519 signing key + Release binary signing key. This document is the operational source of truth — the keys themselves are not committed to this repo (stored in hardware).

---

## 1. Key Inventory

| Key | Use | Storage | Rotation |
|---|---|---|---|
| `runtime-doctor-journal-v1` | Signs each entry of the `runtime_doctor_journal` append-only audit log (spec §12.4 / §14) | HW key (YubiKey 5.7+ / NitroKey 3) — 2-person co-custody | 90d + 30d grace (FG8) |
| `release-signing-v1` (Ed25519) | Signs binary release tags | HW key — leader-exclusive | 1 year + 30d grace |
| `release-signing-v1-pqc` (MlDsa65) | PQC Hybrid release signing — activated in a future extension | HW key — leader-exclusive | 1 year |

Currently, 2 are active: `runtime-doctor-journal-v1` + `release-signing-v1`. `release-signing-v1-pqc` is scheduled to be generated and activated in line with the spec §14.7 PQC timeline (`runtime_max ≥ "0.30"`).

---

## 2. Key generation procedure (one-time per key)

### 2.1 Environment requirements

- **Air-gapped machine** (network-disconnected). Live OS (Tails / pure Live USB) recommended.
- 2 or more HW security keys (YubiKey 5.7+ FIPS / NitroKey 3) (primary + backup).
- 2 operators physically present (witness).

### 2.2 Ed25519 key generation

```bash
# Run on the air-gapped machine.
# Choose one of ssh-keygen + age + GPG — currently using the age-based path.

# Option A: age + sshagent (recommended, simpler)
age-keygen -o /media/yubikey/runtime-doctor-journal-v1.private
# The public key is output to stdout — commit to §4 of this document.

# Option B: GPG --expert → Ed25519 sign-only subkey
gpg --expert --full-generate-key
# (1) ECC sign only, (5) Ed25519, key-usage = sign
# Move only the subkey to the HW key (keep the primary offline).
```

### 2.3 Move to HW key

**YubiKey**:
```bash
# Use the OpenPGP applet instead of ykman piv.
gpg --edit-key runtime-doctor-journal-v1
# keytocard → 3 (Authentication key slot) or select subkey
```

**NitroKey**:
```bash
nitropy nk3 info
# After importing the private key, set the smart-card PIN (6-8 digits).
```

### 2.4 Backup HW key generation

Move the same private key material as the primary to a secondary HW key. **Complete the secondary before reconnecting to the network**. If the primary is lost, the secondary can take over immediately.

### 2.5 Commit public key to this repo

```
Add the public key hex to §4 of docs/release-keys.md (this document) + git commit.
```

**Never commit private keys**. Also complete disk wipe of the air-gapped machine.

---

## 3. 2-person co-custody policy

### runtime-doctor-journal-v1

- Primary HW key — held by **auditor**.
- Secondary HW key — held by **veteran**.
- PIN: each of the 2 people sets their own PIN separately (unknown to the other). When signing a log, the custodian enters their own PIN.
- **Solo signing forbidden** — if either of the 2 operators is absent, signing waits.
- When signing a single journal entry, the primary is used; the secondary is for disaster recovery.

### release-signing-v1

- Both primary and secondary are held **solely by the leader** (sole release decision-maker).
- However, release PRs require mandatory review by auditor + veteran (immediately before key use).

---

## 4. Public Key Pinning

Current state: **key generation not yet completed**. This section will be filled in after key generation.

```
runtime-doctor-journal-v1:
  algorithm: Ed25519
  public_key_hex: <TODO: fill in at key generation>
  created: <YYYY-MM-DD>
  primary_operator: auditor
  secondary_operator: veteran

release-signing-v1:
  algorithm: Ed25519
  public_key_hex: <TODO: fill in at key generation>
  created: <YYYY-MM-DD>
  operator: leader

release-signing-v1-pqc:
  algorithm: MlDsa65 (Dilithium FIPS 204)
  public_key_hex: <TODO: fill in when activated in a future extension>
```

### External publication

- Note the public key fingerprints (BLAKE3 first 8 bytes) of `runtime-doctor-journal-v1` + `release-signing-v1` at the top of the Runtime repo `README.md`.
- Dedicated repo `aceamro/arkhe-release-keys` (GitHub, public) — historical key archive.

---

## 5. Rotation Procedure

### 5.1 runtime-doctor-journal-v1 (90d cycle)

1. **D-30**: pre-notify operators + prepare the new key generation procedure.
2. **D+0**: generate the new key (`runtime-doctor-journal-v2`) (§2 procedure).
3. **D+0 ~ D+30** (grace period): both keys are valid for verify-only — existing journal entries can be verified. New entries are signed with the v2 key.
4. **D+30**: demote the v1 key to verify-only (new signing forbidden). v2 is active.
5. **D+90** (next rotation): physically destroy the v1 key HW (drill + hammer). Add a "destroyed at <tick>" entry to `runtime_doctor_journal` (signed with v2 to prevent self-signed forgery).

### 5.2 release-signing-v1 (1-year cycle)

- Same grace policy + public key archive in the `arkhe-release-keys` repo.
- After rotation, existing release tags can still be verified historically with the v1 public key.

---

## 6. Disaster Recovery

### Primary HW key loss / physical destruction

1. **Immediately**: switch serving to the secondary HW key (the corresponding operator enters the PIN).
2. **Within D+1**: generate a new primary HW key + re-inject the same private key as the secondary.
3. **Within D+7**: generate a new secondary HW key (reconstruct backup).
4. **Journal entry**: record "primary-hw-key-rotation" in the `runtime_doctor_journal`.

### PIN loss (operator forgets PIN)

- HW key **lockout after 3 wrong PIN attempts** → equivalent to physical destruction.
- The corresponding key is handled as rotation (same path as §5.1).

---

## 7. Rollout prerequisites

- [x] Commit this document (`docs/release-keys.md`).
- [ ] Secure an air-gapped machine + purchase HW keys (auditor + veteran + leader).
- [ ] Generate `runtime-doctor-journal-v1` + `release-signing-v1`.
- [ ] Fill in §4 Public Key Pinning (after the keys exist).

Currently at the **policy + procedure documentation** stage — actual key generation comes after HW procurement.

---

## 8. References

- Spec §12.4 `runtime_doctor_journal` chain-signed (audit log tamper-resistance).
- Spec §14.7 PQC timeline — `release-signing-v1-pqc` activation point.
- Implementation plan §18 Supply chain security — signed release key management.
- Implementation plan §14 Threat model actor 2 (malicious runtime operator) — 2-person co-custody mitigation.

---

## 9. Sigstore release signing (keyless)

When a release tag is pushed, the `.github/workflows/ci.yml` `release-sign` job attaches Sigstore keyless cosign signatures **independently of** the `release-signing-v1` HW key. The two paths are layered defenses rather than substitutes for each other.

### 9.1 Trigger conditions

- Trigger: `if: startsWith(github.ref, 'refs/tags/v')` — `v*` tags only.
- Runner: `ubuntu-latest`. Required upstream jobs: `test`, `reproducibility`, `supply-chain`, `l0-baseline` all green.
- Permissions: `id-token: write` (OIDC), `contents: read`. No stored keys — GitHub Actions OIDC token → Fulcio short-lived certificate.

### 9.2 Signed artifacts

| Type | Path |
|---|---|
| Release binaries | `target/release/dice-domain` |
| Crate tarballs | `cargo package --no-verify` output of the publish-true crates (`target/package/<crate>-0.13.0.crate`) |

Crate list: `arkhe-kernel`, `arkhe-macros`. `examples/dice` stays `publish = false` and is not signed.

### 9.3 Flow summary

1. Deterministic build (`SOURCE_DATE_EPOCH` + `--remap-path-prefix`) produces the binaries — same environment as the §3 reproducibility job.
2. In dependency order (`arkhe-macros` → `arkhe-kernel`), run `cargo publish --dry-run --allow-dirty --no-verify -p <crate>` to assemble + validate each `.crate`. Whenever `cargo publish --dry-run` fails for any reason (e.g. a path-dep not yet on crates.io, a transient network error, registry throttling), the tarball for that crate is defensively skipped with a WARN — release tag signing is not blocked on it because the actual publish happens in a separate operator-gated workflow.
3. `cosign sign-blob --yes --bundle <artifact>.cosign.bundle <artifact>` per available artifact. The bundle packages the cert + signature + Rekor transparency log inclusion proof.
4. `actions/upload-artifact@v4` uploads the entire `artifacts/` directory as `arkhe-release-<tag>`.

### 9.4 Verification (downstream consumer)

```bash
cosign verify-blob \
  --bundle dice-domain.cosign.bundle \
  --certificate-identity-regexp "^https://github\\.com/aceamro/ArkheKernel/\\.github/workflows/ci\\.yml@refs/tags/v" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  dice-domain
```

The `certificate-identity-regexp` only accepts certificates issued by this repo's `ci.yml` under a tag build — certificates from another repo or branch are rejected.

### 9.5 Relation to the HW key (§1)

| Axis | `release-signing-v1` (HW key) | Sigstore keyless cosign |
|---|---|---|
| Key material | YubiKey / NitroKey (offline storage) | Short-lived OIDC-scoped X.509 (Fulcio) |
| Signer | leader (physical access) | GitHub Actions runner (OIDC identity) |
| Evidence | binary detached signature | Rekor transparency log entry |
| Rotation | 1 year + 30d grace | Automatic (cert ttl ~ 10 min, takes effect immediately when the OIDC identity is rotated) |
| On failure | leader rotates manually | Recover the runner OIDC configuration |

Providing both signatures cross-cuts the "HW key compromise" and "Rekor offline" attack paths.

---

## 10. Pre-publish gate (mandatory)

Before any `v*` tag is pushed (which triggers the §9 `release-sign` job) **and** before any `cargo publish` is invoked manually, run:

```bash
bash scripts/pre-publish-verify.sh
```

The script runs the same 5 gates that CI enforces, in the same order, and exits non-zero on the first failure. **`cargo publish` is permitted only when the script exits 0.** Pushing a `v*` tag without a green local run is a process violation — CI is the safety-net, not the primary gate.

### 10.1 Gate map

| Gate | Check | CI counterpart |
|---|---|---|
| 1/5 | `cargo test --workspace --all-features` | `test` job |
| 2/5 | `cargo clippy --workspace --all-targets -- -D warnings` | `lint` job |
| 3/5 | `bash scripts/verify-l0-baseline.sh` (DO-NOT-TOUCH 8 SHA-256) | `l0-baseline` job |
| 4/5 | `bash scripts/verify-axiom-cite.sh` (axiom inventory ↔ TLA+ INV + Rust impl test 1:1) | axiom-cite step |
| 5/5 | `apalache-mc typecheck formal/tla-plus/*.tla` | `tla-plus-check` job |

Gate 5 is **SKIP-with-warning** when `apalache-mc` is not installed locally — CI's `tla-plus-check` job remains authoritative. Local installation per `formal/tla-plus/README.md` §Tooling is recommended for full parity.

### 10.2 Operator checklist (per release)

1. `git status` — working tree clean, on the release branch.
2. `bash scripts/pre-publish-verify.sh` — wait for `[5/5] all gates green`.
3. `git tag -s v<version>` — sign the tag with `release-signing-v1` (HW key, §1).
4. `git push origin v<version>` — pushes the signed tag; CI runs the §9 `release-sign` job.
5. `cargo publish -p <crate>` — in the dependency order documented in §9.2.

If gate 1-5 fails: do **not** delete the failure output — it is the audit trail for the operator log.

### 10.3 Why a separate pre-flight (not just CI)

CI runs after a tag is pushed; a tag push is a public, observable event. A failing gate caught only at CI leaves a published failed-tag in the git history (or worse, a partially published crate set on crates.io). The pre-publish script collapses the round-trip — the same gates run locally, before any external surface is touched.

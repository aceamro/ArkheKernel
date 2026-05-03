# Spec Drift Candidates — input for the next spec patch round (DIP)

The spec body in `runtime-book/src/architecture/runtime-spec.md` is frozen under
the v0.11 single-release policy, but four entries in this release diverge
slightly from the spec text. None of them break the wire contract, axioms,
or user-facing surface — they are all implementation-ahead drifts. The next
spec patch round (DIP) consumes this document as input and corrects the spec.

Each entry uses this form:

- **Spec location**: § reference in the spec body.
- **Current spec text**: quoted.
- **Implementation reality**: actual code location + behaviour.
- **Drift type**: implementation-ahead / spec-ahead / wire-equivalent.
- **Resolution path**: how the spec patch closes the gap.
- **Source commit**: drift-introducing commit hash.

---

## 1. AES-GCM nonce invocation field

- **Spec location**: `runtime-book/src/en/architecture/14-open-questions.md` §14.9.1 §§3 (split-structure post-v0.11; single-file `runtime-spec.md` no longer present).
- **Current spec text**: "AES-GCM(-SIV) 12-byte nonce = `random[4] || counter[8]` (single-writer: `random[4]` is instance-pinned and stable across replay)".
- **Implementation reality**: `arkhe-forge-platform/src/crypto.rs::aes_gcm_nonce_from_counter` builds `replica_id.to_be_bytes()[4] || counter.to_be_bytes()[8]`. `Dek::with_config(material, DekConfig { replica_id })` defaults `replica_id = 0` for single-writer and switches to per-replica ids for federation builds. Matches NIST SP 800-38D §8.2.1 single-writer Option 1.
- **Drift type**: implementation-ahead (federation-ready). With a single writer (`replica_id = 0`) the two paths are wire-equivalent — existing WAL records remain compatible.
- **Resolution path**: amend spec §§3 to define the invocation field as the instance-pinned `replica_id: u32`. Add an F6 multi-region reservation note. State that any `replica_id` change requires a manifest-anchored `SignatureClassPolicy`-style event (§14.7).
- **Source commit**: `2e568b5` (AES-GCM counter nonce + process protection FFI).

---

## 2. BLAKE3 domain string list

- **Spec location**: `runtime-book/src/en/architecture/14-open-questions.md` §14.7 (canonical SoT) / `03-ecs-meta.md` §3.2 (mirror) — domain separator list. Path updated post-v0.11 split-structure refactor (single-file `runtime-spec.md` no longer present).
- **Current spec text**: four declared domain strings (`arkhe-forge-entity-id` / `arkhe-forge-manifest-digest` / `arkhe-forge-dek-shred-attestation` / `arkhe-forge-aws-kms-dek-id`).
- **Implementation reality**: `arkhe-forge-platform/src/hf2_kms/journal.rs::JournalEntry::compute_chain_hash` uses an additional domain, `arkhe-runtime-doctor-journal-chain`, for the `runtime_doctor_journal` chain-signed persistence (spec §12.4 / §14.11.2 HF2 audit-log tamper-resistance).
- **Drift type**: spec-ahead (spec list is incomplete).
- **Resolution path**: add `arkhe-runtime-doctor-journal-chain` to the spec §3.2 domain separator table. Cross-reference the chain hash definition + domain in §12.4.
- **Source commit**: `2e568b5`.
- **Resolution-applied**: spec body §14.7 m4 table row + §3.2 mirror list + §12.4 chain hash domain cross-ref added; `arkhe-forge-platform/src/hf2_kms/journal.rs` L43-45 advisory comment rewritten as English-only registered-status; PQC co-register reviewed (no new domain needed — `arkhe-forge-audit-receipt` already covers Ed25519 + Hybrid receipt MAC). Resolving commit: see git log for "BLAKE3 domain spec patch (doctor journal register)".

---

## 3. UserSalt typed anchor

- **Spec location**: `runtime-book/src/en/architecture/14-open-questions.md` §14.9.1 §§4 — body_hash composition (split-structure post-v0.11).
- **Current spec text**: "`body_hash = BLAKE3(body || user_salt || entry_nonce)`. `user_salt` is a per-user 16-byte HSM-held value".
- **Implementation reality**: `arkhe-forge-core/src/pii.rs::UserSalt` is a newtype, `pub struct UserSalt(pub [u8; 16])`, with `Zeroize` and `!Clone` (single-owner-per-fetch invariant). `compute_body_hash` takes `(body, user_salt: &UserSalt, entry_nonce)` — typed anchor.
- **Drift type**: wire-equivalent + type-safe wrapper. `postcard` serialises a transparent newtype identically to the inner array — wire compatible.
- **Resolution path**: amend spec §§4 to note that `UserSalt` is exposed as a typed anchor over `[u8; 16]`, with runtime-enforced `Zeroize` + non-Clone single-owner-per-fetch semantics. State the wire layout is unchanged.
- **Source commit**: `2e568b5`.

---

## 4. `TIER0_DEV_DIGEST_V0_11` regression sentinel

- **Spec location**: new invariant — `runtime-book/src/en/architecture/05-l1-l2-boundary.md` §5.6 / `14-open-questions.md` §14.7 (manifest canonical digest, split-structure post-v0.11).
- **Current spec text**: "the manifest canonical digest is `blake3::keyed_hash(derive_key(\"arkhe-forge-manifest-digest\"), toml_canonical_bytes)`". The spec does not state any invariant about `toml` crate ordering / whitespace normalisation.
- **Implementation reality**: `arkhe-forge-platform/src/manifest.rs::digest_invariant` hard-pins `TIER0_DEV_DIGEST_V0_11: [u8; 32]` and the `tier0_dev_digest_matches_v0_11_sentinel` test verifies the digest on every build. A `toml` 1.x → 2.x major bump that changes byte-level output surfaces immediately as a sentinel mismatch — operators amend the spec drift in lock-step with the sentinel update (Option C documented in `manifest.rs` rustdoc).
- **Drift type**: implementation-ahead (spec lacks the invariant; code provides a stronger guarantee).
- **Resolution path**: amend spec §5.6 / §14.7 to add a "manifest canonical digest wire-stability invariant" subsection: a `toml` crate major bump that changes byte-level output requires a spec drift correction plus a `TIER0_DEV_DIGEST` sentinel update.
- **Source commit**: `2e568b5`.

---

## Misidentified candidates — NOT spec drifts

### `arkhe-forge-macros` rustfmt-default delta (NOT a drift)

`cargo fmt -p arkhe-forge-macros -- --check` reports a delta at `src/lib.rs:323+472`,
collapsing multi-line `fn` signature forms to single-line. This is **not a spec drift**:
`.github/workflows/ci.yml:57-59` explicitly excludes `arkhe-forge-macros` (alongside
`arkhe-macros` and L0) from the runtime-crate fmt scope to preserve the proc-macro
`darling`/`syn` manual style. The current multi-line form is the preserved convention,
and applying `cargo fmt` would violate the exclusion policy. No fix is needed; this
entry exists so the same `--check` delta is not re-detected as a candidate in a future
sweep.

---

## Working notes for the next round

The next spec patch DIP uses this document as an archeology entry. Each candidate's
spec patch must clear a 4-person review (theorist / cryptographer / auditor /
veteran). After a patch lands, the corresponding entry above is annotated
with a **resolution-applied** flag plus the resolving commit hash.

This document is **append-only history** — resolved entries stay in place
with an updated annotation rather than being deleted.

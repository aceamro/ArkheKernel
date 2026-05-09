# MSRV Policy — Minimum Supported Rust Version

**Purpose**: pin the **Minimum Supported Rust Version (MSRV)** for the
L0 kernel (and the sibling ArkheForge Runtime under the same baseline)
so toolchain changes never violate the "later releases must not
destabilise earlier ones" directive.

---

## 1. Current MSRV

- **Rust stable 1.80+**.
- Workspace-wide — L0 (`arkhe-kernel`) / `arkhe-macros` / every Runtime
  crate / the `examples/dice` demo all target the same baseline.
- The workspace `Cargo.toml` `[workspace.package]` table pins
  `rust-version = "1.80"`; every publish-true crate inherits via
  `rust-version.workspace = true`. `cargo build` refuses pre-1.80
  toolchains up front.
- No `rust-toolchain.toml` pin yet — CI runs the `stable` channel.
  A future extension may add an explicit pin (§5).

**Rationale**: 1.80 shipped 2024-07. As of 2026-04 the ecosystem has had
~20 months to absorb the release; edition 2021 features are stable, and
the cargo-features needed by the workspace (dependency inheritance,
`workspace.package` inheritance) are present.

---

## 2. No MSRV bump within the current release

**Hard rule**: do not bump MSRV during the current release window.

**Rationale**:

- "Later releases must not destabilise earlier ones" directive — MSRV
  changes propagate into downstream shell toolchains, so a post-alpha
  MSRV change is a breaking change.
- Removes the temptation to use nightly-only features mid-release —
  stable 1.80 only.

**Exceptions**: none. The current release uses stable 1.80.

---

## 3. Future-extension bump gates (decision criteria)

A future extension may bump MSRV if **any one** of the conditions below
holds:

### 3.1 Security patch (unavoidable)

**Trigger**: an upstream Rust / LLVM / sysroot security vulnerability
is published, and the patch requires a newer MSRV.

**Action**:

- Confirm the `CVE-YYYY-NNNN` ID + affected range.
- Determine the minimum bump (e.g. 1.80 → 1.83, not 1.85).
- Handle as a future-extension DIP (not a current-release patch).
- Record the security-driven MSRV bump in `CHANGELOG.md`.

### 3.2 Ecosystem crate MSRV bump (strong dependency)

**Trigger**: a core dependency (`ed25519-dalek` / `postcard` / `blake3` /
`serde`, etc. — workspace deps) bumps MSRV.

**Action**:

- Decide whether an old-MSRV-compatible version pin remains viable
  (e.g. is the security patch backported to a 0.x branch?).
- If not, bump MSRV.
- Evaluate alternative crates (`ed25519-zebra` vs `ed25519-dalek`, etc.).

### 3.3 Language-feature dependency (rare)

**Trigger**: a Rust language feature (e.g. `generic_const_exprs`
stabilisation, `async fn in trait` improvements) is **required to
resolve a current-spec problem**.

**Action**:

- Define the "spec problem" precisely — convenience improvements are
  rejected.
- Pass a 4-person review in the future-extension DIP cycle.
- Allow ≥ 6 months of grace for the shell ecosystem to migrate after
  the bump.

---

## 4. Bump procedure

When an MSRV bump is approved:

1. **DIP proposal** — include the bump in the future-extension DIP
   round. Critical classification → emergency patch; otherwise a
   planned DIP item.
2. **Notice** — `CHANGELOG.md` + `README.md` + shell maintainer
   notification (≥ 6 weeks lead time).
3. **`rust-toolchain.toml` pin** (§5) updated.
4. **CI matrix** — old MSRV + new MSRV both build for at least 2
   release cycles before old MSRV drops.
5. **Release notes** — call out the breaking change explicitly.
6. **Documentation** — update this policy + add a migration-guide link.

---

## 5. `rust-toolchain.toml` pin

No pin today; CI uses the `stable` channel. A future extension may
adopt a pin:

**Pro**:

- Reproducibility — "same toolchain → same binary" enforced automatically
  (see `docs/build-reproducibility.md`).
- Developer / CI parity — local builds and CI use the same compiler.

**Con**:

- Toolchain rotation — every new Rust release needs a PR within ~30 days.
- Nightly-only tooling (`cargo-expand` / `cargo-udeps` …) needs an
  override per developer.

**Decision**: stay un-pinned. CI = stable + MSRV = 1.80+ verification is
sufficient.

**Future review**: switch to a pin if reproducibility tightening becomes
the top priority.

---

## 6. Edition policy

- Current: **Rust 2021 edition** (workspace-wide).
- Edition 2024 migration is a separate bump — bumping MSRV and edition
  simultaneously is **forbidden** (two risk vectors at once).
- Edition 2024 requires (a) stable 1.85+ and (b) zero spec drift; only
  consider it in a dedicated future-extension DIP.

---

## 7. Promise to downstream shells

Downstream shell maintainers get this commitment:

- Minor bumps **do not** change MSRV.
- **Major-impact bumps** may change MSRV — only after §3 conditions are
  met and the 6-week notice has been given.
- An MSRV-driven shell breakage **is a breaking change**. No 2-version
  grace period applies — MSRV is a toolchain setting and takes effect
  immediately.

---

## 8. Summary table

| Event | Current release | Future extension |
|-------|------------------|------------------|
| Internal MSRV bump (convenience) | **Forbidden** | §3 conditions + DIP review required |
| Security patch forced | **Forbidden** (release frozen) | Allowed (future patch or DIP) |
| Ecosystem-crate bump forced | **Forbidden** (alternative pin retained) | Allowed (crate swap or MSRV bump) |
| Nightly feature usage | **Forbidden** (stable only) | Forbidden (stable channel only) |
| Edition bump (2021 → 2024) | **Forbidden** | Separate future-extension DIP |

---

## 9. References

- `Cargo.toml` `[workspace.package]` — `rust-version = "1.80"` pin.
- `docs/build-reproducibility.md` — same-toolchain → same-binary policy.
- `CHANGELOG.md` — release notes.

---

*Repo baseline policy. Reconsider only at the next future-extension DIP.*

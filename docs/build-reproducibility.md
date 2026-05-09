# Binary Reproducibility Scope

**Purpose**: specify the "same source → same hash" guarantee range for the release. Avoid over-promising.

---

## 1. Scope — Same Machine, Same Toolchain, Linux x86_64

Reproducibility is guaranteed **only under the following conditions**.

| Axis | Required | Future extension |
|---|---|---|
| **Machine** | Same physical / VM (same linker, same libc) | Cross-machine (CI matrix) |
| **Toolchain** | `rustup stable` (workspace MSRV 1.80+) | `rust-toolchain.toml` pin |
| **Target** | `x86_64-unknown-linux-gnu` | aarch64-linux / darwin / windows |
| **Build command** | `cargo build --release --locked -p dice-domain` | distributed build systems |
| **Flags** | `RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/build"` | — |
| **Epoch** | `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)` | — |

**Outside scope** (non-goals):

- Cross-platform (Linux binary ≠ macOS / Windows binary).
- Cross-architecture (x86_64 ≠ aarch64).
- Reproducibility after LLVM / rustc major version upgrade.
- Incremental compilation (`cargo build` without `--release` / dirty cache) — always destroys reproducibility.
- Proc-macros outside crates.io — `arkhe-macros` is deterministic, but determinism of external proc-macros is subject to separate audit.

---

## 2. Verification — `scripts/reproduce-build.sh`

Build the `dice-domain` release binary twice and compare SHA-256. Mismatch → exit 1.

```bash
./scripts/reproduce-build.sh
```

Non-Linux platforms (macOS / Windows) exit 0 as a skip — outside scope, not a failure.

Script internals:

1. Pin `SOURCE_DATE_EPOCH` to `git log -1 --format=%ct HEAD`.
2. Add `--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/build` to `RUSTFLAGS` — block path leakage.
3. `cargo clean --release -p dice-domain` → `cargo build --release --locked -p dice-domain`.
4. Capture `sha256sum target/release/dice-domain`.
5. Repeat 2-4 → diff the two hash sets. Identical → green; different → fail.

---

## 3. CI verification — `.github/workflows/ci.yml` `reproducibility` job

Ubuntu-only (`runs-on: ubuntu-latest`). Runs after the `test` job. Steps:

1. `actions/checkout@v4` (fetch-depth: 0 — `SOURCE_DATE_EPOCH` needs full history).
2. `dtolnay/rust-toolchain@stable`.
3. Run `./scripts/reproduce-build.sh`. Hash diff → exit 1 → CI red.

On release tag (`refs/tags/v*`) push, the `release-sign` job attaches Sigstore keyless cosign signatures to the same binaries.

---

## 4. Factors that destroy reproducibility — checklist

Operators confirm on each release PR:

- [ ] `SOURCE_DATE_EPOCH` set — blocks timestamp embedding.
- [ ] `--remap-path-prefix` configured for both prefixes — `$HOME` and `$PWD` collapse to `/build`.
- [ ] `Cargo.lock` committed + `--locked` used — dependency versions pinned.
- [ ] No `build.rs` in the workspace — re-confirmed.
- [ ] No parallel-build non-determinism — cargo release profile uses fixed codegen-units and is deterministic.
- [ ] Proc-macro determinism — `arkhe-macros` verified; external proc-macros governed by cargo-vet.
- [ ] Embedded resources (version / date) only via `SOURCE_DATE_EPOCH`.

---

## 5. Future extensions

After Alpha dogfood stabilization, expand along these axes:

- **Docker image pin** — `Dockerfile.reproducible` + digest-pinned `rust:1.80-slim-bookworm@sha256:<digest>`. Secures cross-machine reproducibility. Add CI job `reproducibility-docker` + third-party verifier rebuild.
- **Cross-platform** — add CI matrix for aarch64-linux-gnu / darwin (Apple Silicon + Intel) / windows-msvc. Compare binary hashes per target.
- **Wider artifact scope** — currently only the dice binary. To include runtime `.rlib` requires additional RUSTFLAGS work.

---

## 6. Supply-chain integration

Reproducibility is one component of supply chain security:

1. `cargo-audit` + `cargo-deny` + `cargo-vet` (see `supply-chain/`) guarantee dep integrity.
2. Reproducibility (this document) guarantees source-to-binary integrity.
3. **Sigstore keyless cosign** — on release tag push, CI attaches OIDC-signed signatures to binaries + `cargo package` tarballs.

### Local audit

To run supply-chain checks locally:

```bash
cargo install --locked cargo-deny
cargo deny check
```

CI runs the same command in the `supply-chain` job. Running locally before push prevents PR rejection — any PR that modifies `Cargo.lock` should invoke this once beforehand.

The same pattern applies to `cargo-audit` and `cargo-vet` (`cargo install --locked cargo-audit` → `cargo audit`; `cargo install --locked cargo-vet` → `cargo vet check`).

---

## 7. References

- Reproducible Builds project: https://reproducible-builds.org/
- SOURCE_DATE_EPOCH specification: https://reproducible-builds.org/specs/source-date-epoch/
- `scripts/reproduce-build.sh` — execution script.
- `.github/workflows/ci.yml` `reproducibility` + `release-sign` jobs.

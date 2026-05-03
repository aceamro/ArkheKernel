#!/usr/bin/env bash
#
# scripts/pre-publish-verify.sh — local 5-gate publish verifier.
#
# Runs the same gates CI enforces, in the same order, before a `cargo publish`
# (or `git tag v* && git push --tags`). Each gate is a hard veto: the first
# non-zero exit aborts and `cargo publish` MUST NOT proceed.
#
# Gate map (mirrors `.github/workflows/ci.yml`):
#   1/5  cargo test --workspace --all-features         (test job)
#   2/5  cargo clippy --workspace --all-targets -Dwarn (lint job)
#   3/5  scripts/verify-l0-baseline.sh                 (l0-baseline job)
#   4/5  scripts/verify-axiom-cite.sh                  (axiom-cite step)
#   5/5  apalache-mc typecheck formal/tla-plus/*.tla   (tla-plus-check job;
#        SKIP-with-warning if Apalache absent locally — CI is authoritative)
#
# Exit codes:
#   0 — all 5 gates green; `cargo publish` is ALLOWED
#   1 — one or more gates failed
#   2 — environment / repo-root resolution error
#
# Usage:
#   bash scripts/pre-publish-verify.sh
#
# Reference: docs/release-keys.md §10 (publish-gate obligation).

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT_DIR}" || ! -d "${ROOT_DIR}" ]]; then
    echo "ERROR: not inside a git working tree — cannot resolve repo root" >&2
    exit 2
fi
cd "${ROOT_DIR}"

# --- Helpers ---

GATE_TOTAL=5

print_header() {
    local idx="$1"
    local name="$2"
    echo
    echo "================================================================"
    echo "[${idx}/${GATE_TOTAL}] ${name}"
    echo "================================================================"
}

fail() {
    local idx="$1"
    local name="$2"
    local reason="$3"
    echo
    echo "::error::[${idx}/${GATE_TOTAL}] ${name} FAILED — ${reason}"
    echo "::error::cargo publish DENIED. Resolve the gate above and re-run."
    exit 1
}

# --- Gate 1/5: workspace test (all features) ---

print_header 1 "cargo test --workspace --all-features"
if ! cargo test --workspace --all-features --no-fail-fast; then
    fail 1 "workspace test" "one or more tests failed under --all-features"
fi

# --- Gate 2/5: clippy zero-warning ---

print_header 2 "cargo clippy --workspace --all-targets -- -D warnings"
if ! cargo clippy --workspace --all-targets --all-features -- -D warnings; then
    fail 2 "clippy" "lint warnings or errors detected (-D warnings is hard veto)"
fi

# --- Gate 3/5: L0 baseline (DO-NOT-TOUCH 8) ---

print_header 3 "scripts/verify-l0-baseline.sh"
if [[ ! -x scripts/verify-l0-baseline.sh && ! -f scripts/verify-l0-baseline.sh ]]; then
    fail 3 "L0 baseline" "scripts/verify-l0-baseline.sh missing"
fi
if ! bash scripts/verify-l0-baseline.sh; then
    fail 3 "L0 baseline" "L0 SHA-256 baseline mismatch (DO-NOT-TOUCH 8 violated)"
fi

# --- Gate 4/5: axiom-cite inventory ↔ TLA+ INV + Rust impl test 1:1 ---

print_header 4 "scripts/verify-axiom-cite.sh"
if [[ ! -f scripts/verify-axiom-cite.sh ]]; then
    fail 4 "axiom-cite" "scripts/verify-axiom-cite.sh missing"
fi
if ! bash scripts/verify-axiom-cite.sh; then
    fail 4 "axiom-cite" "axiom inventory cite mismatch (TLA+ INV or impl test missing)"
fi

# --- Gate 5/5: Apalache typecheck on formal/tla-plus/*.tla ---

print_header 5 "apalache-mc typecheck formal/tla-plus/*.tla"
if ! command -v apalache-mc >/dev/null 2>&1; then
    echo "WARN: apalache-mc not on PATH — gate 5 SKIPPED locally."
    echo "WARN: CI tla-plus-check job remains the authoritative gate."
    echo "WARN: install per formal/tla-plus/README.md §Tooling for local parity."
else
    shopt -s nullglob
    tla_files=(formal/tla-plus/*.tla)
    shopt -u nullglob
    if (( ${#tla_files[@]} == 0 )); then
        fail 5 "Apalache typecheck" "no .tla files found under formal/tla-plus/"
    fi
    for f in "${tla_files[@]}"; do
        echo "--- apalache-mc typecheck ${f}"
        if ! apalache-mc typecheck "${f}"; then
            fail 5 "Apalache typecheck" "type-check failed on ${f}"
        fi
    done
fi

# --- All gates green ---

echo
echo "================================================================"
echo "[${GATE_TOTAL}/${GATE_TOTAL}] all gates green — cargo publish ALLOWED"
echo "================================================================"
echo
echo "Next steps (per docs/release-keys.md §10):"
echo "  1. git tag -s v<version>"
echo "  2. git push origin v<version>   # triggers CI release-sign job"
echo "  3. cargo publish -p <crate>     # in dependency order"
exit 0

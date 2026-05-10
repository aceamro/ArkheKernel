#!/usr/bin/env bash
# reproduce-build.sh — Linux x86_64 binary reproducibility verifier.
#
# Double-builds the `dice` release binary with a deterministic
# environment (SOURCE_DATE_EPOCH + --remap-path-prefix + --locked) and
# compares sha256sum across the two builds. Hash drift → exit 1.
#
# Scope: same machine, same toolchain, x86_64-unknown-linux-gnu. macOS skips
# with exit 0 (Mach-O is not bit-reproducible under the current scope; see
# docs/build-reproducibility.md §1). Cross-platform / Docker-based paths are
# future extensions.
#
# Usage:
#   ./scripts/reproduce-build.sh
#
# CI: .github/workflows/ci.yml `reproducibility` job (Ubuntu-only).

set -euo pipefail

UNAME_S="$(uname -s)"
if [[ "$UNAME_S" != "Linux" ]]; then
  echo "reproduce-build: skipping on $UNAME_S (Linux x86_64 only — docs/build-reproducibility.md §1)."
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"
export SOURCE_DATE_EPOCH

# --remap-path-prefix blocks $HOME / $PWD leakage into debug info. Both prefixes
# must collapse to the same canonical placeholder so a third-party rebuilder on
# a different path still produces a byte-identical artifact.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/build"

BIN_DICE="target/release/dice"

hash_artifacts() {
  sha256sum "$BIN_DICE"
}

build_once() {
  cargo build --release --locked -p dice
}

clean_slate() {
  cargo clean --release -p dice >/dev/null 2>&1 || true
}

echo "reproduce-build: SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "reproduce-build: RUSTFLAGS=$RUSTFLAGS"

echo "--- Build A ---"
clean_slate
build_once
FIRST=$(mktemp)
SECOND=""
trap 'rm -f "$FIRST" "${SECOND:-}"' EXIT
hash_artifacts > "$FIRST"
cat "$FIRST"

# Leak probe. Setting both `--remap-path-prefix` and `SOURCE_DATE_EPOCH`
# is not always sufficient: an embedded string literal (RFC 3339 date /
# `env!("HOME")`) or a hardcoded path inside an external dep can still
# leak into the binary. `strings | grep` covers the three most common
# leak patterns (user home dir / cwd / recent-year date literals). The
# probe surfaces via `::warning::` only — false positives are possible,
# so a fatal exit is intentionally avoided. CI surfaces the warning as
# an annotation.
if command -v strings >/dev/null 2>&1; then
  if [[ -f "$BIN_DICE" ]] && strings "$BIN_DICE" | grep -qE "(${HOME}|${PWD}|2025-|2026-)"; then
    echo "::warning::$BIN_DICE contains an absolute path or year literal — reproducibility degraded (see docs/build-reproducibility.md §4)."
  fi
else
  echo "reproduce-build: 'strings' unavailable, skipping leak probe."
fi

echo "--- Build B (clean) ---"
clean_slate
build_once
SECOND=$(mktemp)
hash_artifacts > "$SECOND"
cat "$SECOND"

if diff -u "$FIRST" "$SECOND" > /dev/null; then
  echo
  echo "reproduce-build: OK — dice release binary is byte-identical across rebuilds."
  exit 0
fi

echo "::error::reproduce-build: binary reproducibility violation — hashes diverged."
diff -u "$FIRST" "$SECOND" || true
exit 1

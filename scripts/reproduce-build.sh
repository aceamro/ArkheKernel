#!/usr/bin/env bash
# reproduce-build.sh — Linux x86_64 binary reproducibility verifier.
#
# Double-builds the `dice-domain` release binary with a deterministic
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

BIN_DICE="target/release/dice-domain"

hash_artifacts() {
  sha256sum "$BIN_DICE"
}

build_once() {
  cargo build --release --locked -p dice-domain
}

clean_slate() {
  cargo clean --release -p dice-domain >/dev/null 2>&1 || true
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

# Leak probe — auditor Defer 2a. `--remap-path-prefix` + `SOURCE_DATE_EPOCH`
# 둘 다 설정해도 embedded string literal (RFC 3339 date / `env!("HOME")`) 또는
# 외부 dep 의 하드코딩 경로가 빠져나갈 수 있다. `strings | grep` 으로 가장
# 흔한 세 leak 패턴 (사용자 home dir / cwd / 최근 2 년 날짜 리터럴) 을 탐지
# 하되 `::warning::` 으로만 surface — false positive 가능성 때문에 fatal 처리
# 는 의도적 회피. CI 는 annotation 으로 드러난다.
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
  echo "reproduce-build: OK — dice-domain release binary is byte-identical across rebuilds."
  exit 0
fi

echo "::error::reproduce-build: binary reproducibility violation — hashes diverged."
diff -u "$FIRST" "$SECOND" || true
exit 1

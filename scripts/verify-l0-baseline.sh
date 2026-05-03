#!/usr/bin/env bash
# verify-l0-baseline.sh — L0 DO NOT TOUCH 8-item protection.
#
# Compares current working-tree SHA-256 against `ci/l0-baseline-hashes.txt`.
# On mismatch, fails with "L0 modification detected — L0-specific DIP required".
#
# Usage: ./scripts/verify-l0-baseline.sh
# CI: .github/workflows/ci.yml `l0-baseline` job.

set -euo pipefail

BASELINE="ci/l0-baseline-hashes.txt"
if [[ ! -f "$BASELINE" ]]; then
  echo "::error::$BASELINE missing — L0 baseline hash file must be created"
  exit 1
fi

# Strip header comments + blank lines, then pass to shasum -c.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
grep -v '^#' "$BASELINE" | grep -v '^[[:space:]]*$' > "$TMP"

if ! shasum -a 256 -c "$TMP"; then
  cat <<'MSG'
::error::L0 modification detected — violates L0 modification prohibition directive.

Response paths:
  1. Intentional L0 change: L0-specific DIP must precede the change. Add `l0-dip` label to the PR + attach the L0 DIP document.
  2. Unintentional change: revert the affected file changes.
  3. L0 release accompanies the change: submit a separate baseline update PR + obtain auditor approval.

Baseline regeneration:
  find arkhe-kernel/src arkhe-macros/src -name "*.rs" -print0 | sort -z | xargs -0 shasum -a 256 > ci/l0-baseline-hashes.txt
  # Then reinsert the header comment block at the top of ci/l0-baseline-hashes.txt.
MSG
  exit 1
fi

echo "L0 baseline OK — DO NOT TOUCH 8 items unchanged."

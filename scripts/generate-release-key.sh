#!/usr/bin/env bash
# generate-release-key.sh — generate an Ed25519 signing subkey on the YubiKey
# OpenPGP applet.
#
# Actual key generation MUST be performed on an air-gapped machine only — this
# script is a procedure guide + GPG batch-mode input generator.
#
# Prerequisites:
#   - Air-gapped machine (network disconnected); Live USB recommended (Tails /
#     pure Live Linux).
#   - YubiKey 5.7+ FIPS (OpenPGP applet supported).
#   - GnuPG 2.4+, pcscd running.
#   - Two operators physically present (witness).
#
# Usage:
#   ./scripts/generate-release-key.sh runtime-doctor-journal-v1  [full-name]  [email]
#   ./scripts/generate-release-key.sh release-signing-v1         [full-name]  [email]
#
# After generation:
#   - Keep the primary key only on the air-gapped machine's encrypted disk.
#   - Move the signing subkey only onto the YubiKey via `keytocard`.
#   - Import the same key into a secondary YubiKey (backup) as well —
#     complete this BEFORE reconnecting to the network.
#   - Commit the public key (hex / fingerprint) into docs/release-keys.md §4.
#
# Never commit the private key. End by wiping the air-gapped machine's disk.

set -euo pipefail

KEY_NAME="${1:-}"
FULL_NAME="${2:-ArkheKernel Release Authority}"
EMAIL="${3:-release@arkhekernel.invalid}"

if [[ -z "$KEY_NAME" ]]; then
  cat <<'USAGE'
Usage:
  ./scripts/generate-release-key.sh <key-name> [full-name] [email]

Example:
  ./scripts/generate-release-key.sh runtime-doctor-journal-v1
  ./scripts/generate-release-key.sh release-signing-v1 "ArkheKernel Release" "release@arkhekernel.invalid"

Key-name candidates (see docs/release-keys.md):
  runtime-doctor-journal-v1     # signs runtime_doctor_journal entries (90d rotation)
  release-signing-v1            # signs binary release tags (1y rotation)
  release-signing-v1-pqc        # PQC ML-DSA 65 release signing (runtime_max >= "0.30")
USAGE
  exit 1
fi

# 1. Air-gapped check — warn if any network interface is up.
if command -v ip >/dev/null 2>&1; then
  if ip link show | grep -E "state UP" | grep -vE "lo:" >/dev/null; then
    echo "::warning::A network interface is UP. Run only on an air-gapped machine."
    echo "::warning::Key generation MUST happen on a network-disconnected host."
    read -r -p "Continue anyway? (yes/NO) " yn
    [[ "$yn" == "yes" ]] || exit 1
  fi
fi

# 2. Pre-flight — verify GPG + YubiKey applet tooling.
if ! command -v gpg >/dev/null 2>&1; then
  echo "::error::gpg not installed. GnuPG 2.4+ required."
  exit 1
fi
if ! command -v ykman >/dev/null 2>&1; then
  echo "::warning::ykman not installed. The YubiKey applet must be initialised manually."
fi

# 3. Key generation batch.
BATCH_FILE=$(mktemp)
trap 'shred -u "$BATCH_FILE" 2>/dev/null || rm -f "$BATCH_FILE"' EXIT

cat > "$BATCH_FILE" <<EOF
%echo Generating Ed25519 key: $KEY_NAME
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: $FULL_NAME ($KEY_NAME)
Name-Email: $EMAIL
Expire-Date: 1y
%no-protection
%commit
%echo Key generation complete. Move to YubiKey via: gpg --edit-key '$KEY_NAME' keytocard 3
EOF

echo "=== GPG batch input ==="
cat "$BATCH_FILE"
echo "======================="
read -r -p "Generate the key with the batch above? (yes/NO) " yn
[[ "$yn" == "yes" ]] || exit 1

gpg --batch --generate-key "$BATCH_FILE"

# 4. Post-generation — extract the public key + walk the operator through keytocard.
echo
echo "=== Public key ==="
gpg --list-keys --with-fingerprint "$KEY_NAME" || gpg --list-keys "$EMAIL"
echo

KEYGRIP=$(gpg --list-keys --with-keygrip "$EMAIL" | awk '/Keygrip/ {print $3; exit}')
echo "Keygrip: ${KEYGRIP:-<not-found>}"
echo

cat <<MSG
=== Next steps ===

1. Back the primary key up to an encrypted USB:
   gpg --export-secret-keys --armor "$KEY_NAME" > /media/backup/"$KEY_NAME".priv.asc
   # USB encrypted with LUKS, two-person joint PIN custody.

2. Move the signing subkey to the primary YubiKey:
   gpg --edit-key "$KEY_NAME"
   > key 1                  # select the sign subkey
   > keytocard              # move to smart-card
   > 3                      # Authentication key slot (or Signature slot)
   > save

3. Import the same key into the secondary YubiKey (backup) — complete this
   BEFORE reconnecting the network:
   # Re-import from the backup private key, then keytocard.

4. Export the public key → commit it into docs/release-keys.md §4:
   gpg --export --armor "$KEY_NAME" > /tmp/"$KEY_NAME".pub.asc
   # Commit the hex fingerprint + base64 public key into docs/release-keys.md §4.

5. Wipe the air-gapped machine's disk (dd + shred):
   sudo shred -n 3 -z /dev/sda   # or destroy the Live USB itself.

6. After the journal becomes active, append a journal entry for this run:
   runtime-doctor journal-append --event "key-generation:$KEY_NAME" --operator <...>

MSG

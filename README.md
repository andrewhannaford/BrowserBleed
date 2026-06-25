# BrowserBleed

Authorized red team tool for extracting credentials, session tokens, and cookies from running Chromium-based browsers. Supports Windows (`BrowserBleed.py` / `BrowserBleed.exe`) and macOS (`BrowserBleed_mac.py` / `BrowserBleed_mac`).

> **For authorized use only.** Only run against systems you own or have explicit written permission to test.

---

## Attack Overview

Modern browsers hold decrypted credentials, session tokens, JWTs, and auth cookies entirely in process memory during an active session. An attacker or red teamer with local administrator access (Windows) or root (macOS) can read the virtual address space of every browser process, extract live credentials without touching disk, and use them to impersonate the victim across any service whose tokens appear in memory — regardless of whether the user's disk is encrypted.

This attack is effective against:
- Corporate SSO sessions (Okta, Azure AD, Google Workspace)
- OAuth2 access and refresh tokens
- API keys stored by web apps (GitHub, Anthropic, OpenAI, Slack, HuggingFace, Stripe, npm)
- AWS access keys and session tokens
- Session cookies protected by HttpOnly and Secure flags (bypassed because we read them from memory, not the network)
- SSH private keys resident in memory

---

## How Each Script Works

### Windows — `BrowserBleed.py`

**Prerequisites:** Run as Administrator. Built with `--uac-admin` so Windows auto-elevates on launch.

#### 1. Disk Extraction

Chrome encrypts saved passwords and cookies on disk using **AES-256-GCM** with a master key protected by Windows **DPAPI** (`CryptUnprotectData`). Because we run as the same user, DPAPI decrypts transparently:

1. Read `Local State` JSON → base64-decode the encrypted master key blob
2. Call `CryptUnprotectData` (via `ctypes.windll.crypt32`) to unwrap the master key
3. Open `Login Data` (SQLite) → decrypt each `password_value` with AES-256-GCM using the master key
4. Open `Network/Cookies` (SQLite) → same decryption path for each cookie value

Chrome locks the Cookies file while running. Fallback: **VSS (Volume Shadow Copy)** snapshot to read a consistent copy of the locked file without touching Chrome's file handle.

Multi-profile aware: enumerates `Default`, `Profile 1`–`Profile 19`, and `Guest Profile` per browser.

#### 2. CDP Cookie Extraction

When Chrome is running, BrowserBleed always attempts **Chrome DevTools Protocol** cookie extraction alongside disk extraction. CDP surfaces session-only and HttpOnly cookies that never touch disk. Results are merged with disk cookies (deduped by host+name); CDP-only entries are labeled.

#### 3. Memory Scraping

For each Chrome PID (all processes — renderer, GPU, network service, browser):

1. `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)` → get a handle
2. `VirtualQueryEx` → walk the virtual address space, enumerate all `MEM_COMMIT` regions that aren't `PAGE_NOACCESS`, `PAGE_GUARD`, or `MEM_IMAGE` (DLL/EXE code sections — skipped; no credentials live there)
3. **Pre-filter**: before running any regex, check each 64 KB chunk for known credential prefixes (`eyJ`, `Bearer `, `ghp_`, `sk-ant-`, `AKIA`, `-----BEGIN`, etc.) using C-speed `bytes.__contains__`. Skips ~85% of Chrome memory without regex overhead.
4. `ReadProcessMemory` → read each qualifying region in **64 KB chunks** (vs. 4 KB previously — 16× fewer syscalls)
5. Scan each chunk with `CREDENTIAL_PATTERNS` (20 regex patterns covering JWTs, Bearer tokens, OAuth tokens, API keys, session tokens, session IDs, cookies, passwords, SSH private keys)
6. **512-byte overlap**: retain the last 512 bytes of each chunk and prepend to the next. Prevents credentials split across chunk boundaries from being missed.
7. PIDs scraped in parallel via `ThreadPoolExecutor` (up to 8 workers)

#### 4. PID → Site Attribution

Chrome renderer processes expose `--site-instance-site=https://...` in their command line (one renderer per site origin under strict site isolation). A single `Get-WmiObject Win32_Process` batch query retrieves all Chrome command lines at once, building a `pid → site_url` map. The site URL is injected into each hit's context for service identification.

#### 5. Deduplication

Two-pass dedup:
1. **Prefix key**: group hits by `label:value[:50]` to collapse near-identical captures of the same token
2. **Prefix collapse**: within each label group, if a shorter value is a prefix of a longer one, keep the longer (handles chunk-boundary truncations)

#### 6. Service Identification

Each hit passes through a 6-level identification chain:

| Priority | Method | Example |
|----------|--------|---------|
| 1 | Token prefix patterns | `ya29.` → Google OAuth2, `ghp_` → GitHub |
| 2 | JWT header `kid` patterns | `key-\d+` → Google (empirical) |
| 3 | JWT `iss`/`aud` claims vs `_ISS_MAP` | `github.com` in iss → GitHub |
| 4 | OIDC discovery | Fetch `<iss>/.well-known/openid-configuration` |
| 5 | JWT claim URL scan | `redirect_uri` value → service domain |
| 6 | Context window byte scan | `Host: api.slack.com` near the token in memory |

#### 7. Token Verification (`--verify`)

Makes live outbound requests to verify token validity:

| Service | Endpoint |
|---------|----------|
| Google OAuth2 | `oauth2.googleapis.com/tokeninfo` |
| GitHub | `api.github.com/user` |
| Slack | `slack.com/api/auth.test` |
| Anthropic | `api.anthropic.com/v1/models` |
| OpenAI | `api.openai.com/v1/models` |
| Stripe | `api.stripe.com/v1/account` |
| AWS | `sts.amazonaws.com` (GetCallerIdentity) |
| JWT (generic) | Local `exp` claim check |

---

### macOS — `BrowserBleed_mac.py`

**Prerequisites:** Run as root (`sudo`). `task_for_pid` requires root or the `com.apple.security.cs.debugger` entitlement.

#### 1. Disk Extraction

Chrome on macOS encrypts cookies/passwords using **AES-128-CBC** with a key derived from a password stored in the **macOS Keychain**:

1. `security find-generic-password -w -s "Chrome Safe Storage" -a "Chrome"` → retrieve the Keychain password
2. Derive a 16-byte AES key: `PBKDF2-HMAC-SHA1(password, salt=b"saltysalt", iterations=1003, dklen=16)`
3. Decrypt each `v10`-prefixed value: strip the 3-byte `v10` prefix, use a fixed IV of 16 space bytes (`b" " * 16`), AES-128-CBC decrypt, strip PKCS#7 padding

Multi-profile aware: enumerates `Default`, `Profile 1`–`Profile 19`, and `Guest Profile` per browser.

Chrome v20+ uses app-bound encryption for cookies — these are labeled in output but not decryptable from outside the browser process.

#### 2. CDP Cookie Extraction

Same as Windows: attempts DevTools Protocol extraction when browser is running, merges with disk results, labels CDP-only entries.

#### 3. Memory Scraping

For each Chrome PID:

1. `task_for_pid(mach_task_self(), pid, &task)` → obtain a Mach task port for the target process
2. `mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64, ...)` → iterate all readable memory regions (`VM_PROT_READ`)
3. **Pre-filter**: same C-speed prefix scan as Windows before running regex
4. `mach_vm_read_overwrite` → read each qualifying region in **64 KB chunks**
5. **512-byte overlap** between chunks
6. Same 20-pattern `CREDENTIAL_PATTERNS` scanning as Windows
7. PIDs scraped in parallel via `ThreadPoolExecutor` (up to 8 workers)

#### 4. PID → Site Attribution

Uses `ps -ww -A` to read Chrome process command lines and extract `--site-instance-site=URL` — same logic as Windows.

#### 5–7. Deduplication, Identification, and Verification

Identical to Windows: same two-pass dedup, same `_DOMAIN_SVC`, `_ISS_MAP`, `_KID_MAP`, OIDC discovery, context scanning, and verifiers.

---

## Output

Both versions write two files to the same directory as the binary:

| File | Contents |
|------|----------|
| `bb_results.txt` | Human-readable report. Memory hits formatted as an aligned flat table sorted by credential tier (high-value first). Values truncated at 80 chars for readability. Session IDs and Cookie headers collapsed to a count summary. |
| `bb_results.csv` | Full untruncated values for all memory hits. Columns: `browser, profile, label, service, value, address`. Import directly into Excel or Sheets for sorting/filtering. |

---

## Usage

### Windows

```
BrowserBleed.exe                    # all browsers, disk + memory
BrowserBleed.exe --browser chrome   # target one browser
BrowserBleed.exe --memory-only      # skip disk extraction
BrowserBleed.exe --disk-only        # skip memory scraping
BrowserBleed.exe --verify           # verify tokens (makes outbound requests)
BrowserBleed.exe --max-hits 500     # raise memory hit cap per browser (default: 300)
BrowserBleed.exe --out results.txt  # custom output path
BrowserBleed.exe --self-delete      # delete exe after run (opsec)
```

### macOS

```bash
sudo ./BrowserBleed_mac                        # all browsers, disk + memory
sudo ./BrowserBleed_mac --browser chrome       # target one browser
sudo ./BrowserBleed_mac --memory-only          # skip disk extraction
sudo ./BrowserBleed_mac --disk-only            # skip memory scraping
sudo ./BrowserBleed_mac --verify               # verify tokens (makes outbound requests)
sudo ./BrowserBleed_mac --max-hits 500         # raise memory hit cap per browser (default: 300)
sudo ./BrowserBleed_mac --out /tmp/results.txt # custom output path
sudo ./BrowserBleed_mac --self-delete          # delete binary after run (opsec)
```

---

## Building

### Windows

```powershell
pip install cryptography pyinstaller
python -m PyInstaller --onefile --noconsole --uac-admin --name BrowserBleed `
    --distpath . --workpath $env:TEMP\bb_build --specpath $env:TEMP\bb_build `
    BrowserBleed.py
```

### macOS

```bash
pip3 install cryptography pyinstaller
chmod +x build_mac.sh && ./build_mac.sh
```

The build script strips the Gatekeeper quarantine attribute automatically. If you re-download the binary, run:
```bash
xattr -dr com.apple.quarantine BrowserBleed_mac
```

---

## Supported Browsers

Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Chromium

Firefox: unencrypted cookies extracted (login decryption not yet implemented).

---

## Detection Opportunities

For blue teamers: this tool generates detectable signals at each stage.

| Stage | Signal |
|-------|--------|
| Memory read | `OpenProcess` / `task_for_pid` calls from a non-browser process targeting Chrome PIDs |
| VSS access (Windows) | `IVssBackupComponents::InitializeForBackup` from a non-backup process |
| Disk credential read | SQLite open on `Login Data` / `Cookies` from a process that isn't Chrome |
| CDP connection | WebSocket connection to `localhost:9222` from a non-browser process |
| Outbound verification | HTTP requests to `oauth2.googleapis.com/tokeninfo`, `api.github.com/user`, `slack.com/api/auth.test`, `api.anthropic.com/v1/models` from a non-browser process |
| OIDC discovery | Unexpected `GET /.well-known/openid-configuration` from a non-browser process |

EDR products with process injection detection (CrowdStrike, SentinelOne, Defender for Endpoint) will typically alert on cross-process `ReadProcessMemory` / `task_for_pid` targeting a browser.

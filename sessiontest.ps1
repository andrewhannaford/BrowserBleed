# BrowserBleed Session Test wrapper — one-command testing
param(
    [string]$CsvFile,
    [switch]$Browser,
    [int]$Timeout = 10,
    [switch]$NoVerifySsl,
    [switch]$Json,
    [float]$Delay = 0.3,
    [switch]$Latest
)

$ScriptDir = Split-Path -Parent (Resolve-Path $PSCommandPath)
$SessionTestPy = Join-Path $ScriptDir "sessiontest.py"

$Args = @()
if ($CsvFile) {
    $Args += $CsvFile
}

if ($Browser) {
    $Args += "--browser"
}

if ($Timeout -ne 10) {
    $Args += "--timeout", $Timeout
}

if ($NoVerifySsl) {
    $Args += "--no-verify-ssl"
}

if ($Json) {
    $Args += "--json"
}

if ($Delay -ne 0.3) {
    $Args += "--delay", $Delay
}

# Run sessiontest.py
& python3 $SessionTestPy @Args

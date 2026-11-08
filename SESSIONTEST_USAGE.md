# sessiontest.py — Simplified Usage Guide

## Quick Start

### No arguments needed:
```bash
python3 sessiontest.py
```

The script will automatically:
1. Search for the most recent BrowserBleed report ZIP in `~/Downloads` (e.g., `TheMachine_2026-07-02.zip`)
2. Extract the CSV from inside it
3. Run tests against the extracted credentials

This is the easiest way to use sessiontest after exporting a report from the server.

## Usage Options

### Explicit file path:
```bash
python3 sessiontest.py /path/to/results.csv
```

### With browser sessions (opens Playwright):
```bash
python3 sessiontest.py --browser
```

### JSON output (for parsing):
```bash
python3 sessiontest.py --json
```

### Adjust timeout (default 10s):
```bash
python3 sessiontest.py --timeout 15
```

### Skip SSL verification:
```bash
python3 sessiontest.py --no-verify-ssl
```

### Adjust delay between requests (default 0.3s):
```bash
python3 sessiontest.py --delay 0.5
```

## Environment Variables

### `BB_RESULTS_CSV`
Explicitly specify the CSV file path (checked first before auto-detection):
```bash
export BB_RESULTS_CSV=/path/to/results.csv
python3 sessiontest.py
```

### `BB_QUIET`
Suppress the "Auto-extracted" message:
```bash
export BB_QUIET=1
python3 sessiontest.py
```

## Auto-Detection Priority

When no file is specified, sessiontest looks for the CSV in this order:

1. **Environment variable**: `BB_RESULTS_CSV` if set (highest priority)
2. **Downloads folder (extracted CSVs)**: Most recent `*_YYYY-MM-DD.csv` file in `~/Downloads`
3. **Current directory**: `bb_results.csv`
4. **Script directory**: `bb_results.csv` alongside the script
5. **Download ZIP (auto-extract)**: Most recent `*_YYYY-MM-DD.zip` in `~/Downloads` (lowest priority)

## PowerShell Wrapper

A PowerShell wrapper script is available for convenience:

```powershell
.\sessiontest.ps1
.\sessiontest.ps1 -Browser
.\sessiontest.ps1 -Json
```

## Workflow

**Server → Downloads → sessiontest:**

1. Export report from `browserbleed.lanarchy.net` → Downloads as ZIP
2. Run `python3 sessiontest.py` in any directory
3. Script auto-finds and tests credentials

No manual extraction or file navigation required.

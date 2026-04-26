# Downpour v29 Titanium — Enhanced Compatibility System Guide

## Overview

The enhanced compatibility system (`enhanced_bypass_system.py`) manages
Windows Defender exclusions for Downpour's project directory. It provides
eight numbered methods that all perform the same class of operation:
adding Allow-list entries so Defender does not interfere with normal
Python execution inside the project folder.

---

## What the Eight Methods Do

| Method | Operation |
|--------|-----------|
| 1 | PowerShell `Add-MpPreference` — path and process exclusions |
| 2 | Registry write to `Defender\Exclusions\Paths` |
| 3 | Registry write to `Policies\...\Defender\Exclusions\Paths` |
| 4 | Repeat of Method 1 (process exclusions) |
| 5 | No-op (placeholder for API compatibility) |
| 6 | Inbound Windows Firewall allow-rule for python.exe |
| 7 | No-op (placeholder for API compatibility) |
| 8 | No-op (placeholder for API compatibility) |

All methods are additive exclusion operations only. Defender remains
fully enabled throughout.

---

## Usage

**Automatic** — exclusions are applied on every launch via `LAUNCH.bat`.

**Manual**:

```cmd
python enhanced_bypass_system.py
```

Results are saved to `enhanced_bypass_config.json`.

---

## Checking Status

```python
from enhanced_bypass_system import SophisticatedDefenderCompatibility
m = SophisticatedDefenderCompatibility()
print(m.get_compatibility_metrics())
```

---

## Troubleshooting

The same guidance as `DEFENDER_BYPASS_GUIDE.md` applies — run as
Administrator for registry-based methods, and verify exclusions with
`(Get-MpPreference).ExclusionPath` in PowerShell.

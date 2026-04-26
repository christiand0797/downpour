# Downpour v28 Titanium — Windows Defender Compatibility Guide

## Overview

Downpour v28 Titanium is a security monitoring application that needs to coexist
with Windows Defender. This guide explains how Defender exclusions are managed.

---

## How Exclusions Work

Downpour adds **allow-list exclusions only** — it never disables Defender,
stops the WinDefend service, or modifies scan policies. The only changes made are:

- `Add-MpPreference -ExclusionPath "<project_dir>"` — tells Defender not to scan
  Downpour's own folder (prevents false positives on Python source files)
- `Add-MpPreference -ExclusionProcess "python.exe"` — prevents Defender from
  scanning every Python bytecode load during startup
- One inbound Windows Firewall allow-rule for `python.exe`

These are the same steps any Python application installer would perform.
Defender remains fully active and protects the rest of the system.

---

## Running the Exclusion Setup

The exclusion setup runs automatically when you launch via `LAUNCH.bat`.
You can also run it manually:

```powershell
# Run as Administrator
powershell -NoProfile -Command "Add-MpPreference -ExclusionPath 'C:\path\to\downpour_consolidated' -Force"
powershell -NoProfile -Command "Add-MpPreference -ExclusionProcess 'python.exe' -Force"
```

Or use the built-in helper:

```cmd
python defender_bypass_system.py
```

---

## Verifying Exclusions Were Applied

```powershell
(Get-MpPreference).ExclusionPath
(Get-MpPreference).ExclusionProcess
```

---

## Troubleshooting

**"Access denied" when adding exclusion**
Run the launcher or the exclusion script as Administrator (right-click → Run as administrator).

**Defender still flagging files after exclusion**
Allow a few minutes for the exclusion to propagate. If the issue persists, verify
the exact path used matches the project folder location.

**Running on a corporate machine with Group Policy restrictions**
Group Policy can prevent user-level exclusions. Ask your IT administrator to add
an exclusion for the Downpour folder at the policy level.

---

## What Downpour Does NOT Do

- Does not disable Windows Defender real-time protection
- Does not stop the WinDefend or MpsSvc services
- Does not write antispyware-disabling registry values
- Does not modify UAC settings
- Does not hide files or alter timestamps
- Does not create scheduled tasks or startup persistence entries

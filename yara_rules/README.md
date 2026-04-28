# YARA Rules - Downpour v29 Titanium

This directory contains YARA rules for malware detection.

## Rules Overview

| File | Category | Description |
|------|----------|-------------|
| `ransomware.yar` | Ransomware | Extension changes, ransom notes, encryption APIs |
| `middleware.yar` | Malware | Process injection, hidden processes, keyloggers |
| `rootkit.yar` | Rootkit | NT hooks, inline hooks, SSDT hooks |
| `cryptominer.yar` | Cryptominer | Pool connections, miner binaries |

## Usage

These rules are loaded by `advanced_file_analyzer.py` for file scanning.

Version: 29.0.0
Date: 2026-04-27
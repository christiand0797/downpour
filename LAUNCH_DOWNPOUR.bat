@echo off
setlocal EnableDelayedExpansion
title Downpour v28 Titanium
chcp 65001 >nul 2>&1
color 0B

:: ============================================================
::  DOWNPOUR v28 TITANIUM  -  ULTIMATE LAUNCHER
::  Auto-elevates, installs deps, Defender bypass, C2 block
:: ============================================================

:: ── 1. UAC ELEVATION ──────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

:: ── 2. ENVIRONMENT ────────────────────────────────────────
set "APPDIR=%~dp0"
set "TEMP=%APPDIR%downpour_tmp"
set "TMP=%TEMP%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONWARNINGS=ignore::DeprecationWarning:pkg_resources,ignore::FutureWarning"
set "PYTHONTRACEMALLOC=0"
set "PYTHONFAULTHANDLER=1"
if not exist "%TEMP%" mkdir "%TEMP%"

echo.
echo  ================================================================
echo                  DOWNPOUR v28 TITANIUM
echo               Advanced Security Suite
echo  ================================================================
echo.

:: ── 3. LOCATE PYTHON ──────────────────────────────────────
set "PY="
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
) do ( if exist %%~P if "!PY!"=="" set "PY=%%~P" )
if "!PY!"=="" (
    for /f "usebackq tokens=*" %%P in (`where python 2^>nul`) do (
        if "!PY!"=="" (
            "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
            if !errorlevel!==0 set "PY=%%P"
        )
    )
)
if "!PY!"=="" (
    echo.
    echo  [ERROR] Python 3.11+ not found.
    echo  Download from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
echo   [OK] Python: !PY!

:: ── 4. INSTALL / UPDATE DEPENDENCIES ──────────────────────
echo   [..] Checking dependencies...
:: Ensure nvidia-ml-py is installed (drop-in replacement for deprecated pynvml)
"!PY!" -m pip install --quiet --break-system-packages psutil requests cryptography watchdog nvidia-ml-py colorama wmi pywin32 scikit-learn yara-python pillow dnspython netifaces 2>nul
if %errorlevel%==0 (
    echo   [OK] All dependencies installed
) else (
    echo   [!!] Some dependencies failed - app may have reduced functionality
)

:: ── 5. REMOVE DEPRECATED PYNVML ───────────────────────────
"!PY!" -c "import pynvml" >nul 2>&1
if %errorlevel%==0 (
    "!PY!" -m pip uninstall pynvml -y --quiet >nul 2>&1
    echo   [OK] Removed deprecated pynvml
)

:: ── 6. WINDOWS DEFENDER BYPASS ────────────────────────────
echo   [..] Configuring Defender exclusions...
powershell -NoProfile -Command "Add-MpPreference -ExclusionPath '%APPDIR%' -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -Command "Add-MpPreference -ExclusionProcess '!PY!' -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -Command "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue" >nul 2>&1
echo   [OK] Defender exclusions applied (scan engines run freely)

:: ── 7. KIMWOLF / MOZI C2 FIREWALL BLOCK ──────────────────
echo   [..] Applying C2 firewall rules...
netsh advfirewall firewall delete rule name=DOWNPOUR_KIMWOLF_C2    >nul 2>&1
netsh advfirewall firewall delete rule name=DOWNPOUR_KIMWOLF_C2_IN >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_KIMWOLF_C2 dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_KIMWOLF_C2_IN dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
echo   [OK] Kimwolf/Mozi C2 IPs blocked

:: ── 8. CLEAN STALE CACHES ────────────────────────────────
del /q "%APPDIR%downpour_tmp\downpour_secure_*" >nul 2>&1
del /q "%APPDIR%crash_fault.log" >nul 2>&1

:: ── 9. STATUS BANNER ─────────────────────────────────────
echo.
echo  ================================================================
echo   Python   : !PY!
echo   Admin    : YES (elevated)
echo   Defender : Exclusions applied
echo   Firewall : Kimwolf C2 blocked
echo   Cache    : Cleaned
echo  ================================================================
echo.
echo   Starting Downpour v28 Titanium...
echo   Window appears in ~5 seconds. Full GUI in ~15 seconds.
echo   DNS Security + Cleanup tabs load on first click.
echo.

:: ── 10. LAUNCH WITH STDERR CAPTURE ───────────────────────
"!PY!" -X utf8 -X faulthandler -u -W ignore::FutureWarning "%APPDIR%downpour_v28_titanium.py" --no-admin --no-install 2>"%APPDIR%dp_stderr.txt"
set "EXIT_CODE=%errorlevel%"

:: ── 11. EXIT HANDLING ────────────────────────────────────
echo.
if %EXIT_CODE%==0 (
    echo  [OK] Downpour exited cleanly.
) else (
    echo  [!!] Downpour exited with code %EXIT_CODE%
    echo.
    if exist "%APPDIR%crash_fault.log" (
        echo  === C-Level Crash Trace ===
        type "%APPDIR%crash_fault.log"
        echo.
    )
    echo  === Last 15 lines of stderr ===
    powershell -NoProfile -Command "Get-Content '%APPDIR%dp_stderr.txt' -Tail 15" 2>nul
)
echo.
pause

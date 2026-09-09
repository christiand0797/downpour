@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium -- Launching...
chcp 65001 >nul 2>&1
color 0B

:: =============================================================================
::  DOWNPOUR v29 TITANIUM  --  Unified Launcher
::  Features: Admin elevation, Persistent intel, Background physics engine,
::           Auto-defender/ASR exclusions, Firewall C2 blocks, Log rotation
:: =============================================================================

@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium -- Initializing...
chcp 65001 >nul 2>&1
color 0A

:: =============================================================================
::  1. ADMIN ELEVATION (UAC if needed)
:: =============================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2>nul
    exit /b
)

:: =============================================================================
:: 2. ENVIRONMENT SETUP
:: =============================================================================
cd /d "%~dp0"
set "APPDIR=%~dp0"
set "DOWNPOUR_TMP=%APPDIR%downpour_tmp"
set "TEMP=%DOWNPOUR_TMP%"
set "TMP=%DOWNPOUR_TMP%"

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONWARNINGS=ignore::DeprecationWarning:pkg_resources,ignore::FutureWarning,ignore::UserWarning:sklearn"
set "PYTHONTRACEMALLOC=0"
set "PYTHONFAULTHANDLER=1"

if not exist "%DOWNPOUR_TMP%" mkdir "%DOWNPOUR_TMP%"

:: =============================================================================
:: 2. PYTHON DISCOVERY (3.10+ required, prefers 3.12+)
:: =============================================================================
set "PY="
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Python310\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles%\Python310\python.exe"
    "%ProgramFiles(x86)%\Python312\python.exe"
    "%ProgramFiles(x86)%\Python311\python.exe"
    "%ProgramFiles(x86)%\Python310\python.exe"
    "%SystemDrive%\Python312\python.exe"
    "%SystemDrive%\Python311\python.exe"
    "%SystemDrive%\Python310\python.exe"
) do (
    if exist %%~P if "!PY!"=="" (
        %%~P -c "import sys; exit(0 if sys.version_info>=(3,10) and sys.version_info.releaselevel=='final' else 1)" >nul 2>&1
        if !errorlevel!==0 set "PY=%%~P"
    )
)
if "!PY!"=="" (
    for /f "usebackq tokens=*" %%P in (`where python 2^>nul`) do (
        if "!PY!"=="" (
            "%%P" -c "import sys; exit(0 if sys.version_info>=(3,10) and sys.version_info.releaselevel=='final' else 1)" >nul 2>&1
            if !errorlevel!==0 set "PY=%%P"
        )
    )
)
if "!PY!"=="" (
    echo  [ERROR] Python 3.10+ (stable release) not found.
    echo  Download: https://www.python.org/downloads/
    echo  (Tick "Add Python to PATH" during install)
    echo.
    pause & exit /b 1
)
echo   [OK] Python: !PY!

for /f "usebackq tokens=*" %%V in (`"!PY!" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2^>nul`) do set "PYVER=%%V"
echo   [OK] Version: !PYVER!

:: =============================================================================
:: 4. DEPENDENCY CHECK (binary wheels first, no compilation)
:: =============================================================================
echo   [..] Verifying dependencies...
"!PY!" -c "import psutil, requests, cryptography, watchdog, nvidia_ml_py, colorama, wmi, pywin32, sklearn, yara, PIL, dns, netifaces, joblib, tqdm, pyperclip, dateutil, numpy, scipy" >nul 2>&1
if !errorlevel! neq 0 (
    echo   [..] Installing missing dependencies...
    "!PY!" -m pip install --upgrade pip --quiet --break-system-packages --no-warn-script-location >nul 2>&1
    for %%P in (psutil requests cryptography watchdog nvidia-ml-py colorama wmi pywin32 scikit-learn yara-python pillow dnspython netifaces joblib tqdm pyperclip dateutil numpy scipy) do (
        "!PY!" -c "import %%P" >nul 2>&1
        if !errorlevel! neq 0 (
            echo     [..] Installing %%P...
            "!PY!" -m pip install "%%P" --quiet --break-system-packages --only-binary :all: --no-warn-script-location >nul 2>&1
            if !errorlevel! neq 0 (
                "!PY!" -m pip install "%%P" --quiet --break-system-packages --no-warn-script-location >nul 2>&1
            )
        )
    )
    "!PY!" -c "import scapy" >nul 2>&1
    if !errorlevel! neq 0 (
        echo     [..] Installing scapy (optional)...
        "!PY!" -m pip install scapy --quiet --break-system-packages --no-warn-script-location >nul 2>&1
    )
)
echo   [OK] Dependencies verified

:: =============================================================================
:: 5. REMOVE DEPRECATED PYNVML
:: =============================================================================
"!PY!" -c "import pynvml" >nul 2>&1
if !errorlevel!==0 (
    "!PY!" -m pip uninstall pynvml -y --quiet >nul 2>&1
    echo   [OK] Removed deprecated pynvml (nvidia-ml-py is the maintained replacement)
)

:: =============================================================================
:: 6. DEFENDER EXCLUSIONS (data dirs only + ASR)
:: =============================================================================
echo   [..] Configuring Defender + ASR exclusions...
:: v29.42w (TASK-011, audit 2026-09-07): DATA DIRECTORIES ONLY. Never exclude
:: the install dir or python.exe as a process -- that hands same-user malware
:: a standing Defender blind spot. Only write-heavy data dirs are excluded.
powershell -NoProfile -NonInteractive -Command "Add-MpPreference -ExclusionPath '%APPDIR%downpour_data' -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -NonInteractive -Command "Add-MpPreference -ExclusionPath '%APPDIR%downpour_v27_data' -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -NonInteractive -Command "Add-MpPreference -ExclusionPath '%APPDIR%downpour_tmp' -ErrorAction SilentlyContinue" >nul 2>&1

:: ASR exclusions -- DIFFERENT subsystem from ExclusionPath. Data dirs only.
powershell -NoProfile -NonInteractive -Command "Add-MpPreference -AttackSurfaceReductionOnlyExclusions '%APPDIR%downpour_tmp' -ErrorAction SilentlyContinue" >nul 2>&1

:: Disable ASR 3b576869 ONLY while pip installs run. Restored to ENABLED after.
powershell -NoProfile -NonInteractive -Command "Set-MpPreference -AttackSurfaceReductionRules_Ids '3b576869-a4ec-4529-8536-b80a7769e899' -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue" >nul 2>&1

echo   [OK] Defender + ASR configured

:: =============================================================================
:: 7. FIREWALL: BLOCK KNOWN C2 / BOTNET IPs
:: =============================================================================
echo   [..] Applying C2 firewall rules...

for %%R in (DOWNPOUR_C2_KIMWOLF DOWNPOUR_C2_KIMWOLF_IN DOWNPOUR_C2_BADBOX2 DOWNPOUR_C2_MOZI DOWNPOUR_C2_AISURU DOWNPOUR_C2_COBALT) do (
    netsh advfirewall firewall delete rule name=%%R >nul 2>&1
)

netsh advfirewall firewall add rule name=DOWNPOUR_C2_KIMWOLF dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.55,93.95.112.56,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_C2_KIMWOLF_IN dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_C2_BADBOX2 dir=out action=block remoteip=46.21.147.0/24,91.92.248.0/24,194.165.16.0/24 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_C2_MOZI dir=out action=block remoteip=103.145.12.0/24,45.142.212.0/24 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_C2_AISURU dir=out action=block remoteip=185.174.136.0/24,91.109.6.0/24 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_C2_COBALT dir=out action=block remoteip=23.106.160.188,194.165.16.134,185.220.101.47,45.142.212.100 enable=yes >nul 2>&1

echo   [OK] C2 IPs blocked (Kimwolf/BadBox2/Mozi/AISURU/CobaltStrike)

:: =============================================================================
:: 8. LOG ROTATION & TEMP CLEANUP
:: =============================================================================
echo   [..] Rotating logs (keeping last 3)...
call :RotateLog "%APPDIR%crash_fault.log"
call :RotateLog "%APPDIR%dp_stderr.txt"
call :RotateLog "%APPDIR%tk_callback_errors.txt"
del /q "%DOWNPOUR_TMP%\downpour_secure_*" >nul 2>&1
del /q "%DOWNPOUR_TMP%\*.tmp" >nul 2>&1
echo   [OK] Logs rotated, temp cleaned

:: =============================================================================
:: 9. FREE RAM CHECK
:: =============================================================================
for /f "usebackq tokens=*" %%M in (`powershell -NoProfile -Command "(Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory" 2^>nul`) do set "FREE_MEM=%%M"
if defined FREE_MEM (
    set /a "FREE_MB=!FREE_MEM!/1024"
    if !FREE_MB! LSS 2048 (
        echo   [WARN] Low RAM: !FREE_MB! MB free -- close other apps for best performance
    ) else (
        echo   [OK] Free RAM: !FREE_MB! MB
    )
)

:: =============================================================================
:: 10. RESTORE ASR RULE (ENABLED)
:: =============================================================================
:: v29.42w (TASK-011): restore to Enabled, not AuditMode -- a hardening rule
:: should end up enforcing, not just auditing.
powershell -NoProfile -NonInteractive -Command "Set-MpPreference -AttackSurfaceReductionRules_Ids '3b576869-a4ec-4529-8536-b80a7769e899' -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue" >nul 2>&1

:: =============================================================================
:: 10. STATUS BANNER
:: =============================================================================
echo.
echo  =============================================================================
echo   PRE-FLIGHT STATUS
echo  -----------------------------------------------------------------------------
echo   Python   : !PY!
echo   Version  : !PYVER!
echo   Admin    : YES
echo   Defender : ExclusionPath + ASR (AttackSurfaceReductionOnlyExclusions) set
echo   ASR 3b   : AuditMode (disabled during pip, now restored)
echo   Firewall : 5 C2/botnet block rules applied
echo   Logs     : Rotated (last 3 kept)
echo   Target   : downpour_v29_titanium.py
echo  =============================================================================
echo.
echo   Launching Downpour v29 Titanium...
echo   GUI appears in ~3-5 sec  |  All engines ready in ~15 sec
echo.

:: =============================================================================
:: 11. LAUNCH (with all features enabled)
:: =============================================================================
"!PY!" -X utf8 -X faulthandler -u ^
    -W "ignore::FutureWarning" ^
    -W "ignore::DeprecationWarning" ^
    -W "ignore::UserWarning:sklearn" ^
    "%TARGET%" ^
    2>"%APPDIR%dp_stderr.txt"

set "EXIT_CODE=%errorlevel%"
title Downpour v29 -- Exited (code !EXIT_CODE!)

:: =============================================================================
:: 12. EXIT / CRASH HANDLER
:: =============================================================================
echo.
if "!EXIT_CODE!"=="0" (
    echo  [OK] Downpour v29 exited cleanly.
) else (
    echo  [!!] Downpour v29 exited with code !EXIT_CODE!
    echo.
    if exist "%APPDIR%crash_fault.log" (
        echo  --- C-Level Crash Trace ---
        type "%APPDIR%crash_fault.log"
        echo.
    )
    if exist "%APPDIR%dp_stderr.txt" (
        echo  --- Last 20 lines of stderr ---
        powershell -NoProfile -Command "Get-Content '%APPDIR%dp_stderr.txt' -Tail 20" 2>nul
        echo.
    )
    if exist "%APPDIR%tk_callback_errors.txt" (
        echo  --- Last 10 Tkinter callback errors ---
        powershell -NoProfile -Command "Get-Content '%APPDIR%tk_callback_errors.txt' -Tail 10" 2>nul
        echo.
    )
    echo  Share crash_fault.log + dp_stderr.txt to report this crash.
)
echo.
pause
exit /b !EXIT_CODE!

:: =============================================================================
:RotateLog
set "LOGFILE=%~1"
if not exist "%LOGFILE%" goto :EOF
if exist "%LOGFILE%.3" del /q "%LOGFILE%.3" >nul 2>&1
if exist "%LOGFILE%.2" move /y "%LOGFILE%.2" "%LOGFILE%.3" >nul 2>&1
if exist "%LOGFILE%.1" move /y "%LOGFILE%.1" "%LOGFILE%.2" >nul 2>&1
move /y "%LOGFILE%" "%LOGFILE%.1" >nul 2>&1
goto :EOF

:: =============================================================================
::  END OF LAUNCHER
:: =============================================================================
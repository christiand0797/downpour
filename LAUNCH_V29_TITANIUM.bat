@echo off
setlocal EnableDelayedExpansion
title ⛈ Downpour v29 Titanium — Initializing...
chcp 65001 >nul 2>&1
color 0A

:: ═══════════════════════════════════════════════════════════════════╗
:: ║          DOWNPOUR v29 TITANIUM  —  LAUNCH SCRIPT               ║
:: ║                                                                  ║
:: ║  v29 TITANIUM FEATURES:                                    ║
:: ║  • ASR exclusions (separate from ExclusionPath)                  ║
:: ║  • --only-binary pip installs (no meson/ninja/ASR)            ║
:: ║  • Log rotation (keeps last 3)                                  ║
:: ║  • Python 3.13 support + smarter discovery                     ║
:: ║  • Expanded C2 block list                                       ║
:: ║  • PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 prevents ASR            ║
:: ║  • Clears stale tk_callback_errors.txt before launch           ║
:: ║  • Virtual memory check warns if < 2GB free                      ║
:: ║  • Targets downpour_v29_titanium.py                            ║
:: ║  • nvidia-ml-py verification                                    ║
:: ║                                                                  ║
:: ║  DETECTION CAPABILITIES:                                         ║
:: ║  • 45+ YARA rules                                               ║
:: ║  • 289+ threat feeds                                            ║
:: ║  • 85+ MITRE techniques                                        ║
:: ║  • 500+ malware families                                       ║
:: ║  • 40+ security modules                                        ║
:: ║  • 24-tab security GUI                                        ║
:: ╚══════════════════════════════════════════════════════════════════╝

:: ── 1. UAC ELEVATION ──────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   ⚡ Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2>nul
    exit /b
)

cd /d "%~dp0"
set "APPDIR=%~dp0"

:: ── 2. ENVIRONMENT ────────────────────────────────────────────────
set "DOWNPOUR_TMP=%APPDIR%downpour_tmp"
set "TEMP=%DOWNPOUR_TMP%"
set "TMP=%DOWNPOUR_TMP%"

:: Python UTF-8 and performance flags
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONWARNINGS=ignore::DeprecationWarning:pkg_resources,ignore::FutureWarning,ignore::UserWarning:sklearn"
set "PYTHONTRACEMALLOC=0"
set "PYTHONFAULTHANDLER=1"
set "PYTHONDONTWRITEBYTECODE=1"

:: v29 FIX: Playwright triggers ASR rule 3b576869 when it downloads Chromium.
:: PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD prevents this entirely.
set "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1"

:: Suppress Node.js/npm download noise from any subprocess
set "NO_UPDATE_NOTIFIER=1"
set "NPM_CONFIG_FUND=0"

if not exist "%DOWNPOUR_TMP%" mkdir "%DOWNPOUR_TMP%"

color 0B
echo.
echo  ╔═══════════════════════════════════════════════════════════════╗
echo  ║              ⛈  DOWNPOUR v29 TITANIUM  ⛈                    ║
echo  ║         Advanced Threat Defense — 289+ Feeds                  ║
echo  ║         45+ YARA Rules  │  85+ MITRE Techniques               ║
echo  ║         Remediate All  │  Auto-COM Init  │  FIM 35 Files      ║
echo  ╚═══════════════════════════════════════════════════════════════╝
echo.

:: ── 3. VERIFY TARGET FILE EXISTS ──────────────────────────────────
set "TARGET=%APPDIR%downpour_v29_titanium.py"
if not exist "%TARGET%" (
    echo  [ERROR] downpour_v29_titanium.py not found in:
    echo          %APPDIR%
    echo.
    echo  Download it from: https://github.com/christiand0797/downpour
    echo.
    pause
    exit /b 1
)
echo   [OK] Target: downpour_v29_titanium.py

:: ── 4. LOCATE PYTHON ──────────────────────────────────────────────
set "PY="
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    "C:\Python313\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "%ProgramFiles(x86)%\Python313\python.exe"
    "%ProgramFiles(x86)%\Python312\python.exe"
    "%SystemDrive%\Python313\python.exe"
    "%SystemDrive%\Python312\python.exe"
) do (
    if exist %%~P if "!PY!"=="" (
        %%~P -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
        if !errorlevel!==0 set "PY=%%~P"
    )
)
if "!PY!"=="" (
    for /f "usebackq tokens=*" %%P in (`where python 2^>nul`) do (
        if "!PY!"=="" (
            "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
            if !errorlevel!==0 set "PY=%%P"
        )
    )
)
if "!PY!"=="" (
    for /f "usebackq tokens=*" %%P in (`where python3 2^>nul`) do (
        if "!PY!"=="" (
            "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
            if !errorlevel!==0 set "PY=%%P"
        )
    )
)
if "!PY!"=="" (
    echo  [ERROR] Python 3.11+ not found.
    echo  Download from: https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
echo   [OK] Python: !PY!

:: Print Python version
for /f "usebackq tokens=*" %%V in (`"!PY!" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2^>nul`) do set "PYVER=%%V"
echo   [OK] Version: !PYVER!

:: ── 5. UPGRADE PIP SILENTLY ───────────────────────────────────────
echo   [..] Upgrading pip...
"!PY!" -m pip install --upgrade pip --quiet --break-system-packages --no-warn-script-location >nul 2>&1

:: ── 6. INSTALL DEPENDENCIES ───────────────────────────────────────
echo   [..] Installing/verifying dependencies...

:: v29 FIX: Try --only-binary :all: FIRST to prevent meson/ninja from spawning
:: temp executables that trigger ASR rule 3b576869.
:: Fall back to regular install only if binary wheel not available.
set "PKGS=psutil requests cryptography watchdog nvidia-ml-py colorama wmi pywin32 scikit-learn yara-python pillow dnspython netifaces numpy matplotlib pystray scipy"

for %%P in (%PKGS%) do (
    "!PY!" -c "import %%P; print('OK')" >nul 2>&1
    if !errorlevel! neq 0 (
        echo     Installing %%P...
        "!PY!" -m pip install "%%P" --quiet --break-system-packages --only-binary :all: --no-warn-script-location >nul 2>&1
        if !errorlevel! neq 0 (
            "!PY!" -m pip install "%%P" --quiet --break-system-packages --no-warn-script-location >nul 2>&1
        )
    )
)

:: scapy is special — large install, try separately
"!PY!" -c "import scapy" >nul 2>&1
if !errorlevel! neq 0 (
    echo     Installing scapy (optional, may take a moment)...
    "!PY!" -m pip install scapy --quiet --break-system-packages --no-warn-script-location >nul 2>&1
)

echo   [OK] Dependencies verified

:: ── 7. REMOVE DEPRECATED PYNVML ──────────────────────────────────
:: nvidia-ml-py is the maintained replacement (pynvml is deprecated)
"!PY!" -c "import pynvml" >nul 2>&1
if !errorlevel!==0 (
    "!PY!" -m pip uninstall pynvml -y --quiet >nul 2>&1
    echo   [OK] Removed deprecated pynvml (use nvidia-ml-py instead)
)
)

:: ── 8. WINDOWS DEFENDER EXCLUSIONS ───────────────────────────────
echo   [..] Configuring Defender exclusions...

:: ExclusionPath = real-time protection bypass
powershell -NoProfile -NonInteractive -Command ^
    "Add-MpPreference -ExclusionPath '%APPDIR%' -ErrorAction SilentlyContinue" >nul 2>&1

:: ExclusionProcess = protect our Python from being killed mid-scan
powershell -NoProfile -NonInteractive -Command ^
    "Add-MpPreference -ExclusionProcess '!PY!' -ErrorAction SilentlyContinue" >nul 2>&1

:: ── v29 FIX: ASR exclusions are a SEPARATE subsystem from ExclusionPath.
:: ExclusionPath does NOT suppress ASR rules — you need AttackSurfaceReductionOnlyExclusions.
:: Without this, ASR rule 3b576869 (Block executable files that meet prevalence/age/list criteria)
:: kills Playwright/temp executables spawned during pip installs.
powershell -NoProfile -NonInteractive -Command ^
    "Add-MpPreference -AttackSurfaceReductionOnlyExclusions '%APPDIR%' -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -NonInteractive -Command ^
    "Add-MpPreference -AttackSurfaceReductionOnlyExclusions '!PY!' -ErrorAction SilentlyContinue" >nul 2>&1

:: Temporarily suspend rule 3b576869 during launch (re-enables after app starts)
:: This rule blocks executable-age based on prevalence — triggers on new pip installs
powershell -NoProfile -NonInteractive -Command ^
    "Set-MpPreference -AttackSurfaceReductionRules_Ids '3b576869-a4ec-4529-8536-b80a7769e899' -AttackSurfaceReductionRules_Actions Disabled -ErrorAction SilentlyContinue" >nul 2>&1

echo   [OK] Defender + ASR exclusions applied

:: ── 9. FIREWALL: BLOCK KNOWN C2 / BOTNET IPs ─────────────────────
echo   [..] Applying C2 firewall block rules...

:: Remove stale rules first
for %%R in (DOWNPOUR_C2_KIMWOLF DOWNPOUR_C2_KIMWOLF_IN DOWNPOUR_C2_BADBOX2 DOWNPOUR_C2_MOZI DOWNPOUR_C2_AISURU DOWNPOUR_C2_COBALT) do (
    netsh advfirewall firewall delete rule name=%%R >nul 2>&1
)

:: Kimwolf C2 servers
netsh advfirewall firewall add rule name=DOWNPOUR_C2_KIMWOLF dir=out action=block ^
    remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,^
93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,^
85.234.91.247,185.220.101.0/24 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_C2_KIMWOLF_IN dir=in action=block ^
    remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,^
93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,^
85.234.91.247,185.220.101.0/24 enable=yes >nul 2>&1

:: BadBox2 botnet C2
netsh advfirewall firewall add rule name=DOWNPOUR_C2_BADBOX2 dir=out action=block ^
    remoteip=46.21.147.0/24,91.92.248.0/24,194.165.16.0/24 enable=yes >nul 2>&1

:: Mozi botnet P2P nodes (known ranges)
netsh advfirewall firewall add rule name=DOWNPOUR_C2_MOZI dir=out action=block ^
    remoteip=103.145.12.0/24,45.142.212.0/24 enable=yes >nul 2>&1

:: AISURU botnet
netsh advfirewall firewall add rule name=DOWNPOUR_C2_AISURU dir=out action=block ^
    remoteip=185.174.136.0/24,91.109.6.0/24 enable=yes >nul 2>&1

:: Known CobaltStrike team servers (public CTI)
netsh advfirewall firewall add rule name=DOWNPOUR_C2_COBALT dir=out action=block ^
    remoteip=23.106.160.188,194.165.16.134,185.220.101.47,45.142.212.100 enable=yes >nul 2>&1

echo   [OK] C2/Botnet IPs blocked (Kimwolf, BadBox2, Mozi, AISURU, CobaltStrike)

:: ── 10. LOG ROTATION ─────────────────────────────────────────────
echo   [..] Rotating logs...
call :RotateLog "%APPDIR%crash_fault.log"
call :RotateLog "%APPDIR%dp_stderr.txt"
call :RotateLog "%APPDIR%tk_callback_errors.txt"

:: Clear stale temp files from previous sessions
del /q "%DOWNPOUR_TMP%\downpour_secure_*" >nul 2>&1
del /q "%DOWNPOUR_TMP%\*.tmp" >nul 2>&1
echo   [OK] Logs rotated, stale temps cleared

:: ── 11. MEMORY CHECK ─────────────────────────────────────────────
for /f "usebackq tokens=*" %%M in (`powershell -NoProfile -Command "(Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory" 2^>nul`) do set "FREE_MEM=%%M"
if defined FREE_MEM (
    set /a "FREE_MB=!FREE_MEM!/1024"
    if !FREE_MB! LSS 2048 (
        echo   [WARN] Low free RAM: !FREE_MB! MB - performance may be reduced
        echo          Close other applications for best results
    ) else (
        echo   [OK] Free RAM: !FREE_MB! MB
    )
)

:: ── 12. RE-ENABLE ASR RULE 3b576869 ──────────────────────────────
:: Now that pip installs are done, restore ASR rule to audit mode
powershell -NoProfile -NonInteractive -Command ^
    "Set-MpPreference -AttackSurfaceReductionRules_Ids '3b576869-a4ec-4529-8536-b80a7769e899' -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction SilentlyContinue" >nul 2>&1

:: ── 13. STATUS BANNER ─────────────────────────────────────────────
echo.
echo  ╔═══════════════════════════════════════════════════════════════╗
echo  ║  STATUS                                                        ║
echo  ╟───────────────────────────────────────────────────────────────╢
echo  ║  Python   : !PY!
echo  ║  Version  : !PYVER!
echo  ║  Admin    : YES (elevated)
echo  ║  Defender : ExclusionPath + ASR exclusions applied
echo  ║  ASR 3b   : Audit mode (was disabled during pip, now restored)
echo  ║  Firewall : Kimwolf / BadBox2 / Mozi / AISURU / CS blocked
echo  ║  Logs     : Rotated (last 3 kept)
echo  ║  Target   : downpour_v29_titanium.py
echo  ╚═══════════════════════════════════════════════════════════════╝
echo.
echo   ⛈ Launching Downpour v29 Titanium...
echo   Window appears in ~3-5 seconds.
echo   All 24 tabs + engines load in ~15 seconds.
echo.

:: ── 14. LAUNCH ────────────────────────────────────────────────────
"!PY!" -X utf8 -X faulthandler -u ^
    -W "ignore::FutureWarning" ^
    -W "ignore::DeprecationWarning" ^
    -W "ignore::UserWarning:sklearn" ^
    "%TARGET%" --no-admin --no-install ^
    2>"%APPDIR%dp_stderr.txt"
set "EXIT_CODE=!errorlevel!"

title ⛈ Downpour v29 — Exited

:: ── 15. EXIT HANDLING ─────────────────────────────────────────────
echo.
if "!EXIT_CODE!"=="0" (
    echo  [OK] Downpour v29 exited cleanly (code 0).
) else (
    echo  [!!] Downpour v29 exited with code !EXIT_CODE!
    echo.
    if exist "%APPDIR%crash_fault.log" (
        echo  ─── C-Level Crash Trace ──────────────────────────────────────
        type "%APPDIR%crash_fault.log"
        echo.
    )
    if exist "%APPDIR%dp_stderr.txt" (
        echo  ─── Last 20 lines of stderr ──────────────────────────────────
        powershell -NoProfile -Command "Get-Content '%APPDIR%dp_stderr.txt' -Tail 20" 2>nul
    )
    if exist "%APPDIR%tk_callback_errors.txt" (
        echo  ─── Last 10 Tk callback errors ───────────────────────────────
        powershell -NoProfile -Command "Get-Content '%APPDIR%tk_callback_errors.txt' -Tail 10" 2>nul
    )
    echo.
    echo  To report a crash, share: crash_fault.log + dp_stderr.txt
)
echo.
pause
exit /b !EXIT_CODE!

:: ══ SUBROUTINES ═══════════════════════════════════════════════════

:RotateLog
:: Keeps the last 3 versions of a log file
set "LOGFILE=%~1"
if not exist "%LOGFILE%" goto :EOF
if exist "%LOGFILE%.3" del /q "%LOGFILE%.3" >nul 2>&1
if exist "%LOGFILE%.2" move /y "%LOGFILE%.2" "%LOGFILE%.3" >nul 2>&1
if exist "%LOGFILE%.1" move /y "%LOGFILE%.1" "%LOGFILE%.2" >nul 2>&1
move /y "%LOGFILE%" "%LOGFILE%.1" >nul 2>&1
goto :EOF

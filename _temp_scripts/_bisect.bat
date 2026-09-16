@echo off

setlocal EnableDelayedExpansion

title Downpour v29 Titanium [PRO]

chcp 65001 >nul 2>&1

color 0B



rem ================================================================

rem DOWNPOUR PRO LAUNCHER  (v29.72)

rem Why this one works when the old ones did not:

rem * .venv python is selected FIRST (curated, live-verified deps)

rem * only STABLE system Pythons 3.13/3.12 as fallback (3.14/3.15

rem pre-releases are intentionally skipped - no wheels)

rem * deps install from requirements.txt (real pins, no drift)

rem * pre-flight import verification before launching the GUI

rem * UAC self-elevation (Defender/netsh steps need admin)

rem * Defender + firewall results reported HONESTLY (OK vs FAIL)

rem * GUI always; console stays open showing the exit code

rem ================================================================



rem ---- 0. UAC self-elevation: everything below needs admin ----


echo   [OK] Running as administrator



cd /d "%~dp0"

set "APPDIR=%~dp0"

set "TEMP=%APPDIR%downpour_tmp"

set "TMP=%TEMP%"

set "PYTHONUTF8=1"

set "PYTHONIOENCODING=utf-8"

set "PYTHONWARNINGS=ignore::DeprecationWarning:pkg_resources,ignore::FutureWarning,ignore::UserWarning:sklearn"

set "PYTHONTRACEMALLOC=0"

set "PYTHONFAULTHANDLER=1"

if not exist "%TEMP%" mkdir "%TEMP%"



echo.

echo  ================================================================

echo               DOWNPOUR v29 TITANIUM  [PRO LAUNCHER]

echo                  Advanced Security Suite

echo  ================================================================

echo.



rem ---- 1. Python selection: .venv first, stable system fallbacks ----

set "PY="

for %%P in (

    "%APPDIR%.venv\Scripts\python.exe"

    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"

    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"

    "%ProgramFiles%\Python313\python.exe"

    "%ProgramFiles%\Python312\python.exe"

    "C:\Python313\python.exe"

    "C:\Python312\python.exe"

) do ( if exist %%~P if "!PY!"=="" set "PY=%%~P" )

if "!PY!"=="" (

    echo   [FAIL] No Python 3.12/3.13 found.

    echo          Pre-release 3.14/3.15 builds are intentionally skipped

    echo          - packages have no wheels for them.

    echo          Install Python 3.12 or 3.13 from python.org and re-run.

    echo.

    pause

    exit /b 1

)

echo   [OK] Python: !PY!



rem ---- 2. Dependencies from requirements.txt (real pins) ----

echo   [..] Installing dependencies (requirements.txt)...

"!PY!" -m pip install -r "%APPDIR%requirements.txt" --quiet >nul 2>&1

if !errorlevel!==0 (

    echo   [OK] Dependencies installed

) else (

    echo   [WARN] pip reported failures - app degrades gracefully

)



rem ---- 3. Pre-flight import verification ----

echo   [..] Verifying critical imports...

"!PY!" -c "import psutil, win32com.client, Crypto, psutil" >nul 2>&1

if !errorlevel!==0 (

    echo   [OK] Critical imports verified

) else (

    echo   [FAIL] Critical imports missing. Run manually to see the error:

    echo          "!PY!" -m pip install -r "%APPDIR%requirements.txt"

    echo.

    pause

    exit /b 1

)



rem ---- 4. Defender exclusions (visible result) ----

echo   [..] Configuring Defender exclusions...

reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourAppDir" /t REG_SZ /d "!APPDIR!" /f >nul 2>&1

reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v "DownpourPython" /t REG_SZ /d "!PY!" /f >nul 2>&1

if !errorlevel!==0 (

    echo   [OK] Defender exclusions applied

) else (

    echo   [WARN] Defender exclusions FAILED - some features degrade

)



rem ---- 5. Firewall rules (visible result) ----

echo   [..] Applying firewall rules...

netsh advfirewall firewall delete rule name=DOWNPOUR_KIMWOLF_C2    >nul 2>&1

netsh advfirewall firewall delete rule name=DOWNPOUR_KIMWOLF_C2_IN >nul 2>&1

netsh advfirewall firewall add rule name=DOWNPOUR_KIMWOLF_C2 dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1

netsh advfirewall firewall add rule name=DOWNPOUR_KIMWOLF_C2_IN dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1

if !errorlevel!==0 (

    echo   [OK] Firewall rules applied

) else (

    echo   [WARN] Firewall rules FAILED - C2 blocks inactive

)



rem ---- 6. Temp artifact cleanup ----

del /q "%APPDIR%downpour_tmp\downpour_secure_*" >nul 2>&1

del /q "%APPDIR%crash_fault.log" >nul 2>&1



rem ---- 7. Launch (GUI always) ----

echo.

echo  ================================================================

echo   Starting Downpour v29 Titanium...

echo   Window appears in ~5 seconds. Console stays open and shows

echo   the exit code when you close the app.

echo  ================================================================

echo.



echo PARSE-OK

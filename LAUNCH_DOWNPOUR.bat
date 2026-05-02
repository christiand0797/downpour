@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium
chcp 65001 >nul 2>&1
color 0B

echo.
echo  ================================================================
echo                  DOWNPOUR v29 TITANIUM
echo               Advanced Security Suite
echo  ================================================================
echo.

cd /d "%~dp0"

set "APPDIR=%~dp0"
set "TEMP=%APPDIR%downpour_tmp"
set "TMP=%TEMP%"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "PYTHONWARNINGS=ignore::DeprecationWarning:pkg_resources,ignore::FutureWarning"
set "PYTHONTRACEMALLOC=0"
set "PYTHONFAULTHANDLER=1"
if not exist "%TEMP%" mkdir "%TEMP%"

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

echo   [..] Installing all dependencies...
"!PY!" -m pip install psutil requests cryptography watchdog nvidia-ml-py colorama wmi pywin32 scikit-learn yara-python pillow dnspython netifaces joblib tqdm pyperclip python-dateutil charset-normalizer idna urllib3 certifi
if %errorlevel%==0 (
    echo   [OK] All dependencies installed successfully
) else (
    echo   [!!] Some dependencies failed to install
)

echo   [..] Configuring Defender exclusions...
powershell -NoProfile -Command "Add-MpPreference -ExclusionPath '!APPDIR!' -ErrorAction SilentlyContinue" >nul 2>&1
powershell -NoProfile -Command "Add-MpPreference -ExclusionProcess '!PY!' -ErrorAction SilentlyContinue" >nul 2>&1
echo   [OK] Defender exclusions applied

echo   [..] Applying firewall rules...
netsh advfirewall firewall delete rule name=DOWNPOUR_KIMWOLF_C2    >nul 2>&1
netsh advfirewall firewall delete rule name=DOWNPOUR_KIMWOLF_C2_IN >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_KIMWOLF_C2 dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name=DOWNPOUR_KIMWOLF_C2_IN dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
echo   [OK] Firewall rules applied

del /q "%APPDIR%downpour_tmp\downpour_secure_*" >nul 2>&1
del /q "%APPDIR%crash_fault.log" >nul 2>&1

echo.
echo  ================================================================
echo   Starting Downpour v29 Titanium...
echo   Window appears in ~5 seconds.
echo  ================================================================
echo.

"!PY!" -X utf8 -X faulthandler -u -W ignore::FutureWarning "%APPDIR%downpour_v29_titanium.py" --no-admin --no-install 2>"%APPDIR%dp_stderr.txt"
set "EXIT_CODE=%errorlevel%"

echo.
if %EXIT_CODE%==0 (
    echo  [OK] Downpour exited cleanly.
) else (
    echo  [!!] Downpour exited with code %EXIT_CODE%
    powershell -NoProfile -Command "Get-Content '%APPDIR%dp_stderr.txt' -Tail 10" 2>nul
)
echo.
pause
@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium
chcp 65001 >nul 2>&1
color 0B

echo.
echo  ================================================================
echo                  DOWNPOUR v29 TITANIUM
echo              Advanced Security Suite
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

set "VENV_DIR=%APPDIR%.venv"
set "VENV_PYTHON=%APPDIR%.venv\Scripts\python.exe"

REM Check if virtual environment exists
if not exist "%VENV_PYTHON%" (
    echo.
    echo  [ERROR] Virtual environment not found!
    echo.
    echo  This appears to be a fresh clone or the installer hasn't been run yet.
    echo  Please run the installer FIRST:
    echo.
    echo      INSTALL_DOWNPOUR.bat
    echo.
    echo  This will:
    echo    - Install Python 3.12.10 if needed
    echo    - Create the virtual environment .venv
    echo    - Install all dependencies
    echo    - Set up directories, Defender exclusions, and firewall rules
    echo    - Initialize ML models
    echo.
    pause
    exit /b 1
)

set "PY=%VENV_PYTHON%"
echo   [OK] Using virtual environment: %VENV_DIR%

REM Verify dependencies are installed
echo   [..] Verifying dependencies...
"%VENV_PYTHON%" -c "import psutil, requests, cryptography, watchdog, colorama, wmi, sklearn, yara, pillow, dnspython, netifaces, joblib, tqdm, pyperclip, python-dateutil, charset_normalizer, idna, urllib3, certifi" 2>nul
if %errorlevel% neq 0 (
    echo   [!!] Some dependencies missing. Running quick install...
    "%VENV_DIR%\Scripts\pip.exe" install psutil requests cryptography watchdog nvidia-ml-py colorama wmi pywin32 scikit-learn yara-python pillow dnspython netifaces joblib tqdm pyperclip python-dateutil charset-normalizer idna urllib3 certifi --quiet
    if %errorlevel%==0 (
        echo   [OK] Dependencies installed
    ) else (
        echo   [!!] Some dependencies failed to install
    )
) else (
    echo   [OK] All dependencies verified
)

echo   [..] Configuring Defender exclusions...
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourAppDir" /t REG_SZ /d "%APPDIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourDataDir" /t REG_SZ /d "%APPDIR%downpour_data" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourTempDir" /t REG_SZ /d "%APPDIR%downpour_tmp" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourQuarantineDir" /t REG_SZ /d "%APPDIR%downpour_data\quarantine" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v "DownpourPython" /t REG_SZ /d "%VENV_PYTHON%" /f >nul 2>&1
echo   [OK] Defender exclusions applied registry

echo   [..] Applying firewall rules...
netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2" >nul 2>&1
netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2_IN" >nul 2>&1
netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2" dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2_IN" dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
echo   [OK] Firewall rules applied

del /q "%APPDIR%downpour_tmp\downpour_secure_*" >nul 2>&1
del /q "%APPDIR%crash_fault.log" >nul 2>&1

echo.
echo  ================================================================
echo   Starting Downpour v29 Titanium...
echo   Window appears in ~5 seconds.
echo  ================================================================
echo.

"%VENV_PYTHON%" -X utf8 -X faulthandler -u -W ignore::FutureWarning "%APPDIR%downpour_v29_titanium.py" --no-admin --no-install 2>"%APPDIR%dp_stderr.txt"
set "EXIT_CODE=%errorlevel%"

echo.
if %EXIT_CODE%==0 (
    echo  [OK] Downpour exited cleanly.
) else (
    echo  [!!] Downpour exited with code %EXIT_CODE%
    if exist "%APPDIR%dp_stderr.txt" (
        echo.
        echo  Last 20 lines of error log:
        echo  ---------------------------
        powershell -Command "Get-Content '%APPDIR%dp_stderr.txt' -Tail 20" 2>nul || type "%APPDIR%dp_stderr.txt" 2>nul
    )
)
echo.
pause
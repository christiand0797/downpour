@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium - Complete Setup and Dependency Installer
color 0A
chcp 65001 >nul 2>&1

REM ================================================================
REM ROBUST PATH HANDLING - Capture script directory immediately
REM Works even with spaces, special chars, UNC paths, etc.
REM ================================================================
set "SCRIPT_FULL=%~f0"
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

echo ================================================================
echo                  DOWNPOUR v29 TITANIUM
echo              Complete Setup and Dependency Installer
echo ================================================================
echo.
echo [INFO] Installer location: %SCRIPT_DIR%
echo [INFO] Installer file: %SCRIPT_FULL%
echo.

REM ================================================================
REM PRE-FLIGHT CHECKS
REM ================================================================

REM Check we can read our own directory
if not exist "%SCRIPT_DIR%\downpour_v29_titanium.py" (
    echo [ERROR] Cannot find downpour_v29_titanium.py in %SCRIPT_DIR%
    echo [ERROR] Make sure you extracted/cloned the complete repository
    echo [ERROR] Current directory: %CD%
    pause
    exit /b 1
)

REM Check requirements.txt exists
if not exist "%SCRIPT_DIR%\requirements.txt" (
    echo [ERROR] Cannot find requirements.txt in %SCRIPT_DIR%
    pause
    exit /b 1
)

echo [INFO] Repository files verified OK
echo.

REM ================================================================
REM ELEVATION - Re-launch as Admin if needed
REM Uses multiple methods for maximum compatibility
REM ================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [..] Requesting Administrator privileges...
    echo [INFO] Re-launching from: %SCRIPT_DIR%
    
    REM Method 1: PowerShell with explicit working directory
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process cmd.exe -ArgumentList '/c \"%SCRIPT_FULL%\"' -Verb RunAs -WorkingDirectory '%SCRIPT_DIR%'" 2>nul
    
    if %errorlevel% neq 0 (
        REM Method 2: PowerShell alternative syntax
        powershell -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c \"%SCRIPT_FULL%\"' -Verb RunAs -WorkingDirectory '%SCRIPT_DIR%'"
    )
    
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to auto-elevate. Please manually run as Administrator:
        echo [ERROR]   1. Right-click this file
        echo [ERROR]   2. Select "Run as administrator"
        pause
        exit /b 1
    )
    exit /b
)

echo [SUCCESS] Running with Administrator privileges
echo.

REM ================================================================
REM CONFIGURATION - All paths derived from SCRIPT_DIR
REM ================================================================
set "APPDIR=%SCRIPT_DIR%\"
set "VENV_DIR=%APPDIR%.venv"
set "PYTHON_VERSION=3.12.10"
set "PYTHON_INSTALLER=python-%PYTHON_VERSION%-amd64.exe"
set "PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/%PYTHON_INSTALLER%"
set "REQUIREMENTS=%APPDIR%requirements.txt"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"

REM Directory structure
set "DATA_DIR=%APPDIR%downpour_data"
set "TMP_DIR=%APPDIR%downpour_tmp"
set "LOGS_DIR=%DATA_DIR%\logs"
set "QUARANTINE_DIR=%DATA_DIR%\quarantine"
set "QUARANTINE_FILES=%QUARANTINE_DIR%\files"
set "QUARANTINE_META=%QUARANTINE_DIR%\metadata"
set "QUARANTINE_SNAPS=%QUARANTINE_DIR%\snapshots"
set "CONFIG_DIR=%DATA_DIR%\config"
set "INTEL_DIR=%DATA_DIR%\intel"
set "MODELS_DIR=%DATA_DIR%\models"
set "SANDBOX_DIR=%DATA_DIR%\sandbox"
set "CONTAINMENT_DIR=%DATA_DIR%\containment"
set "BACKUP_DIR=%DATA_DIR%\backups"
set "CACHE_DIR=%DATA_DIR%\cache"
set "EXPORTS_DIR=%DATA_DIR%\exports"
set "DOCS_DIR=%DATA_DIR%\docs"
set "REPORTS_DIR=%DATA_DIR%\reports"
set "TEMP_SCRIPTS=%APPDIR%_temp_scripts"

REM ================================================================
REM LOGGING HELPERS
REM ================================================================
:LOG_INFO    & echo [INFO]    %* & goto :EOF
:LOG_OK      & echo [OK]      %* & goto :EOF
:LOG_WARN    & echo [WARN]    %* & goto :EOF
:LOG_ERROR   & echo [ERROR]   %* & goto :EOF
:LOG_STEP    & echo. & echo ========== %* ========== & echo. & goto :EOF

REM ================================================================
REM PYTHON CHECK - Multiple detection strategies
REM ================================================================
:CHECK_PYTHON
call :LOG_INFO "Checking for Python %PYTHON_VERSION%..."

REM Strategy 1: Check if our venv already has it
if exist "%VENV_PYTHON%" (
    "%VENV_PYTHON%" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_EXE=%VENV_PYTHON%"
        call :LOG_OK "Found in virtual environment: %VENV_PYTHON%"
        goto :EOF
    )
)

REM Strategy 2: Check system Python
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%P in ('where python') do (
        "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
        if !errorlevel! equ 0 (
            "%%P" --version 2>&1 | findstr /R "%PYTHON_VERSION:" >nul
            if !errorlevel! equ 0 (
                set "PYTHON_EXE=%%P"
                call :LOG_OK "Found system Python: %%P"
                goto :EOF
            )
        )
    )
)

REM Strategy 3: Check common install locations
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Program Files\Python312\python.exe"
    "C:\Program Files\Python311\python.exe"
) do (
    if exist "%%P" (
        "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
        if !errorlevel! equ 0 (
            "%%P" --version 2>&1 | findstr /R "%PYTHON_VERSION:" >nul
            if !errorlevel! equ 0 (
                set "PYTHON_EXE=%%P"
                call :LOG_OK "Found at: %%P"
                goto :EOF
            )
        )
    )
)

set "PYTHON_EXE="
call :LOG_WARN "Python %PYTHON_VERSION% not found"
goto :EOF

REM ================================================================
REM DOWNLOAD PYTHON INSTALLER
REM ================================================================
:DOWNLOAD_PYTHON
call :LOG_INFO "Downloading Python %PYTHON_VERSION% installer..."
call :LOG_INFO "URL: %PYTHON_URL%"
call :LOG_INFO "Saving to: %TEMP%\%PYTHON_INSTALLER%"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "try { Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%TEMP%\%PYTHON_INSTALLER%' -UseBasicParsing -TimeoutSec 120; exit 0 } catch { Write-Error $_.Exception.Message; exit 1 }"

if not exist "%TEMP%\%PYTHON_INSTALLER%" (
    call :LOG_ERROR "Download failed"
    call :LOG_INFO "Please manually download from: %PYTHON_URL%"
    call :LOG_INFO "Save as: %TEMP%\%PYTHON_INSTALLER%"
    call :LOG_INFO "Then re-run this installer"
    pause
    exit /b 1
)

call :LOG_OK "Downloaded Python installer"
goto :EOF

REM ================================================================
REM INSTALL PYTHON
REM ================================================================
:INSTALL_PYTHON
call :LOG_INFO "Installing Python %PYTHON_VERSION% (this may take 2-5 minutes)..."
call :LOG_INFO "Running: %TEMP%\%PYTHON_INSTALLER% /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 Include_pip=1"

"%TEMP%\%PYTHON_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 Include_pip=1

if %errorlevel% neq 0 (
    call :LOG_ERROR "Python installation failed (exit code %errorlevel%)"
    call :LOG_INFO "Try manual install: https://www.python.org/downloads/release/python-31210/"
    pause
    exit /b 1
)

call :LOG_OK "Python installed successfully"
REM Refresh PATH
set "PATH=%PATH%;%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts"
goto :EOF

REM ================================================================
REM CREATE VIRTUAL ENVIRONMENT
REM ================================================================
:CREATE_VENV
call :LOG_INFO "Creating virtual environment at %VENV_DIR%..."

if exist "%VENV_DIR%" (
    call :LOG_INFO "Removing existing virtual environment..."
    rmdir /s /q "%VENV_DIR%" 2>nul
)

"%PYTHON_EXE%" -m venv "%VENV_DIR%" --clear

if %errorlevel% neq 0 (
    call :LOG_ERROR "Failed to create virtual environment"
    call :LOG_INFO "Try manually: \"%PYTHON_EXE%\" -m venv .venv"
    pause
    exit /b 1
)

call :LOG_OK "Virtual environment created"
goto :EOF

REM ================================================================
REM UPGRADE PIP
REM ================================================================
:UPGRADE_PIP
call :LOG_INFO "Upgrading pip, setuptools, wheel..."
"%VENV_PIP%" install --upgrade pip setuptools wheel --quiet
if %errorlevel% neq 0 (
    call :LOG_WARN "pip upgrade failed (continuing anyway)"
)
goto :EOF

REM ================================================================
REM INSTALL REQUIREMENTS - Robust multi-pass approach
REM ================================================================
:INSTALL_REQUIREMENTS
call :LOG_INFO "Installing dependencies from requirements.txt..."

REM First pass: install all
"%VENV_PIP%" install -r "%REQUIREMENTS%" --quiet
if %errorlevel% equ 0 (
    call :LOG_OK "All dependencies installed"
    goto :EOF
)

call :LOG_WARN "Some packages failed. Trying core packages only..."

REM Second pass: core packages only (no version constraints)
"%VENV_PIP%" install psutil requests cryptography watchdog nvidia-ml-py colorama wmi pywin32 scikit-learn yara-python pillow dnspython netifaces joblib tqdm pyperclip python-dateutil charset-normalizer idna urllib3 certifi scipy pefile pydantic pyyaml tomli aiohttp aiodns click rich packaging importlib-metadata tenacity schedule prometheus-client slack-sdk python-telegram-bot discord.py psycopg2-binary redis pycryptodome paramiko pyjwt pyotp qrcode python-nmap shodan censys greyNoise weasyprint pdfkit python-magic prompt-toolkit --quiet

if %errorlevel% equ 0 (
    call :LOG_OK "Core dependencies installed"
    goto :EOF
)

call :LOG_ERROR "Core package installation failed"
pause
exit /b 1

REM ================================================================
REM CREATE ALL DIRECTORIES
REM ================================================================
:CREATE_DIRS
call :LOG_INFO "Creating directory structure..."

for %%D in (
    "%DATA_DIR%"
    "%TMP_DIR%"
    "%LOGS_DIR%"
    "%QUARANTINE_DIR%"
    "%QUARANTINE_FILES%"
    "%QUARANTINE_META%"
    "%QUARANTINE_SNAPS%"
    "%CONFIG_DIR%"
    "%INTEL_DIR%"
    "%MODELS_DIR%"
    "%SANDBOX_DIR%"
    "%CONTAINMENT_DIR%"
    "%BACKUP_DIR%"
    "%CACHE_DIR%"
    "%EXPORTS_DIR%"
    "%DOCS_DIR%"
    "%REPORTS_DIR%"
    "%TEMP_SCRIPTS%"
) do (
    if not exist "%%~D" (
        mkdir "%%~D" 2>nul
        if not exist "%%~D" (
            call :LOG_WARN "Failed to create: %%~D"
        )
    )
)

call :LOG_OK "Directory structure created"
goto :EOF

REM ================================================================
REM CREATE CONFIG
REM ================================================================
:CREATE_CONFIG
call :LOG_INFO "Creating configuration files..."

if not exist "%CONFIG_DIR%\settings.ini" (
    >"%CONFIG_DIR%\settings.ini" (
        echo [General]
        echo version=29.118
        echo first_run=true
        echo debug_mode=false
        echo log_level=INFO
        echo auto_update_intel=true
        echo intel_refresh_interval=120
        echo dns_refresh_interval=4
        echo enable_cis=true
        echo enable_vpn=false
        echo enable_cleanup=true
        echo theme=dark
        echo language=en
        echo.
        echo [Performance]
        echo max_workers=auto
        echo gpu_acceleration=true
        echo memory_limit_mb=2048
        echo.
        echo [Network]
        echo block_known_c2=true
        echo monitor_dns=true
        echo monitor_connections=true
        echo.
        echo [Security]
        echo quarantine_on_detect=true
        echo auto_remediate=false
        echo defender_integration=true
        echo firewall_integration=true
    )
    call :LOG_OK "Created settings.ini"
) else (
    call :LOG_INFO "settings.ini already exists"
)
goto :EOF

REM ================================================================
REM DEFENDER EXCLUSIONS
REM ================================================================
:SETUP_DEFENDER
call :LOG_INFO "Configuring Windows Defender exclusions..."

reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourAppDir" /t REG_SZ /d "%APPDIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourDataDir" /t REG_SZ /d "%DATA_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourTempDir" /t REG_SZ /d "%TMP_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourQuarantineDir" /t REG_SZ /d "%QUARANTINE_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v "DownpourPython" /t REG_SZ /d "%VENV_PYTHON%" /f >nul 2>&1

call :LOG_OK "Defender exclusions applied"
goto :EOF

REM ================================================================
REM FIREWALL RULES
REM ================================================================
:SETUP_FIREWALL
call :LOG_INFO "Applying firewall rules (blocking known C2 IPs)..."

netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2" >nul 2>&1
netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2_IN" >nul 2>&1

netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2" dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2_IN" dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1

call :LOG_OK "Firewall rules applied"
goto :EOF

REM ================================================================
REM INITIALIZE ML MODELS
REM ================================================================
:INIT_MODELS
call :LOG_INFO "Initializing ML models..."

if not exist "%MODELS_DIR%\behavior_classifier.pkl" (
    "%VENV_PYTHON%" -c "
import os, pickle, numpy as np
from sklearn.ensemble import IsolationForest
os.makedirs(r'%MODELS_DIR%', exist_ok=True)
iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
X = np.random.randn(100, 23)
iso.fit(X)
with open(r'%MODELS_DIR%\behavior_classifier.pkl', 'wb') as f:
    pickle.dump(iso, f)
iso2 = IsolationForest(contamination=0.05, random_state=42, n_estimators=50)
X2 = np.random.randn(50, 10)
iso2.fit(X2)
with open(r'%MODELS_DIR%\process_anomaly_model.pkl', 'wb') as f:
    pickle.dump(iso2, f)
print('Models initialized')
" 2>&1
    if %errorlevel% neq 0 (
        call :LOG_WARN "ML model init failed (will create on first run)"
    ) else (
        call :LOG_OK "ML models initialized"
    )
) else (
    call :LOG_INFO "ML models already exist"
)
goto :EOF

REM ================================================================
REM FINAL VERIFICATION
REM ================================================================
:VERIFY
call :LOG_INFO "Running final verification..."

"%VENV_PYTHON%" -c "
import sys
sys.path.insert(0, r'%APPDIR%')
import downpour_v29_titanium as dp
print('Downpour import: OK')
print('CIS available:', dp.COGNITIVE_IMMUNE_SYSTEM_AVAILABLE)
print('Threat Response Center available:', dp.THREAT_RESPONSE_CENTER_AVAILABLE)

methods = ['_build_dashboard', '_build_threats_tab', '_build_intel_tab', '_build_network_tab',
           '_build_forensics_tab', '_build_defense_tab', '_build_performance_tab',
           '_build_tools_tab', '_build_processes_tab', '_build_cis_tab',
           '_threats_apply_filter', '_threats_filter_changed',
           '_intel_view_changed', '_net_view_changed', '_forensics_view_changed',
           '_defense_view_changed', '_tools_view_changed']

missing = [m for m in methods if not hasattr(dp.downpour, m)]
if missing:
    print('MISSING methods:', missing)
    sys.exit(1)
print('All methods present: OK')

import re
with open(r'%APPDIR%downpour_v29_titanium.py', 'r') as f:
    content = f.read()
idx = content.find('_TAB_DEFS: Any = [')
end_idx = content.find(']', idx)
labels = re.findall(r\"'\\\\U[0-9a-f]+ ([^']+)'\", content[idx:end_idx])
print('Tab count:', len(labels))
" 2>&1

if %errorlevel% neq 0 (
    call :LOG_ERROR "Verification failed"
    pause
    exit /b 1
)

call :LOG_OK "All verification checks passed"
goto :EOF

REM ================================================================
REM MAIN FLOW
REM ================================================================
call :LOG_STEP "DOWNPOUR v29 TITANIUM INSTALLATION"

REM 1. Create directories first
call :LOG_STEP "STEP 1: Directory Structure"
call :CREATE_DIRS

REM 2. Create config
call :LOG_STEP "STEP 2: Configuration"
call :CREATE_CONFIG

REM 3. Python
call :LOG_STEP "STEP 3: Python Environment"
call :CHECK_PYTHON
if not defined PYTHON_EXE (
    call :DOWNLOAD_PYTHON
    call :INSTALL_PYTHON
    call :CHECK_PYTHON
)
if not defined PYTHON_EXE (
    call :LOG_ERROR "Python setup failed"
    pause
    exit /b 1
)
call :LOG_OK "Using Python: %PYTHON_EXE%"

REM 4. Virtual environment
call :CREATE_VENV

REM 5. Upgrade pip
call :UPGRADE_PIP

REM 6. Install requirements
call :INSTALL_REQUIREMENTS

REM 7. Initialize models
call :INIT_MODELS

REM 8. Defender exclusions
call :SETUP_DEFENDER

REM 9. Firewall rules
call :SETUP_FIREWALL

REM 10. Verification
call :VERIFY

REM ================================================================
REM COMPLETION
REM ================================================================
echo.
echo ================================================================
call :LOG_OK "Downpour v29 Titanium setup complete!"
echo ================================================================
echo.
echo Installation Summary:
echo   Python: %PYTHON_VERSION% (%PYTHON_EXE%)
echo   Virtual Environment: %VENV_DIR%
echo   Application Directory: %APPDIR%
echo   Data Directory: %DATA_DIR%
echo   Temp Directory: %TMP_DIR%
echo   Logs Directory: %LOGS_DIR%
echo   Quarantine Directory: %QUARANTINE_DIR%
echo   Config Directory: %CONFIG_DIR%
echo   Models Directory: %MODELS_DIR%
echo.
echo Next Steps:
echo   1. Run LAUNCH_DOWNPOUR.bat to start the application
echo   2. Or run: .\.venv\Scripts\python.exe downpour_v29_titanium.py --no-admin --no-install
echo.
echo For development: .\venv\Scripts\activate
echo.
pause
goto :EOF

:EOF
endlocal
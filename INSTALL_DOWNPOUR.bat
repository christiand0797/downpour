@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium - Complete Setup and Dependency Installer
color 0A
chcp 65001 >nul 2>&1

echo ================================================================
echo                  DOWNPOUR v29 TITANIUM
echo              Complete Setup and Dependency Installer
echo ================================================================
echo.

REM ================================================================
REM Capture the script directory BEFORE any elevation
REM ================================================================
set "SCRIPT_DIR=%~dp0"

REM ================================================================
REM Check for Administrator privileges
REM ================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [..] Requesting Administrator privileges...
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"%~f0\"' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

REM ================================================================
REM Configuration - use captured script directory
REM ================================================================
set "APPDIR=%SCRIPT_DIR%"
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
REM Helper Functions
REM ================================================================
:LOG_INFO
echo [INFO] %*
goto :EOF

:LOG_WARN
echo [WARN] %*
goto :EOF

:LOG_ERROR
echo [ERROR] %*
goto :EOF

:LOG_SUCCESS
echo [SUCCESS] %*
goto :EOF

:CHECK_ADMIN
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Administrator privileges required!
    echo Please run this installer as Administrator.
    pause
    exit /b 1
)
goto :EOF

:CHECK_PYTHON
where python >nul 2>&1
if %errorlevel% equ 0 (
    python --version 2>&1 | findstr /R "^Python %PYTHON_VERSION%" >nul
    if !errorlevel! equ 0 (
        echo [INFO] Python %PYTHON_VERSION% found
        set PYTHON_EXE=python
        goto :EOF
    )
    echo [WARN] Python version mismatch. Required: %PYTHON_VERSION%
)
set PYTHON_EXE=
goto :EOF

:CHECK_VENV
if exist "%VENV_PYTHON%" (
    echo [INFO] Virtual environment found
    set VENV_READY=1
) else (
    set VENV_READY=0
)
goto :EOF

:INSTALL_PYTHON
call :LOG_INFO "Downloading Python %PYTHON_VERSION% installer..."
powershell -Command "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%TEMP%\%PYTHON_INSTALLER%'"
if not exist "%TEMP%\%PYTHON_INSTALLER%" (
    call :LOG_ERROR "Failed to download Python installer"
    exit /b 1
)
call :LOG_INFO "Installing Python %PYTHON_VERSION%..."
"%TEMP%\%PYTHON_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 Include_pip=1
if %errorlevel% neq 0 (
    call :LOG_ERROR "Python installation failed"
    exit /b 1
)
call :LOG_SUCCESS "Python %PYTHON_VERSION% installed successfully"
goto :EOF

:CREATE_VENV
call :LOG_INFO "Creating virtual environment..."
"%PYTHON_EXE%" -m venv "%VENV_DIR%" --clear
if %errorlevel% neq 0 (
    call :LOG_ERROR "Failed to create virtual environment"
    exit /b 1
)
call :LOG_SUCCESS "Virtual environment created"
goto :EOF

:UPGRADE_PIP
call :LOG_INFO "Upgrading pip, setuptools, wheel..."
"%VENV_PIP%" install --upgrade pip setuptools wheel --quiet
if %errorlevel% neq 0 (
    call :LOG_WARN "Failed to upgrade pip/setuptools/wheel (continuing anyway)"
)
goto :EOF

:INSTALL_REQUIREMENTS
if exist "%REQUIREMENTS%" (
    call :LOG_INFO "Installing dependencies from requirements.txt..."
    "%VENV_PIP%" install -r "%REQUIREMENTS%" --quiet
    if %errorlevel% neq 0 (
        call :LOG_WARN "Some packages failed to install (continuing anyway)"
    ) else (
        call :LOG_SUCCESS "All dependencies installed successfully"
    )
) else (
    call :LOG_WARN "requirements.txt not found, skipping"
)
goto :EOF

:INSTALL_ADDITIONAL_PACKAGES
call :LOG_INFO "Installing additional packages..."
"%VENV_PIP%" install --quiet tenacity prometheus-client psycopg2-binary python-telegram-bot discord.py slack-sdk pycryptodome paramiko python-nmap shodan censys greyNoise pyotp qrcode weasyprint pdfkit schedule elasticsearch redis pyjwt 2>&1 | findstr /V "Requirement already satisfied" | findstr /V "Successfully installed" | findstr /V "already satisfied"
if %errorlevel% neq 0 (
    call :LOG_WARN "Some additional packages failed (may be optional)"
) else (
    call :LOG_SUCCESS "Additional packages installed"
)
goto :EOF

:DOWNLOAD_PYTHON
call :LOG_INFO "Downloading Python %PYTHON_VERSION%..."
powershell -Command "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%TEMP%\%PYTHON_INSTALLER%'"
if not exist "%TEMP%\%PYTHON_INSTALLER%" (
    call :LOG_ERROR "Failed to download Python installer"
    exit /b 1
)
goto :EOF

:VERIFY_INSTALL
call :CHECK_VENV
if %VENV_READY% equ 1 (
    call :LOG_SUCCESS "Virtual environment verified"
) else (
    call :LOG_ERROR "Virtual environment verification failed"
    exit /b 1
)
"%VENV_PYTHON%" -c "import sys; print('Python:', sys.version); import psutil; print('psutil OK'); import requests; print('requests OK'); import cryptography; print('cryptography OK')" 2>&1
if %errorlevel% neq 0 (
    call :LOG_WARN "Some imports failed (may be optional)"
) else (
    call :LOG_SUCCESS "Core dependencies verified"
)
goto :EOF

:CREATE_DIRECTORIES
call :LOG_INFO "Creating directory structure..."
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%TMP_DIR%" mkdir "%TMP_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"
if not exist "%QUARANTINE_DIR%" mkdir "%QUARANTINE_DIR%"
if not exist "%QUARANTINE_FILES%" mkdir "%QUARANTINE_FILES%"
if not exist "%QUARANTINE_META%" mkdir "%QUARANTINE_META%"
if not exist "%QUARANTINE_SNAPS%" mkdir "%QUARANTINE_SNAPS%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%INTEL_DIR%" mkdir "%INTEL_DIR%"
if not exist "%MODELS_DIR%" mkdir "%MODELS_DIR%"
if not exist "%SANDBOX_DIR%" mkdir "%SANDBOX_DIR%"
if not exist "%CONTAINMENT_DIR%" mkdir "%CONTAINMENT_DIR%"
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
if not exist "%CACHE_DIR%" mkdir "%CACHE_DIR%"
if not exist "%EXPORTS_DIR%" mkdir "%EXPORTS_DIR%"
if not exist "%DOCS_DIR%" mkdir "%DOCS_DIR%"
if not exist "%REPORTS_DIR%" mkdir "%REPORTS_DIR%"
if not exist "%TEMP_SCRIPTS%" mkdir "%TEMP_SCRIPTS%"
call :LOG_SUCCESS "Directory structure created"
goto :EOF

:CREATE_CONFIG_FILES
call :LOG_INFO "Creating initial configuration files..."
if not exist "%CONFIG_DIR%\settings.ini" (
    echo [General]>"%CONFIG_DIR%\settings.ini"
    echo version=29.112>>"%CONFIG_DIR%\settings.ini"
    echo first_run=true>>"%CONFIG_DIR%\settings.ini"
    echo debug_mode=false>>"%CONFIG_DIR%\settings.ini"
    echo log_level=INFO>>"%CONFIG_DIR%\settings.ini"
    echo auto_update_intel=true>>"%CONFIG_DIR%\settings.ini"
    echo intel_refresh_interval=120>>"%CONFIG_DIR%\settings.ini"
    echo dns_refresh_interval=4>>"%CONFIG_DIR%\settings.ini"
    echo enable_cis=true>>"%CONFIG_DIR%\settings.ini"
    echo enable_vpn=false>>"%CONFIG_DIR%\settings.ini"
    echo enable_cleanup=true>>"%CONFIG_DIR%\settings.ini"
    echo theme=dark>>"%CONFIG_DIR%\settings.ini"
    echo language=en>>"%CONFIG_DIR%\settings.ini"
    echo.>>"%CONFIG_DIR%\settings.ini"
    echo [Performance]>>"%CONFIG_DIR%\settings.ini"
    echo max_workers=auto>>"%CONFIG_DIR%\settings.ini"
    echo gpu_acceleration=true>>"%CONFIG_DIR%\settings.ini"
    echo memory_limit_mb=2048>>"%CONFIG_DIR%\settings.ini"
    echo.>>"%CONFIG_DIR%\settings.ini"
    echo [Network]>>"%CONFIG_DIR%\settings.ini"
    echo block_known_c2=true>>"%CONFIG_DIR%\settings.ini"
    echo monitor_dns=true>>"%CONFIG_DIR%\settings.ini"
    echo monitor_connections=true>>"%CONFIG_DIR%\settings.ini"
    echo.>>"%CONFIG_DIR%\settings.ini"
    echo [Security]>>"%CONFIG_DIR%\settings.ini"
    echo quarantine_on_detect=true>>"%CONFIG_DIR%\settings.ini"
    echo auto_remediate=false>>"%CONFIG_DIR%\settings.ini"
    echo defender_integration=true>>"%CONFIG_DIR%\settings.ini"
    echo firewall_integration=true>>"%CONFIG_DIR%\settings.ini"
    call :LOG_SUCCESS "Configuration files created"
) else (
    call :LOG_INFO "Configuration files already exist"
)
goto :EOF

:SETUP_DEFENDER_EXCLUSIONS
call :LOG_INFO "Configuring Windows Defender exclusions..."
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourAppDir" /t REG_SZ /d "%APPDIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourDataDir" /t REG_SZ /d "%DATA_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourTempDir" /t REG_SZ /d "%TMP_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourQuarantineDir" /t REG_SZ /d "%QUARANTINE_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v "DownpourPython" /t REG_SZ /d "%VENV_PYTHON%" /f >nul 2>&1
call :LOG_SUCCESS "Defender exclusions configured"
goto :EOF

:SETUP_FIREWALL_RULES
call :LOG_INFO "Applying firewall rules..."
netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2" >nul 2>&1
netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2_IN" >nul 2>&1
netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2" dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2_IN" dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
call :LOG_SUCCESS "Firewall rules applied"
goto :EOF

:INITIALIZE_MODELS
call :LOG_INFO "Initializing ML models directory..."
if not exist "%MODELS_DIR%\behavior_classifier.pkl" (
    "%VENV_PYTHON%" -c "
import os, pickle, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Create dummy models for first run
os.makedirs(r'%MODELS_DIR%', exist_ok=True)

# Behavior classifier (Isolation Forest)
iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
X_dummy = np.random.randn(100, 23)
iso.fit(X_dummy)
with open(r'%MODELS_DIR%\behavior_classifier.pkl', 'wb') as f:
    pickle.dump(iso, f)

# Process anomaly model
iso2 = IsolationForest(contamination=0.05, random_state=42, n_estimators=50)
X_dummy2 = np.random.randn(50, 10)
iso2.fit(X_dummy2)
with open(r'%MODELS_DIR%\process_anomaly_model.pkl', 'wb') as f:
    pickle.dump(iso2, f)

print('Models initialized')
" 2>&1
    if %errorlevel% neq 0 (
        call :LOG_WARN "Failed to initialize ML models (will be created on first run)"
    ) else (
        call :LOG_SUCCESS "ML models initialized"
    )
) else (
    call :LOG_INFO "ML models already exist"
)
goto :EOF

:VERIFY_COMPLETE
call :LOG_INFO "Running final verification..."
"%VENV_PYTHON%" -c "
import sys
sys.path.insert(0, r'%APPDIR%')
import downpour_v29_titanium as dp
print('Downpour import: OK')
print('CIS available:', dp.COGNITIVE_IMMUNE_SYSTEM_AVAILABLE)
print('Threat Response Center available:', dp.THREAT_RESPONSE_CENTER_AVAILABLE)

# Verify all key methods exist
methods = ['_build_dashboard', '_build_threats_tab', '_build_intel_tab', '_build_network_tab',
           '_build_forensics_tab', '_build_defense_tab', '_build_performance_tab',
           '_build_tools_tab', '_build_processes_tab', '_build_cis_tab',
           '_threats_apply_filter', '_threats_filter_changed',
           '_intel_view_changed', '_net_view_changed', '_forensics_view_changed',
           '_defense_view_changed', '_tools_view_changed']

missing = []
for m in methods:
    if not hasattr(dp.downpour, m):
        missing.append(m)

if missing:
    print('MISSING methods:', missing)
    sys.exit(1)
else:
    print('All methods present: OK')

# Verify tab count
import re
with open(r'%APPDIR%downpour_v29_titanium.py', 'r') as f:
    content = f.read()
idx = content.find('_TAB_DEFS: Any = [')
end_idx = content.find(']', idx)
labels = re.findall(r\"'\\U[0-9a-f]+ ([^']+)'\", content[idx:end_idx])
print('Tab count:', len(labels))
" 2>&1
if %errorlevel% neq 0 (
    call :LOG_ERROR "Verification failed"
    exit /b 1
) else (
    call :LOG_SUCCESS "All verification checks passed"
)
goto :EOF

REM ================================================================
REM MAIN INSTALLATION FLOW
REM ================================================================
echo.
call :LOG_INFO "Starting Downpour v29 Titanium complete setup..."
echo.

REM Step 1: Check for Administrator
call :CHECK_ADMIN

REM Step 2: Create directory structure FIRST
call :CREATE_DIRECTORIES

REM Step 3: Create initial config files
call :CREATE_CONFIG_FILES

REM Step 4: Check for existing Python
call :CHECK_PYTHON
if defined PYTHON_EXE (
    call :LOG_SUCCESS "Python found: !PYTHON_EXE!"
) else (
    call :LOG_WARN "Python %PYTHON_VERSION% not found, will install"
    call :DOWNLOAD_PYTHON
    call :INSTALL_PYTHON
    call :CHECK_PYTHON
)

REM Step 5: Create Virtual Environment
call :LOG_INFO "Setting up virtual environment..."
if not exist "%VENV_DIR%" (
    call :CREATE_VENV
) else (
    call :LOG_INFO "Virtual environment exists, verifying..."
    call :CHECK_VENV
    if %VENV_READY% equ 0 (
        call :LOG_WARN "Virtual environment corrupted, recreating..."
        rmdir /s /q "%VENV_DIR%" 2>nul
        call :CREATE_VENV
    )
)

REM Step 6: Upgrade pip
call :UPGRADE_PIP

REM Step 7: Install Requirements
call :INSTALL_REQUIREMENTS

REM Step 8: Install additional packages
call :INSTALL_ADDITIONAL_PACKAGES

REM Step 9: Initialize ML models
call :INITIALIZE_MODELS

REM Step 10: Setup Defender exclusions
call :SETUP_DEFENDER_EXCLUSIONS

REM Step 11: Setup firewall rules
call :SETUP_FIREWALL_RULES

REM Step 12: Final verification
call :VERIFY_COMPLETE

REM ================================================================
REM COMPLETION
REM ================================================================
echo.
echo ================================================================
call :LOG_SUCCESS "Downpour v29 Titanium setup complete!"
echo ================================================================
echo.
echo Installation Summary:
echo   Python: %PYTHON_VERSION%
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
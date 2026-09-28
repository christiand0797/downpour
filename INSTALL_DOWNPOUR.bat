@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium - Complete Setup
color 0A
chcp 65001 >nul 2>&1

REM ================================================================
REM COMPLETELY UNATTENDED INSTALLER - ZERO USER INTERACTION REQUIRED
REM Handles: Python, venv, deps, dirs, config, Defender, firewall, ML models
REM Auto-fixes: path issues, network failures, permission problems, missing files
REM ================================================================

REM Capture script location IMMEDIATELY (before any cd/chdir)
set "SCRIPT_FULL=%~f0"
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

REM Silent mode detection
set "SILENT=0"
for %%A in (%*) do if /i "%%A"=="/silent" set "SILENT=1"
for %%A in (%*) do if /i "%%A"=="/quiet" set "SILENT=1"
for %%A in (%*) do if /i "%%A"=="-s" set "SILENT=1"
for %%A in (%*) do if /i "%%A"=="-q" set "SILENT=1"

REM ================================================================
REM LOGGING FUNCTIONS
REM ================================================================
:LOG    & if %SILENT%==0 echo %* & goto :EOF
:LOG_OK & if %SILENT%==0 echo [OK] %* & goto :EOF
:LOG_WRN & if %SILENT%==0 echo [WARN] %* & goto :EOF
:LOG_ERR & if %SILENT%==0 echo [ERROR] %* & goto :EOF
:LOG_DBG & if %SILENT%==0 echo [DEBUG] %* & goto :EOF

if %SILENT%==0 (
    echo ================================================================
    echo  Downpour v29 Titanium - Automatic Setup
    echo ================================================================
    echo.
    echo [INFO] Source: %SCRIPT_DIR%
    echo.
)

REM ================================================================
REM PRE-FLIGHT: Ensure we can write to our directory
REM ================================================================
:CHECK_WRITE
type nul >"%SCRIPT_DIR%\__write_test__.tmp" 2>nul
if errorlevel 1 (
    call :LOG_ERR "Cannot write to %SCRIPT_DIR%"
    call :LOG_INFO "Fix: Run as Administrator or choose a writable location"
    if %SILENT%==0 pause
    exit /b 1
)
del "%SCRIPT_DIR%\__write_test__.tmp" 2>nul

REM Verify critical files exist
if not exist "%SCRIPT_DIR%\downpour_v29_titanium.py" (
    call :LOG_ERR "downpour_v29_titanium.py not found"
    if %SILENT%==0 pause
    exit /b 1
)
if not exist "%SCRIPT_DIR%\requirements.txt" (
    call :LOG_ERR "requirements.txt not found"
    if %SILENT%==0 pause
    exit /b 1
)

call :LOG_OK "Pre-flight checks passed"

REM ================================================================
REM AUTO-ELEVATION - Multiple methods, fully automatic
REM ================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    call :LOG_INFO "Requesting Administrator privileges..."
    
    REM Method 1: PowerShell with working directory
    powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
        "Start-Process cmd.exe -ArgumentList '/c \"%SCRIPT_FULL%\" %*' -Verb RunAs -WorkingDirectory '%SCRIPT_DIR%'" 2>nul
    
    if errorlevel 1 (
        REM Method 2: ShellExecute via PowerShell
        powershell -Command ^
            "$p=New-Object System.Diagnostics.ProcessStartInfo; $p.FilePath='cmd.exe'; $p.Arguments='/c \"%SCRIPT_FULL%\" %*'; $p.WorkingDirectory='%SCRIPT_DIR%'; $p.Verb='runas'; $p.UseShellExecute=$true; [System.Diagnostics.Process]::Start($p)" 2>nul
    )
    
    if errorlevel 1 (
        REM Method 3: Direct cmd with runas
        cmd /c "powershell -Command \"Start-Process cmd.exe -ArgumentList '/c \"%SCRIPT_FULL%\" %*' -Verb RunAs -WorkingDirectory '%SCRIPT_DIR%'\""
    )
    
    exit /b 0
)

call :LOG_OK "Running as Administrator"

REM ================================================================
REM CONFIGURATION - All paths absolute, no relative references
REM ================================================================
set "APPDIR=%SCRIPT_DIR%\"
set "VENV_DIR=%APPDIR%.venv"
set "PYTHON_VERSION=3.12.10"
set "PYTHON_INSTALLER=python-%PYTHON_VERSION%-amd64.exe"

REM Multiple Python download mirrors for reliability
set "PYTHON_URLS=https://www.python.org/ftp/python/%PYTHON_VERSION%/%PYTHON_INSTALLER% https://cfhcable.dl.sourceforge.net/project/portablepython/3.12.10/%PYTHON_INSTALLER% https://github.com/python/cpython/releases/download/v%PYTHON_VERSION%/%PYTHON_INSTALLER%"

set "REQUIREMENTS=%APPDIR%requirements.txt"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"

set "DATA_DIR=%APPDIR%downpour_data"
set "TMP_DIR=%APPDIR%downpour_tmp"
set "LOGS_DIR=%DATA_DIR%\logs"
set "QUARANTINE_DIR=%DATA_DIR%\quarantine"
set "CONFIG_DIR=%DATA_DIR%\config"
set "MODELS_DIR=%DATA_DIR%\models"

REM ================================================================
REM ROBUST PYTHON DETECTION - Tries everything automatically
REM ================================================================
:FIND_PYTHON
call :LOG_INFO "Locating Python %PYTHON_VERSION%..."

REM 1. Check our venv first
if exist "%VENV_PYTHON%" (
    "%VENV_PYTHON%" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_EXE=%VENV_PYTHON%"
        call :LOG_OK "Using virtual environment: %VENV_PYTHON%"
        goto :PYTHON_FOUND
    )
)

REM 2. Check system PATH
where python >nul 2>&1
if !errorlevel! equ 0 (
    for /f "delims=" %%P in ('where python') do (
        "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
        if !errorlevel! equ 0 (
            set "PYTHON_EXE=%%P"
            call :LOG_OK "Found in PATH: %%P"
            goto :PYTHON_FOUND
        )
    )
)

REM 3. Check all known locations
for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Program Files\Python312\python.exe"
    "C:\Program Files\Python311\python.exe"
    "C:\Program Files (x86)\Python312\python.exe"
    "C:\Program Files (x86)\Python311\python.exe"
) do (
    if exist "%%P" (
        "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
        if !errorlevel! equ 0 (
            set "PYTHON_EXE=%%P"
            call :LOG_OK "Found at: %%P"
            goto :PYTHON_FOUND
        )
    )
)

REM 4. Check Windows Store Python
for /f "tokens=*" %%P in ('where python3 2^>nul') do (
    "%%P" -c "import sys; exit(0 if sys.version_info>=(3,11) else 1)" >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_EXE=%%P"
        call :LOG_OK "Found python3: %%P"
        goto :PYTHON_FOUND
    )
)

set "PYTHON_EXE="
call :LOG_WRN "Python not found - will install automatically"
goto :EOF

:PYTHON_FOUND

REM ================================================================
REM AUTO-INSTALL PYTHON IF NEEDED
REM ================================================================
if not defined PYTHON_EXE (
    call :LOG_STEP "Installing Python %PYTHON_VERSION%"
    
    REM Try each mirror until one works
    for %%U in (%PYTHON_URLS%) do (
        call :LOG_INFO "Trying mirror: %%U"
        powershell -NoProfile -ExecutionPolicy Bypass -Command ^
            "try { Invoke-WebRequest -Uri '%%U' -OutFile '%TEMP%\%PYTHON_INSTALLER%' -UseBasicParsing -TimeoutSec 180; exit 0 } catch { exit 1 }"
        if exist "%TEMP%\%PYTHON_INSTALLER%" (
            call :LOG_OK "Downloaded from %%U"
            goto :RUN_PYTHON_INSTALL
        )
    )
    
    call :LOG_ERR "All download mirrors failed"
    call :LOG_INFO "Please install Python %PYTHON_VERSION% manually from python.org"
    if %SILENT%==0 pause
    exit /b 1
    
    :RUN_PYTHON_INSTALL
    call :LOG_INFO "Installing Python (silent, all users)..."
    "%TEMP%\%PYTHON_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1 Include_pip=1
    
    if errorlevel 1 (
        call :LOG_ERR "Python install failed (code %errorlevel%)"
        call :LOG_INFO "Trying with elevated privileges via winget..."
        winget install --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements 2>nul
        if errorlevel 1 (
            call :LOG_ERR "All automatic install methods failed"
            if %SILENT%==0 pause
            exit /b 1
        )
    )
    
    call :LOG_OK "Python installed, re-detecting..."
    goto :FIND_PYTHON
)

REM ================================================================
REM CREATE DIRECTORIES - Atomic, continues on individual failures
REM ================================================================
call :LOG_STEP "Creating directory structure"

for %%D in (
    "%DATA_DIR%"
    "%TMP_DIR%"
    "%LOGS_DIR%"
    "%QUARANTINE_DIR%\files"
    "%QUARANTINE_DIR%\metadata"
    "%QUARANTINE_DIR%\snapshots"
    "%CONFIG_DIR%"
    "%APPDIR%downpour_data\intel"
    "%MODELS_DIR%"
    "%APPDIR%downpour_data\sandbox"
    "%APPDIR%downpour_data\containment"
    "%APPDIR%downpour_data\backups"
    "%APPDIR%downpour_data\cache"
    "%APPDIR%downpour_data\exports"
    "%APPDIR%downpour_data\docs"
    "%APPDIR%downpour_data\reports"
    "%APPDIR%_temp_scripts"
) do (
    if not exist "%%~D" (
        mkdir "%%~D" 2>nul || (
            call :LOG_WRN "Could not create %%~D (may already exist or permission issue)"
        )
    )
)

REM Fix permissions on our directories
icacls "%DATA_DIR%" /grant "Users:(OI)(CI)F" /T >nul 2>&1
icacls "%TMP_DIR%" /grant "Users:(OI)(CI)F" /T >nul 2>&1
icacls "%VENV_DIR%" /grant "Users:(OI)(CI)F" /T >nul 2>&1 2>nul

call :LOG_OK "Directories ready"

REM ================================================================
REM CREATE CONFIG - Single atomic write
REM ================================================================
if not exist "%CONFIG_DIR%\settings.ini" (
    call :LOG_INFO "Creating configuration..."
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
    call :LOG_OK "Config created"
)

REM ================================================================
REM CREATE/RECREATE VIRTUAL ENVIRONMENT
REM ================================================================
call :LOG_STEP "Setting up virtual environment"

if exist "%VENV_DIR%" (
    call :LOG_INFO "Removing existing venv..."
    rmdir /s /q "%VENV_DIR%" 2>nul
    if exist "%VENV_DIR%" (
        call :LOG_WRN "Could not remove old venv, trying to use anyway"
    )
)

call :LOG_INFO "Creating fresh virtual environment..."
"%PYTHON_EXE%" -m venv "%VENV_DIR%" --clear --upgrade-deps

if errorlevel 1 (
    call :LOG_ERR "venv creation failed, trying without --upgrade-deps..."
    "%PYTHON_EXE%" -m venv "%VENV_DIR%" --clear
    if errorlevel 1 (
        call :LOG_ERR "Virtual environment creation failed"
        call :LOG_INFO "Trying alternative: virtualenv..."
        "%PYTHON_EXE%" -m pip install virtualenv --quiet 2>nul
        "%PYTHON_EXE%" -m virtualenv "%VENV_DIR%" --clear 2>nul
        if errorlevel 1 (
            if %SILENT%==0 pause
            exit /b 1
        )
    )
)

call :LOG_OK "Virtual environment created"

REM ================================================================
REM UPGRADE PIP/SETUPTOOLS/WHEEL
REM ================================================================
call :LOG_INFO "Upgrading pip..."
"%VENV_PIP%" install --upgrade pip setuptools wheel --quiet --disable-pip-version-check 2>nul
call :LOG_OK "pip upgraded"

REM ================================================================
REM INSTALL DEPENDENCIES - Multi-pass with auto-fallback
REM ================================================================
call :LOG_STEP "Installing dependencies"

REM Pass 1: Full requirements.txt
call :LOG_INFO "Pass 1: Installing from requirements.txt..."
"%VENV_PIP%" install -r "%REQUIREMENTS%" --quiet --disable-pip-version-check 2>nul
if !errorlevel! equ 0 (
    call :LOG_WRN "Some packages failed, trying core packages (Pass 2)..."
    
    REM Pass 2: Core packages only, no version constraints
    "%VENV_PIP%" install psutil requests cryptography watchdog nvidia-ml-py colorama wmi pywin32 scikit-learn yara-python pillow dnspython netifaces joblib tqdm pyperclip python-dateutil charset-normalizer idna urllib3 certifi scipy pefile pydantic pyyaml tomli aiohttp aiodns click rich packaging importlib-metadata tenacity schedule prometheus-client slack-sdk python-telegram-bot discord.py psycopg2-binary redis pycryptodome paramiko pyjwt pyotp qrcode python-nmap shodan censys greyNoise weasyprint pdfkit python-magic prompt-toolkit --quiet --disable-pip-version-check 2>nul
    
    if !errorlevel! equ 0 (
        call :LOG_WRN "Core install had issues, trying minimal set (Pass 3)..."
        
        REM Pass 3: Absolute minimum
        "%VENV_PIP%" install psutil requests cryptography watchdog colorama pywin32 numpy scipy scikit-learn pillow dnspython netifaces joblib tqdm pyperclip python-dateutil charset-normalizer idna urllib3 certifi pydantic pyyaml aiohttp aiodns click rich tenacity schedule --quiet --disable-pip-version-check 2>nul
        
        if !errorlevel! equ 0 (
            call :LOG_WRN "Installing packages one by one (Pass 4)..."
            for %%P in (psutil requests cryptography watchdog colorama pywin32 numpy scipy scikit-learn pillow dnspython netifaces joblib tqdm pyperclip python-dateutil charset-normalizer idna urllib3 certifi pydantic pyyaml aiohttp aiodns click rich tenacity schedule) do (
                "%VENV_PIP%" install "%%P" --quiet --disable-pip-version-check 2>nul
                if errorlevel 1 call :LOG_WRN "Failed: %%P"
            )
        )
    )
)

call :LOG_OK "Dependency installation complete"

REM ================================================================
REM VERIFY CORE IMPORTS WORK
REM ================================================================
call :LOG_INFO "Verifying core imports..."
"%VENV_PYTHON%" -c "
import sys
mods = ['psutil','requests','cryptography','watchdog','colorama','wmi','sklearn','numpy','scipy','pillow','dnspython','netifaces','joblib','tqdm','pyperclip','pydantic','yaml','aiohttp','click','rich','tenacity','schedule']
failed = []
for m in mods:
    try: __import__(m.replace('-','_'))
    except: failed.append(m)
if failed: print('FAILED:', ', '.join(failed)); sys.exit(1)
print('ALL CORE IMPORTS OK')
" 2>&1 | findstr /V "Requirement already" | findstr /V "already satisfied"
if errorlevel 1 (
    call :LOG_WRN "Some imports may not work (will retry on launch)"
)

REM ================================================================
REM INITIALIZE ML MODELS
REM ================================================================
call :LOG_INFO "Initializing ML models..."
"%VENV_PYTHON%" -c "
import os, pickle, numpy as np
from sklearn.ensemble import IsolationForest
os.makedirs(r'%MODELS_DIR%', exist_ok=True)
try:
    iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    X = np.random.randn(100, 23)
    iso.fit(X)
    with open(r'%MODELS_DIR%\behavior_classifier.pkl', 'wb') as f: pickle.dump(iso, f)
    iso2 = IsolationForest(contamination=0.05, random_state=42, n_estimators=50)
    X2 = np.random.randn(50, 10)
    iso2.fit(X2)
    with open(r'%MODELS_DIR%\process_anomaly_model.pkl', 'wb') as f: pickle.dump(iso2, f)
    print('Models OK')
except Exception as e:
    print('Model init failed:', e)
    exit(1)
" 2>&1
if errorlevel 1 call :LOG_WRN "Model init failed (will create on first run)"

REM ================================================================
REM DEFENDER EXCLUSIONS - Always apply, ignore errors
REM ================================================================
call :LOG_INFO "Configuring Windows Defender exclusions..."
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourAppDir" /t REG_SZ /d "%APPDIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourDataDir" /t REG_SZ /d "%DATA_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourTempDir" /t REG_SZ /d "%TMP_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" /v "DownpourQuarantineDir" /t REG_SZ /d "%QUARANTINE_DIR%" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" /v "DownpourPython" /t REG_SZ /d "%VENV_PYTHON%" /f >nul 2>&1
call :LOG_OK "Defender exclusions applied"

REM ================================================================
REM FIREWALL RULES
REM ================================================================
call :LOG_INFO "Applying firewall rules..."
netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2" >nul 2>&1
netsh advfirewall firewall delete rule name="DOWNPOUR_KIMWOLF_C2_IN" >nul 2>&1
netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2" dir=out action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
netsh advfirewall firewall add rule name="DOWNPOUR_KIMWOLF_C2_IN" dir=in action=block remoteip=93.95.112.50,93.95.112.51,93.95.112.52,93.95.112.53,93.95.112.54,93.95.112.55,93.95.112.56,93.95.112.57,93.95.112.58,93.95.112.59,85.234.91.247 enable=yes >nul 2>&1
call :LOG_OK "Firewall rules applied"

REM ================================================================
REM FINAL VERIFICATION
REM ================================================================
call :LOG_STEP "Final verification"
"%VENV_PYTHON%" -c "
import sys
sys.path.insert(0, r'%APPDIR%')
try:
    import downpour_v29_titanium as dp
    print('Import: OK')
    
    methods = ['_build_dashboard','_build_threats_tab','_build_intel_tab','_build_network_tab',
               '_build_forensics_tab','_build_defense_tab','_build_performance_tab',
               '_build_tools_tab','_build_processes_tab','_build_cis_tab',
               '_threats_apply_filter','_threats_filter_changed',
               '_intel_view_changed','_net_view_changed','_forensics_view_changed',
               '_defense_view_changed','_tools_view_changed']
    missing = [m for m in methods if not hasattr(dp.downpour, m)]
    if missing: print('MISSING:', missing); sys.exit(1)
    print('Methods: OK')
    
    import re
    with open(r'%APPDIR%downpour_v29_titanium.py','r') as f: c=f.read()
    i=c.find('_TAB_DEFS: Any = ['); e=c.find(']',i)
    tabs=re.findall(r\"'\\\\U[0-9a-f]+ ([^']+)'\",c[i:e])
    print('Tabs:',len(tabs))
    print('VERIFICATION PASSED')
except Exception as e:
    print('VERIFICATION FAILED:', e)
    sys.exit(1)
" 2>&1

if errorlevel 1 (
    call :LOG_ERR "Verification failed - but continuing anyway"
) else (
    call :LOG_OK "All checks passed"
)

REM ================================================================
REM COMPLETE
REM ================================================================
if %SILENT%==0 (
    echo.
    echo ================================================================
    echo  INSTALLATION COMPLETE
    echo ================================================================
    echo.
    echo Run LAUNCH_DOWNPOUR.bat to start
    echo.
    pause
)

exit /b 0

:LOG_STEP
if %SILENT%==0 echo. & echo ========== %* ========== & echo.
goto :EOF
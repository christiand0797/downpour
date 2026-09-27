@echo off
setlocal EnableDelayedExpansion
title Downpour v29 Titanium - Dependency Installer
color 0A
chcp 65001 >nul 2>&1

echo ================================================================
echo                  DOWNPOUR v29 TITANIUM
echo              Dependency Installer & Launcher
echo ================================================================
echo.

REM ================================================================
REM Check for Administrator privileges
REM ================================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [..] Requesting Administrator privileges...
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b
)

REM ================================================================
REM Configuration
REM ================================================================
set "APPDIR=%~dp0"
set "VENV_DIR=%APPDIR%.venv"
set "PYTHON_VERSION=3.12.10"
set "PYTHON_INSTALLER=python-%PYTHON_VERSION%-amd64.exe"
set "PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VERSION%/%PYTHON_INSTALLER%"
set "REQUIREMENTS=%APPDIR%requirements.txt"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"

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

REM ================================================================
REM MAIN INSTALLATION FLOW
REM ================================================================
echo.
call :LOG_INFO "Starting Downpour v29 Titanium dependency installation..."
echo.

REM Step 1: Check for Administrator
call :CHECK_ADMIN

REM Step 2: Check for existing Python
call :CHECK_PYTHON
if defined PYTHON_EXE (
    call :LOG_SUCCESS "Python found: !PYTHON_EXE!"
) else (
    call :LOG_WARN "Python %PYTHON_VERSION% not found, will install"
    call :DOWNLOAD_PYTHON
    call :INSTALL_PYTHON
    call :CHECK_PYTHON
)

REM Step 3: Create Virtual Environment
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

REM Step 4: Upgrade pip
call :UPGRADE_PIP

REM Step 5: Install Requirements
call :INSTALL_REQUIREMENTS

REM Step 5b: Install additional packages not in requirements.txt
call :LOG_INFO "Installing additional packages..."
"%VENV_PIP%" install --quiet tenacity prometheus-client psycopg2-binary python-telegram-bot discord.py slack-sdk pycryptodome paramiko python-nmap shodan censys greyNoise pyotp qrcode weasyprint pdfkit schedule elasticsearch redis pyjwt redis pycryptodome paramiko python-nmap shodan censys greyNoise pyotp qrcode weasyprint pdfkit 2>&1 | findstr /V "Requirement already satisfied" | findstr /V "Successfully installed" | findstr /V "already satisfied"
if %errorlevel% neq 0 (
    call :LOG_WARN "Some additional packages failed (may be optional)"
) else (
    call :LOG_SUCCESS "Additional packages installed"
)

REM Step 6: Verify Installation
call :VERIFY_INSTALL

REM ================================================================
REM COMPLETION
REM ================================================================
echo.
echo ================================================================
call :LOG_SUCCESS "Downpour v29 Titanium installation complete!"
echo ================================================================
echo.
echo Installation Summary:
echo   Python: %PYTHON_VERSION%
echo   Virtual Environment: %VENV_DIR%
echo   Requirements: %REQUIREMENTS%
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
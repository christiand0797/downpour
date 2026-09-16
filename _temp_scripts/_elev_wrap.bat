@echo off
cd /d "%~dp0"
echo === ELEVATED LAUNCH %date% %time% ===
call "%~dp0LAUNCH_DOWNPOUR_PRO.bat" > "%~dp0_pro_launch_log.txt" 2>&1
echo === LAUNCHER EXITED code=%errorlevel% ===

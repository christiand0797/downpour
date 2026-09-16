@echo off
setlocal EnableDelayedExpansion
set "APPDIR=C:\Users\purpl\Desktop\downpour_consolidated\"
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
echo PY=!PY!

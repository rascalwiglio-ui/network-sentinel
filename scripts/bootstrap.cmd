@echo off
setlocal
cd /d "%~dp0.."
set "PYTHON=python"
where python >nul 2>nul
if errorlevel 1 (
  set "PYTHON=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
)
if not exist ".venv\Scripts\python.exe" (
  "%PYTHON%" -m venv .venv || exit /b 1
)
".venv\Scripts\python.exe" -m pip install --upgrade pip || exit /b 1
".venv\Scripts\python.exe" -m pip install -r requirements.txt || exit /b 1
echo Bootstrap complete.

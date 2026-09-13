@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment missing. Run scripts\bootstrap.cmd first.
  exit /b 1
)
".venv\Scripts\python.exe" -m sentinel.app

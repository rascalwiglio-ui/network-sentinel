@echo off
setlocal
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment missing. Run scripts\bootstrap.cmd first.
  exit /b 1
)
echo Installing optional packet-capture dependency...
".venv\Scripts\python.exe" -m pip install -r requirements-capture.txt
if errorlevel 1 exit /b 1
echo.
echo Scapy installed.
echo On Windows, live capture also requires Npcap from https://npcap.com/
echo After Npcap is installed, start Sentinel with:
echo   scripts\run-capture.cmd

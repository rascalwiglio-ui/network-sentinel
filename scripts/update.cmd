@echo off
setlocal
cd /d "%~dp0.."
where git >nul 2>nul || (echo Git not found.& exit /b 1)
for /f %%i in ('git status --porcelain') do (
  echo Update cancelled: repository has uncommitted changes.
  echo Commit them first or run: git stash -u
  exit /b 2
)
git fetch origin --tags || exit /b 1
git pull --ff-only origin main || exit /b 1
if not exist ".venv\Scripts\python.exe" (
  call scripts\bootstrap.cmd
  exit /b %errorlevel%
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt || exit /b 1
echo Update complete.

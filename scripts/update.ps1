$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git non trovato."
}

$Dirty = git status --porcelain
if ($Dirty) {
    Write-Host "Update cancelled: the repository has uncommitted changes." -ForegroundColor Yellow
    Write-Host "Commit them first, or run: git stash -u"
    exit 2
}

Write-Host "Fetching updates..."
git fetch origin --tags

Write-Host "Applying origin/main (fast-forward only)..."
git pull --ff-only origin main

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Virtual environment missing; running bootstrap."
    & ".\scripts\bootstrap.ps1"
    exit
}

Write-Host "Refreshing dependencies..."
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt

Write-Host "Update complete."

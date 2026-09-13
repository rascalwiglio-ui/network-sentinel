$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

function Find-Python {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return "python"
    }

    $Candidate = Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"
    if (Test-Path $Candidate) {
        return $Candidate
    }

    throw "Python non trovato. Installa Python 3.13 e riapri PowerShell."
}

$Python = Find-Python

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    & $Python -m venv .venv
}

Write-Host "Installing/updating dependencies..."
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt

Write-Host ""
Write-Host "Bootstrap complete."
Write-Host "Start Sentinel with: .\scripts\run.ps1"

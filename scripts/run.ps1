$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    throw "Virtual environment missing. Run .\scripts\bootstrap.ps1 first."
}

& ".\.venv\Scripts\python.exe" -m sentinel.app

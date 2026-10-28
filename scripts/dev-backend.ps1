$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$backendPath = Join-Path $repoRoot "backend"
$venvPython = Join-Path $backendPath ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    throw "Backend environment not found. Run .\scripts\setup-backend.ps1 first."
}

$env:DATABASE_URL = "sqlite:///./siem.db"
$env:ML_MODEL_DIR = Join-Path $backendPath "models"

Push-Location $backendPath
try {
    Write-Host "Backend: http://localhost:8000"
    Write-Host "API docs: http://localhost:8000/docs"
    & $venvPython -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
    if ($LASTEXITCODE -ne 0) {
        throw "Backend server exited with code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$backendPath = Join-Path $repoRoot "backend"
$venvPath = Join-Path $backendPath ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

Push-Location $repoRoot
try {
    if (-not (Test-Path $venvPython)) {
        $pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
        if ($pythonLauncher) {
            & $pythonLauncher.Source -3.12 -m venv $venvPath
        }
        else {
            $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
            if (-not $pythonCommand) {
                throw "Python 3.12 is required. Install Python or the Windows Python launcher, then retry."
            }
            & $pythonCommand.Source -m venv $venvPath
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Python 3.12 is required. Install Python 3.12, then retry setup."
        }
    }

    & $venvPython -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)"
    if ($LASTEXITCODE -ne 0) {
        throw "backend\.venv must use Python 3.12. Recreate it with Python 3.12, then retry setup."
    }

    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "Could not upgrade pip in backend\.venv."
    }

    & $venvPython -m pip install -r (Join-Path $backendPath "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not install backend requirements."
    }

    $previousDatabaseUrl = $env:DATABASE_URL
    try {
        $env:DATABASE_URL = "sqlite:///./siem.db"
        Push-Location $backendPath
        try {
            & $venvPython -m alembic upgrade head
            if ($LASTEXITCODE -ne 0) {
                throw "Could not apply backend database migrations."
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:DATABASE_URL = $previousDatabaseUrl
    }

    Write-Host "Backend setup complete. Start it with .\scripts\dev-backend.ps1"
}
finally {
    Pop-Location
}

# Run from PowerShell: .\scripts\setup.ps1
$ErrorActionPreference = 'Stop'
$TraceRoot = Split-Path -Parent $PSScriptRoot
Push-Location $TraceRoot
try {
    if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment' }
    }
    $TracePython = Join-Path $TraceRoot '.venv\Scripts\python.exe'
    & $TracePython -m pip install -r requirements-dev.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
    & $TracePython -m pip install --no-deps -e .
    if ($LASTEXITCODE -ne 0) { throw 'TRACE installation failed' }
    if (-not (Test-Path -LiteralPath '.env')) { Copy-Item -LiteralPath '.env.example' -Destination '.env' }
    Write-Output 'Ready. Add SARVAM_API_KEY to .env for optional AI features.'
    Write-Output 'Sample loop: .\.venv\Scripts\python.exe scripts\validate_loop.py'
} finally { Pop-Location }

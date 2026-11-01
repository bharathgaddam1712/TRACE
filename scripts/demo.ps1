# Run from the repository root. Uses local DuckDB and in-memory graphs; no AI key/Neo4j required.
param([string]$LogPath = 'C:\Users\bhara\OneDrive\Desktop\miti\firex-10G.log',
      [string]$Output = (Join-Path $env:LOCALAPPDATA 'TRACE\firex-full-optimized'),
      [int]$Threads = [Math]::Min(4,[Environment]::ProcessorCount),
      [string]$Memory = '1536MB')
$ErrorActionPreference = 'Stop'
$DemoProject = Split-Path -Parent $PSScriptRoot
Push-Location $DemoProject
try {
    $DemoPython = Join-Path $DemoProject '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $DemoPython)) { throw 'Run scripts/setup.ps1 first.' }
    function Invoke-DemoPython {
        & $DemoPython @args
        if ($LASTEXITCODE -ne 0) { throw "Demo command failed with exit code $LASTEXITCODE" }
    }
    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) { throw "Input log not found: $LogPath" }
    $DemoInput = (Resolve-Path -LiteralPath $LogPath).Path
    Invoke-DemoPython scripts/run_optimized_demo.py --input $DemoInput --out $Output --threads $Threads --memory $Memory
    Write-Output "Demo ready. Start UI: $DemoPython scripts/start_web.py --out `"$Output`""
} finally { Pop-Location }

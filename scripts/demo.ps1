# Run from the repository root. Uses local DuckDB and in-memory graphs; no AI key/Neo4j required.
param([string]$LogPath = 'C:\Users\bhara\OneDrive\Desktop\miti\firex-10G.log',
      [string]$Output = 'out/firex-full-demo', [int]$MaxTemporalEvents = 100000)
$ErrorActionPreference = 'Stop'
$DemoProject = Split-Path -Parent $PSScriptRoot
Push-Location $DemoProject
try {
    $DemoPython = Join-Path $DemoProject '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $DemoPython)) { throw 'Run scripts/setup.ps1 first (Python 3.12+ for temporal extras).' }
    function Invoke-DemoPython {
        & $DemoPython @args
        if ($LASTEXITCODE -ne 0) { throw "Demo command failed with exit code $LASTEXITCODE" }
    }
    Invoke-DemoPython -m pip install -e '.[temporal]'
    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) { throw "Input log not found: $LogPath" }
    $DemoInput = (Resolve-Path -LiteralPath $LogPath).Path
    Invoke-DemoPython -m tracekc run --input $DemoInput --out $Output --keep-work --set engine.memory_limit=3GB --set engine.threads=4 --set engine.profile_queries=true
    Invoke-DemoPython -m tracekc temporal-benchmark --events "$Output/work/events.parquet" --out $Output --max-events $MaxTemporalEvents
    Invoke-DemoPython -m tracekc export-history --out $Output --save "$Output/histories.json"
    Invoke-DemoPython -m tracekc forecast-benchmark --input "$Output/histories.json" --out "$Output/forecast-comparison.json" --model-out "$Output/forecast-model.json"
    $DemoModel = (Resolve-Path -LiteralPath "$Output/forecast-model.json").Path
    # Attach to saved evidence without repeating the expensive detection pass.
    Invoke-DemoPython -m tracekc attach-forecast --out $Output --model $DemoModel
    Write-Output "Demo ready. Start UI: $DemoPython -m tracekc serve --out $Output --port 8001"
    Write-Output 'Forecasts fitted to TRACE labels are exploratory; inspect evaluation warnings.'
} finally { Pop-Location }

# Run from the repository root. Uses local DuckDB and in-memory graphs; no AI key/Neo4j required.
param([string]$Output = 'out/firex-demo', [int]$MaxTemporalEvents = 100000)
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
    $DemoInput = Join-Path $DemoProject 'data/benchmarks/firex-500mib.log'
    if (-not (Test-Path -LiteralPath $DemoInput) -or (Get-Item -LiteralPath $DemoInput).Length -lt 500000000) {
        throw 'Fetch the sample first: git lfs pull --include=data/benchmarks/firex-500mib.log'
    }
    $DemoManifest = Get-Content -LiteralPath ($DemoInput + '.manifest.json') -Raw | ConvertFrom-Json
    if ((Get-FileHash -LiteralPath $DemoInput -Algorithm SHA256).Hash.ToLowerInvariant() -ne $DemoManifest.sha256) {
        throw 'Demo input does not match the published SHA-256.'
    }
    Invoke-DemoPython -m tracekc run --input $DemoInput --out $Output --keep-work --set engine.memory_limit=3GB --set engine.threads=4
    Invoke-DemoPython -m tracekc temporal-benchmark --events "$Output/work/events.parquet" --out $Output --max-events $MaxTemporalEvents
    Invoke-DemoPython -m tracekc export-history --out $Output --save "$Output/histories.json"
    Invoke-DemoPython -m tracekc forecast-benchmark --input "$Output/histories.json" --out "$Output/forecast-comparison.json" --model-out "$Output/forecast-model.json"
    $DemoModel = (Resolve-Path -LiteralPath "$Output/forecast-model.json").Path
    # Second run reuses normalized chunks. The model refuses incidents before its
    # training cutoff. Its labels remain explicitly unreviewed in the UI.
    Invoke-DemoPython -m tracekc run --input $DemoInput --out $Output --keep-work --set engine.memory_limit=3GB --set engine.threads=4 --set "forecast.model_path=$DemoModel"
    Write-Output "Demo ready. Start UI: $DemoPython -m tracekc serve --out $Output --port 8001"
    Write-Output 'Forecasts fitted to TRACE labels are exploratory; inspect evaluation warnings.'
} finally { Pop-Location }

param([string]$Output = 'out/firex-full-demo', [int]$Port = 8501)
$ErrorActionPreference = 'Stop'
$TraceDemoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $TraceDemoRoot
try {
    $env:TRACE_DEMO_OUT = [System.IO.Path]::GetFullPath($Output)
    & .\.venv\Scripts\python.exe -m streamlit run streamlit_app.py --server.address 127.0.0.1 --server.port $Port --server.headless true --browser.gatherUsageStats false
    if ($LASTEXITCODE -ne 0) { throw 'Streamlit failed to start. Install: pip install -e ".[demo]"' }
} finally { Pop-Location }

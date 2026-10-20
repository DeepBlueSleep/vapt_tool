param([int]$Port = 8000)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$localBrowserCache = Join-Path $PSScriptRoot '.browser-cache'
if (Test-Path -LiteralPath $localBrowserCache) {
    $env:PLAYWRIGHT_BROWSERS_PATH = $localBrowserCache
}
& (Join-Path $PSScriptRoot '.venv\Scripts\python.exe') -m platform.api --host 127.0.0.1 --port $Port

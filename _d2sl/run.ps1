param(
    [int]$ListenPort = 11437,
    [int]$Deep2Port = 11436,
    [int]$Workers = 2,
    [string]$ApiKey = ""
)

$ErrorActionPreference = "Stop"

$env:DEEP2_SERVERLESS_PORT = "$ListenPort"
$env:DEEP2_UPSTREAM_PORT = "$Deep2Port"
$env:DEEP2_SERVERLESS_WORKERS = "$Workers"
$env:DEEP2_SERVERLESS_API_KEY = $ApiKey

$exe = Join-Path $PSScriptRoot "build\Release\deep2-serverless.exe"
if (-not (Test-Path $exe)) {
    $exe = Join-Path $PSScriptRoot "build\deep2-serverless.exe"
}
if (-not (Test-Path $exe)) {
    throw "Build first with .\build.ps1"
}

& $exe

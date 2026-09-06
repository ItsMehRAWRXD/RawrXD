# Smoke-CommandHome.ps1 — headless ScreenPilot lease/generation smoke (no GUI)
# Usage:
#   powershell -File F:\~dev\rawrxd\scripts\Smoke-CommandHome.ps1
#   $env:RAWRXD_SMOKE_GGUF='G:\OllamaModels\some-chat.gguf'
#   powershell -File F:\~dev\rawrxd\scripts\Smoke-CommandHome.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root 'build-ninja'
if (-not (Test-Path (Join-Path $build 'build.ninja'))) {
    $build = Join-Path $root 'build-ninja-fresh'
}
if (-not (Test-Path (Join-Path $build 'build.ninja'))) {
    throw "No build-ninja / build-ninja-fresh found under $root"
}

Push-Location $build
try {
    Write-Host "Building command_home_smoke in $build ..."
    ninja command_home_smoke
    if ($LASTEXITCODE -ne 0) { throw "ninja command_home_smoke failed: $LASTEXITCODE" }
    $exe = Join-Path $build 'bin\command_home_smoke.exe'
    if (-not (Test-Path $exe)) { throw "missing $exe" }
    Write-Host "Running $exe"
    & $exe
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}

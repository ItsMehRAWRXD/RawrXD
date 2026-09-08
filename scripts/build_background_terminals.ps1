# build_background_terminals.ps1
$ErrorActionPreference = "Stop"
$root = "G:\~dev\rawrxd"
$build = Join-Path $root "build-fd"
cmake --build $build --target rawr_terminal_host rawr_termctl rawrxd_background_terminals_001 -j 4
& "$build\bin\rawrxd_background_terminals_001.exe"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "RAWRXD_BACKGROUND_TERMINALS_001 sealed"

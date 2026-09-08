# build_remaining_style_cli.ps1
$ErrorActionPreference = "Stop"
$root = "G:\~dev\rawrxd"
$build = Join-Path $root "build-fd"
cmake --build $build --target rawrxd_remaining_style_cli_001 -j 4
& "$build\bin\rawrxd_remaining_style_cli_001.exe"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "RAWRXD_REMAINING_STYLE_CLI_001 sealed"

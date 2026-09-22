param(
    [string]$Repo = "F:\~dev\rawrxd",
    [string]$Build = "F:\~dev\build_win32ide_strict_b2",
    [string]$Evidence = "F:\~dev\evidence\STRICT_IDE_SOURCE_CLOSURE_002"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null

$configureArgs = @(
    "-S", $Repo,
    "-B", $Build,
    "-G", "NMake Makefiles",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DRAWRXD_BUILD_WIN32IDE=ON",
    "-DRAWRXD_BUILD_RAWRENGINE=OFF",
    "-DRAWRXD_BUILD_CLI=OFF",
    "-DRAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON",
    "-DRAWRXD_ENABLE_MISSING_HANDLER_STUBS=OFF",
    "-DRAWRXD_INCLUDE_STRESS_AND_REPLAY_SOURCES=OFF",
    "-DRAWR_SSOT_PROVIDER=AUTO"
)

& cmake @configureArgs 2>&1 |
    Tee-Object -FilePath (Join-Path $Evidence "configure.txt")
$configRc = $LASTEXITCODE
"CONFIGURE_EXIT=$configRc" | Set-Content (Join-Path $Evidence "configure_exit.txt")
if ($configRc -ne 0) {
    Write-Host "Configure failed. This is authoritative; do not add stubs."
    exit $configRc
}

& cmake --build $Build --target RawrXD-Win32IDE 2>&1 |
    Tee-Object -FilePath (Join-Path $Evidence "build.txt")
$buildRc = $LASTEXITCODE
"BUILD_EXIT=$buildRc" | Set-Content (Join-Path $Evidence "build_exit.txt")

$buildLog = Join-Path $Evidence "build.txt"
$symbolsOut = Join-Path $Evidence "batch3_unresolved_symbols.txt"
if (Test-Path $buildLog) {
    Get-Content $buildLog |
        Select-String 'LNK2001|LNK2019|LNK1120|unresolved external symbol|error C[0-9]{4}|fatal error C[0-9]{4}' |
        ForEach-Object { $_.Line } |
        Sort-Object -Unique |
        Set-Content $symbolsOut
}

Write-Host "Strict build exit: $buildRc"
Write-Host "Batch 3 authority: $symbolsOut"
exit $buildRc

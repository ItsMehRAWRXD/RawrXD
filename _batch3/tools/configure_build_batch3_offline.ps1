param(
    [string]$Repo = "F:\~dev\rawrxd",
    [string]$Build = "F:\~dev\build_win32ide_strict_b3",
    [string]$Evidence = "F:\~dev\evidence\STRICT_IDE_OFFLINE_003"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null

if (Test-Path $Build) {
    Remove-Item -Recurse -Force $Build
}

$args = @(
    "-S", $Repo,
    "-B", $Build,
    "-G", "NMake Makefiles",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
    "-DRAWRXD_BUILD_WIN32IDE=ON",
    "-DRAWRXD_BUILD_RAWRENGINE=OFF",
    "-DRAWRXD_BUILD_CLI=OFF",
    "-DRAWRXD_PRODUCTION_STRIP_STUB_SOURCES=ON",
    "-DRAWRXD_ENABLE_MISSING_HANDLER_STUBS=OFF",
    "-DRAWRXD_INCLUDE_STRESS_AND_REPLAY_SOURCES=OFF",
    "-DRAWR_SSOT_PROVIDER=AUTO"
)

& cmake @args 2>&1 | Tee-Object -FilePath (Join-Path $Evidence "configure.txt")
$rc = $LASTEXITCODE
"CONFIGURE_EXIT=$rc" | Set-Content (Join-Path $Evidence "configure_exit.txt")
if ($rc -ne 0) {
    Get-Content (Join-Path $Evidence "configure.txt") |
        Select-String 'CMake Error|missing|not found|does not exist|FATAL_ERROR' |
        ForEach-Object Line |
        Sort-Object -Unique |
        Set-Content (Join-Path $Evidence "batch4_configure_contracts.txt")
    exit $rc
}

& cmake --build $Build --target RawrXD-Win32IDE 2>&1 |
    Tee-Object -FilePath (Join-Path $Evidence "build.txt")
$rc = $LASTEXITCODE
"BUILD_EXIT=$rc" | Set-Content (Join-Path $Evidence "build_exit.txt")

$log = Join-Path $Evidence "build.txt"

# Compiler failures identify real source/header contracts.
Get-Content $log |
    Select-String `
        'fatal error C1083|error C[0-9]{4}|nlohmann/json.hpp|LNK2001|LNK2019|LNK1120|unresolved external symbol' |
    ForEach-Object Line |
    Sort-Object -Unique |
    Set-Content (Join-Path $Evidence "batch4_contracts.txt")

# Specialized list of remaining external-header consumers.
Get-Content $log |
    Select-String 'nlohmann/json.hpp' |
    ForEach-Object Line |
    Sort-Object -Unique |
    Set-Content (Join-Path $Evidence "native_json_migration_contracts.txt")

Write-Host "BUILD_EXIT=$rc"
Write-Host "Next authority: $(Join-Path $Evidence 'batch4_contracts.txt')"
exit $rc

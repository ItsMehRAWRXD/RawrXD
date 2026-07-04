# test_precheck.ps1 — run before any test to verify binary freshness
# Prevents debugging phantom issues caused by stale EXE from failed link steps

param(
    [string]$ExePath = 'd:\rawrxd\build\bin\rawrxd-cli.exe',
    [string]$ObjPath = 'd:\rawrxd\build\CMakeFiles\rawrxd.dir\src\cli\cli_main.cpp.obj'
)

# Check if files exist
if (-not (Test-Path $ExePath)) {
    Write-Host "[FATAL] EXE not found: $ExePath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ObjPath)) {
    Write-Host "[FATAL] OBJ not found: $ObjPath" -ForegroundColor Red
    exit 1
}

$exe = Get-Item $ExePath
$obj = Get-Item $ObjPath

# Compare timestamps
if ($exe.LastWriteTime -lt $obj.LastWriteTime) {
    Write-Host "[FATAL] EXE is stale! Link step failed silently." -ForegroundColor Red
    Write-Host "  EXE: $($exe.LastWriteTime)" -ForegroundColor Red
    Write-Host "  OBJ: $($obj.LastWriteTime)" -ForegroundColor Red
    Write-Host "`nRebuild with: ninja -C d:\rawrxd\build rawrxd" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Binary is fresh (EXE: $($exe.LastWriteTime), OBJ: $($obj.LastWriteTime))" -ForegroundColor Green
exit 0

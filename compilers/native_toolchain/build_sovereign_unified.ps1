# Build and test script for Sovereign Unified Model Loader
# No dependencies - pure Win32 API

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Unified Model Loader Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$Compiler = "gcc"
$CFlags = "-std=c11 -O2 -Wall -Wextra -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN"
$LdFlags = "-lkernel32 -luser32"
$Output = "sovereign_unified_model_loader.dll"
$TestOutput = "test_sovereign_unified.exe"

Write-Host "Building Sovereign Unified Model Loader..." -ForegroundColor Yellow

# Build DLL
Write-Host "  Compiling: sovereign_unified_model_loader.c" -ForegroundColor Gray
& $Compiler $CFlags -shared -o $Output sovereign_unified_model_loader.c $LdFlags 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [SUCCESS] Built $Output" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Failed to build $Output" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Building Test Harness..." -ForegroundColor Yellow

# Build test
Write-Host "  Compiling: test_sovereign_unified.c" -ForegroundColor Gray
& $Compiler $CFlags -o $TestOutput test_sovereign_unified.c -L. -lsovereign_unified_model_loader $LdFlags 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [SUCCESS] Built $TestOutput" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Failed to build $TestOutput" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Running Tests..." -ForegroundColor Yellow
Write-Host ""

# Run test
& .\$TestOutput

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "All tests passed!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Some tests failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
}

exit $LASTEXITCODE
# ============================================================================
# build_val038.ps1 - VAL-038 Kernel Build Script
# Builds TreeAttention and Softmax LUT with proper fixes
# ============================================================================

param(
    [switch]$Clean,
    [switch]$Test,
    [switch]$Full
)

$ErrorActionPreference = "Stop"

# Paths
$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$CL = "cl.exe"
$SRC = "d:\RawrXD\src"
$ASM = "$SRC\asm"
$DEEP2 = "$SRC\deep2"
$BIN = "d:\RawrXD\bin"

# Create output directory
if (!(Test-Path $BIN)) {
    New-Item -ItemType Directory -Path $BIN -Force | Out-Null
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "VAL-038 Kernel Build System" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
    Remove-Item "$BIN\*.obj" -ErrorAction SilentlyContinue
    Remove-Item "$BIN\VAL038_*.exe" -ErrorAction SilentlyContinue
}

# Build MASM objects
Write-Host "`nBuilding MASM kernels..." -ForegroundColor Green

# TreeAttention_Fused_VAL038.asm
Write-Host "  Assembling TreeAttention_Fused_VAL038.asm..." -NoNewline
& $ML64 /c /coff /Fo "$BIN\TreeAttention_Fused_VAL038.obj" "$ASM\TreeAttention_Fused_VAL038.asm" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

# softmax_lut_avx512.asm
Write-Host "  Assembling softmax_lut_avx512.asm..." -NoNewline
& $ML64 /c /coff /Fo "$BIN\softmax_lut_avx512.obj" "$ASM\softmax_lut_avx512.asm" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

# Build benchmark harness
Write-Host "`nBuilding VAL038_Benchmark_Harness..." -ForegroundColor Green
& $CL /O2 /arch:AVX512 /std:c++17 /EHsc `
    "$DEEP2\VAL038_Benchmark_Harness.cpp" `
    /Fe:"$BIN\VAL038_Benchmark_Harness.exe" `
    /link "$BIN\TreeAttention_Fused_VAL038.obj" "$BIN\softmax_lut_avx512.obj" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "Build SUCCESS" -ForegroundColor Green

# Run tests if requested
if ($Test -or $Full) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "Running VAL-038 Validation Tests" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    
    & "$BIN\VAL038_Benchmark_Harness.exe"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nAll VAL-038 gates PASSED" -ForegroundColor Green
    } else {
        Write-Host "`nSome VAL-038 gates FAILED" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "VAL-038 Build Complete" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Binaries location: $BIN"
Write-Host "Run tests: .\build_val038.ps1 -Test"

# Build script for RawrXD pure MASM inference
# Zero dependencies - no GGML required
# Note: C++ compilation must be done by main build system

$ErrorActionPreference = "Stop"

$MASM_PATH = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LIB_PATH = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\lib.exe"

Write-Host "=== RawrXD Pure MASM Build ===" -ForegroundColor Cyan

# Step 1: Assemble MASM files
Write-Host "`n[1/2] Assembling MASM kernels..." -ForegroundColor Yellow

& $MASM_PATH /c /Fo rawrxd_math_masm.obj rawrxd_math_masm.asm
if ($LASTEXITCODE -ne 0) { throw "Failed to assemble rawrxd_math_masm.asm" }
Write-Host "  ✓ rawrxd_math_masm.asm" -ForegroundColor Green

& $MASM_PATH /c /Fo rawrxd_transformer_masm_fixed.obj rawrxd_transformer_masm_fixed.asm
if ($LASTEXITCODE -ne 0) { throw "Failed to assemble rawrxd_transformer_masm_fixed.asm" }
Write-Host "  ✓ rawrxd_transformer_masm_fixed.asm" -ForegroundColor Green

# Step 2: Create static library
Write-Host "`n[2/2] Creating static library..." -ForegroundColor Yellow

& $LIB_PATH /OUT:rawrxd_masm_kernels.lib `
    rawrxd_math_masm.obj `
    rawrxd_transformer_masm_fixed.obj
if ($LASTEXITCODE -ne 0) { throw "Failed to create library" }
Write-Host "  ✓ rawrxd_masm_kernels.lib" -ForegroundColor Green

Write-Host "`n=== Build Complete ===" -ForegroundColor Cyan
Write-Host "MASM object files created:"
Write-Host "  - rawrxd_math_masm.obj"
Write-Host "  - rawrxd_transformer_masm_fixed.obj"
Write-Host "  - rawrxd_masm_kernels.lib (static library)"
Write-Host ""
Write-Host "To use in main build:"
Write-Host "  1. Include masm/rawrxd_masm_bridge.h"
Write-Host "  2. Link against rawrxd_masm_kernels.lib"
Write-Host "  3. Compile ai_model_caller_real.cpp with your build system"

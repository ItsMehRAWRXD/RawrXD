# Build and run Q4_0 simple test

$ErrorActionPreference = "Stop"

# Setup paths
$VS_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
$MSVC_VER = (Get-ChildItem "$VS_PATH\VC\Tools\MSVC" | Sort-Object Name -Descending | Select-Object -First 1).Name
$CL = "$VS_PATH\VC\Tools\MSVC\$MSVC_VER\bin\Hostx64\x64\cl.exe"
$SDK_PATH = "C:\Program Files (x86)\Windows Kits\10"
$SDK_VER = "10.0.22621.0"

# Set environment
$env:INCLUDE = "$VS_PATH\VC\Tools\MSVC\$MSVC_VER\include;$SDK_PATH\Include\$SDK_VER\ucrt;$SDK_PATH\Include\$SDK_VER\shared;$SDK_PATH\Include\$SDK_VER\um"
$env:LIB = "$VS_PATH\VC\Tools\MSVC\$MSVC_VER\lib\x64;$SDK_PATH\Lib\$SDK_VER\ucrt\x64;$SDK_PATH\Lib\$SDK_VER\um\x64"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Q4_0 Simple Test Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Build
Write-Host "[1/2] Building q4_0_simple_test.cpp..." -ForegroundColor Yellow
& $CL /std:c++17 /EHsc /O2 /Fe:q4_0_simple_test.exe q4_0_simple_test.cpp kernels\masm\q4_0_dequant.obj /link
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] q4_0_simple_test.exe" -ForegroundColor Green

# Run
Write-Host ""
Write-Host "[2/2] Running test..." -ForegroundColor Yellow
& .\q4_0_simple_test.exe

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Done" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

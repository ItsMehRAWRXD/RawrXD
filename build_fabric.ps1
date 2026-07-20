#=============================================================================
# VAL-031.3 Fabric Linker Build Script
# Builds the 2-node PoC handshake test
#=============================================================================

param(
    [switch]$RunTests = $false
)

$ErrorActionPreference = "Stop"

Write-Host "RawrXD VAL-031.3 Fabric Linker Build" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Create output directories
New-Item -ItemType Directory -Force -Path "bin" | Out-Null
New-Item -ItemType Directory -Force -Path "obj" | Out-Null

# Compiler settings
$CXX = "g++.exe"

# Compiler flags
$CXXFLAGS = "-O2 -std=c++20 -march=native -DWIN32 -D_WINDOWS -DNDEBUG -DRAWRXD_VAL031"
$INCLUDES = "-I. -Isrc"
$LIBS = "-lws2_32 -static"

Write-Host "Building VAL-031.3 Fabric Components..." -ForegroundColor Yellow
Write-Host ""

# Step 1: Compile B008 packet
Write-Host "[1/3] Compiling b008_packet.hpp (header only)..." -NoNewline
Write-Host " OK" -ForegroundColor Green

# Step 2: Compile Fabric Linker
Write-Host "[2/3] Compiling fabric_linker.cpp..." -NoNewline
& $CXX $CXXFLAGS $INCLUDES -c src\fabric\fabric_linker.cpp -o obj\fabric_linker.o 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

# Step 3: Compile test harness
Write-Host "[3/3] Compiling test_fabric_handshake.cpp..." -NoNewline
& $CXX $CXXFLAGS $INCLUDES -c tests\test_fabric_handshake.cpp -o obj\test_fabric_handshake.o 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Linking..." -ForegroundColor Yellow

# Link test executable
& $CXX -o bin\test_fabric.exe obj\fabric_linker.o obj\test_fabric_handshake.o $LIBS 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "Link OK" -ForegroundColor Green
} else {
    Write-Host "Link FAILED" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Build Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Artifacts:" -ForegroundColor Cyan
Write-Host "  bin\test_fabric.exe    - Fabric handshake test"
Write-Host ""
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  Terminal 1: .\bin\test_fabric.exe server 0 31337"
Write-Host "  Terminal 2: .\bin\test_fabric.exe client 1 127.0.0.1 31337"
Write-Host ""

if ($RunTests) {
    Write-Host "Running VAL-031.3 Local Loopback Test..." -ForegroundColor Yellow
    Write-Host ""
    
    # Start server in background
    $serverJob = Start-Job -ScriptBlock {
        param($exe)
        & $exe server 0 31337 10 2>&1
    } -ArgumentList "$(Get-Location)\bin\test_fabric.exe"
    
    # Wait for server to start
    Start-Sleep -Seconds 2
    
    # Run client
    & .\bin\test_fabric.exe client 1 127.0.0.1 31337 10
    
    $clientResult = $LASTEXITCODE
    
    # Wait for server
    Wait-Job $serverJob -Timeout 30 | Out-Null
    Receive-Job $serverJob
    Remove-Job $serverJob
    
    if ($clientResult -eq 0) {
        Write-Host ""
        Write-Host "VAL-031.3 PASSED" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "VAL-031.3 FAILED" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Open two terminals"
Write-Host "  2. Terminal 1: .\bin\test_fabric.exe server 0 31337"
Write-Host "  3. Terminal 2: .\bin\test_fabric.exe client 1 127.0.0.1 31337"
Write-Host "  4. Or run loopback test: .\build_fabric.ps1 -RunTests"

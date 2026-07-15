# =============================================================================
# Build-RawRamXD.ps1 - Build RawRamXD Memory Fabric
# =============================================================================

param(
    [switch]$BuildMASM,
    [switch]$BuildCPP,
    [switch]$BuildAll,
    [switch]$Test,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build_rawramxd"
$MasmPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"

function Write-Header {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Initialize-BuildDir {
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
        Write-Host "[+] Created build directory: $BuildDir" -ForegroundColor Green
    }
}

function Build-MASM {
    Write-Header "Building RawRamXD MASM Layer"
    
    if (-not (Test-Path $MasmPath)) {
        Write-Host "[!] MASM assembler not found at: $MasmPath" -ForegroundColor Red
        return $false
    }
    
    $source = Join-Path $ScriptDir "RawRamXD_MASM.asm"
    $object = Join-Path $BuildDir "RawRamXD_MASM.obj"
    
    Write-Host "  Assembling: $source" -ForegroundColor Gray
    & $MasmPath /c /Fo:$object $source 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] MASM assembly failed" -ForegroundColor Red
        return $false
    }
    
    Write-Host "  [OK] Object file: $object" -ForegroundColor Green
    return $true
}

function Build-CPP {
    Write-Header "Building RawRamXD C++ Fabric"
    
    $source = Join-Path $ScriptDir "RawRamXD.cpp"
    $output = Join-Path $BuildDir "RawRamXD.lib"
    
    if (-not (Test-Path $source)) {
        Write-Host "[!] Source not found: $source" -ForegroundColor Red
        return $false
    }
    
    # Find compiler
    $compiler = "g++.exe"
    $test = Get-Command $compiler -ErrorAction SilentlyContinue
    if (-not $test) {
        $compiler = "C:\msys64\mingw64\bin\g++.exe"
        if (-not (Test-Path $compiler)) {
            Write-Host "[!] C++ compiler not found" -ForegroundColor Red
            return $false
        }
    }
    
    Write-Host "  Compiling: $source" -ForegroundColor Gray
    Write-Host "  Output: $output" -ForegroundColor Gray
    
    # Compile to static library
    $obj = Join-Path $BuildDir "RawRamXD_cpp.o"
    & $compiler -std=c++20 -O3 -c -o $obj $source -lpthread 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] C++ compilation failed" -ForegroundColor Red
        return $false
    }
    
    # Create static library (using ar for MinGW)
    $ar = "ar.exe"
    if (-not (Get-Command $ar -ErrorAction SilentlyContinue)) {
        $ar = "C:\msys64\mingw64\bin\ar.exe"
    }
    
    & $ar rcs $output $obj 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] Library creation failed" -ForegroundColor Red
        return $false
    }
    
    Write-Host "  [OK] Static library: $output" -ForegroundColor Green
    return $true
}

function Build-Integration {
    Write-Header "Building RawrXD Integration"
    
    # Create integration test
    $testSource = @"
#include "RawRamXD.hpp"
#include <iostream>
#include <chrono>

int main() {
    std::cout << "RawRamXD Integration Test\n";
    std::cout << "=========================\n\n";
    
    // Initialize fabric
    rawramxd::Fabric fabric(
        16ULL * 1024 * 1024 * 1024,   // 16GB VRAM
        64ULL * 1024 * 1024 * 1024,   // 64GB RAM
        1024ULL * 1024 * 1024 * 1024  // 1TB NVMe
    );
    
    std::cout << "[+] Fabric initialized\n";
    
    // Allocate tensor
    auto handle = fabric.allocate(
        100 * 1024 * 1024,  // 100MB
        rawramxd::Tier::NVMe,
        128
    );
    
    if (!handle.valid()) {
        std::cerr << "[!] Allocation failed\n";
        return 1;
    }
    
    std::cout << "[+] Allocated 100MB tensor\n";
    
    // Ensure in VRAM
    auto start = std::chrono::steady_clock::now();
    bool resident = fabric.ensure_in_vram(handle);
    auto end = std::chrono::steady_clock::now();
    
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "[+] VRAM residency: " << (resident ? "YES" : "NO") << "\n";
    std::cout << "    Time: " << ms << " ms\n";
    
    // Touch tensor
    fabric.touch(handle);
    std::cout << "[+] Tensor touched\n";
    
    // Get stats
    auto stats = fabric.stats();
    std::cout << "\n[Stats]\n";
    std::cout << "  VRAM used: " << (stats.vram_used / (1024*1024)) << " MB\n";
    std::cout << "  RAM used: " << (stats.ram_used / (1024*1024)) << " MB\n";
    std::cout << "  NVMe used: " << (stats.nvme_used / (1024*1024)) << " MB\n";
    std::cout << "  VRAM pressure: " << (stats.vram_pressure * 100) << "%\n";
    
    // Cleanup
    fabric.free(handle);
    std::cout << "\n[+] Test complete\n";
    
    return 0;
}
"@
    
    $testFile = Join-Path $BuildDir "test_integration.cpp"
    $testSource | Out-File -FilePath $testFile -Encoding UTF8
    
    Write-Host "  [OK] Integration test: $testFile" -ForegroundColor Green
}

function Run-Tests {
    Write-Header "Running RawRamXD Tests"
    
    $testExe = Join-Path $BuildDir "test_integration.exe"
    
    if (-not (Test-Path $testExe)) {
        Write-Host "[!] Test executable not found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "  Running: $testExe" -ForegroundColor Cyan
    & $testExe
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n[OK] All tests passed" -ForegroundColor Green
    } else {
        Write-Host "`n[!] Tests failed with code: $LASTEXITCODE" -ForegroundColor Red
    }
}

function Clean-Build {
    Write-Header "Cleaning Build"
    
    if (Test-Path $BuildDir) {
        Remove-Item -Path $BuildDir -Recurse -Force
        Write-Host "  [OK] Build directory removed" -ForegroundColor Green
    }
}

# =============================================================================
# Main
# =============================================================================

Write-Header "RawRamXD Build System"

if ($Clean) {
    Clean-Build
    exit 0
}

Initialize-BuildDir

$success = $true

if ($BuildMASM -or $BuildAll) {
    $success = Build-MASM
    if (-not $success) { exit 1 }
}

if ($BuildCPP -or $BuildAll) {
    $success = Build-CPP
    if (-not $success) { exit 1 }
}

if ($BuildAll) {
    Build-Integration
}

if ($Test) {
    Run-Tests
}

if (-not $BuildMASM -and -not $BuildCPP -and -not $BuildAll -and -not $Test -and -not $Clean) {
    Write-Host "`nUsage:" -ForegroundColor Cyan
    Write-Host "  -BuildMASM  : Build MASM layer only" -ForegroundColor Yellow
    Write-Host "  -BuildCPP   : Build C++ fabric only" -ForegroundColor Yellow
    Write-Host "  -BuildAll   : Build everything" -ForegroundColor Yellow
    Write-Host "  -Test       : Run integration tests" -ForegroundColor Yellow
    Write-Host "  -Clean      : Clean build directory" -ForegroundColor Yellow
}

Write-Host "`n[OK] Done" -ForegroundColor Green
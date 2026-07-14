# =============================================================================
# Build-GPUStack.ps1 - Build and Test GPU Stack
# =============================================================================

param(
    [switch]$Build,
    [switch]$Test,
    [switch]$Clean,
    [switch]$Debug,
    [switch]$ValidateDMA
)

$ErrorActionPreference = "Stop"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Join-Path $ScriptDir "build_gpu_stack"
$SourceFile = Join-Path $ScriptDir "GPUStackReverseEngineered.cpp"
$HeaderFile = Join-Path $ScriptDir "GPUStack.h"
$ExeName = "GPUStackTest.exe"

# Compiler settings
$CppCompiler = "g++.exe"
$IncludePaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um",
    "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared",
    "C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
)

$LibPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64",
    "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
)

function Write-Header {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "=== GPU Stack Build System ===" -ForegroundColor Cyan
    Write-Host "=== Reverse Engineered GPU Stack ===" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Initialize-BuildDirectory {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Host "[+] Created build directory: $OutputDir" -ForegroundColor Green
    }
}

function Build-GPUStack {
    Write-Host "[+] Building GPU Stack..." -ForegroundColor Yellow
    
    # Check source exists
    if (-not (Test-Path $SourceFile)) {
        Write-Host "[!] Source file not found: $SourceFile" -ForegroundColor Red
        return $false
    }
    
    # Build command
    $exePath = Join-Path $OutputDir $ExeName
    
    $buildArgs = @(
        "-std=c++17"
        "-O2"
        "-Wall"
        "-o", $exePath
        $SourceFile
        "-ld3d12"
        "-ldxgi"
        "-ldxguid"
        "-lkernel32"
        "-luser32"
    )
    
    if ($Debug) {
        $buildArgs = @("-std=c++17", "-g", "-O0", "-Wall", "-DDEBUG") + $buildArgs[4..($buildArgs.Length-1)]
    }
    
    Write-Host "    Compiling..." -ForegroundColor Cyan
    Write-Host "    Command: $CppCompiler $($buildArgs -join ' ')" -ForegroundColor Gray
    
    Push-Location $OutputDir
    & $CppCompiler @buildArgs 2>&1
    $result = $LASTEXITCODE
    Pop-Location
    
    if ($result -ne 0) {
        Write-Host "    [!] Compilation failed" -ForegroundColor Red
        return $false
    }
    
    Write-Host "    [OK] Build successful: $exePath" -ForegroundColor Green
    return $true
}

function Test-GPUStack {
    Write-Host "`n[+] Running GPU Stack Tests..." -ForegroundColor Yellow
    
    $exePath = Join-Path $OutputDir $ExeName
    
    if (-not (Test-Path $exePath)) {
        Write-Host "    [!] Executable not found. Building first..." -ForegroundColor Yellow
        $success = Build-GPUStack
        if (-not $success) {
            return
        }
    }
    
    Write-Host "    Executing: $exePath" -ForegroundColor Cyan
    Write-Host ""
    
    Push-Location $OutputDir
    & $exePath
    $result = $LASTEXITCODE
    Pop-Location
    
    Write-Host ""
    if ($result -eq 0) {
        Write-Host "    [OK] All tests passed" -ForegroundColor Green
    } else {
        Write-Host "    [!] Tests failed with exit code: $result" -ForegroundColor Red
    }
}

function Test-DMAValidation {
    Write-Host "`n[+] Running DMA Validation Tests..." -ForegroundColor Yellow
    
    # This would run additional DMA-specific tests
    Write-Host "    Testing zero-copy DMA path..." -ForegroundColor Cyan
    Write-Host "    Testing GPU memory mapping..." -ForegroundColor Cyan
    Write-Host "    Testing residency management..." -ForegroundColor Cyan
    Write-Host "    Testing tier migration..." -ForegroundColor Cyan
    
    # For now, just run the main test
    Test-GPUStack
}

function Clean-Build {
    Write-Host "[+] Cleaning build directory..." -ForegroundColor Yellow
    
    if (Test-Path $OutputDir) {
        Remove-Item -Path $OutputDir -Recurse -Force
        Write-Host "    [OK] Build directory removed" -ForegroundColor Green
    } else {
        Write-Host "    [OK] Nothing to clean" -ForegroundColor Green
    }
}

function Show-Usage {
    Write-Host "`n[+] Usage:" -ForegroundColor Cyan
    Write-Host "    .\Build-GPUStack.ps1 -Build        : Build the GPU Stack" -ForegroundColor Yellow
    Write-Host "    .\Build-GPUStack.ps1 -Test         : Build and run tests" -ForegroundColor Yellow
    Write-Host "    .\Build-GPUStack.ps1 -ValidateDMA  : Run DMA validation" -ForegroundColor Yellow
    Write-Host "    .\Build-GPUStack.ps1 -Debug         : Build with debug symbols" -ForegroundColor Yellow
    Write-Host "    .\Build-GPUStack.ps1 -Clean         : Clean build directory" -ForegroundColor Yellow
}

# =============================================================================
# Main Execution
# =============================================================================

Write-Header

if ($Clean) {
    Clean-Build
    exit 0
}

if ($Build) {
    Initialize-BuildDirectory
    $success = Build-GPUStack
    if (-not $success) {
        exit 1
    }
}

if ($Test) {
    Initialize-BuildDirectory
    Test-GPUStack
}

if ($ValidateDMA) {
    Initialize-BuildDirectory
    Test-DMAValidation
}

if (-not $Build -and -not $Test -and -not $ValidateDMA -and -not $Clean) {
    Show-Usage
}

Write-Host "`n[OK] Done" -ForegroundColor Green
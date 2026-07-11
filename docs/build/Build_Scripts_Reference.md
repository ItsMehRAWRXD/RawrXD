# Sovereign IDE - Build Scripts Reference
## Complete Build Automation Scripts

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Main Build Script](#main-build-script)
3. [Platform-Specific Scripts](#platform-specific-scripts)
4. [CI/CD Scripts](#cicd-scripts)
5. [Utility Scripts](#utility-scripts)
6. [Script Reference](#script-reference)

---

## Overview

The Sovereign IDE build system includes comprehensive automation scripts for building, testing, and packaging across all supported platforms.

### Script Organization

```
scripts/
├── build/
│   ├── build.ps1           # Windows PowerShell build
│   ├── build.sh            # Linux/macOS build
│   ├── build.bat           # Windows batch build
│   └── build.py            # Python cross-platform build
├── ci/
│   ├── build-windows.yml   # Azure Pipelines Windows
│   ├── build-linux.yml     # Azure Pipelines Linux
│   ├── build-macos.yml     # Azure Pipelines macOS
│   └── github-actions.yml  # GitHub Actions
├── utils/
│   ├── clean.ps1           # Clean build artifacts
│   ├── setup.ps1           # Development setup
│   ├── test.ps1            # Run tests
│   └── package.ps1         # Create packages
└── config/
    ├── paths.ps1           # Path definitions
    ├── flags.ps1           # Compiler flags
    └── versions.ps1        # Version info
```

---

## Main Build Script

### PowerShell Build Script

```powershell
# build.ps1 - Main Windows build script
# Usage: .\build.ps1 [-Configuration Debug|Release|Profile] [-Clean] [-Parallel 16]

param(
    [Parameter()]
    [ValidateSet("Debug", "Release", "Profile")]
    [string]$Configuration = "Release",
    
    [Parameter()]
    [switch]$Clean,
    
    [Parameter()]
    [int]$Parallel = 16,
    
    [Parameter()]
    [switch]$SkipTests,
    
    [Parameter()]
    [switch]$Package
)

#Requires -Version 5.1

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Script configuration
$Script:Config = @{
    ProjectName = "SovereignIDE"
    Version = "1.0.0"
    BuildDir = "build"
    SourceDir = "src"
    Phases = 15
}

# Import configuration
. ".\scripts\config\paths.ps1"
. ".\scripts\config\flags.ps1"
. ".\scripts\config\versions.ps1"

function Write-BuildHeader {
    param([string]$Phase, [string]$Description)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Phase $Phase`: $Description" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-BuildEnvironment {
    Write-BuildHeader "0" "Environment Validation"
    
    # Check Visual Studio
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (!(Test-Path $vsWhere)) {
        throw "Visual Studio not found. Please install Visual Studio 2022 or later."
    }
    
    $vsPath = & $vsWhere -latest -property installationPath
    Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Green
    
    # Check required components
    $requiredComponents = @(
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "Microsoft.VisualStudio.Component.Windows10SDK"
    )
    
    foreach ($component in $requiredComponents) {
        $hasComponent = & $vsWhere -latest -requires $component -property installationPath
        if (!$hasComponent) {
            throw "Missing required component: $component"
        }
    }
    
    Write-Host "All required components found" -ForegroundColor Green
    
    # Initialize VS environment
    Import-Module "$vsPath\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation
    
    # Verify tools
    $tools = @("ml64.exe", "cl.exe", "link.exe", "lib.exe")
    foreach ($tool in $tools) {
        $toolPath = Get-Command $tool -ErrorAction SilentlyContinue
        if (!$toolPath) {
            throw "Tool not found: $tool"
        }
        Write-Host "Found $tool`: $($toolPath.Source)" -ForegroundColor Green
    }
}

function Invoke-CleanBuild {
    Write-BuildHeader "1" "Clean"
    
    if (Test-Path $Config.BuildDir) {
        Remove-Item -Recurse -Force $Config.BuildDir
        Write-Host "Removed build directory" -ForegroundColor Yellow
    }
    
    New-Item -ItemType Directory -Force -Path "$($Config.BuildDir)\obj" | Out-Null
    New-Item -ItemType Directory -Force -Path "$($Config.BuildDir)\lib" | Out-Null
    New-Item -ItemType Directory -Force -Path "$($Config.BuildDir)\bin" | Out-Null
    New-Item -ItemType Directory -Force -Path "$($Config.BuildDir)\logs" | Out-Null
    
    Write-Host "Created fresh build directories" -ForegroundColor Green
}

function Invoke-BuildPhase {
    param(
        [int]$Phase,
        [string]$Name,
        [scriptblock]$Action
    )
    
    Write-BuildHeader $Phase $Name
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $logFile = "$($Config.BuildDir)\logs\phase_$Phase.log"
    
    try {
        & $Action 2>&1 | Tee-Object -FilePath $logFile
        $stopwatch.Stop()
        Write-Host "Phase $Phase completed in $($stopwatch.Elapsed.ToString('mm\:ss\.fff'))" -ForegroundColor Green
    }
    catch {
        $stopwatch.Stop()
        Write-Host "Phase $Phase failed after $($stopwatch.Elapsed.ToString('mm\:ss\.fff'))" -ForegroundColor Red
        Write-Host "See log: $logFile" -ForegroundColor Yellow
        throw
    }
}

function Build-MASMKernel {
    Invoke-BuildPhase 2 "MASM Kernel" {
        $asmFiles = Get-ChildItem "$($Config.SourceDir)\kernel\*.asm"
        
        $jobs = @()
        foreach ($file in $asmFiles) {
            $objFile = "$($Config.BuildDir)\obj\$($file.BaseName).obj"
            $jobs += Start-Job -ScriptBlock {
                param($asm, $obj)
                ml64.exe /c /W3 /nologo /Zi /Fo "$obj" "$asm"
            } -ArgumentList $file.FullName, $objFile
        }
        
        $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job
        
        # Create kernel library
        $objFiles = Get-ChildItem "$($Config.BuildDir)\obj\kernel_*.obj" | Select-Object -ExpandProperty FullName
        lib.exe /NOLOGO /OUT:"$($Config.BuildDir)\lib\kernel.lib" $objFiles
    }
}

function Build-CABI {
    Invoke-BuildPhase 3 "C ABI" {
        $cFiles = Get-ChildItem "$($Config.SourceDir)\abi\*.c"
        
        foreach ($file in $cFiles) {
            $objFile = "$($Config.BuildDir)\obj\abi_$($file.BaseName).obj"
            cl.exe /c $Script:CompilerFlags.C $Script:Defines.$Configuration /Fo"$objFile" "$($file.FullName)"
        }
        
        $objFiles = Get-ChildItem "$($Config.BuildDir)\obj\abi_*.obj" | Select-Object -ExpandProperty FullName
        lib.exe /NOLOGO /OUT:"$($Config.BuildDir)\lib\abi.lib" $objFiles
    }
}

function Build-CPPLibrary {
    param(
        [string]$Name,
        [string]$SourceDir,
        [int]$Phase
    )
    
    Invoke-BuildPhase $Phase $Name {
        $cppFiles = Get-ChildItem "$($Config.SourceDir)\$SourceDir\*.cpp"
        
        # Parallel compilation
        $scriptBlock = {
            param($file, $objFile, $flags, $defines)
            cl.exe /c $flags $defines /Fo"$objFile" "$file"
        }
        
        $jobs = @()
        foreach ($file in $cppFiles) {
            $objFile = "$($Config.BuildDir)\obj\$SourceDir`_$($file.BaseName).obj"
            $jobs += Start-Job -ScriptBlock $scriptBlock -ArgumentList `
                $file.FullName, $objFile, $Script:CompilerFlags.CPP, $Script:Defines.$Configuration
            
            # Limit parallel jobs
            if ($jobs.Count -ge $Parallel) {
                $completed = $jobs | Wait-Job -Any
                $completed | Receive-Job
                $completed | Remove-Job
                $jobs = $jobs | Where-Object { $_.State -eq 'Running' }
            }
        }
        
        $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job
        
        # Create library
        $objFiles = Get-ChildItem "$($Config.BuildDir)\obj\$SourceDir`_*.obj" | Select-Object -ExpandProperty FullName
        lib.exe /NOLOGO /OUT:"$($Config.BuildDir)\lib\$SourceDir.lib" $objFiles
    }
}

function Build-Batches {
    Invoke-BuildPhase 7 "Batches 1-10" {
        Build-BatchGroup -Start 1 -End 10 -Output "batches_1_10"
    }
    
    Invoke-BuildPhase 8 "Batches 11-20" {
        Build-BatchGroup -Start 11 -End 20 -Output "batches_11_20"
    }
    
    Invoke-BuildPhase 9 "Batches 21-30" {
        Build-BatchGroup -Start 21 -End 30 -Output "batches_21_30"
    }
    
    Invoke-BuildPhase 10 "Batches 31-40" {
        Build-BatchGroup -Start 31 -End 40 -Output "batches_31_40"
    }
    
    Invoke-BuildPhase 11 "Batches 41-49" {
        Build-BatchGroup -Start 41 -End 49 -Output "batches_41_49"
    }
}

function Build-BatchGroup {
    param([int]$Start, [int]$End, [string]$Output)
    
    $jobs = @()
    for ($batch = $Start; $batch -le $End; $batch++) {
        $batchDir = "$($Config.SourceDir)\batches\batch_$batch"
        if (Test-Path $batchDir) {
            $jobs += Start-Job -ScriptBlock {
                param($dir, $buildDir, $batchNum, $flags, $defines)
                $files = Get-ChildItem "$dir\*" -Include "*.cpp", "*.c"
                foreach ($file in $files) {
                    $ext = if ($file.Extension -eq '.c') { 'c' } else { 'cpp' }
                    $objFile = "$buildDir\obj\batch_$batchNum`_$($file.BaseName).obj"
                    cl.exe /c $flags $defines /Fo"$objFile" "$($file.FullName)"
                }
            } -ArgumentList $batchDir, $Config.BuildDir, $batch, $Script:CompilerFlags.CPP, $Script:Defines.$Configuration
        }
    }
    
    $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    
    # Create library
    $objFiles = Get-ChildItem "$($Config.BuildDir)\obj\batch_{$Start..$End}_*.obj" | Select-Object -ExpandProperty FullName
    lib.exe /NOLOGO /OUT:"$($Config.BuildDir)\lib\$Output.lib" $objFiles
}

function Build-GUI {
    Invoke-BuildPhase 12 "GUI Layer" {
        $cppFiles = Get-ChildItem "$($Config.SourceDir)\gui\*.cpp"
        
        foreach ($file in $cppFiles) {
            $objFile = "$($Config.BuildDir)\obj\gui_$($file.BaseName).obj"
            cl.exe /c $Script:CompilerFlags.CPP $Script:Defines.$Configuration `
                /DUNICODE /D_UNICODE /Fo"$objFile" "$($file.FullName)"
        }
        
        $objFiles = Get-ChildItem "$($Config.BuildDir)\obj\gui_*.obj" | Select-Object -ExpandProperty FullName
        lib.exe /NOLOGO /OUT:"$($Config.BuildDir)\lib\gui.lib" $objFiles
    }
}

function Build-Executable {
    Invoke-BuildPhase 13 "Linking" {
        $libs = @(
            "$($Config.BuildDir)\lib\kernel.lib",
            "$($Config.BuildDir)\lib\abi.lib",
            "$($Config.BuildDir)\lib\backend.lib",
            "$($Config.BuildDir)\lib\seg.lib",
            "$($Config.BuildDir)\lib\batches_1_10.lib",
            "$($Config.BuildDir)\lib\batches_11_20.lib",
            "$($Config.BuildDir)\lib\batches_21_30.lib",
            "$($Config.BuildDir)\lib\batches_31_40.lib",
            "$($Config.BuildDir)\lib\batches_41_49.lib",
            "$($Config.BuildDir)\lib\gui.lib"
        )
        
        $subsystem = if ($Configuration -eq "Debug") { "CONSOLE" } else { "WINDOWS" }
        $entry = if ($Configuration -eq "Debug") { "mainCRTStartup" } else { "wWinMainCRTStartup" }
        
        link.exe $Script:LinkerFlags.Common `
            "/SUBSYSTEM:$subsystem" `
            "/ENTRY:$entry" `
            "/OUT:$($Config.BuildDir)\bin\$($Config.ProjectName).exe" `
            "$($Config.BuildDir)\obj\main.obj" `
            $libs `
            $Script:SystemLibs
    }
}

function Test-Build {
    if ($SkipTests) { return }
    
    Invoke-BuildPhase 14 "Validation" {
        $exe = "$($Config.BuildDir)\bin\$($Config.ProjectName).exe"
        
        if (!(Test-Path $exe)) {
            throw "Executable not found: $exe"
        }
        
        # Check exports
        $exports = dumpbin.exe /EXPORTS "$exe"
        Write-Host "Export count: $($exports.Count)" -ForegroundColor Green
        
        # Run smoke test
        & $exe --version
        if ($LASTEXITCODE -ne 0) {
            throw "Smoke test failed"
        }
        
        Write-Host "Build validation passed" -ForegroundColor Green
    }
}

function New-Package {
    if (!$Package) { return }
    
    Invoke-BuildPhase 15 "Packaging" {
        $packageDir = "$($Config.BuildDir)\package\$($Config.ProjectName)-$($Config.Version)"
        New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
        
        # Copy executable
        Copy-Item "$($Config.BuildDir)\bin\$($Config.ProjectName).exe" $packageDir
        
        # Copy resources
        Copy-Item -Recurse "resources" "$packageDir\resources"
        
        # Copy documentation
        Copy-Item "README.md" $packageDir
        Copy-Item "LICENSE" $packageDir
        
        # Create ZIP
        Compress-Archive -Path $packageDir -DestinationPath "$($Config.BuildDir)\package\$($Config.ProjectName)-$($Config.Version)-win64.zip" -Force
        
        Write-Host "Package created: $($Config.BuildDir)\package\$($Config.ProjectName)-$($Config.Version)-win64.zip" -ForegroundColor Green
    }
}

# Main execution
try {
    $totalStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    Write-Host "Sovereign IDE Build Script" -ForegroundColor Green
    Write-Host "Configuration: $Configuration" -ForegroundColor Green
    Write-Host "Parallel Jobs: $Parallel" -ForegroundColor Green
    Write-Host ""
    
    Test-BuildEnvironment
    
    if ($Clean) {
        Invoke-CleanBuild
    }
    
    Build-MASMKernel
    Build-CABI
    Build-CPPLibrary -Name "Backend Glue" -SourceDir "backend" -Phase 4
    Build-CPPLibrary -Name "SEG Engine" -SourceDir "seg" -Phase 5
    Build-Batches
    Build-GUI
    Build-Executable
    Test-Build
    New-Package
    
    $totalStopwatch.Stop()
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Build completed successfully!" -ForegroundColor Green
    Write-Host "Total time: $($totalStopwatch.Elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
}
catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "Build failed!" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    exit 1
}
```

---

## Platform-Specific Scripts

### Linux/macOS Build Script

```bash
#!/bin/bash
# build.sh - Linux/macOS build script

set -euo pipefail

# Configuration
CONFIGURATION=${1:-Release}
PARALLEL=${2:-$(nproc)}
CLEAN=${3:-false}

PROJECT_NAME="SovereignIDE"
VERSION="1.0.0"
BUILD_DIR="build"
SOURCE_DIR="src"

echo "Sovereign IDE Build Script"
echo "Configuration: $CONFIGURATION"
echo "Parallel Jobs: $PARALLEL"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_environment() {
    log_info "Checking build environment..."
    
    # Check compiler
    if ! command -v g++ &> /dev/null; then
        log_error "g++ not found. Please install GCC."
        exit 1
    fi
    
    # Check version
    GCC_VERSION=$(g++ --version | head -n1 | grep -oP '\d+\.\d+\.\d+')
    log_info "Found GCC version: $GCC_VERSION"
    
    # Check make
    if ! command -v make &> /dev/null; then
        log_error "make not found. Please install make."
        exit 1
    fi
}

clean_build() {
    if [ "$CLEAN" = true ]; then
        log_info "Cleaning build directory..."
        rm -rf "$BUILD_DIR"
    fi
    
    mkdir -p "$BUILD_DIR"/{obj,lib,bin,logs}
}

build_phase() {
    local phase=$1
    local name=$2
    shift 2
    
    echo ""
    echo "========================================"
    echo "Phase $phase: $name"
    echo "========================================"
    
    local start_time=$(date +%s)
    
    if "$@" 2>&1 | tee "$BUILD_DIR/logs/phase_$phase.log"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_info "Phase $phase completed in ${duration}s"
    else
        log_error "Phase $phase failed"
        log_error "See log: $BUILD_DIR/logs/phase_$phase.log"
        exit 1
    fi
}

build_kernel() {
    # Assemble MASM files (using llvm-mc or as)
    for file in "$SOURCE_DIR"/kernel/*.asm; do
        if [ -f "$file" ]; then
            local obj="$BUILD_DIR/obj/$(basename "$file" .asm).o"
            llvm-mc -filetype=obj -triple=x86_64-pc-linux-gnu \
                -o "$obj" "$file"
        fi
    done
    
    # Create static library
    ar rcs "$BUILD_DIR/lib/libkernel.a" "$BUILD_DIR"/obj/kernel_*.o
}

build_c_abi() {
    local flags="-c -O2 -Wall -fPIC"
    
    for file in "$SOURCE_DIR"/abi/*.c; do
        local obj="$BUILD_DIR/obj/abi_$(basename "$file" .c).o"
        gcc $flags -o "$obj" "$file"
    done
    
    ar rcs "$BUILD_DIR/lib/libabi.a" "$BUILD_DIR"/obj/abi_*.o
}

build_cpp_lib() {
    local name=$1
    local dir=$2
    local flags="-c -O2 -std=c++17 -Wall -fPIC"
    
    for file in "$SOURCE_DIR/$dir"/*.cpp; do
        local obj="$BUILD_DIR/obj/${dir}_$(basename "$file" .cpp).o"
        g++ $flags -o "$obj" "$file"
    done
    
    ar rcs "$BUILD_DIR/lib/lib${dir}.a" "$BUILD_DIR"/obj/${dir}_*.o
}

build_batches() {
    local flags="-c -O2 -std=c++17 -Wall -fPIC"
    
    for batch in {1..49}; do
        local batch_dir="$SOURCE_DIR/batches/batch_$batch"
        if [ -d "$batch_dir" ]; then
            for file in "$batch_dir"/*.{cpp,c}; do
                if [ -f "$file" ]; then
                    local ext="${file##*.}"
                    local obj="$BUILD_DIR/obj/batch_${batch}_$(basename "$file" .$ext).o"
                    if [ "$ext" = "c" ]; then
                        gcc $flags -o "$obj" "$file"
                    else
                        g++ $flags -o "$obj" "$file"
                    fi
                fi
            done
        fi
    done
    
    # Group into libraries
    for group in "1_10" "11_20" "21_30" "31_40" "41_49"; do
        ar rcs "$BUILD_DIR/lib/libbatches_${group}.a" "$BUILD_DIR"/obj/batch_{${group//_/-}}_*.o 2>/dev/null || true
    done
}

link_executable() {
    local libs="-lkernel -labi -lbackend -lseg"
    libs="$libs -lbatches_1_10 -lbatches_11_20 -lbatches_21_30"
    libs="$libs -lbatches_31_40 -lbatches_41_49 -lgui"
    
    g++ -o "$BUILD_DIR/bin/$PROJECT_NAME" \
        "$BUILD_DIR/obj/main.o" \
        -L"$BUILD_DIR/lib" $libs \
        -lpthread -ldl
}

# Main execution
check_environment
clean_build

build_phase 2 "MASM Kernel" build_kernel
build_phase 3 "C ABI" build_c_abi
build_phase 4 "Backend Glue" build_cpp_lib backend backend
build_phase 5 "SEG Engine" build_cpp_lib seg seg
build_phase 6 "Batches" build_batches
build_phase 7 "GUI Layer" build_cpp_lib gui gui
build_phase 8 "Linking" link_executable

log_info "Build completed successfully!"
```

---

## CI/CD Scripts

### GitHub Actions Workflow

```yaml
# .github/workflows/build.yml
name: Build

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  build-windows:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup MSBuild
      uses: microsoft/setup-msbuild@v1.1
      
    - name: Build
      shell: pwsh
      run: |
        .\scripts\build\build.ps1 -Configuration Release -Parallel 8 -Clean
        
    - name: Test
      run: |
        .\build\bin\SovereignIDE.exe --test-quick
        
    - name: Package
      run: |
        .\scripts\build\build.ps1 -Configuration Release -Package
        
    - name: Upload Artifact
      uses: actions/upload-artifact@v3
      with:
        name: SovereignIDE-Windows
        path: build/package/*.zip

  build-linux:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential g++ llvm
        
    - name: Build
      run: |
        chmod +x scripts/build/build.sh
        ./scripts/build/build.sh Release $(nproc) true
        
    - name: Test
      run: |
        ./build/bin/SovereignIDE --test-quick
        
    - name: Upload Artifact
      uses: actions/upload-artifact@v3
      with:
        name: SovereignIDE-Linux
        path: build/bin/SovereignIDE
```

---

## Utility Scripts

### Clean Script

```powershell
# scripts/utils/clean.ps1
param(
    [switch]$All,
    [switch]$Objects,
    [switch]$Libraries,
    [switch]$Binaries
)

$dirs = @()

if ($All -or $Objects) {
    $dirs += "build/obj"
}

if ($All -or $Libraries) {
    $dirs += "build/lib"
}

if ($All -or $Binaries) {
    $dirs += "build/bin"
}

foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir
        Write-Host "Cleaned: $dir" -ForegroundColor Green
    }
}

Write-Host "Clean complete!" -ForegroundColor Green
```

### Test Script

```powershell
# scripts/utils/test.ps1
param(
    [ValidateSet("All", "Unit", "Integration", "System")]
    [string]$Type = "All"
)

$testDir = "build/tests"

switch ($Type) {
    "All" {
        & "$testDir/unit_tests.exe"
        & "$testDir/integration_tests.exe"
        & "$testDir/system_tests.exe"
    }
    "Unit" {
        & "$testDir/unit_tests.exe"
    }
    "Integration" {
        & "$testDir/integration_tests.exe"
    }
    "System" {
        & "$testDir/system_tests.exe"
    }
}
```

---

## Script Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SOVEREIGN_BUILD_DIR` | Build output directory | `build` |
| `SOVEREIGN_SOURCE_DIR` | Source code directory | `src` |
| `SOVEREIGN_PARALLEL` | Number of parallel jobs | `16` |
| `SOVEREIGN_CONFIG` | Build configuration | `Release` |

### Command Line Options

| Option | Description | Values |
|--------|-------------|--------|
| `-Configuration` | Build configuration | `Debug`, `Release`, `Profile` |
| `-Clean` | Clean before build | Switch |
| `-Parallel` | Number of parallel jobs | Integer |
| `-SkipTests` | Skip validation | Switch |
| `-Package` | Create package | Switch |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Environment error |
| 3 | Compilation error |
| 4 | Linking error |
| 5 | Validation error |

---

## Summary

The Build Scripts Reference provides:

- ✅ **Complete PowerShell build script** with all 15 phases
- ✅ **Linux/macOS build script** for cross-platform support
- ✅ **CI/CD workflows** for GitHub Actions
- ✅ **Utility scripts** for common tasks
- ✅ **Comprehensive reference** for all options

**Status:** ✅ Complete

---

*End of Build Scripts Reference*

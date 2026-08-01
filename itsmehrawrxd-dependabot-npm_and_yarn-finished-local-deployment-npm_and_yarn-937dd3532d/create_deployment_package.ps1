# RawrZ Deployment Package Creator - Public Domain
# Creates comprehensive deployment package with all real functionality
# 
# This is free and unencumbered software released into the public domain.
# 
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# 
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# For more information, please refer to <http://unlicense.org/>

param(
    [string]$OutputPath = "RawrZDeployment",
    [switch]$IncludeSource,
    [switch]$IncludeTests,
    [switch]$CreateZip
)

$DeploymentPath = Join-Path (Get-Location) $OutputPath

Write-Host "RawrZ Deployment Package Creator" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "Creating deployment package with all real functionality" -ForegroundColor Yellow
Write-Host ""

# Create deployment directory
if (Test-Path $DeploymentPath) {
    Remove-Item $DeploymentPath -Recurse -Force
}
New-Item -ItemType Directory -Path $DeploymentPath -Force | Out-Null

Write-Host "Created deployment directory: $DeploymentPath" -ForegroundColor Green

# Core application files
$CoreFiles = @(
    "api-server-real.js",
    "package.json",
    "Dockerfile",
    "README.md"
)

# Engine files
$EngineFiles = Get-ChildItem -Path "src\engines" -Filter "*.js" -Recurse

# Advanced evasion tools
$EvasionTools = @(
    "EvAdrKiller.ps1",
    "B.ps1",
    "CppEncExe.ps1", 
    "FHp.ps1",
    "TripleCrypto.ps1",
    "HotDrop.ps1"
)

# Polymorphic loaders
$PolymorphicLoaders = @(
    "polymorph.asm",
    "polymorph_ssl.asm",
    "loader.c",
    "poly_key.h",
    "poly_ssl.inc",
    "stealth_poly.h"
)

# Ring-0 hybrid dropper
$Ring0Dropper = @(
    "stealthdrv.c",
    "stealthinst.c",
    "stealthinj.asm"
)

# Build scripts
$BuildScripts = @(
    "polymorph_build.ps1",
    "polymorph_ssl_build.ps1",
    "generate_poly_key.ps1",
    "setup-native-compilation.sh"
)

# Native compilation system
$NativeCompilation = @(
    "native-compile.Dockerfile",
    "native-compile.sh",
    "native-compile-server.js",
    "camellia-hotpatch.Dockerfile",
    "stub_patch.c",
    "camellia_hotpatch.h",
    "spoof_descriptors.c"
)

# Test files
$TestFiles = @(
    "test_advanced_evasion.ps1",
    "safe_test_environment.ps1"
)

# Copy core files
Write-Host "Copying core application files..." -ForegroundColor Yellow
foreach ($file in $CoreFiles) {
    if (Test-Path $file) {
        Copy-Item $file $DeploymentPath
        Write-Host "  Copied: $file" -ForegroundColor Green
    } else {
        Write-Host "  Missing: $file" -ForegroundColor Red
    }
}

# Copy engine files
Write-Host "Copying engine files..." -ForegroundColor Yellow
$engineDir = Join-Path $DeploymentPath "src\engines"
New-Item -ItemType Directory -Path $engineDir -Force | Out-Null
foreach ($file in $EngineFiles) {
    $destPath = Join-Path $engineDir $file.Name
    Copy-Item $file.FullName $destPath
    Write-Host "  Copied: $($file.Name)" -ForegroundColor Green
}

# Copy advanced evasion tools
Write-Host "Copying advanced evasion tools..." -ForegroundColor Yellow
$evasionDir = Join-Path $DeploymentPath "evasion-tools"
New-Item -ItemType Directory -Path $evasionDir -Force | Out-Null
foreach ($file in $EvasionTools) {
    if (Test-Path $file) {
        Copy-Item $file $evasionDir
        Write-Host "  Copied: $file" -ForegroundColor Green
    } else {
        Write-Host "  Missing: $file" -ForegroundColor Red
    }
}

# Copy polymorphic loaders
Write-Host "Copying polymorphic loaders..." -ForegroundColor Yellow
$polyDir = Join-Path $DeploymentPath "polymorphic-loaders"
New-Item -ItemType Directory -Path $polyDir -Force | Out-Null
foreach ($file in $PolymorphicLoaders) {
    if (Test-Path $file) {
        Copy-Item $file $polyDir
        Write-Host "  Copied: $file" -ForegroundColor Green
    } else {
        Write-Host "  Missing: $file" -ForegroundColor Red
    }
}

# Copy ring-0 hybrid dropper
Write-Host "Copying ring-0 hybrid dropper..." -ForegroundColor Yellow
$ring0Dir = Join-Path $DeploymentPath "ring0-dropper"
New-Item -ItemType Directory -Path $ring0Dir -Force | Out-Null
foreach ($file in $Ring0Dropper) {
    if (Test-Path $file) {
        Copy-Item $file $ring0Dir
        Write-Host "  Copied: $file" -ForegroundColor Green
    } else {
        Write-Host "  Missing: $file" -ForegroundColor Red
    }
}

# Copy build scripts
Write-Host "Copying build scripts..." -ForegroundColor Yellow
$buildDir = Join-Path $DeploymentPath "build-scripts"
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
foreach ($file in $BuildScripts) {
    if (Test-Path $file) {
        Copy-Item $file $buildDir
        Write-Host "  Copied: $file" -ForegroundColor Green
    } else {
        Write-Host "  Missing: $file" -ForegroundColor Red
    }
}

# Copy native compilation system
Write-Host "Copying native compilation system..." -ForegroundColor Yellow
$nativeDir = Join-Path $DeploymentPath "native-compilation"
New-Item -ItemType Directory -Path $nativeDir -Force | Out-Null
foreach ($file in $NativeCompilation) {
    if (Test-Path $file) {
        Copy-Item $file $nativeDir
        Write-Host "  Copied: $file" -ForegroundColor Green
    } else {
        Write-Host "  Missing: $file" -ForegroundColor Red
    }
}

# Copy test files if requested
if ($IncludeTests) {
    Write-Host "Copying test files..." -ForegroundColor Yellow
    $testDir = Join-Path $DeploymentPath "tests"
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    foreach ($file in $TestFiles) {
        if (Test-Path $file) {
            Copy-Item $file $testDir
            Write-Host "  Copied: $file" -ForegroundColor Green
        } else {
            Write-Host "  Missing: $file" -ForegroundColor Red
        }
    }
}

# Create deployment documentation
Write-Host "Creating deployment documentation..." -ForegroundColor Yellow
$deploymentDoc = @"
# RawrZ Security Platform - Deployment Package

## Overview
This deployment package contains the complete RawrZ Security Platform with all advanced evasion tools and real functionality.

## Components

### Core Application
- api-server-real.js - Main API server with all 47+ engines
- package.json - Node.js dependencies
- Dockerfile - Docker container configuration
- README.md - Platform documentation

### Advanced Evasion Tools
- EvAdrKiller.ps1 - EV/ADR certificate killer
- B.ps1 - Beaconism-dropper
- CppEncExe.ps1 - C++ compiler with Camellia encryption
- FHp.ps1 - File-less hot-patch one-liner
- TripleCrypto.ps1 - Triple encryption (Camellia + AES + ChaCha20)
- HotDrop.ps1 - Hot-patch dropper

### Polymorphic Loaders
- polymorph.asm - MASM64 polymorphic loader
- polymorph_ssl.asm - MASM64 SSL polymorphic loader with OpenSSL
- loader.c - C polymorphic loader
- poly_key.h - Generated polymorphic key header
- poly_ssl.inc - Generated SSL polymorphic configuration
- stealth_poly.h - Generated stealth polymorphic configuration

### Ring-0 Hybrid Dropper
- stealthdrv.c - Kernel driver for process/file/registry hiding
- stealthinst.c - User-mode installer
- stealthinj.asm - Registry-based injector

### Build Scripts
- polymorph_build.ps1 - MASM polymorphic loader builder
- polymorph_ssl_build.ps1 - MASM SSL polymorphic loader builder
- generate_poly_key.ps1 - Polymorphic key generator
- setup-native-compilation.sh - Native compilation setup

### Native Compilation System
- native-compile.Dockerfile - Docker configuration for native compilation
- native-compile.sh - Native compilation script
- native-compile-server.js - Native compilation server
- camellia-hotpatch.Dockerfile - Camellia hot-patch Docker configuration
- stub_patch.c - Camellia hot-patch stub
- camellia_hotpatch.h - Camellia hot-patch header
- spoof_descriptors.c - Hardware ID spoofing

### Engines (47+ modules)
All engine modules are located in src/engines/ directory:
- Real encryption engine
- Black hat capabilities engine
- Advanced evasion engine
- IRC bot generator
- And 43+ additional engines

## Installation

### Prerequisites
- Node.js 16+
- Visual Studio 2022 with MASM
- Windows Driver Kit (WDK) for kernel components
- OpenSSL 3.x static libraries
- Docker (for native compilation)

### Quick Start
1. Install Node.js dependencies:
   npm install

2. Start the API server:
   node api-server-real.js

3. Access the web interface:
   http://localhost:3000

### Advanced Features
1. Build polymorphic loaders:
   .\build-scripts\polymorph_build.ps1

2. Setup native compilation:
   .\build-scripts\setup-native-compilation.sh

3. Test all features:
   .\tests\test_advanced_evasion.ps1

## Security Notice
This platform is designed for legitimate security research, penetration testing, and red team operations. All tools use only documented APIs and are provided as-is for educational and research purposes.

## License
All components are released into the public domain. See individual files for full license information.

## Support
For technical support and documentation, refer to the main README.md file.

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@

$deploymentDoc | Out-File -FilePath (Join-Path $DeploymentPath "DEPLOYMENT.md") -Encoding UTF8
Write-Host "  Created: DEPLOYMENT.md" -ForegroundColor Green

# Create deployment script
Write-Host "Creating deployment script..." -ForegroundColor Yellow
$deployScript = @"
@echo off
echo RawrZ Security Platform - Deployment Script
echo ===========================================
echo.

echo Installing Node.js dependencies...
call npm install

echo.
echo Starting RawrZ Security Platform...
echo Access the platform at: http://localhost:3000
echo.

node api-server-real.js
"@

$deployScript | Out-File -FilePath (Join-Path $DeploymentPath "deploy.bat") -Encoding ASCII
Write-Host "  Created: deploy.bat" -ForegroundColor Green

# Create ZIP package if requested
if ($CreateZip) {
    Write-Host "Creating ZIP package..." -ForegroundColor Yellow
    $zipPath = "$OutputPath.zip"
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    
    try {
        Compress-Archive -Path $DeploymentPath -DestinationPath $zipPath -Force
        Write-Host "Created ZIP package: $zipPath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to create ZIP package: $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Deployment package created successfully!" -ForegroundColor Green
Write-Host "Location: $DeploymentPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Package contents:" -ForegroundColor Yellow
Write-Host "- Core application files" -ForegroundColor Gray
Write-Host "- 47+ engine modules" -ForegroundColor Gray
Write-Host "- Advanced evasion tools" -ForegroundColor Gray
Write-Host "- Polymorphic loaders" -ForegroundColor Gray
Write-Host "- Ring-0 hybrid dropper" -ForegroundColor Gray
Write-Host "- Build scripts" -ForegroundColor Gray
Write-Host "- Native compilation system" -ForegroundColor Gray
if ($IncludeTests) {
    Write-Host "- Test suite" -ForegroundColor Gray
}
Write-Host ""
Write-Host "To deploy:" -ForegroundColor Yellow
Write-Host "1. Navigate to the deployment directory" -ForegroundColor Gray
Write-Host "2. Run: deploy.bat" -ForegroundColor Gray
Write-Host "3. Access: http://localhost:3000" -ForegroundColor Gray

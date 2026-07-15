#!/usr/bin/env pwsh
# =============================================================================
# build_bindings.ps1
# Automated build script for Sovereign Engine C-API bindings
# Creates: sovereign.dll, Python bindings, and installation package
# =============================================================================

param(
    [string]$Configuration = "Release",
    [string]$OutputDir = ".\build\bindings",
    [switch]$InstallPython = $false,
    [switch]$Clean = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"
$StartTime = Get-Date

# =============================================================================
# Configuration
# =============================================================================

$MSVC_VERSION = "14.51.36231"
$MSVC_PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\$MSVC_VERSION"
$WINSDK_VERSION = "10.0.22621.0"
$WINSDK_PATH = "C:\Program Files (x86)\Windows Kits\10"

$SourceFiles = @(
    "src\bindings\sovereign_c_api.cpp",
    "src\core\sovereign_engine_controller.cpp",
    "src\core\sovereign_gguf_loader.cpp",
    "src\core\sovereign_kv_cache.cpp",
    "src\core\sovereign_memory_pool.cpp",
    "src\core\sovereign_thread_pool.cpp"
)

$IncludePaths = @(
    ".",
    "$MSVC_PATH\include",
    "$WINSDK_PATH\Include\$WINSDK_VERSION\um",
    "$WINSDK_PATH\Include\$WINSDK_VERSION\ucrt",
    "$WINSDK_PATH\Include\$WINSDK_VERSION\shared"
)

$LibPaths = @(
    "$WINSDK_PATH\Lib\$WINSDK_VERSION\um\x64",
    "$WINSDK_PATH\Lib\$WINSDK_VERSION\ucrt\x64",
    "$MSVC_PATH\lib\x64"
)

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Status) {
        "SUCCESS" { "Green" }
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Status] $Message" -ForegroundColor $color
}

function Test-Prerequisites {
    Write-Status "Checking prerequisites..."
    
    # Check MSVC
    if (-not (Test-Path "$MSVC_PATH\bin\Hostx64\x64\cl.exe")) {
        Write-Status "MSVC compiler not found at $MSVC_PATH" "ERROR"
        return $false
    }
    
    # Check Windows SDK
    if (-not (Test-Path "$WINSDK_PATH\Include\$WINSDK_VERSION")) {
        Write-Status "Windows SDK not found" "ERROR"
        return $false
    }
    
    # Check source files
    foreach ($file in $SourceFiles) {
        if (-not (Test-Path $file)) {
            Write-Status "Source file not found: $file" "ERROR"
            return $false
        }
    }
    
    Write-Status "All prerequisites satisfied" "SUCCESS"
    return $true
}

function Invoke-Clean {
    Write-Status "Cleaning output directory..."
    if (Test-Path $OutputDir) {
        Remove-Item -Recurse -Force $OutputDir
    }
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    Write-Status "Clean complete" "SUCCESS"
}

function Build-DLL {
    Write-Status "Building sovereign.dll..."
    
    $clExe = "$MSVC_PATH\bin\Hostx64\x64\cl.exe"
    
    # Build compiler arguments
    $compilerArgs = @(
        "/O2",                          # Optimize for speed
        "/arch:AVX2",                   # Enable AVX2
        "/std:c++17",                   # C++17 standard
        "/EHsc",                        # Exception handling
        "/MD",                          # Multi-threaded DLL runtime
        "/W3",                          # Warning level 3
        "/wd4996",                      # Disable deprecation warnings
        "/D", "SOVEREIGN_API_EXPORTS", # Export macro
        "/D", "NDEBUG",                 # Release build
        "/Fo:$OutputDir\\",            # Object file output
        "/Fe:$OutputDir\sovereign.dll"  # DLL output
    )
    
    # Add include paths
    foreach ($inc in $IncludePaths) {
        $compilerArgs += "/I`"$inc`""
    }
    
    # Add source files
    $compilerArgs += $SourceFiles
    
    # Add linker options
    $compilerArgs += "/link"
    foreach ($lib in $LibPaths) {
        $compilerArgs += "/LIBPATH:`"$lib`""
    }
    $compilerArgs += @(
        "/DLL",
        "/MACHINE:X64",
        "kernel32.lib",
        "user32.lib",
        "advapi32.lib"
    )
    
    if ($Verbose) {
        Write-Status "Compiler command: $clExe $($compilerArgs -join ' ')"
    }
    
    # Execute build
    $process = Start-Process -FilePath $clExe -ArgumentList $compilerArgs `
        -PassThru -Wait -NoNewWindow `
        -RedirectStandardOutput "$OutputDir\build.log" `
        -RedirectStandardError "$OutputDir\build.err"
    
    if ($process.ExitCode -ne 0) {
        Write-Status "Build failed with exit code $($process.ExitCode)" "ERROR"
        Get-Content "$OutputDir\build.err" | Write-Host -ForegroundColor Red
        return $false
    }
    
    Write-Status "Build successful" "SUCCESS"
    return $true
}

function Build-ImportLib {
    Write-Status "Creating import library..."
    
    $libExe = "$MSVC_PATH\bin\Hostx64\x64\lib.exe"
    $defFile = "$OutputDir\sovereign.def"
    
    # Generate .def file from exports
    $exports = @(
        "EXPORTS",
        "    sovereign_version_string",
        "    sovereign_get_version",
        "    sovereign_init",
        "    sovereign_shutdown",
        "    sovereign_engine_create",
        "    sovereign_engine_destroy",
        "    sovereign_engine_load_model",
        "    sovereign_engine_is_ready",
        "    sovereign_engine_get_stats",
        "    sovereign_session_create",
        "    sovereign_session_destroy",
        "    sovereign_session_reset",
        "    sovereign_tokenize",
        "    sovereign_detokenize",
        "    sovereign_generate",
        "    sovereign_generate_token",
        "    sovereign_get_hardware_info",
        "    sovereign_get_memory_usage"
    )
    
    $exports | Out-File -FilePath $defFile -Encoding ASCII
    
    # Create import library
    $libArgs = @(
        "/DEF:`"$defFile`"",
        "/OUT:`"$OutputDir\sovereign.lib`"",
        "/MACHINE:X64"
    )
    
    $process = Start-Process -FilePath $libExe -ArgumentList $libArgs `
        -PassThru -Wait -NoNewWindow
    
    if ($process.ExitCode -ne 0) {
        Write-Status "Import library creation failed" "ERROR"
        return $false
    }
    
    Write-Status "Import library created" "SUCCESS"
    return $true
}

function Install-PythonBindings {
    Write-Status "Installing Python bindings..."
    
    $pythonDir = "$OutputDir\python"
    New-Item -ItemType Directory -Force -Path $pythonDir | Out-Null
    
    # Copy Python module
    Copy-Item "src\bindings\python\sovereign.py" "$pythonDir\sovereign.py"
    
    # Copy DLL to Python directory
    Copy-Item "$OutputDir\sovereign.dll" "$pythonDir\sovereign.dll"
    
    # Create __init__.py
    @"
\"\"\"
Sovereign Engine Python Bindings
\"\"\"

from .sovereign import (
    SovereignEngine,
    LoaderConfig,
    InferenceConfig,
    EngineStats,
    GenerationResult,
    HardwareInfo,
    version,
    engine,
    SovereignError
)

__version__ = '1.0.0'
__all__ = [
    'SovereignEngine',
    'LoaderConfig',
    'InferenceConfig',
    'EngineStats',
    'GenerationResult',
    'HardwareInfo',
    'version',
    'engine',
    'SovereignError'
]
"@ | Out-File -FilePath "$pythonDir\__init__.py" -Encoding UTF8
    
    # Create setup.py for pip installation
    @"
from setuptools import setup, find_packages

setup(
    name='sovereign-engine',
    version='1.0.0',
    description='Sovereign Inference Engine Python Bindings',
    author='RawrXD Team',
    packages=find_packages(),
    package_data={'sovereign': ['sovereign.dll']},
    include_package_data=True,
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)
"@ | Out-File -FilePath "$OutputDir\setup.py" -Encoding UTF8
    
    Write-Status "Python bindings installed to $pythonDir" "SUCCESS"
    
    # Test import
    Write-Status "Testing Python import..."
    $testScript = @"
import sys
sys.path.insert(0, '$pythonDir')
try:
    import sovereign
    print(f'Version: {sovereign.version()}')
    print('Import successful!')
except Exception as e:
    print(f'Import failed: {e}')
    sys.exit(1)
"@
    
    $testResult = python -c $testScript 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Python import test passed" "SUCCESS"
        Write-Host $testResult
    } else {
        Write-Status "Python import test failed" "WARNING"
        Write-Host $testResult
    }
}

function New-Package {
    Write-Status "Creating distribution package..."
    
    $packageDir = "$OutputDir\sovereign-engine-1.0.0"
    New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
    
    # Copy files
    Copy-Item "$OutputDir\sovereign.dll" "$packageDir\"
    Copy-Item "$OutputDir\sovereign.lib" "$packageDir\"
    Copy-Item "src\bindings\sovereign_c_api.h" "$packageDir\"
    Copy-Item "$OutputDir\python" "$packageDir\" -Recurse
    
    # Create README
    @"
# Sovereign Engine C-API Bindings v1.0.0

## Contents
- sovereign.dll - Core engine library
- sovereign.lib - Import library (Windows)
- sovereign_c_api.h - C header file
- python/ - Python bindings

## Quick Start

### C/C++
```c
#include "sovereign_c_api.h"

sovereign_engine_t engine;
sovereign_loader_config_t loader = {0};
sovereign_inference_config_t inference = {0};

sovereign_engine_create(&loader, &inference, &engine);
sovereign_generate(engine, "Hello", response, &len, &tokens);
```

### Python
```python
from sovereign import engine

with engine() as eng:
    with eng.create_session() as sess:
        response = sess.generate("Hello")
```

## License
Proprietary - RawrXD Team
"@ | Out-File -FilePath "$packageDir\README.md" -Encoding UTF8
    
    # Create ZIP
    Compress-Archive -Path "$packageDir\*" -DestinationPath "$OutputDir\sovereign-engine-1.0.0-win64.zip" -Force
    
    Write-Status "Package created: sovereign-engine-1.0.0-win64.zip" "SUCCESS"
}

# =============================================================================
# Main
# =============================================================================

Write-Status "========================================"
Write-Status "  Sovereign Engine Bindings Builder"
Write-Status "  Configuration: $Configuration"
Write-Status "  Output: $OutputDir"
Write-Status "========================================"

# Clean if requested
if ($Clean) {
    Invoke-Clean
}

# Ensure output directory exists
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Check prerequisites
if (-not (Test-Prerequisites)) {
    exit 1
}

# Build DLL
if (-not (Build-DLL)) {
    exit 1
}

# Build import library
if (-not (Build-ImportLib)) {
    exit 1
}

# Install Python bindings
if ($InstallPython) {
    Install-PythonBindings
}

# Create package
New-Package

# Summary
$duration = (Get-Date) - $StartTime
Write-Status "========================================"
Write-Status "  Build Complete!"
Write-Status "  Duration: $($duration.ToString('mm\:ss'))"
Write-Status "  Output: $OutputDir"
Write-Status "========================================"

# List outputs
Write-Status "Generated files:"
Get-ChildItem $OutputDir -File | ForEach-Object {
    Write-Host "  - $($_.Name) ($([math]::Round($_.Length/1KB, 2)) KB)"
}

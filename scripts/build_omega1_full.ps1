# RawrXD OMEGA-1 Full Build Script
# Builds all binaries with OMEGA-1 integration and dual GPU support

param(
    [string]$BuildType = "Release",
    [string]$BuildDir = "d:\rawrxd\build",
    [string]$SourceDir = "d:\rawrxd",
    [switch]$Clean = $false,
    [switch]$SkipTests = $false
)

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Full Build Pipeline                                         ║" -ForegroundColor Cyan
Write-Host "║     Build Type: $BuildType" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $BuildType.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# =============================================================================
# Phase 1: Environment Validation
# =============================================================================
Write-Header "Phase 1: Environment Validation"

# Check Visual Studio
$vsPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
if (Test-Path "$vsPath\cl.exe") {
    Write-Status "Visual Studio 2022 found" "OK"
} else {
    Write-Status "Visual Studio 2022 not found at expected path" "FAIL"
    exit 1
}

# Check CMake
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if ($cmake) {
    Write-Status "CMake found: $($cmake.Source)" "OK"
} else {
    Write-Status "CMake not found in PATH" "FAIL"
    exit 1
}

# Check Ninja
$ninja = Get-Command ninja -ErrorAction SilentlyContinue
if ($ninja) {
    Write-Status "Ninja found: $($ninja.Source)" "OK"
} else {
    Write-Status "Ninja not found, will use MSBuild" "WARN"
}

# Check source files
$requiredSources = @(
    "$SourceDir\include\omega1_ipc_protocol.h",
    "$SourceDir\src\win32ide\Win32IDE_Omega1Integration.cpp",
    "$SourceDir\src\engine\Omega1Engine_Server.cpp",
    "$SourceDir\src\core\dual_gpu_load_balancer.cpp"
)

$missingFiles = @()
foreach ($file in $requiredSources) {
    if (!(Test-Path $file)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -eq 0) {
    Write-Status "All OMEGA-1 source files present" "OK"
} else {
    Write-Status "Missing source files:" "FAIL"
    foreach ($file in $missingFiles) {
        Write-Host "    - $file" -ForegroundColor Red
    }
    exit 1
}

# =============================================================================
# Phase 2: Clean Build (if requested)
# =============================================================================
Write-Header "Phase 2: Build Preparation"

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Status "Cleaning build directory..." "OK"
    Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
}

if (!(Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    Write-Status "Created build directory: $BuildDir" "OK"
}

# =============================================================================
# Phase 3: CMake Configuration
# =============================================================================
Write-Header "Phase 3: CMake Configuration"

Push-Location $BuildDir

try {
    $cmakeArgs = @(
        "-S", $SourceDir,
        "-B", $BuildDir,
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DCMAKE_C_COMPILER=$vsPath\cl.exe",
        "-DCMAKE_CXX_COMPILER=$vsPath\cl.exe",
        "-DRAWRXD_ENABLE_OMEGA1=ON",
        "-DRAWRXD_ENABLE_DUAL_GPU=ON"
    )
    
    Write-Status "Running CMake configuration..." "OK"
    & cmake @cmakeArgs 2>&1 | Tee-Object -FilePath "$BuildDir\cmake_config.log"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Status "CMake configuration failed" "FAIL"
        exit 1
    }
    
    Write-Status "CMake configuration complete" "OK"
} finally {
    Pop-Location
}

# =============================================================================
# Phase 4: Build Win32IDE
# =============================================================================
Write-Header "Phase 4: Building Win32IDE"

Push-Location $BuildDir

try {
    Write-Status "Building RawrXD-Win32IDE..." "OK"
    & cmake --build . --target RawrXD-Win32IDE --config $BuildType -j8 2>&1 | Tee-Object -FilePath "$BuildDir\build_win32ide.log"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Win32IDE build failed" "FAIL"
        exit 1
    }
    
    # Verify binary
    $win32ideBin = "$BuildDir\bin\RawrXD-Win32IDE.exe"
    if (Test-Path $win32ideBin) {
        $size = (Get-Item $win32ideBin).Length / 1MB
        Write-Status "Win32IDE built: $([math]::Round($size, 2)) MB" "OK"
    } else {
        Write-Status "Win32IDE binary not found" "FAIL"
        exit 1
    }
} finally {
    Pop-Location
}

# =============================================================================
# Phase 5: Build Omega1Engine
# =============================================================================
Write-Header "Phase 5: Building Omega1Engine"

Push-Location $BuildDir

try {
    Write-Status "Building RawrXD-Omega1Engine..." "OK"
    & cmake --build . --target RawrXD-Omega1Engine --config $BuildType -j8 2>&1 | Tee-Object -FilePath "$BuildDir\build_omega1engine.log"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Omega1Engine build failed" "FAIL"
        exit 1
    }
    
    # Verify binary
    $engineBin = "$BuildDir\bin\RawrXD-Omega1Engine.exe"
    if (Test-Path $engineBin) {
        $size = (Get-Item $engineBin).Length / 1MB
        Write-Status "Omega1Engine built: $([math]::Round($size, 2)) MB" "OK"
    } else {
        Write-Status "Omega1Engine binary not found" "FAIL"
        exit 1
    }
} finally {
    Pop-Location
}

# =============================================================================
# Phase 6: Build Dual GPU Load Balancer
# =============================================================================
Write-Header "Phase 6: Building Dual GPU Components"

Push-Location $BuildDir

try {
    Write-Status "Building dual_gpu_load_balancer..." "OK"
    & cmake --build . --target dual_gpu_load_balancer --config $BuildType -j8 2>&1 | Tee-Object -FilePath "$BuildDir\build_loadbalancer.log"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Load balancer build failed" "WARN"
    } else {
        Write-Status "Load balancer built successfully" "OK"
    }
} finally {
    Pop-Location
}

# =============================================================================
# Phase 7: Copy Binaries
# =============================================================================
Write-Header "Phase 7: Deploying Binaries"

$binDir = "$SourceDir\bin"
if (!(Test-Path $binDir)) {
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
}

$binaries = @(
    "$BuildDir\bin\RawrXD-Win32IDE.exe",
    "$BuildDir\bin\RawrXD-Omega1Engine.exe"
)

foreach ($bin in $binaries) {
    if (Test-Path $bin) {
        Copy-Item $bin $binDir -Force
        $name = Split-Path $bin -Leaf
        Write-Status "Deployed: $name" "OK"
    }
}

# =============================================================================
# Phase 8: Run Tests (if not skipped)
# =============================================================================
if (!$SkipTests) {
    Write-Header "Phase 8: Running Validation Tests"
    
    $testScript = "$SourceDir\scripts\dual_gpu_live_test.ps1"
    if (Test-Path $testScript) {
        Write-Status "Running dual GPU live test..." "OK"
        & powershell -ExecutionPolicy Bypass -File $testScript -BinDir $binDir
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "All tests passed" "OK"
        } else {
            Write-Status "Some tests failed" "WARN"
        }
    } else {
        Write-Status "Test script not found: $testScript" "WARN"
    }
}

# =============================================================================
# Summary
# =============================================================================
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Header "Build Summary"

Write-Status "Build completed in $($Duration.ToString('hh\:mm\:ss'))" "OK"
Write-Status "Binaries location: $binDir" "OK"

Get-ChildItem $binDir\*.exe | ForEach-Object {
    $size = $_.Length / 1MB
    Write-Status "  - $($_.Name): $([math]::Round($size, 2)) MB" "OK"
}

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     ✅ RawrXD OMEGA-1 Build Complete                                             ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

exit 0

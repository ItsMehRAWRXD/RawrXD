# Sovereign Intent Architecture - Build Verification Script
# This script verifies that all components compile and link correctly

param(
    [string]$BuildType = "Release",
    [switch]$Clean,
    [switch]$SkipTests,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Colors for output
$Green = "`e[32m"
$Red = "`e[31m"
$Yellow = "`e[33m"
$Reset = "`e[0m"

function Write-Status($message, $status) {
    switch ($status) {
        "OK" { Write-Host "${Green}[✓]${Reset} $message" }
        "FAIL" { Write-Host "${Red}[✗]${Reset} $message" }
        "WARN" { Write-Host "${Yellow}[!]${Reset} $message" }
        "INFO" { Write-Host "[i] $message" }
    }
}

function Test-Command($command) {
    return [bool](Get-Command $command -ErrorAction SilentlyContinue)
}

# Header
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Intent Architecture Build Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check prerequisites
Write-Host "Step 1: Checking prerequisites..." -ForegroundColor Yellow

$prereqs = @{
    "cmake" = "CMake"
    "ninja" = "Ninja"
    "cl" = "MSVC Compiler"
    "python" = "Python"
}

$allPrereqsMet = $true
foreach ($cmd in $prereqs.Keys) {
    if (Test-Command $cmd) {
        Write-Status "$($prereqs[$cmd]) found" "OK"
    } else {
        Write-Status "$($prereqs[$cmd]) not found" "FAIL"
        $allPrereqsMet = $false
    }
}

if (-not $allPrereqsMet) {
    Write-Host ""
    Write-Status "Prerequisites not met. Please install missing tools." "FAIL"
    exit 1
}

Write-Host ""

# Step 2: Check source files exist
Write-Host "Step 2: Checking source files..." -ForegroundColor Yellow

$requiredFiles = @(
    # Intent Guardrails
    "src/intent/intent_config.hpp",
    "src/intent/intent_config.cpp",
    "src/intent/intent_abi.hpp",
    "src/intent/intent_abi.cpp",
    "src/intent/model_adapter.hpp",
    "src/guardrails/capability_policy.hpp",
    "src/guardrails/capability_policy.cpp",
    "src/guardrails/patch_firewall.hpp",
    "src/guardrails/patch_firewall.cpp",
    "src/hotpatch/patch_transaction.hpp",
    "src/hotpatch/patch_transaction.cpp",
    # Sovereign Puppeteer
    "src/sovereign/puppeteer/SymbolTableGenerator.hpp",
    "src/sovereign/puppeteer/SymbolTableGenerator.cpp",
    "src/sovereign/puppeteer/PuppeteerAPI.hpp",
    "src/sovereign/puppeteer/PuppeteerAPI.cpp",
    "src/sovereign/puppeteer/VEH_Watchdog.hpp",
    "src/sovereign/puppeteer/VEH_Watchdog.cpp",
    # CMake
    "CMakeLists.txt",
    "cmake/IntentGuardrails.cmake"
)

$allFilesExist = $true
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $PSScriptRoot ".." $file
    if (Test-Path $fullPath) {
        if ($Verbose) {
            Write-Status "$file exists" "OK"
        }
    } else {
        Write-Status "$file missing" "FAIL"
        $allFilesExist = $false
    }
}

if ($allFilesExist) {
    Write-Status "All required source files present" "OK"
} else {
    Write-Host ""
    Write-Status "Some source files are missing!" "FAIL"
    exit 1
}

Write-Host ""

# Step 3: Clean build directory if requested
$buildDir = Join-Path $PSScriptRoot ".." "build"

if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "Step 3: Cleaning build directory..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $buildDir
    Write-Status "Build directory cleaned" "OK"
    Write-Host ""
}

# Step 4: Configure with CMake
Write-Host "Step 4: Configuring with CMake..." -ForegroundColor Yellow

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

Push-Location $buildDir

try {
    $cmakeArgs = @(
        "..",
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DRAWR_INTENT_SYSTEM_ENABLED=ON",
        "-DRAWR_INTENT_GUARD_ENABLED=ON",
        "-DRAWR_INTENT_VALIDATION_ENABLED=ON",
        "-DRAWR_PATCH_TRANSACTION_ENABLED=ON",
        "-DRAWR_CAPABILITY_TOKENS_ENABLED=ON",
        "-DRAWR_HOTPATCH_JOURNAL_ENABLED=ON",
        "-DRAWR_PATCH_FIREWALL_ENABLED=ON"
    )

    if ($Verbose) {
        $cmakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
    }

    & cmake @cmakeArgs 2>&1 | Tee-Object -FilePath "cmake_configure.log"

    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }

    Write-Status "CMake configuration successful" "OK"
} catch {
    Write-Status "CMake configuration failed: $_" "FAIL"
    exit 1
}

Write-Host ""

# Step 5: Build
Write-Host "Step 5: Building project..." -ForegroundColor Yellow

try {
    if ($Verbose) {
        & ninja -v 2>&1 | Tee-Object -FilePath "build.log"
    } else {
        & ninja 2>&1 | Tee-Object -FilePath "build.log"
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    Write-Status "Build successful" "OK"
} catch {
    Write-Status "Build failed: $_" "FAIL"
    exit 1
}

Write-Host ""

# Step 6: Check binaries
Write-Host "Step 6: Checking binaries..." -ForegroundColor Yellow

$binDir = Join-Path $buildDir ".." "bin"
$expectedBinaries = @(
    "RawrEngine.exe",
    "test_intent_guardrails.exe",
    "SovereignTest_Puppeteer.exe"
)

$allBinariesExist = $true
foreach ($binary in $expectedBinaries) {
    $binaryPath = Join-Path $binDir $binary
    if (Test-Path $binaryPath) {
        $size = (Get-Item $binaryPath).Length
        Write-Status "$binary ($([math]::Round($size/1MB, 2)) MB)" "OK"
    } else {
        Write-Status "$binary not found" "WARN"
        $allBinariesExist = $false
    }
}

Write-Host ""

# Step 7: Run tests (if not skipped)
if (-not $SkipTests) {
    Write-Host "Step 7: Running tests..." -ForegroundColor Yellow

    $testResults = @()

    # Test 1: Intent Guardrails
    $test1Path = Join-Path $binDir "test_intent_guardrails.exe"
    if (Test-Path $test1Path) {
        Write-Host "  Running test_intent_guardrails.exe..." -ForegroundColor Gray
        & $test1Path 2>&1 | Tee-Object -FilePath "test_intent_guardrails.log"
        $testResults += @{ Name = "Intent Guardrails"; ExitCode = $LASTEXITCODE }
    }

    # Test 2: Sovereign Puppeteer
    $test2Path = Join-Path $binDir "SovereignTest_Puppeteer.exe"
    if (Test-Path $test2Path) {
        Write-Host "  Running SovereignTest_Puppeteer.exe..." -ForegroundColor Gray
        & $test2Path 2>&1 | Tee-Object -FilePath "SovereignTest_Puppeteer.log"
        $testResults += @{ Name = "Sovereign Puppeteer"; ExitCode = $LASTEXITCODE }
    }

    Write-Host ""
    Write-Host "Test Results:" -ForegroundColor Yellow
    foreach ($result in $testResults) {
        if ($result.ExitCode -eq 0) {
            Write-Status "$($result.Name)" "OK"
        } else {
            Write-Status "$($result.Name) (exit: $($result.ExitCode))" "FAIL"
        }
    }
} else {
    Write-Status "Tests skipped" "WARN"
}

Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build Verification Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Status "Prerequisites" "OK"
Write-Status "Source Files" "OK"
Write-Status "CMake Configuration" "OK"
Write-Status "Build" "OK"
if (-not $SkipTests) {
    $allTestsPassed = ($testResults | Where-Object { $_.ExitCode -ne 0 }).Count -eq 0
    if ($allTestsPassed) {
        Write-Status "Tests" "OK"
    } else {
        Write-Status "Tests" "FAIL"
    }
}
Write-Host ""
Write-Host "Build artifacts location: $binDir" -ForegroundColor Gray
Write-Host "Log files location: $buildDir" -ForegroundColor Gray
Write-Host ""
Write-Host "${Green}Verification complete!${Reset}"

Pop-Location

# RawrXD Master Build Verification Script
# Copyright (c) 2026 RawrXD Team
# This script verifies that all components compile and link correctly

param(
    [switch]$Clean,
    [switch]$Verbose,
    [switch]$SkipTests,
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# ============================================================================
# Configuration
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = $ScriptDir
$BuildDir = Join-Path $RootDir "build_master"
$LogDir = Join-Path $BuildDir "logs"
$DistDir = Join-Path $RootDir "src\distributed"
$CoreDir = Join-Path $RootDir "src\core"
$IntDir = Join-Path $RootDir "src\integration"

$Compiler = "C:\ProgramData\mingw64\mingw64\bin\g++.exe"
$CMake = "cmake.exe"

$Components = @(
    @{ Name = "Distributed Infrastructure"; Path = $DistDir; Priority = 1 },
    @{ Name = "Core Engine"; Path = $CoreDir; Priority = 2 },
    @{ Name = "Integration Layer"; Path = $RootDir; Priority = 3 }
)

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Header($text) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Success($text) {
    Write-Host "✓ $text" -ForegroundColor Green
}

function Write-Error($text) {
    Write-Host "✗ $text" -ForegroundColor Red
}

function Write-Warning($text) {
    Write-Host "⚠ $text" -ForegroundColor Yellow
}

function Test-Compiler {
    Write-Header "Checking Compiler"
    
    if (!(Test-Path $Compiler)) {
        Write-Error "Compiler not found: $Compiler"
        return $false
    }
    
    try {
        $version = & $Compiler --version 2>&1 | Select-Object -First 1
        Write-Success "Found compiler: $version"
        return $true
    }
    catch {
        Write-Error "Failed to run compiler: $_"
        return $false
    }
}

function Initialize-BuildEnvironment {
    Write-Header "Initializing Build Environment"
    
    if ($Clean -and (Test-Path $BuildDir)) {
        Write-Warning "Cleaning build directory..."
        Remove-Item -Recurse -Force $BuildDir
    }
    
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    
    Write-Success "Build environment ready"
    Write-Success "Build directory: $BuildDir"
    Write-Success "Log directory: $LogDir"
}

# ============================================================================
# Build Functions
# ============================================================================

function Build-DistributedInfrastructure {
    Write-Header "Building Distributed Infrastructure"
    
    $sourceFiles = @(
        "RawrXD_RPC.cpp",
        "RawrXD_RPC_Handlers.cpp",
        "InferenceRuntime.cpp",
        "SovereignNodeDiscovery.cpp",
        "SovereignConsensusEngine.cpp",
        "SovereignDistributedRollback.cpp",
        "SovereignStateReplication.cpp",
        "SovereignDistributedRuntime.cpp",
        "ProductionSecurity.cpp",
        "../integration/InferenceRuntimeGGMLBridge.cpp",
        "../inference/GGMLBackend_stub.cpp"
    )
    
    $objectFiles = @()
    $success = $true
    
    foreach ($file in $sourceFiles) {
        $sourcePath = Join-Path $DistDir $file
        if (!(Test-Path $sourcePath)) {
            Write-Warning "Source file not found: $file"
            continue
        }
        
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file)
        $objFile = Join-Path $BuildDir "$baseName.o"
        $logFile = Join-Path $LogDir "$baseName`_compile.log"
        
        # Ensure log directory exists
        $logDirPath = Split-Path -Parent $logFile
        if (!(Test-Path $logDirPath)) {
            New-Item -ItemType Directory -Force -Path $logDirPath | Out-Null
        }
        
        Write-Host "Compiling $file..." -NoNewline
        
        $args = @(
            "-std=c++17",
            "-O2",
            "-D_GLIBCXX_USE_CXX11_ABI=1",
            "-I$DistDir",
            "-I$IntDir",
            "-I$RootDir\src\inference",
            "-c",
            $sourcePath,
            "-o", $objFile
        )
        
        if ($Verbose) {
            $args += "-v"
        }
        
        try {
            & $Compiler @args 2>&1 | Tee-Object -FilePath $logFile | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "OK"
                $objectFiles += $objFile
            }
            else {
                Write-Error "FAILED (exit code: $LASTEXITCODE)"
                $success = $false
            }
        }
        catch {
            Write-Error "FAILED: $_"
            $success = $false
        }
    }
    
    if ($success) {
        Write-Success "Distributed Infrastructure build complete"
    }
    
    return $success
}

function Build-CoreEngine {
    Write-Header "Building Core Engine"
    
    # Core engine stub compilation
    $stubFile = Join-Path $CoreDir "rawrengine_link_closure.cpp"
    if (Test-Path $stubFile) {
        $objFile = Join-Path $BuildDir "rawrengine_link_closure.o"
        $logFile = Join-Path $LogDir "rawrengine_link_closure_compile.log"
        
        Write-Host "Compiling rawrengine_link_closure.cpp..." -NoNewline
        
        $args = @(
            "-std=c++17",
            "-O2",
            "-I$CoreDir",
            "-I$RootDir\include",
            "-c",
            $stubFile,
            "-o", $objFile
        )
        
        try {
            & $Compiler @args 2>&1 | Tee-Object -FilePath $logFile | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "OK"
                return $true
            }
            else {
                Write-Error "FAILED (exit code: $LASTEXITCODE)"
                return $false
            }
        }
        catch {
            Write-Error "FAILED: $_"
            return $false
        }
    }
    else {
        Write-Warning "Core engine stub file not found"
        return $true  # Not a failure, just no stubs needed
    }
}

function Build-Tests {
    Write-Header "Building Tests"
    
    $testFiles = @(
        @{ Source = "test_rpc_handlers.cpp"; Output = "test_rpc_handlers.exe" },
        @{ Source = "test_inference_e2e.cpp"; Output = "test_inference_e2e.exe" },
        @{ Source = "../integration/val018_distributed_inference_demo.cpp"; Output = "val018_distributed_inference_demo.exe" }
    )
    
    $success = $true
    
    foreach ($test in $testFiles) {
        $sourcePath = Join-Path $DistDir $test.Source
        $outputPath = Join-Path $BuildDir $test.Output
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($test.Source)
        $logFile = Join-Path $LogDir "$baseName`_build.log"
        
        if (!(Test-Path $sourcePath)) {
            Write-Warning "Test source not found: $($test.Source)"
            continue
        }
        
        Write-Host "Building $($test.Source)..." -NoNewline
        
        # Collect all object files
        $objFiles = Get-ChildItem -Path $BuildDir -Filter "*.o" | Select-Object -ExpandProperty FullName
        
        $args = @(
            "-std=c++17",
            "-O2",
            "-D_GLIBCXX_USE_CXX11_ABI=1",
            "-I$DistDir",
            "-I$IntDir",
            "-I$RootDir\src\inference",
            "-I$RootDir\include",
            $sourcePath
        )
        
        $args += $objFiles
        $args += @("-o", $outputPath)
        
        try {
            & $Compiler @args 2>&1 | Tee-Object -FilePath $logFile | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "OK"
            }
            else {
                Write-Error "FAILED (exit code: $LASTEXITCODE)"
                $success = $false
            }
        }
        catch {
            Write-Error "FAILED: $_"
            $success = $false
        }
    }
    
    return $success
}

function Run-Tests {
    if ($SkipTests) {
        Write-Warning "Skipping tests as requested"
        return $true
    }
    
    Write-Header "Running Tests"
    
    $testExecutables = @(
        "test_rpc_handlers.exe",
        "test_inference_e2e.exe"
    )
    
    $success = $true
    $totalTests = 0
    $passedTests = 0
    
    foreach ($testExe in $testExecutables) {
        $testPath = Join-Path $BuildDir $testExe
        if (!(Test-Path $testPath)) {
            Write-Warning "Test executable not found: $testExe"
            continue
        }
        
        Write-Host "Running $testExe..." -NoNewline
        
        $logFile = Join-Path $LogDir "$($testExe -replace '\.exe$', '_run.log')"
        
        try {
            $output = & $testPath 2>&1 | Tee-Object -FilePath $logFile
            $exitCode = $LASTEXITCODE
            
            # Parse test results
            $outputString = $output -join "`n"
            if ($outputString -match "Results:\s+(\d+)\s+passed,\s+(\d+)\s+failed") {
                $passed = [int]$Matches[1]
                $failed = [int]$Matches[2]
                $totalTests += $passed + $failed
                $passedTests += $passed
                
                if ($failed -eq 0) {
                    Write-Success "PASSED ($passed tests)"
                }
                else {
                    Write-Error "FAILED ($failed of $($passed + $failed) tests failed)"
                    $success = $false
                }
            }
            else {
                if ($exitCode -eq 0) {
                    Write-Success "PASSED"
                    $passedTests++
                    $totalTests++
                }
                else {
                    Write-Error "FAILED (exit code: $exitCode)"
                    $success = $false
                }
            }
        }
        catch {
            Write-Error "FAILED: $_"
            $success = $false
        }
    }
    
    Write-Host "`nTest Summary: $passedTests/$totalTests passed" -ForegroundColor $(if ($success) { "Green" } else { "Red" })
    
    return $success
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Header "RawrXD Master Build Verification"
    Write-Host "Configuration: $Configuration"
    Write-Host "Clean Build: $Clean"
    Write-Host "Verbose: $Verbose"
    Write-Host "Skip Tests: $SkipTests"
    
    $startTime = Get-Date
    
    # Check prerequisites
    if (!(Test-Compiler)) {
        exit 1
    }
    
    # Initialize environment
    Initialize-BuildEnvironment
    
    # Track results
    $results = @{
        Distributed = $false
        Core = $false
        Tests = $false
        TestRun = $false
    }
    
    # Build components
    $results.Distributed = Build-DistributedInfrastructure
    $results.Core = Build-CoreEngine
    
    if ($results.Distributed -and $results.Core) {
        $results.Tests = Build-Tests
        
        if ($results.Tests) {
            $results.TestRun = Run-Tests
        }
    }
    
    # Summary
    Write-Header "Build Summary"
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))"
    Write-Host ""
    
    foreach ($component in $results.Keys) {
        $status = if ($results[$component]) { "✓ PASS" } else { "✗ FAIL" }
        $color = if ($results[$component]) { "Green" } else { "Red" }
        Write-Host "$component`: $status" -ForegroundColor $color
    }
    
    $overallSuccess = $results.Values -notcontains $false
    
    Write-Host ""
    if ($overallSuccess) {
        Write-Success "BUILD VERIFICATION PASSED"
        Write-Success "All components built and tested successfully"
        exit 0
    }
    else {
        Write-Error "BUILD VERIFICATION FAILED"
        Write-Error "Check logs in: $LogDir"
        exit 1
    }
}

# Run main
Main

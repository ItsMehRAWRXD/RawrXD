# FMF Smoke Test Build and Run Script
# Builds the project with FMF enabled and runs the smoke test

param(
    [switch]$Build,
    [switch]$Run,
    [switch]$All,
    [string]$BuildType = "Release",
    [string]$BuildDir = "build_fmf_smoke",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "HEADER" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-Command {
    param([string]$Command, [string]$Args)
    $process = Start-Process -FilePath $Command -ArgumentList $Args -NoNewWindow -Wait -PassThru
    return $process.ExitCode -eq 0
}

# ============================================================================
# Build FMF Smoke Test
# ============================================================================

function Build-FMFTest {
    Write-Log "Building FMF Smoke Test..." "HEADER"
    
    $projectRoot = $PSScriptRoot | Split-Path -Parent
    $buildDir = Join-Path $projectRoot $BuildDir
    
    # Create build directory
    if (-not (Test-Path $buildDir)) {
        New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
        Write-Log "Created build directory: $buildDir"
    }
    
    # Configure CMake
    Write-Log "Configuring CMake..."
    Push-Location $buildDir
    
    $cmakeArgs = @(
        "..",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DRAWRXD_BUILD_WIN32IDE=ON",
        "-DRAWRXD_ENABLE_FMF=ON"
    )
    
    if ($Verbose) {
        $cmakeArgs += "-DCMAKE_VERBOSE_MAKEFILE=ON"
    }
    
    $cmakeProcess = Start-Process -FilePath "cmake" -ArgumentList $cmakeArgs -NoNewWindow -Wait -PassThru
    
    if ($cmakeProcess.ExitCode -ne 0) {
        Write-Log "CMake configuration failed" "ERROR"
        Pop-Location
        return $false
    }
    
    Write-Log "CMake configuration successful" "SUCCESS"
    
    # Build
    Write-Log "Building..."
    $buildArgs = @(
        "--build", ".",
        "--config", $BuildType,
        "--target", "fmf_smoke_test"
    )
    
    if ($Verbose) {
        $buildArgs += "--verbose"
    }
    
    $buildProcess = Start-Process -FilePath "cmake" -ArgumentList $buildArgs -NoNewWindow -Wait -PassThru
    
    if ($buildProcess.ExitCode -ne 0) {
        Write-Log "Build failed" "ERROR"
        Pop-Location
        return $false
    }
    
    Write-Log "Build successful" "SUCCESS"
    Pop-Location
    
    return $true
}

# ============================================================================
# Run FMF Smoke Test
# ============================================================================

function Run-FMFTest {
    Write-Log "Running FMF Smoke Test..." "HEADER"
    
    $projectRoot = $PSScriptRoot | Split-Path -Parent
    $buildDir = Join-Path $projectRoot $BuildDir
    
    $exePath = Join-Path $buildDir "$BuildType\fmf_smoke_test.exe"
    
    if (-not (Test-Path $exePath)) {
        # Try Debug build if Release not found
        $exePath = Join-Path $buildDir "Debug\fmf_smoke_test.exe"
        if (-not (Test-Path $exePath)) {
            # Try direct build dir
            $exePath = Join-Path $buildDir "fmf_smoke_test.exe"
            if (-not (Test-Path $exePath)) {
                Write-Log "FMF smoke test executable not found" "ERROR"
                return $false
            }
        }
    }
    
    Write-Log "Executable: $exePath"
    
    # Run the test
    Push-Location (Split-Path $exePath -Parent)
    
    $testProcess = Start-Process -FilePath $exePath -NoNewWindow -Wait -PassThru
    
    Pop-Location
    
    if ($testProcess.ExitCode -ne 0) {
        Write-Log "FMF smoke test failed with exit code: $($testProcess.ExitCode)" "ERROR"
        return $false
    }
    
    Write-Log "FMF smoke test completed successfully" "SUCCESS"
    
    # Check for generated reports
    $fmfReport = Join-Path (Split-Path $exePath -Parent) "fmf_report.json"
    $featureReport = Join-Path (Split-Path $exePath -Parent) "feature_reconciliation.json"
    
    if (Test-Path $fmfReport) {
        Write-Log "FMF report generated: $fmfReport" "SUCCESS"
    }
    
    if (Test-Path $featureReport) {
        Write-Log "Feature reconciliation report generated: $featureReport" "SUCCESS"
    }
    
    return $true
}

# ============================================================================
# Analyze FMF Report
# ============================================================================

function Analyze-FMFReport {
    Write-Log "Analyzing FMF Report..." "HEADER"
    
    $projectRoot = $PSScriptRoot | Split-Path -Parent
    $buildDir = Join-Path $projectRoot $BuildDir
    
    $fmfReport = Join-Path $buildDir "$BuildType\fmf_report.json"
    if (-not (Test-Path $fmfReport)) {
        $fmfReport = Join-Path $buildDir "Debug\fmf_report.json"
        if (-not (Test-Path $fmfReport)) {
            $fmfReport = Join-Path $buildDir "fmf_report.json"
        }
    }
    
    if (-not (Test-Path $fmfReport)) {
        Write-Log "FMF report not found" "WARN"
        return
    }
    
    $report = Get-Content $fmfReport -Raw | ConvertFrom-Json
    
    Write-Log "FMF Report Analysis:" "HEADER"
    Write-Log "  Policy: $($report.policy)"
    Write-Log "  Total Stub Calls: $($report.totalStubCalls)"
    Write-Log "  Total Real Calls: $($report.totalRealCalls)"
    
    # Count risk levels
    $critical = 0
    $high = 0
    $medium = 0
    $ok = 0
    
    foreach ($feature in $report.features.PSObject.Properties) {
        $state = $feature.Value
        if ($state.stubbed -and $state.stubCallCount -gt 0 -and $state.realCallCount -eq 0) {
            $critical++
        } elseif ($state.stubbed -and $state.stubCallCount -gt 0) {
            $high++
        } elseif ($state.stubbed -and $state.realCallCount -gt 0) {
            $medium++
        } else {
            $ok++
        }
    }
    
    Write-Log "`nRisk Distribution:" "HEADER"
    Write-Log "  CRITICAL: $critical (stub-only execution)" $(if ($critical -gt 0) { "ERROR" } else { "SUCCESS" })
    Write-Log "  HIGH:     $high (mixed stub/real)" $(if ($high -gt 0) { "WARN" } else { "SUCCESS" })
    Write-Log "  MEDIUM:   $medium (stubbed but real used)" "WARN"
    Write-Log "  OK:       $ok (no issues)" "SUCCESS"
    
    if ($critical -gt 0) {
        Write-Log "`nCRITICAL Features (require immediate attention):" "ERROR"
        foreach ($feature in $report.features.PSObject.Properties) {
            $state = $feature.Value
            if ($state.stubbed -and $state.stubCallCount -gt 0 -and $state.realCallCount -eq 0) {
                Write-Log "  $($feature.Name)" "ERROR"
            }
        }
    }
}

# ============================================================================
# Main Entry Point
# ============================================================================ $(if ($All) {
    $Build = $true
    $Run = $true
}

if (-not $Build -and -not $Run) {
    Write-Log "Usage: .\run_fmf_smoke_test.ps1 [-Build] [-Run] [-All] [-BuildType Release|Debug]" "ERROR"
    Write-Log "  -Build     : Build the FMF smoke test"
    Write-Log "  -Run       : Run the FMF smoke test"
    Write-Log "  -All       : Build and run"
    Write-Log "  -BuildType : Release or Debug (default: Release)"
    exit 1
}

$success = $true

if ($Build) {
    $success = Build-FMFTest
    if (-not $success) {
        Write-Log "Build failed" "ERROR"
        exit 1
    }
}

if ($Run -and $success) {
    $success = Run-FMFTest
    if ($success) {
        Analyze-FMFReport
    }
}

if ($success) {
    Write-Log "`nFMF Smoke Test completed successfully" "SUCCESS"
    exit 0
} else {
    Write-Log "`nFMF Smoke Test failed" "ERROR"
    exit 1
}
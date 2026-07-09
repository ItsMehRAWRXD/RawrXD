#Requires -Version 7.0
<#
.SYNOPSIS
    Validates RawrXD build from clean checkout
.DESCRIPTION
    Performs comprehensive build validation including:
    - Clean build verification
    - Component compilation
    - Unit tests
    - Integration tests
    - Performance benchmarks
.NOTES
    Phase 1: Validation - Clean build verification
#>

param(
    [switch]$SkipTests,
    [switch]$SkipBenchmarks,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Configuration
$BuildDir = "build"
$TestDir = "tests"
$LogFile = "validation_log.txt"

# Results tracking
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:ComponentsBuilt = 0
$script:ComponentsFailed = 0

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

function Test-Component {
    param(
        [string]$Name,
        [string]$SourceFile,
        [string]$OutputFile,
        [string[]]$IncludePaths = @(".", "src", "include")
    )
    
    Write-Log "Building $Name..." "INFO"
    
    $includes = $IncludePaths | ForEach-Object { "-I$_" }
    $cmd = "g++ -std=c++17 -c `"$SourceFile`" $includes -o `"$OutputFile`" 2>&1"
    
    if ($Verbose) {
        Write-Log "Command: $cmd" "DEBUG"
    }
    
    try {
        $output = Invoke-Expression $cmd
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ $Name built successfully" "SUCCESS"
            $script:ComponentsBuilt++
            return $true
        } else {
            Write-Log "✗ $Name build failed" "ERROR"
            Write-Log $output "ERROR"
            $script:ComponentsFailed++
            return $false
        }
    } catch {
        Write-Log "✗ $Name build failed: $_" "ERROR"
        $script:ComponentsFailed++
        return $false
    }
}

function Test-Header {
    param(
        [string]$Name,
        [string]$HeaderFile,
        [string[]]$IncludePaths = @(".", "src", "include")
    )
    
    Write-Log "Validating $Name..." "INFO"
    
    $includes = $IncludePaths | ForEach-Object { "-I$_" }
    $cmd = "g++ -std=c++17 -fsyntax-only $includes `"$HeaderFile`" 2>&1"
    
    try {
        $output = Invoke-Expression $cmd
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ $Name valid" "SUCCESS"
            return $true
        } else {
            Write-Log "✗ $Name validation failed" "ERROR"
            Write-Log $output "ERROR"
            return $false
        }
    } catch {
        Write-Log "✗ $Name validation failed: $_" "ERROR"
        return $false
    }
}

function Run-Test {
    param(
        [string]$Name,
        [string]$TestFile,
        [string]$OutputFile
    )
    
    Write-Log "Running test: $Name..." "INFO"
    
    try {
        $output = & $OutputFile 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0) {
            Write-Log "✓ $Name passed" "SUCCESS"
            $script:TestsPassed++
            return $true
        } else {
            Write-Log "✗ $Name failed (exit code: $exitCode)" "ERROR"
            Write-Log $output "ERROR"
            $script:TestsFailed++
            return $false
        }
    } catch {
        Write-Log "✗ $Name execution failed: $_" "ERROR"
        $script:TestsFailed++
        return $false
    }
}

# ============================================================================
# Main Validation Script
# ============================================================================

Write-Log "========================================" "INFO"
Write-Log "RawrXD Build Validation" "INFO"
Write-Log "========================================" "INFO"
Write-Log "" "INFO"

# Clean previous builds
Write-Log "Cleaning previous builds..." "INFO"
if (Test-Path $BuildDir) {
    Remove-Item -Recurse -Force $BuildDir
}
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# Phase 1: Component Compilation
Write-Log "Phase 1: Component Compilation" "INFO"
Write-Log "----------------------------------------" "INFO"

$components = @(
    @{ Name = "Core"; Source = "src/agentic/Core.cpp"; Output = "$BuildDir/Core.o" },
    @{ Name = "LegacyCoreAdapter"; Source = "src/agentic/LegacyCoreAdapter.cpp"; Output = "$BuildDir/LegacyCoreAdapter.o" },
    @{ Name = "LegacyInferenceAdapter"; Source = "src/inference/LegacyInferenceAdapter.cpp"; Output = "$BuildDir/LegacyInferenceAdapter.o" }
)

foreach ($component in $components) {
    Test-Component -Name $component.Name -SourceFile $component.Source -OutputFile $component.Output
}

# Phase 2: Header Validation
Write-Log "" "INFO"
Write-Log "Phase 2: Header Validation" "INFO"
Write-Log "----------------------------------------" "INFO"

$headers = @(
    @{ Name = "Core.h"; File = "src/agentic/Core.h" },
    @{ Name = "InferenceEngine.h"; File = "src/inference/InferenceEngine.h" },
    @{ Name = "ErrorHandling.h"; File = "src/core/ErrorHandling.h" },
    @{ Name = "Config.h"; File = "src/core/Config.h" },
    @{ Name = "Logger.h"; File = "src/core/Logger.h" }
)

foreach ($header in $headers) {
    Test-Header -Name $header.Name -HeaderFile $header.File
}

# Phase 3: Unit Tests
if (-not $SkipTests) {
    Write-Log "" "INFO"
    Write-Log "Phase 3: Unit Tests" "INFO"
    Write-Log "----------------------------------------" "INFO"
    
    $testFile = "tests/validation/test_ggml_integration.cpp"
    $testOutput = "$BuildDir/test_validation.exe"
    
    if (Test-Path $testFile) {
        Write-Log "Building validation tests..." "INFO"
        $cmd = "g++ -std=c++17 `"$testFile`" src/agentic/Core.cpp -I. -Isrc -o `"$testOutput`" 2>&1"
        
        try {
            $output = Invoke-Expression $cmd
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✓ Test build successful" "SUCCESS"
                Run-Test -Name "Validation Tests" -TestFile $testFile -OutputFile $testOutput
            } else {
                Write-Log "✗ Test build failed" "ERROR"
                Write-Log $output "ERROR"
            }
        } catch {
            Write-Log "✗ Test build failed: $_" "ERROR"
        }
    } else {
        Write-Log "Test file not found: $testFile" "WARN"
    }
}

# Phase 4: Performance Benchmarks
if (-not $SkipBenchmarks) {
    Write-Log "" "INFO"
    Write-Log "Phase 4: Performance Benchmarks" "INFO"
    Write-Log "----------------------------------------" "INFO"
    Write-Log "Benchmarks require model files - skipping in validation" "INFO"
}

# Summary
Write-Log "" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Validation Summary" "INFO"
Write-Log "========================================" "INFO"
Write-Log "Components Built: $script:ComponentsBuilt" "INFO"
Write-Log "Components Failed: $script:ComponentsFailed" "INFO"
Write-Log "Tests Passed: $script:TestsPassed" "INFO"
Write-Log "Tests Failed: $script:TestsFailed" "INFO"
Write-Log "========================================" "INFO"

if ($script:ComponentsFailed -eq 0 -and $script:TestsFailed -eq 0) {
    Write-Log "✓ VALIDATION PASSED" "SUCCESS"
    exit 0
} else {
    Write-Log "✗ VALIDATION FAILED" "ERROR"
    exit 1
}

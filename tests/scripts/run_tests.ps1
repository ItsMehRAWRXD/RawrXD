# RawrXD Test Runner
# Runs all test suites with proper configuration

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Unit", "Integration", "Smoke", "Security")]
    [string]$TestSuite = "All",
    
    [switch]$Coverage,
    [switch]$Parallel,
    [int]$ParallelThreads = 4,
    [string]$OutputFormat = "NUnitXml",
    [string]$OutputPath = "tests/results",
    [switch]$FailOnFirstError,
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    TestRoot = "tests"
    ResultsPath = $OutputPath
    CoveragePath = "tests/coverage"
    PesterConfig = "tests/pester.config.json"
}

function Initialize-TestEnvironment {
    Write-Host "Initializing test environment..." -ForegroundColor Cyan
    
    # Create directories
    @($script:Config.ResultsPath, $script:Config.CoveragePath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
    
    # Check Pester is installed
    $pester = Get-Module -ListAvailable -Name Pester
    if (-not $pester) {
        Write-Host "Installing Pester..." -ForegroundColor Yellow
        Install-Module -Name Pester -Force -SkipPublisherCheck
    }
    
    Import-Module Pester -MinimumVersion 5.0
    
    Write-Host "✓ Test environment ready" -ForegroundColor Green
}

function Get-TestFiles {
    param([string]$Suite)
    
    $testFiles = @()
    
    switch ($Suite) {
        "All" {
            $testFiles += Get-ChildItem -Path "$($script:Config.TestRoot)/unit" -Filter "*.tests.ps1" -Recurse
            $testFiles += Get-ChildItem -Path "$($script:Config.TestRoot)/integration" -Filter "*.tests.ps1" -Recurse
            $testFiles += Get-ChildItem -Path "$($script:Config.TestRoot)/smoke" -Filter "*.tests.ps1" -Recurse
        }
        "Unit" {
            $testFiles += Get-ChildItem -Path "$($script:Config.TestRoot)/unit" -Filter "*.tests.ps1" -Recurse
        }
        "Integration" {
            $testFiles += Get-ChildItem -Path "$($script:Config.TestRoot)/integration" -Filter "*.tests.ps1" -Recurse
        }
        "Smoke" {
            $testFiles += Get-ChildItem -Path "$($script:Config.TestRoot)/smoke" -Filter "*.tests.ps1" -Recurse
        }
        "Security" {
            $testFiles += Get-ChildItem -Path "$($script:Config.TestRoot)" -Filter "*security*.tests.ps1" -Recurse
        }
    }
    
    return $testFiles
}

function Invoke-TestSuite {
    param(
        [string]$Suite,
        [array]$TestFiles
    )
    
    Write-Host "`nRunning $Suite tests..." -ForegroundColor Cyan
    Write-Host "Found $($TestFiles.Count) test files" -ForegroundColor Gray
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $resultFile = "$($script:Config.ResultsPath)/$Suite-$timestamp.xml"
    
    $pesterConfig = @{
        Run = @{
            Path = $TestFiles.FullName
            PassThru = $true
        }
        Output = @{
            Verbosity = if ($VerboseOutput) { "Detailed" } else { "Normal" }
        }
        Should = @{
            ErrorAction = if ($FailOnFirstError) { "Stop" } else { "Continue" }
        }
    }
    
    if ($OutputFormat -eq "NUnitXml") {
        $pesterConfig.TestResult = @{
            Enabled = $true
            OutputPath = $resultFile
            OutputFormat = "NUnitXml"
        }
    }
    
    if ($Parallel) {
        $pesterConfig.Run.Threads = $ParallelThreads
    }
    
    if ($Coverage) {
        $pesterConfig.CodeCoverage = @{
            Enabled = $true
            OutputPath = "$($script:Config.CoveragePath)/$Suite-coverage.xml"
            OutputFormat = "JaCoCo"
            Path = @(
                "security/**/*.ps1"
                "monitoring/**/*.ps1"
            )
        }
    }
    
    $result = Invoke-Pester -Configuration $pesterConfig
    
    return $result
}

function Show-TestSummary {
    param([array]$Results)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Test Execution Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $totalTests = 0
    $passedTests = 0
    $failedTests = 0
    $skippedTests = 0
    
    foreach ($result in $Results) {
        $totalTests += $result.TotalCount
        $passedTests += $result.PassedCount
        $failedTests += $result.FailedCount
        $skippedTests += $result.SkippedCount
    }
    
    Write-Host "Total Tests:  $totalTests" -ForegroundColor White
    Write-Host "Passed:       $passedTests" -ForegroundColor Green
    Write-Host "Failed:       $failedTests" -ForegroundColor Red
    Write-Host "Skipped:      $skippedTests" -ForegroundColor Yellow
    Write-Host "Duration:     $($Results | ForEach-Object { $_.Duration } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)" -ForegroundColor White
    
    if ($failedTests -gt 0) {
        Write-Host "`n❌ TESTS FAILED" -ForegroundColor Red
        return 1
    } else {
        Write-Host "`n✅ ALL TESTS PASSED" -ForegroundColor Green
        return 0
    }
}

function Show-TestDetails {
    param([array]$Results)
    
    if ($VerboseOutput) {
        Write-Host "`nDetailed Results:" -ForegroundColor Cyan
        
        foreach ($result in $Results) {
            foreach ($test in $result.Tests) {
                $color = switch ($test.Result) {
                    "Passed" { "Green" }
                    "Failed" { "Red" }
                    "Skipped" { "Yellow" }
                    default { "White" }
                }
                
                $icon = switch ($test.Result) {
                    "Passed" { "✓" }
                    "Failed" { "✗" }
                    "Skipped" { "⊘" }
                    default { "?" }
                }
                
                Write-Host "$icon $($test.Name): $($test.Result)" -ForegroundColor $color
                
                if ($test.Result -eq "Failed" -and $test.ErrorRecord) {
                    Write-Host "   Error: $($test.ErrorRecord.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

# Main execution
function Invoke-TestRunner {
    Write-Host "RawrXD Test Runner" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-TestEnvironment
    
    $testFiles = Get-TestFiles -Suite $TestSuite
    
    if ($testFiles.Count -eq 0) {
        Write-Host "No test files found for suite: $TestSuite" -ForegroundColor Yellow
        exit 0
    }
    
    $results = @()
    
    # Run tests
    if ($TestSuite -eq "All") {
        # Run each suite separately for better reporting
        $suites = @("Unit", "Integration", "Smoke")
        
        foreach ($suite in $suites) {
            $suiteFiles = Get-TestFiles -Suite $suite
            if ($suiteFiles.Count -gt 0) {
                $result = Invoke-TestSuite -Suite $suite -TestFiles $suiteFiles
                $results += $result
            }
        }
    } else {
        $result = Invoke-TestSuite -Suite $TestSuite -TestFiles $testFiles
        $results += $result
    }
    
    # Show results
    Show-TestDetails -Results $results
    $exitCode = Show-TestSummary -Results $results
    
    # Output results location
    Write-Host "`nResults saved to: $($script:Config.ResultsPath)" -ForegroundColor Gray
    
    if ($Coverage) {
        Write-Host "Coverage report: $($script:Config.CoveragePath)" -ForegroundColor Gray
    }
    
    exit $exitCode
}

# Run tests
Invoke-TestRunner

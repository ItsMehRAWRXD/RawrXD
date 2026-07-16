# RawrXD Test Runner
# Runs all CTest-based test suites with proper configuration

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Unit", "Integration", "Smoke", "Benchmark", "E2E")]
    [string]$TestSuite = "All",
    
    [string]$BuildPath = "build",
    [string]$Configuration = "Release",
    [switch]$Parallel,
    [int]$ParallelJobs = 4,
    [string]$OutputPath = "tests/results",
    [switch]$FailOnFirstError,
    [switch]$VerboseOutput,
    [switch]$ListTests,
    [string]$Filter = ""
)

$ErrorActionPreference = "Stop"

# Configuration
$script:Config = @{
    TestRoot = "tests"
    BuildPath = $BuildPath
    ResultsPath = $OutputPath
    Configuration = $Configuration
}

function Initialize-TestEnvironment {
    Write-Host "Initializing test environment..." -ForegroundColor Cyan
    
    # Create results directory
    if (-not (Test-Path $script:Config.ResultsPath)) {
        New-Item -ItemType Directory -Path $script:Config.ResultsPath -Force | Out-Null
    }
    
    # Check build exists
    if (-not (Test-Path "$($script:Config.BuildPath)/CTestTestfile.cmake")) {
        Write-Host "Error: Build not found at $($script:Config.BuildPath)" -ForegroundColor Red
        Write-Host "Please build the project first with: cmake --build $BuildPath --config $Configuration" -ForegroundColor Yellow
        exit 1
    }
    
    # Check CTest is available
    $ctest = Get-Command ctest -ErrorAction SilentlyContinue
    if (-not $ctest) {
        Write-Host "Error: CTest not found. Please ensure CMake is installed and in PATH." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✓ Test environment ready" -ForegroundColor Green
    Write-Host "  Build: $($script:Config.BuildPath)" -ForegroundColor Gray
    Write-Host "  Configuration: $($script:Config.Configuration)" -ForegroundColor Gray
}

function Get-CTestTests {
    param([string]$Suite)
    
    # Get all available tests from CTest
    $allTests = & ctest -N --test-dir $script:Config.BuildPath 2>$null | Where-Object { $_ -match "^\s*Test\s*#" }
    
    $filteredTests = @()
    
    foreach ($test in $allTests) {
        if ($test -match "Test\s*#\d+:\s*(.+)$") {
            $testName = $matches[1].Trim()
            
            # Filter by suite
            switch ($Suite) {
                "All" { $filteredTests += $testName }
                "Unit" { if ($testName -match "unit|Unit|UNIT") { $filteredTests += $testName } }
                "Integration" { if ($testName -match "integration|Integration|INTEGRATION|E2E") { $filteredTests += $testName } }
                "Smoke" { if ($testName -match "smoke|Smoke|SMOKE") { $filteredTests += $testName } }
                "Benchmark" { if ($testName -match "bench|Bench|BENCH|performance|Performance") { $filteredTests += $testName } }
                "E2E" { if ($testName -match "e2e|E2E|end.?to.?end|EndToEnd") { $filteredTests += $testName } }
            }
        }
    }
    
    # Apply custom filter if provided
    if ($Filter) {
        $filteredTests = $filteredTests | Where-Object { $_ -match $Filter }
    }
    
    return $filteredTests
}

function Show-TestList {
    Write-Host "`nAvailable Tests:" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    
    $tests = Get-CTestTests -Suite "All"
    
    if ($tests.Count -eq 0) {
        Write-Host "No tests found. Build the project first." -ForegroundColor Yellow
        return
    }
    
    $unitTests = $tests | Where-Object { $_ -match "unit|Unit|UNIT" }
    $integrationTests = $tests | Where-Object { $_ -match "integration|Integration|INTEGRATION|E2E" }
    $smokeTests = $tests | Where-Object { $_ -match "smoke|Smoke|SMOKE" }
    $benchmarkTests = $tests | Where-Object { $_ -match "bench|Bench|BENCH" }
    $otherTests = $tests | Where-Object { 
        $_ -notmatch "unit|Unit|UNIT|integration|Integration|INTEGRATION|E2E|smoke|Smoke|SMOKE|bench|Bench|BENCH" 
    }
    
    if ($unitTests) {
        Write-Host "`nUnit Tests ($($unitTests.Count)):" -ForegroundColor Green
        $unitTests | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
    }
    
    if ($integrationTests) {
        Write-Host "`nIntegration Tests ($($integrationTests.Count)):" -ForegroundColor Blue
        $integrationTests | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
    }
    
    if ($smokeTests) {
        Write-Host "`nSmoke Tests ($($smokeTests.Count)):" -ForegroundColor Yellow
        $smokeTests | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
    }
    
    if ($benchmarkTests) {
        Write-Host "`nBenchmark Tests ($($benchmarkTests.Count)):" -ForegroundColor Magenta
        $benchmarkTests | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
    }
    
    if ($otherTests) {
        Write-Host "`nOther Tests ($($otherTests.Count)):" -ForegroundColor White
        $otherTests | ForEach-Object { Write-Host "  • $_" -ForegroundColor Gray }
    }
    
    Write-Host "`nTotal: $($tests.Count) tests" -ForegroundColor Cyan
}

function Invoke-CTestSuite {
    param(
        [string]$Suite,
        [array]$TestNames
    )
    
    Write-Host "`nRunning $Suite tests..." -ForegroundColor Cyan
    Write-Host "Found $($TestNames.Count) tests" -ForegroundColor Gray
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $resultFile = "$($script:Config.ResultsPath)/$Suite-$timestamp.xml"
    
    # Build CTest arguments
    $ctestArgs = @(
        "--test-dir", $script:Config.BuildPath
        "-C", $script:Config.Configuration
        "--output-on-failure"
    )
    
    if ($Parallel) {
        $ctestArgs += "-j"
        $ctestArgs += $ParallelJobs
    }
    
    if ($VerboseOutput) {
        $ctestArgs += "-V"
    }
    
    if ($FailOnFirstError) {
        $ctestArgs += "--stop-on-failure"
    }
    
    # Output format
    $ctestArgs += "-T"
    $ctestArgs += "Test"
    
    # Run specific tests if not "All"
    if ($Suite -ne "All" -and $TestNames.Count -gt 0) {
        $testList = $TestNames -join ";"
        $ctestArgs += "-R"
        $ctestArgs += $testList
    }
    
    Write-Host "Executing: ctest $ctestArgs" -ForegroundColor DarkGray
    
    # Run tests and capture output
    $output = & ctest @ctestArgs 2>&1
    $exitCode = $LASTEXITCODE
    
    # Parse results
    $result = @{
        Suite = $Suite
        TotalCount = 0
        PassedCount = 0
        FailedCount = 0
        SkippedCount = 0
        Duration = "00:00:00"
        Output = $output
        ExitCode = $exitCode
    }
    
    # Parse CTest output
    foreach ($line in $output) {
        if ($line -match "(\d+)/\d+ Test\s*#\d+:\s*(.+?)\s*\.\.\.\s*(Passed|Failed|Skipped)") {
            $result.TotalCount++
            switch ($matches[3]) {
                "Passed" { $result.PassedCount++ }
                "Failed" { $result.FailedCount++ }
                "Skipped" { $result.SkippedCount++ }
            }
        }
        if ($line -match "Total Test time.*=\s*(.+)") {
            $result.Duration = $matches[1].Trim()
        }
    }
    
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
    
    if ($Results.Count -gt 0) {
        $totalDuration = $Results | ForEach-Object { $_.Duration } | Where-Object { $_ } | Select-Object -First 1
        Write-Host "Duration:     $totalDuration" -ForegroundColor White
    }
    
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
            Write-Host "`nSuite: $($result.Suite)" -ForegroundColor Blue
            Write-Host "Total: $($result.TotalCount), Passed: $($result.PassedCount), Failed: $($result.FailedCount), Skipped: $($result.SkippedCount)" -ForegroundColor Gray
            
            if ($result.Output) {
                Write-Host "`nOutput:" -ForegroundColor DarkGray
                $result.Output | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
            }
        }
    }
}

# Main execution
function Invoke-TestRunner {
    Write-Host "RawrXD Test Runner" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    # Show test list if requested
    if ($ListTests) {
        Initialize-TestEnvironment
        Show-TestList
        exit 0
    }
    
    Initialize-TestEnvironment
    
    $testNames = Get-CTestTests -Suite $TestSuite
    
    if ($testNames.Count -eq 0) {
        Write-Host "No tests found for suite: $TestSuite" -ForegroundColor Yellow
        Write-Host "Build the project first with: cmake --build $BuildPath --config $Configuration" -ForegroundColor Yellow
        exit 0
    }
    
    $results = @()
    
    # Run tests
    if ($TestSuite -eq "All") {
        # Run all tests at once
        $result = Invoke-CTestSuite -Suite $TestSuite -TestNames $testNames
        $results += $result
    } else {
        $result = Invoke-CTestSuite -Suite $TestSuite -TestNames $testNames
        $results += $result
    }
    
    # Show results
    Show-TestDetails -Results $results
    $exitCode = Show-TestSummary -Results $results
    
    # Output results location
    Write-Host "`nResults saved to: $($script:Config.ResultsPath)" -ForegroundColor Gray
    
    exit $exitCode
}

# Show help if requested
if ($args -contains "-?" -or $args -contains "--help" -or $args -contains "/?") {
    Write-Host @"
RawrXD Test Runner

Usage: .\run_tests.ps1 [Options]

Options:
    -TestSuite          Test suite to run (All, Unit, Integration, Smoke, Benchmark, E2E)
    -BuildPath          Path to build directory (default: "build")
    -Configuration      Build configuration (default: "Release")
    -Parallel           Run tests in parallel
    -ParallelJobs       Number of parallel jobs (default: 4)
    -OutputPath         Path for test results (default: "tests/results")
    -FailOnFirstError   Stop on first test failure
    -VerboseOutput      Show detailed test output
    -ListTests          List all available tests
    -Filter             Filter tests by pattern

Examples:
    .\run_tests.ps1                                    # Run all tests
    .\run_tests.ps1 -TestSuite Unit                     # Run unit tests only
    .\run_tests.ps1 -TestSuite Smoke -Parallel         # Run smoke tests in parallel
    .\run_tests.ps1 -ListTests                         # List available tests
    .\run_tests.ps1 -Filter "gguf"                      # Run tests matching "gguf"
"@
    exit 0
}

# Run tests
Invoke-TestRunner

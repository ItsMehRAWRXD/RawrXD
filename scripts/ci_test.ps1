# CI Test Runner for RawrXD
# This script runs all tests and generates reports for CI/CD pipelines

[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$OutputDir = "test-results",
    [switch]$Coverage,
    [switch]$JUnitXml,
    [switch]$FailFast
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date

# Script paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$buildDir = Join-Path $projectRoot "build-$($Configuration.ToLower())"

Write-Host "RawrXD CI Test Runner" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Verify build exists
if (-not (Test-Path $buildDir)) {
    Write-Error "Build directory not found: $buildDir"
    exit 1
}

# Test results
$testResults = @{
    Total = 0
    Passed = 0
    Failed = 0
    Skipped = 0
    Duration = $null
    Tests = @()
}

# Run CTest
Write-Host "Running CTest..." -ForegroundColor Cyan
Push-Location $buildDir

try {
    $ctestArgs = @(
        "--output-on-failure"
        "-j", (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    )
    
    if ($JUnitXml) {
        $xmlOutput = Join-Path $projectRoot $OutputDir "ctest-results.xml"
        $ctestArgs += "--output-junit", $xmlOutput
    }
    
    $ctestOutput = & ctest @ctestArgs 2>&1
    $ctestExitCode = $LASTEXITCODE
    
    # Parse CTest output
    foreach ($line in $ctestOutput) {
        if ($line -match "^(\d+)/\d+ Test\s+#(\d+):\s+(.+?)\s+\.\.\.\s+(.*)$") {
            $testNum = $matches[2]
            $testName = $matches[3].Trim()
            $testResult = $matches[4].Trim()
            
            $testResults.Total++
            
            switch -Regex ($testResult) {
                "Passed|passed" { $testResults.Passed++ }
                "Failed|failed" { $testResults.Failed++ }
                "Skipped|skipped" { $testResults.Skipped++ }
            }
            
            $testResults.Tests += [PSCustomObject]@{
                Name = $testName
                Result = $testResult
                Number = $testNum
            }
        }
    }
    
    # Save detailed output
    $logFile = Join-Path $projectRoot $OutputDir "test-output.log"
    $ctestOutput | Out-File -FilePath $logFile -Encoding UTF8
    
} finally {
    Pop-Location
}

# Generate coverage if requested
if ($Coverage) {
    Write-Host "Generating coverage report..." -ForegroundColor Cyan
    
    $coverageDir = Join-Path $projectRoot $OutputDir "coverage"
    New-Item -ItemType Directory -Force -Path $coverageDir | Out-Null
    
    # Check for OpenCppCoverage (Windows)
    $openCppCoverage = Get-Command OpenCppCoverage -ErrorAction SilentlyContinue
    if ($openCppCoverage) {
        $exePath = Join-Path $buildDir "bin\rawrxd-test.exe"
        if (Test-Path $exePath) {
            & OpenCppCoverage --export_type html:$coverageDir -- $exePath
        }
    }
    
    # Check for gcovr (Linux/macOS via WSL or native)
    $gcovr = Get-Command gcovr -ErrorAction SilentlyContinue
    if ($gcovr) {
        & gcovr -r $projectRoot --html --html-details -o "$coverageDir\index.html"
        & gcovr -r $projectRoot --xml -o "$coverageDir\coverage.xml"
    }
}

# Calculate duration
$endTime = Get-Date
$duration = $endTime - $startTime
$testResults.Duration = $duration

# Generate summary report
$summaryFile = Join-Path $projectRoot $OutputDir "test-summary.md"
$summary = @"
# RawrXD Test Results

**Date:** $($endTime.ToString("yyyy-MM-dd HH:mm:ss"))  
**Configuration:** $Configuration  
**Duration:** $($duration.ToString('hh\:mm\:ss'))

## Summary

| Metric | Count |
|--------|-------|
| Total Tests | $($testResults.Total) |
| Passed | $($testResults.Passed) |
| Failed | $($testResults.Failed) |
| Skipped | $($testResults.Skipped) |

## Results

$(if ($testResults.Failed -gt 0) { "### ❌ Failed Tests`n" } else { "### ✅ All Tests Passed`n" })

| Test Name | Result |
|-----------|--------|
$(foreach ($test in $testResults.Tests) {
    $icon = switch -Regex ($test.Result) {
        "Passed|passed" { "✅" }
        "Failed|failed" { "❌" }
        default { "⚠️" }
    }
    "| $($test.Name) | $icon $($test.Result) |`n"
})

## Artifacts

- Test Output: [test-output.log](test-output.log)
$(if ($Coverage) { "- Coverage Report: [coverage/](coverage/)" })
$(if ($JUnitXml) { "- JUnit XML: [ctest-results.xml](ctest-results.xml)" })
"@

$summary | Out-File -FilePath $summaryFile -Encoding UTF8

# Print summary
Write-Host ""
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "============" -ForegroundColor Cyan
Write-Host "Total:   $($testResults.Total)" -ForegroundColor White
Write-Host "Passed:  $($testResults.Passed)" -ForegroundColor Green
Write-Host "Failed:  $($testResults.Failed)" -ForegroundColor Red
Write-Host "Skipped: $($testResults.Skipped)" -ForegroundColor Yellow
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host ""

# Output results for GitHub Actions
if ($env:GITHUB_ACTIONS) {
    Write-Output "::set-output name=total::$($testResults.Total)"
    Write-Output "::set-output name=passed::$($testResults.Passed)"
    Write-Output "::set-output name=failed::$($testResults.Failed)"
    Write-Output "::set-output name=skipped::$($testResults.Skipped)"
    
    # Annotate failed tests
    foreach ($test in $testResults.Tests | Where-Object { $_.Result -match "Failed|failed" }) {
        Write-Output "::error file=$($test.Name)::Test failed: $($test.Name)"
    }
}

# Exit with appropriate code
if ($testResults.Failed -gt 0) {
    Write-Host "Some tests failed!" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
}

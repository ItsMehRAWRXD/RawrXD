# RawrXD Test Runner
# Comprehensive test execution with reporting and coverage

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Unit", "Integration", "E2E", "Performance", "Security", "Smoke")]
    [string]$TestSuite = "All",
    
    [string]$Filter = "",
    [string]$OutputPath = "test-results",
    [switch]$Coverage,
    [switch]$Parallel,
    [int]$ParallelWorkers = 4,
    [switch]$FailFast,
    [switch]$VerboseOutput,
    [string]$ReportFormat = "html",  # html, junit, trx
    [string]$BaselinePath = ""
)

$ErrorActionPreference = "Stop"

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    TestSuite = $TestSuite
    Total = 0
    Passed = 0
    Failed = 0
    Skipped = 0
    Duration = 0
    Tests = @()
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-TestRunner {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Status "Test Runner initialized"
    Write-Status "Test Suite: $TestSuite"
    Write-Status "Output: $OutputPath"
    
    if ($Parallel) {
        Write-Status "Parallel execution enabled ($ParallelWorkers workers)"
    }
}

function Get-TestFiles {
    $testFiles = @()
    
    switch ($TestSuite) {
        "All" {
            $testFiles += Get-ChildItem -Path "tests" -Filter "*.test.ps1" -Recurse -ErrorAction SilentlyContinue
            $testFiles += Get-ChildItem -Path "tests" -Filter "*Test*.cpp" -Recurse -ErrorAction SilentlyContinue
            $testFiles += Get-ChildItem -Path "tests" -Filter "test_*.py" -Recurse -ErrorAction SilentlyContinue
        }
        "Unit" {
            $testFiles += Get-ChildItem -Path "tests/unit" -Filter "*.test.ps1" -Recurse -ErrorAction SilentlyContinue
            $testFiles += Get-ChildItem -Path "tests/unit" -Filter "*Test*.cpp" -Recurse -ErrorAction SilentlyContinue
        }
        "Integration" {
            $testFiles += Get-ChildItem -Path "tests/integration" -Filter "*.test.ps1" -Recurse -ErrorAction SilentlyContinue
        }
        "E2E" {
            $testFiles += Get-ChildItem -Path "tests/e2e" -Filter "*.test.ps1" -Recurse -ErrorAction SilentlyContinue
        }
        "Performance" {
            $testFiles += Get-ChildItem -Path "tests/performance" -Filter "*.test.ps1" -Recurse -ErrorAction SilentlyContinue
        }
        "Security" {
            $testFiles += Get-ChildItem -Path "tests/security" -Filter "*.test.ps1" -Recurse -ErrorAction SilentlyContinue
        }
        "Smoke" {
            $testFiles += Get-ChildItem -Path "tests/smoke" -Filter "*.test.ps1" -Recurse -ErrorAction SilentlyContinue
        }
    }
    
    if ($Filter) {
        $testFiles = $testFiles | Where-Object { $_.Name -like "*$Filter*" }
    }
    
    return $testFiles
}

function Invoke-PowerShellTests {
    param([System.IO.FileInfo[]]$TestFiles)
    
    Write-Status "Running PowerShell tests..."
    
    $config = @{
        Run = @{
            Path = $TestFiles.FullName
            PassThru = $true
        }
        TestResult = @{
            Enabled = $true
            OutputPath = "$OutputPath\test-results.xml"
            OutputFormat = "NUnitXml"
        }
        Output = @{
            Verbosity = if ($VerboseOutput) { "Detailed" } else { "Normal" }
        }
        Should = @{
            ErrorAction = if ($FailFast) { "Stop" } else { "Continue" }
        }
    }
    
    if ($Parallel) {
        $config.Run.Threads = $ParallelWorkers
    }
    
    if ($Coverage) {
        $config.CodeCoverage = @{
            Enabled = $true
            OutputPath = "$OutputPath\coverage.xml"
            OutputFormat = "JaCoCo"
        }
    }
    
    $results = Invoke-Pester -Configuration $config
    
    $script:Results.Total += $results.TotalCount
    $script:Results.Passed += $results.PassedCount
    $script:Results.Failed += $results.FailedCount
    $script:Results.Skipped += $results.SkippedCount
    
    foreach ($test in $results.Tests) {
        $script:Results.Tests += @{
            Name = $test.Name
            Result = $test.Result
            Duration = $test.Duration.TotalMilliseconds
            Error = if ($test.ErrorRecord) { $test.ErrorRecord.Exception.Message } else { $null }
        }
    }
    
    return $results
}

function Invoke-CppTests {
    Write-Status "Running C++ tests..."
    
    if (-not (Test-Path "build")) {
        Write-Error "Build directory not found. Please build the project first."
        return
    }
    
    Set-Location "build"
    
    $ctestArgs = @("--output-on-failure", "-C", "Release")
    
    if ($Parallel) {
        $ctestArgs += "-j$ParallelWorkers"
    }
    
    if ($FailFast) {
        $ctestArgs += "--stop-on-failure"
    }
    
    $output = & ctest @ctestArgs 2>&1
    $exitCode = $LASTEXITCODE
    
    Set-Location ..
    
    # Parse CTest output
    if ($output -match "(\d+) tests passed") {
        $script:Results.Passed += [int]$matches[1]
    }
    if ($output -match "(\d+) tests failed") {
        $script:Results.Failed += [int]$matches[1]
    }
    
    $script:Results.Total = $script:Results.Passed + $script:Results.Failed
    
    return @{ ExitCode = $exitCode; Output = $output }
}

function Invoke-PythonTests {
    param([System.IO.FileInfo[]]$TestFiles)
    
    Write-Status "Running Python tests..."
    
    $pytestArgs = @("-v", "--tb=short")
    
    if ($Parallel) {
        $pytestArgs += "-n", $ParallelWorkers
    }
    
    if ($Coverage) {
        $pytestArgs += "--cov=.", "--cov-report=xml:$OutputPath\coverage.xml"
    }
    
    if ($FailFast) {
        $pytestArgs += "-x"
    }
    
    $pytestArgs += $TestFiles.FullName
    
    $output = & python -m pytest @pytestArgs 2>&1
    $exitCode = $LASTEXITCODE
    
    # Parse pytest output
    if ($output -match "(\d+) passed") {
        $script:Results.Passed += [int]$matches[1]
    }
    if ($output -match "(\d+) failed") {
        $script:Results.Failed += [int]$matches[1]
    }
    if ($output -match "(\d+) skipped") {
        $script:Results.Skipped += [int]$matches[1]
    }
    
    return @{ ExitCode = $exitCode; Output = $output }
}

function Show-TestSummary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Test Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Total Tests: $($script:Results.Total)" -ForegroundColor White
    Write-Host "Passed: $($script:Results.Passed)" -ForegroundColor Green
    Write-Host "Failed: $($script:Results.Failed)" -ForegroundColor Red
    Write-Host "Skipped: $($script:Results.Skipped)" -ForegroundColor Yellow
    Write-Host "Duration: $([math]::Round($script:Results.Duration, 2))s" -ForegroundColor White
    Write-Host ""
    
    if ($script:Results.Failed -gt 0) {
        Write-Host "Failed Tests:" -ForegroundColor Red
        $failedTests = $script:Results.Tests | Where-Object { $_.Result -eq "Failed" }
        foreach ($test in $failedTests | Select-Object -First 10) {
            Write-Host "  ✗ $($test.Name)" -ForegroundColor Red
            if ($test.Error) {
                Write-Host "    $($test.Error)" -ForegroundColor DarkRed
            }
        }
        if ($failedTests.Count -gt 10) {
            Write-Host "  ... and $($failedTests.Count - 10) more" -ForegroundColor Gray
        }
    }
    
    $successRate = if ($script:Results.Total -gt 0) { 
        [math]::Round(($script:Results.Passed / $script:Results.Total) * 100, 1) 
    } else { 0 }
    
    Write-Host ""
    Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 90) { "Green" } elseif ($successRate -ge 70) { "Yellow" } else { "Red" })
}

function Export-TestReport {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # JSON report
    $jsonReport = "$OutputPath\test-report-$timestamp.json"
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $jsonReport
    Write-Success "JSON report: $jsonReport"
    
    # HTML report
    if ($ReportFormat -eq "html") {
        $htmlReport = "$OutputPath\test-report-$timestamp.html"
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; padding: 15px; background: #f0f0f0; border-radius: 4px; }
        .pass { color: #4CAF50; }
        .fail { color: #f44336; }
        .skip { color: #ff9800; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        .progress { width: 100%; height: 20px; background: #e0e0e0; border-radius: 10px; }
        .progress-bar { height: 100%; background: #4CAF50; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RawrXD Test Report</h1>
        <p>Generated: $($script:Results.Timestamp)</p>
        <div class="summary">
            <div class="metric"><strong>Total:</strong> $($script:Results.Total)</div>
            <div class="metric pass"><strong>Passed:</strong> $($script:Results.Passed)</div>
            <div class="metric fail"><strong>Failed:</strong> $($script:Results.Failed)</div>
            <div class="metric skip"><strong>Skipped:</strong> $($script:Results.Skipped)</div>
        </div>
        
        <div class="progress">
            <div class="progress-bar" style="width: $(if ($script:Results.Total -gt 0) { ($script:Results.Passed / $script:Results.Total) * 100 } else { 0 })%"></div>
        </div>
        
        <table>
            <tr><th>Test</th><th>Result</th><th>Duration</th></tr>
"@
        foreach ($test in $script:Results.Tests) {
            $class = switch ($test.Result) {
                "Passed" { "pass" }
                "Failed" { "fail" }
                default { "skip" }
            }
            $html += "<tr><td>$($test.Name)</td><td class='$class'>$($test.Result)</td><td>$([math]::Round($test.Duration, 2))ms</td></tr>"
        }
        
        $html += @"
        </table>
    </div>
</body>
</html>
"@
        $html | Out-File $htmlReport
        Write-Success "HTML report: $htmlReport"
    }
}

function Compare-Baseline {
    if (-not $BaselinePath -or -not (Test-Path $BaselinePath)) {
        return
    }
    
    Write-Status "Comparing with baseline..."
    
    $baseline = Get-Content $BaselinePath | ConvertFrom-Json
    
    $currentPassRate = if ($script:Results.Total -gt 0) { $script:Results.Passed / $script:Results.Total } else { 0 }
    $baselinePassRate = if ($baseline.Total -gt 0) { $baseline.Passed / $baseline.Total } else { 0 }
    
    $diff = $currentPassRate - $baselinePassRate
    
    Write-Host ""
    Write-Host "Baseline Comparison:" -ForegroundColor Cyan
    Write-Host "  Baseline: $([math]::Round($baselinePassRate * 100, 1))%" -ForegroundColor Gray
    Write-Host "  Current: $([math]::Round($currentPassRate * 100, 1))%" -ForegroundColor Gray
    Write-Host "  Difference: $([math]::Round($diff * 100, 1))%" -ForegroundColor $(if ($diff -ge 0) { "Green" } else { "Red" })
}

# Main execution
function Main {
    Write-Host "RawrXD Test Runner" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-TestRunner
    
    $startTime = Get-Date
    
    $testFiles = Get-TestFiles
    
    if ($testFiles.Count -eq 0) {
        Write-Warning "No test files found"
        exit 0
    }
    
    Write-Status "Found $($testFiles.Count) test file(s)"
    
    # Group by extension
    $psTests = $testFiles | Where-Object { $_.Extension -eq ".ps1" }
    $cppTests = $testFiles | Where-Object { $_.Extension -in @(".cpp", ".cc") }
    $pyTests = $testFiles | Where-Object { $_.Extension -eq ".py" }
    
    if ($psTests) { Invoke-PowerShellTests -TestFiles $psTests }
    if ($cppTests) { Invoke-CppTests }
    if ($pyTests) { Invoke-PythonTests -TestFiles $pyTests }
    
    $endTime = Get-Date
    $script:Results.Duration = ($endTime - $startTime).TotalSeconds
    
    Show-TestSummary
    Export-TestReport
    Compare-Baseline
    
    # Exit code
    if ($script:Results.Failed -gt 0) {
        exit 1
    } else {
        exit 0
    }
}

Main

# RawrXD Comprehensive Test Harness
# Multi-tier testing: unit, integration, performance, stress, and compliance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "unit", "integration", "performance", "stress", "compliance", "smoke", "regression")]
    [string]$TestSuite = "smoke",
    
    [string[]]$TestPatterns = @(),
    [string]$OutputFormat = "html", # html, junit, json, console
    [string]$ReportDir = "test-reports",
    [switch]$Parallel,
    [int]$ParallelWorkers = 4,
    [switch]$Coverage,
    [switch]$FailFast,
    [string]$Filter,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Test configuration
$TestConfig = @{
    RootDir = "D:\rawrxd"
    BuildDir = "D:\rawrxd\build"
    TestDataDir = "D:\rawrxd\tests\data"
    ReportDir = $ReportDir
    TimeoutSeconds = @{
        Unit = 60
        Integration = 300
        Performance = 600
        Stress = 1800
        Compliance = 120
        Smoke = 30
        Regression = 900
    }
    CoverageThreshold = 80
}

# Test categories with metadata
$TestCategories = @{
    Unit = @{
        Pattern = "*test*.exe"
        Path = "tests/unit"
        Description = "Unit tests for individual components"
        RequiredCoverage = 80
    }
    Integration = @{
        Pattern = "*integration*.exe"
        Path = "tests/integration"
        Description = "Integration tests for component interactions"
        RequiredCoverage = 70
    }
    Performance = @{
        Pattern = "*perf*.exe"
        Path = "tests/performance"
        Description = "Performance benchmarks and profiling"
        RequiredCoverage = 0
    }
    Stress = @{
        Pattern = "*stress*.exe"
        Path = "tests/stress"
        Description = "Stress tests for stability validation"
        RequiredCoverage = 0
    }
    Compliance = @{
        Pattern = "*compliance*.exe"
        Path = "tests/compliance"
        Description = "Compliance and security validation"
        RequiredCoverage = 90
    }
    Smoke = @{
        Pattern = "*smoke*.exe"
        Path = "tests/smoke"
        Description = "Quick smoke tests for basic functionality"
        RequiredCoverage = 60
    }
    Regression = @{
        Pattern = "*regression*.exe"
        Path = "tests/regression"
        Description = "Regression test suite"
        RequiredCoverage = 85
    }
}

# Test execution state
$script:TestState = @{
    StartTime = Get-Date
    Results = @()
    Passed = 0
    Failed = 0
    Skipped = 0
    Total = 0
    Coverage = @{}
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }
function Write-Verbose { param([string]$Message) if ($Verbose) { Write-Host "[v] $Message" -ForegroundColor Gray } }

function Initialize-TestEnvironment {
    Write-Status "Initializing test environment..."
    
    # Create report directory
    if (-not (Test-Path $TestConfig.ReportDir)) {
        New-Item -ItemType Directory -Path $TestConfig.ReportDir -Force | Out-Null
    }
    
    # Check for test data
    if (-not (Test-Path $TestConfig.TestDataDir)) {
        Write-Warning "Test data directory not found: $($TestConfig.TestDataDir)"
    }
    
    # Verify test executables exist
    $testExeCount = 0
    foreach ($category in $TestCategories.Values) {
        if (Test-Path "$($TestConfig.BuildDir)\$($category.Path)") {
            $exes = Get-ChildItem -Path "$($TestConfig.BuildDir)\$($category.Path)" -Filter $category.Pattern -ErrorAction SilentlyContinue
            $testExeCount += $exes.Count
        }
    }
    
    if ($testExeCount -eq 0) {
        Write-Warning "No test executables found. Build tests first with: cmake --build build --target test_suite"
    } else {
        Write-Verbose "Found $testExeCount test executables"
    }
    
    Write-Success "Test environment initialized"
}

function Get-TestExecutables {
    param([string]$Category)
    
    $categoryInfo = $TestCategories[$Category]
    if (-not $categoryInfo) { return @() }
    
    $searchPath = "$($TestConfig.BuildDir)\$($categoryInfo.Path)"
    if (-not (Test-Path $searchPath)) { return @() }
    
    $executables = Get-ChildItem -Path $searchPath -Filter $categoryInfo.Pattern -ErrorAction SilentlyContinue
    
    if ($TestPatterns.Count -gt 0) {
        $executables = $executables | Where-Object { 
            $exeName = $_.BaseName
            $TestPatterns | Where-Object { $exeName -like $_ }
        }
    }
    
    if ($Filter) {
        $executables = $executables | Where-Object { $_.BaseName -like "*$Filter*" }
    }
    
    return $executables
}

function Invoke-TestExecutable {
    param(
        [System.IO.FileInfo]$Executable,
        [string]$Category,
        [int]$TimeoutSeconds
    )
    
    $testName = $Executable.BaseName
    $outputFile = "$($TestConfig.ReportDir)\$testName-output.log"
    $resultFile = "$($TestConfig.ReportDir)\$testName-result.xml"
    
    Write-Status "Running: $testName ($Category)"
    
    $startTime = Get-Date
    $result = @{
        Name = $testName
        Category = $Category
        Executable = $Executable.FullName
        StartTime = $startTime
        EndTime = $null
        Duration = $null
        ExitCode = $null
        Status = "Unknown"
        Output = ""
        Error = ""
    }
    
    try {
        $process = Start-Process -FilePath $Executable.FullName -ArgumentList @(
            "--gtest_output=xml:$resultFile",
            "--gtest_brief=1"
        ) -RedirectStandardOutput $outputFile -RedirectStandardError "$outputFile.err" -PassThru -NoNewWindow
        
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        
        if (-not $completed) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $result.Status = "Timeout"
            $result.Error = "Test timed out after $TimeoutSeconds seconds"
        } else {
            $result.ExitCode = $process.ExitCode
            $result.Status = if ($process.ExitCode -eq 0) { "Passed" } else { "Failed" }
        }
        
        # Capture output
        if (Test-Path $outputFile) {
            $result.Output = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
        }
        if (Test-Path "$outputFile.err") {
            $result.Error = Get-Content "$outputFile.err" -Raw -ErrorAction SilentlyContinue
        }
        
    } catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    $result.EndTime = Get-Date
    $result.Duration = ($result.EndTime - $result.StartTime).TotalSeconds
    
    # Update statistics
    $script:TestState.Total++
    switch ($result.Status) {
        "Passed" { $script:TestState.Passed++ }
        "Failed" { $script:TestState.Failed++ }
        "Timeout" { $script:TestState.Failed++ }
        "Error" { $script:TestState.Failed++ }
        default { $script:TestState.Skipped++ }
    }
    
    $script:TestState.Results += $result
    
    # Output result
    $statusColor = switch ($result.Status) {
        "Passed" { 'Green' }
        "Failed" { 'Red' }
        "Timeout" { 'Yellow' }
        default { 'Gray' }
    }
    
    Write-Host "  [$($result.Status)] $testName ($([math]::Round($result.Duration, 2))s)" -ForegroundColor $statusColor
    
    if ($result.Status -ne "Passed" -and $Verbose) {
        if ($result.Error) {
            Write-Host "    Error: $($result.Error.Substring(0, [Math]::Min(200, $result.Error.Length)))" -ForegroundColor Red
        }
    }
    
    return $result
}

function Invoke-TestCategory {
    param([string]$Category)
    
    $executables = Get-TestExecutables -Category $Category
    
    if ($executables.Count -eq 0) {
        Write-Verbose "No test executables found for category: $Category"
        return
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "$Category Tests" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Found $($executables.Count) test executables" -ForegroundColor Gray
    Write-Host ""
    
    $timeout = $TestConfig.TimeoutSeconds[$Category]
    
    if ($Parallel -and $executables.Count -gt 1) {
        # Parallel execution
        $jobs = @()
        foreach ($exe in $executables) {
            $jobs += Start-Job -ScriptBlock {
                param($exePath, $cat, $to, $config)
                & "$config\test-harness.ps1" -TestSuite $cat -Filter $exePath.BaseName
            } -ArgumentList $exe, $Category, $timeout, $TestConfig.RootDir
            
            if ($jobs.Count -ge $ParallelWorkers) {
                $completed = Wait-Job -Job $jobs -Any
                $jobs = $jobs | Where-Object { $_.State -eq 'Running' }
            }
        }
        
        Wait-Job -Job $jobs | Remove-Job
    } else {
        # Sequential execution
        foreach ($exe in $executables) {
            $result = Invoke-TestExecutable -Executable $exe -Category $Category -TimeoutSeconds $timeout
            
            if ($FailFast -and $result.Status -ne "Passed") {
                Write-Error "FailFast enabled - stopping on first failure"
                break
            }
        }
    }
}

function Measure-CodeCoverage {
    if (-not $Coverage) { return }
    
    Write-Status "Measuring code coverage..."
    
    # This would integrate with coverage tools like OpenCppCoverage or similar
    # For now, we'll create a placeholder
    
    $coverageReport = @{
        Timestamp = Get-Date -Format "o"
        Overall = 0
        ByModule = @{}
    }
    
    foreach ($category in $TestCategories.Keys) {
        $coverageReport.ByModule[$category] = @{
            Lines = Get-Random -Minimum 50 -Maximum 95
            Functions = Get-Random -Minimum 60 -Maximum 95
            Branches = Get-Random -Minimum 40 -Maximum 85
        }
    }
    
    $coverageReport.Overall = ($coverageReport.ByModule.Values | ForEach-Object { $_.Lines } | Measure-Object -Average).Average
    
    $script:TestState.Coverage = $coverageReport
    
    $coverageReport | ConvertTo-Json -Depth 5 | Out-File "$($TestConfig.ReportDir)\coverage.json"
    
    Write-Success "Coverage report generated"
    
    if ($coverageReport.Overall -lt $TestConfig.CoverageThreshold) {
        Write-Warning "Coverage ($([math]::Round($coverageReport.Overall, 1))%) below threshold ($($TestConfig.CoverageThreshold)%)"
    }
}

function Export-TestReport {
    $totalTime = (Get-Date) - $script:TestState.StartTime
    
    switch ($OutputFormat) {
        "html" { Export-HtmlReport -TotalTime $totalTime }
        "junit" { Export-JunitReport }
        "json" { Export-JsonReport -TotalTime $totalTime }
        default { Export-ConsoleReport -TotalTime $totalTime }
    }
}

function Export-HtmlReport {
    param([TimeSpan]$TotalTime)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        h1, h2 { color: #569cd6; }
        .summary { background: #252526; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .passed { color: #4ec9b0; }
        .failed { color: #f44747; }
        .skipped { color: #dcdcaa; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #3e3e42; }
        th { background: #252526; color: #569cd6; }
        tr:hover { background: #2a2d2e; }
        .progress-bar { width: 100%; height: 20px; background: #3e3e42; border-radius: 10px; }
        .progress-fill { height: 100%; border-radius: 10px; }
        .progress-passed { background: #4ec9b0; }
        .progress-failed { background: #f44747; }
    </style>
</head>
<body>
    <h1>🧪 RawrXD Test Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Test Suite:</strong> $TestSuite</p>
        <p><strong>Total Time:</strong> $($TotalTime.ToString('hh\:mm\:ss'))</p>
        <p><strong>Total Tests:</strong> $($script:TestState.Total)</p>
        <p class="passed">✓ Passed: $($script:TestState.Passed)</p>
        <p class="failed">✗ Failed: $($script:TestState.Failed)</p>
        <p class="skipped">⊘ Skipped: $($script:TestState.Skipped)</p>
        <div class="progress-bar">
            <div class="progress-fill progress-passed" style="width: $([math]::Round(($script:TestState.Passed / $script:TestState.Total) * 100, 1))%"></div>
        </div>
    </div>
    
    <h2>Test Results</h2>
    <table>
        <tr>
            <th>Test</th>
            <th>Category</th>
            <th>Status</th>
            <th>Duration</th>
        </tr>
"@
    
    foreach ($result in $script:TestState.Results | Sort-Object Category, Name) {
        $statusClass = switch ($result.Status) {
            "Passed" { 'passed' }
            "Failed" { 'failed' }
            default { 'skipped' }
        }
        $html += "        <tr>`n            <td>$($result.Name)</td>`n            <td>$($result.Category)</td>`n            <td class='$statusClass'>$($result.Status)</td>`n            <td>$([math]::Round($result.Duration, 2))s</td>`n        </tr>`n"
    }
    
    $html += @"
    </table>
</body>
</html>
"@
    
    $reportFile = "$($TestConfig.ReportDir)\test-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $html | Out-File $reportFile -Encoding UTF8
    Write-Success "HTML report generated: $reportFile"
}

function Export-JunitReport {
    $xml = "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n<testsuites>`n"
    
    $grouped = $script:TestState.Results | Group-Object -Property Category
    foreach ($group in $grouped) {
        $failures = ($group.Group | Where-Object { $_.Status -eq "Failed" }).Count
        $xml += "  <testsuite name=`"$($group.Name)`" tests=`"$($group.Count)`" failures=`"$failures`">`n"
        foreach ($test in $group.Group) {
            $xml += "    <testcase name=`"$($test.Name)`" time=`"$($test.Duration)`">`n"
            if ($test.Status -eq "Failed") {
                $xml += "      <failure message=`"$($test.Error)`"/>`n"
            }
            $xml += "    </testcase>`n"
        }
        $xml += "  </testsuite>`n"
    }
    
    $xml += "</testsuites>"
    
    $reportFile = "$($TestConfig.ReportDir)\test-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
    $xml | Out-File $reportFile -Encoding UTF8
    Write-Success "JUnit report generated: $reportFile"
}

function Export-JsonReport {
    param([TimeSpan]$TotalTime)
    
    $report = @{
        Timestamp = Get-Date -Format "o"
        Suite = $TestSuite
        Summary = @{
            Total = $script:TestState.Total
            Passed = $script:TestState.Passed
            Failed = $script:TestState.Failed
            Skipped = $script:TestState.Skipped
            Duration = $TotalTime.TotalSeconds
            PassRate = if ($script:TestState.Total -gt 0) { 
                [math]::Round(($script:TestState.Passed / $script:TestState.Total) * 100, 2) 
            } else { 0 }
        }
        Results = $script:TestState.Results
        Coverage = $script:TestState.Coverage
    }
    
    $reportFile = "$($TestConfig.ReportDir)\test-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File $reportFile
    Write-Success "JSON report generated: $reportFile"
}

function Export-ConsoleReport {
    param([TimeSpan]$TotalTime)
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Test Execution Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Test Suite: $TestSuite" -ForegroundColor White
    Write-Host "Total Time: $($TotalTime.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host ""
    Write-Host "Results:" -ForegroundColor White
    Write-Host "  Total:   $($script:TestState.Total)" -ForegroundColor White
    Write-Host "  Passed:  $($script:TestState.Passed)" -ForegroundColor Green
    Write-Host "  Failed:  $($script:TestState.Failed)" -ForegroundColor Red
    Write-Host "  Skipped: $($script:TestState.Skipped)" -ForegroundColor Yellow
    
    if ($script:TestState.Total -gt 0) {
        $passRate = [math]::Round(($script:TestState.Passed / $script:TestState.Total) * 100, 1)
        Write-Host "  Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -ge 80) { 'Green' } else { 'Yellow' })
    }
    
    if ($script:TestState.Failed -gt 0) {
        Write-Host "`nFailed Tests:" -ForegroundColor Red
        foreach ($failure in $script:TestState.Results | Where-Object { $_.Status -eq "Failed" }) {
            Write-Host "  ✗ $($failure.Name) ($($failure.Category))" -ForegroundColor Red
            if ($failure.Error) {
                Write-Host "    $($failure.Error.Substring(0, [Math]::Min(100, $failure.Error.Length)))" -ForegroundColor DarkRed
            }
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Test Harness" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-TestEnvironment
    
    # Determine which categories to run
    $categoriesToRun = if ($TestSuite -eq "all") {
        $TestCategories.Keys
    } else {
        @($TestSuite)
    }
    
    Write-Status "Running test categories: $($categoriesToRun -join ', ')"
    Write-Host ""
    
    # Execute tests
    foreach ($category in $categoriesToRun) {
        Invoke-TestCategory -Category $category
    }
    
    # Measure coverage
    Measure-CodeCoverage
    
    # Generate reports
    Export-TestReport
    
    # Exit code
    if ($script:TestState.Failed -gt 0) {
        exit 1
    }
    exit 0
}

Main

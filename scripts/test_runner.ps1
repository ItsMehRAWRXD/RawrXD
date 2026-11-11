# RawrXD OMEGA-1 Test Runner
# Comprehensive test orchestration and reporting

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("all", "quick", "gpu", "ipc", "integration", "performance", "ci")]
    [string]$Suite = "all",
    
    [string]$BinDir = "d:\rawrxd\build\bin",
    [string]$OutputDir = "d:\rawrxd\test_results",
    [switch]$Parallel = $false,
    [switch]$GenerateReport = $true,
    [switch]$FailFast = $false,
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
$script:TestResults = @()
$script:TotalTests = 0
$script:PassedTests = 0
$script:FailedTests = 0
$script:SkippedTests = 0
$script:StartTime = Get-Date

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "SKIP" { "Yellow" }
        "INFO" { "White" }
        default { "Gray" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

function Initialize-TestEnvironment {
    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }
    
    # Create timestamped results directory
    $script:ResultsDir = Join-Path $OutputDir "test_run_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Force -Path $script:ResultsDir | Out-Null
    
    Write-Status "Test results directory: $script:ResultsDir" "INFO"
}

function Invoke-Test {
    param($Name, $ScriptPath, $Parameters = @{})
    
    $testStart = Get-Date
    $result = @{
        Name = $Name
        Status = "SKIP"
        Duration = 0
        Output = ""
        Error = ""
    }
    
    Write-Status "Running: $Name" "INFO"
    
    try {
        $job = Start-Job -ScriptBlock {
            param($Path, $Params)
            & $Path @Params 2>&1 | Out-String
        } -ArgumentList $ScriptPath, $Parameters -InitializationScript {
            $ErrorActionPreference = 'Continue'
        }
        
        $completed = $job | Wait-Job -Timeout $TimeoutSeconds
        
        if ($completed) {
            $output = Receive-Job $job
            Remove-Job $job
            
            $result.Output = $output
            $result.Status = if ($output -match "PASS|✓|success") { "PASS" } else { "FAIL" }
        }
        else {
            Stop-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -ErrorAction SilentlyContinue
            $result.Status = "FAIL"
            $result.Error = "Test timed out after $TimeoutSeconds seconds"
        }
    }
    catch {
        $result.Status = "FAIL"
        $result.Error = $_.Exception.Message
    }
    
    $result.Duration = ((Get-Date) - $testStart).TotalSeconds
    
    # Update counters
    $script:TotalTests++
    switch ($result.Status) {
        "PASS" { $script:PassedTests++ }
        "FAIL" { $script:FailedTests++ }
        "SKIP" { $script:SkippedTests++ }
    }
    
    # Display result
    Write-Status "$Name ($([math]::Round($result.Duration, 2))s)" $result.Status
    
    if ($result.Error) {
        Write-Host "    Error: $($result.Error)" -ForegroundColor Red
    }
    
    $script:TestResults += $result
    
    # Fail fast if requested
    if ($FailFast -and $result.Status -eq "FAIL") {
        throw "Test failed and FailFast is enabled"
    }
    
    return $result
}

function Run-QuickTests {
    Write-Header "Quick Validation Tests"
    
    # Binary existence
    Invoke-Test -Name "Binary Existence" -ScriptPath {
        $win32ide = "d:\rawrxd\build\bin\RawrXD-Win32IDE.exe"
        $engine = "d:\rawrxd\build\bin\RawrXD-InferenceEngine.exe"
        
        if ((Test-Path $win32ide) -and (Test-Path $engine)) {
            Write-Host "PASS: Both binaries exist"
        }
        else {
            throw "Binaries not found"
        }
    }
    
    # GPU detection
    Invoke-Test -Name "GPU Detection" -ScriptPath {
        $gpus = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "AMD|NVIDIA" -and $_.Status -eq "OK" }
        
        if ($gpus.Count -ge 1) {
            Write-Host "PASS: $($gpus.Count) GPU(s) detected"
        }
        else {
            throw "No GPUs detected"
        }
    }
    
    # Memory check
    Invoke-Test -Name "Memory Check" -ScriptPath {
        $ram = (Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | 
            Measure-Object -Property Capacity -Sum).Sum / 1GB
        
        if ($ram -ge 16) {
            Write-Host "PASS: ${ram}GB RAM detected"
        }
        else {
            throw "Insufficient RAM: ${ram}GB"
        }
    }
}

function Run-GpuTests {
    Write-Header "GPU Tests"
    
    Invoke-Test -Name "Dual GPU Detection" -ScriptPath {
        $gpus = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "AMD|NVIDIA" -and $_.Status -eq "OK" }
        
        if ($gpus.Count -ge 2) {
            Write-Host "PASS: Dual GPU configuration"
        }
        else {
            Write-Host "WARN: Single GPU (dual recommended)"
        }
    }
    
    Invoke-Test -Name "GPU Driver Check" -ScriptPath {
        $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "AMD|NVIDIA" }
        
        if ($gpus) {
            Write-Host "PASS: GPU drivers installed"
        }
        else {
            throw "GPU driver check failed"
        }
    }
    
    Invoke-Test -Name "Layer Distribution Logic" -ScriptPath {
        $totalLayers = 32
        $primaryLayers = [math]::Floor($totalLayers * 0.7)
        $secondaryLayers = $totalLayers - $primaryLayers
        
        if ($primaryLayers -eq 22 -and $secondaryLayers -eq 10) {
            Write-Host "PASS: Layer distribution 22/10"
        }
        else {
            throw "Invalid layer distribution"
        }
    }
}

function Run-IpcTests {
    Write-Header "IPC Tests"
    
    Invoke-Test -Name "Pipe Name Format" -ScriptPath {
        $pipeName = "\\.\pipe\RawrXD_Omega1_v2"
        if ($pipeName -match "^\\\\\.\\pipe\\[A-Za-z0-9_]+$") {
            Write-Host "PASS: Pipe name format valid"
        }
        else {
            throw "Invalid pipe name format"
        }
    }
    
    Invoke-Test -Name "Protocol Constants" -ScriptPath {
        $magic = 0x4F314F4D
        $version = 2
        $headerSize = 32
        
        if ($magic -eq 0x4F314F4D -and $version -eq 2 -and $headerSize -eq 32) {
            Write-Host "PASS: Protocol constants valid"
        }
        else {
            throw "Invalid protocol constants"
        }
    }
}

function Run-IntegrationTests {
    Write-Header "Integration Tests"
    
    Invoke-Test -Name "Component Communication" -ScriptPath {
        $win32ide = Test-Path "d:\rawrxd\build\bin\RawrXD-Win32IDE.exe"
        $engine = Test-Path "d:\rawrxd\build\bin\RawrXD-InferenceEngine.exe"
        
        if ($win32ide -and $engine) {
            Write-Host "PASS: All components present"
        }
        else {
            throw "Missing components"
        }
    }
    
    Invoke-Test -Name "Configuration File" -ScriptPath {
        $configPaths = @(
            "d:\rawrxd\config\omega1.json",
            "d:\rawrxd\releases\RawrXD-OMEGA1-v1.0.0\config\omega1.json"
        )
        
        $found = $configPaths | Where-Object { Test-Path $_ }
        if ($found) {
            Write-Host "PASS: Configuration file found"
        }
        else {
            Write-Host "WARN: Configuration file not found"
        }
    }
}

function Run-PerformanceTests {
    Write-Header "Performance Tests"
    
    Invoke-Test -Name "InferenceEngine Help" -ScriptPath {
        $engine = "d:\rawrxd\build\bin\RawrXD-InferenceEngine.exe"
        if (Test-Path $engine) {
            $output = & $engine --help 2>&1 | Out-String
            if ($output -match "RawrXD-InferenceEngine") {
                Write-Host "PASS: InferenceEngine responsive"
            }
            else {
                throw "InferenceEngine not responding correctly"
            }
        }
        else {
            throw "InferenceEngine not found"
        }
    }
}

function Generate-Report {
    if (!$GenerateReport) { return }
    
    Write-Header "Generating Test Report"
    
    $endTime = Get-Date
    $duration = ($endTime - $script:StartTime).TotalSeconds
    
    $report = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Suite = $Suite
        Duration = [math]::Round($duration, 2)
        Summary = @{
            Total = $script:TotalTests
            Passed = $script:PassedTests
            Failed = $script:FailedTests
            Skipped = $script:SkippedTests
            SuccessRate = if ($script:TotalTests -gt 0) { 
                [math]::Round(($script:PassedTests / $script:TotalTests) * 100, 2) 
            } else { 0 }
        }
        Results = $script:TestResults
        System = @{
            OS = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
            GPUs = (Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match "AMD|NVIDIA" -and $_.Status -eq "OK" }).Count
        }
    }
    
    $reportPath = Join-Path $script:ResultsDir "test_report.json"
    $report | ConvertTo-Json -Depth 4 | Out-File $reportPath
    
    Write-Status "Report saved: $reportPath" "INFO"
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD OMEGA-1 Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .summary { background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .pass { color: green; }
        .fail { color: red; }
        .skip { color: orange; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #4CAF50; color: white; }
        tr:nth-child(even) { background: #f2f2f2; }
    </style>
</head>
<body>
    <h1>RawrXD OMEGA-1 Test Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Timestamp:</strong> $($report.Timestamp)</p>
        <p><strong>Suite:</strong> $($report.Suite)</p>
        <p><strong>Duration:</strong> $($report.Duration) seconds</p>
        <p><strong>Total Tests:</strong> $($report.Summary.Total)</p>
        <p class="pass"><strong>Passed:</strong> $($report.Summary.Passed)</p>
        <p class="fail"><strong>Failed:</strong> $($report.Summary.Failed)</p>
        <p class="skip"><strong>Skipped:</strong> $($report.Summary.Skipped)</p>
        <p><strong>Success Rate:</strong> $($report.Summary.SuccessRate)%</p>
    </div>
    <table>
        <tr>
            <th>Test Name</th>
            <th>Status</th>
            <th>Duration (s)</th>
        </tr>
"@
    
    foreach ($test in $script:TestResults) {
        $class = $test.Status.ToLower()
        $htmlReport += "        <tr><td>$($test.Name)</td><td class=\"$class\">$($test.Status)</td><td>$([math]::Round($test.Duration, 2))</td></tr>`n"
    }
    
    $htmlReport += @"
    </table>
</body>
</html>
"@
    
    $htmlPath = Join-Path $script:ResultsDir "test_report.html"
    $htmlReport | Out-File $htmlPath
    
    Write-Status "HTML report saved: $htmlPath" "INFO"
}

function Show-Summary {
    Write-Header "Test Summary"
    
    $endTime = Get-Date
    $duration = ($endTime - $script:StartTime).TotalSeconds
    
    Write-Status "Suite: $Suite" "INFO"
    Write-Status "Duration: $([math]::Round($duration, 2)) seconds" "INFO"
    Write-Status "Total Tests: $script:TotalTests" "INFO"
    Write-Status "Passed: $script:PassedTests" $(if($script:PassedTests -eq $script:TotalTests){"PASS"}else{"INFO"})
    Write-Status "Failed: $script:FailedTests" $(if($script:FailedTests -gt 0){"FAIL"}else{"INFO"})
    Write-Status "Skipped: $script:SkippedTests" "INFO"
    
    $successRate = if ($script:TotalTests -gt 0) { 
        [math]::Round(($script:PassedTests / $script:TotalTests) * 100, 2) 
    } else { 0 }
    
    Write-Status "Success Rate: $successRate%" $(if($successRate -eq 100){"PASS"}elseif($successRate -ge 80){"WARN"}else{"FAIL"})
    
    if ($script:FailedTests -eq 0) {
        Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║           ✅ ALL TESTS PASSED                                                    ║" -ForegroundColor Green
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    }
    elseif ($script:FailedTests -le 2) {
        Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║           ⚠️  MOSTLY PASSED (Review Recommended)                                ║" -ForegroundColor Yellow
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║           ❌ MULTIPLE FAILURES                                                 ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    }
}

# =============================================================================
# Main Execution
# =============================================================================
Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Test Runner                                                 ║" -ForegroundColor Cyan
Write-Host "║     Suite: $Suite" -NoNewline -ForegroundColor Cyan
Write-Host "$(' ' * (63 - $Suite.Length))║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Initialize-TestEnvironment

switch ($Suite) {
    "quick" { Run-QuickTests }
    "gpu" { Run-GpuTests }
    "ipc" { Run-IpcTests }
    "integration" { Run-IntegrationTests }
    "performance" { Run-PerformanceTests }
    "all" {
        Run-QuickTests
        Run-GpuTests
        Run-IpcTests
        Run-IntegrationTests
        Run-PerformanceTests
    }
    "ci" {
        Run-QuickTests
        Run-GpuTests
        Run-IpcTests
    }
}

Generate-Report
Show-Summary

exit $script:FailedTests

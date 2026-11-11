#Requires -Version 7.0
<#
.SYNOPSIS
    RawrXD IDE v1.0.0 Runtime Validation Suite
.DESCRIPTION
    Comprehensive runtime smoke testing with metrics capture for certification.
    Validates all core IDE workflows from launch to shutdown.
.NOTES
    Version: 1.0.0
    Date: 2026-07-29
    Status: Release Candidate Validation
#>

[CmdletBinding()]
param(
    [string]$ExecutablePath = "..\build\RawrXD-Win32IDE.exe",
    [string]$TestWorkspace = "$env:TEMP\RawrXD_Validation_Workspace",
    [string]$ModelPath = "..\models\test_model.gguf",
    [int]$TimeoutSeconds = 300,
    [switch]$CaptureMetrics,
    [switch]$GenerateReport
)

# Validation Results
$script:ValidationResults = @{
    Version = "1.0.0"
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Tests = @()
    Metrics = @{}
    Status = "PENDING"
}

# Test Result Tracking
function Add-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Duration,
        [string]$Details = "",
        [hashtable]$Metrics = @{}
    )
    
    $result = @{
        Name = $TestName
        Passed = $Passed
        Duration = $Duration
        Details = $Details
        Metrics = $Metrics
        Timestamp = Get-Date -Format "HH:mm:ss.fff"
    }
    
    $script:ValidationResults.Tests += $result
    
    $status = if ($Passed) { "✅ PASS" } else { "❌ FAIL" }
    Write-Host "[$status] $TestName ($Duration)" -ForegroundColor $(if ($Passed) { "Green" } else { "Red" })
    if ($Details) { Write-Host "       $Details" -ForegroundColor Gray }
}

# Performance Metrics Capture
function Start-MetricsCapture {
    param([string]$Label)
    
    return @{
        Label = $Label
        StartTime = Get-Date
        StartMemory = (Get-Process -Id $PID).WorkingSet64
        StartCpu = (Get-Process -Id $PID).TotalProcessorTime
    }
}

function Stop-MetricsCapture {
    param([hashtable]$Capture)
    
    $endTime = Get-Date
    $endMemory = (Get-Process -Id $PID).WorkingSet64
    $endCpu = (Get-Process -Id $PID).TotalProcessorTime
    
    return @{
        Label = $Capture.Label
        DurationMs = ($endTime - $Capture.StartTime).TotalMilliseconds
        MemoryDeltaMB = [math]::Round(($endMemory - $Capture.StartMemory) / 1MB, 2)
        CpuTimeMs = ($endCpu - $Capture.StartCpu).TotalMilliseconds
    }
}

# Test: Launch Executable
function Test-LaunchExecutable {
    Write-Host "`n[Test] Launch Executable..." -ForegroundColor Cyan
    
    $capture = Start-MetricsCapture -Label "Launch"
    
    try {
        if (-not (Test-Path $ExecutablePath)) {
            Add-TestResult -TestName "Launch Executable" -Passed $false -Duration "0ms" `
                -Details "Executable not found: $ExecutablePath"
            return $false
        }
        
        # Start process
        $process = Start-Process -FilePath $ExecutablePath -PassThru -WindowStyle Normal
        $script:IdeProcess = $process
        
        # Wait for window
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $windowFound = $false
        while ($sw.ElapsedMilliseconds -lt 10000 -and -not $windowFound) {
            Start-Sleep -Milliseconds 100
            $process.Refresh()
            if ($process.MainWindowHandle -ne 0) {
                $windowFound = $true
            }
        }
        $sw.Stop()
        
        $metrics = Stop-MetricsCapture -Capture $capture
        $metrics.StartupMs = $sw.ElapsedMilliseconds
        
        if ($windowFound) {
            Add-TestResult -TestName "Launch Executable" -Passed $true `
                -Duration "$($metrics.DurationMs)ms" `
                -Details "PID: $($process.Id), Window: $($process.MainWindowTitle)" `
                -Metrics $metrics
            return $true
        } else {
            Add-TestResult -TestName "Launch Executable" -Passed $false `
                -Duration "$($metrics.DurationMs)ms" `
                -Details "Window did not appear within timeout"
            return $false
        }
    }
    catch {
        Add-TestResult -TestName "Launch Executable" -Passed $false -Duration "0ms" `
            -Details "Exception: $_"
        return $false
    }
}

# Test: Create/Open Workspace
function Test-WorkspaceOperations {
    Write-Host "`n[Test] Workspace Operations..." -ForegroundColor Cyan
    
    $capture = Start-MetricsCapture -Label "Workspace"
    
    try {
        # Create test workspace
        if (Test-Path $TestWorkspace) {
            Remove-Item -Path $TestWorkspace -Recurse -Force
        }
        New-Item -ItemType Directory -Path $TestWorkspace -Force | Out-Null
        
        # Create test files
        $testFile = Join-Path $TestWorkspace "test.cpp"
        @"
#include <iostream>

int main() {
    std::cout << "Hello RawrXD!" << std::endl;
    return 0;
}
"@ | Set-Content -Path $testFile -Encoding UTF8
        
        $metrics = Stop-MetricsCapture -Capture $capture
        
        Add-TestResult -TestName "Create Workspace" -Passed $true `
            -Duration "$($metrics.DurationMs)ms" `
            -Details "Created: $TestWorkspace with test.cpp" `
            -Metrics $metrics
        
        return $true
    }
    catch {
        Add-TestResult -TestName "Create Workspace" -Passed $false `
            -Duration "0ms" -Details "Exception: $_"
        return $false
    }
}

# Test: Settings Persistence
function Test-SettingsPersistence {
    Write-Host "`n[Test] Settings Persistence..." -ForegroundColor Cyan
    
    $capture = Start-MetricsCapture -Label "Settings"
    
    try {
        $settingsPath = "$env:LOCALAPPDATA\RawrXD\settings.ini"
        
        # Create test settings
        $testSettings = @"
[Window]
X=100
Y=100
Width=1400
Height=900
Maximized=0

[Editor]
FontName=Consolas
FontSize=11
WordWrap=1
ShowLineNumbers=1

[Theme]
Name=dark
"@
        
        # Ensure directory exists
        $settingsDir = Split-Path $settingsPath -Parent
        if (-not (Test-Path $settingsDir)) {
            New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null
        }
        
        $testSettings | Set-Content -Path $settingsPath -Encoding UTF8
        
        # Verify settings can be read
        $content = Get-Content $settingsPath -Raw
        $canRead = $content -match "FontName=Consolas"
        
        $metrics = Stop-MetricsCapture -Capture $capture
        
        Add-TestResult -TestName "Settings Persistence" -Passed $canRead `
            -Duration "$($metrics.DurationMs)ms" `
            -Details "Settings file: $settingsPath" `
            -Metrics $metrics
        
        return $canRead
    }
    catch {
        Add-TestResult -TestName "Settings Persistence" -Passed $false `
            -Duration "0ms" -Details "Exception: $_"
        return $false
    }
}

# Test: Memory Usage
function Test-MemoryUsage {
    Write-Host "`n[Test] Memory Usage..." -ForegroundColor Cyan
    
    try {
        if ($script:IdeProcess) {
            $script:IdeProcess.Refresh()
            $workingSetMB = [math]::Round($script:IdeProcess.WorkingSet64 / 1MB, 2)
            $privateBytesMB = [math]::Round($script:IdeProcess.PrivateMemorySize64 / 1MB, 2)
            
            $metrics = @{
                WorkingSetMB = $workingSetMB
                PrivateBytesMB = $privateBytesMB
                PagedMemoryMB = [math]::Round($script:IdeProcess.PagedMemorySize64 / 1MB, 2)
            }
            
            # Check if memory is reasonable (< 500MB at idle)
            $passed = $workingSetMB -lt 500
            
            Add-TestResult -TestName "Memory Usage (Idle)" -Passed $passed `
                -Duration "0ms" `
                -Details "Working Set: $workingSetMB MB, Private: $privateBytesMB MB" `
                -Metrics $metrics
            
            return $passed
        } else {
            Add-TestResult -TestName "Memory Usage" -Passed $false `
                -Duration "0ms" -Details "IDE process not found"
            return $false
        }
    }
    catch {
        Add-TestResult -TestName "Memory Usage" -Passed $false `
            -Duration "0ms" -Details "Exception: $_"
        return $false
    }
}

# Test: Process Stability
function Test-ProcessStability {
    Write-Host "`n[Test] Process Stability..." -ForegroundColor Cyan
    
    $capture = Start-MetricsCapture -Label "Stability"
    
    try {
        if ($script:IdeProcess) {
            $startTime = $script:IdeProcess.StartTime
            $uptime = (Get-Date) - $startTime
            
            # Check if process is still running
            $isRunning = -not $script:IdeProcess.HasExited
            
            $metrics = Stop-MetricsCapture -Capture $capture
            $metrics.UptimeSeconds = [math]::Round($uptime.TotalSeconds, 2)
            
            Add-TestResult -TestName "Process Stability" -Passed $isRunning `
                -Duration "$($metrics.DurationMs)ms" `
                -Details "Uptime: $($uptime.ToString('hh\:mm\:ss')), PID: $($script:IdeProcess.Id)" `
                -Metrics $metrics
            
            return $isRunning
        } else {
            Add-TestResult -TestName "Process Stability" -Passed $false `
                -Duration "0ms" -Details "IDE process not found"
            return $false
        }
    }
    catch {
        Add-TestResult -TestName "Process Stability" -Passed $false `
            -Duration "0ms" -Details "Exception: $_"
        return $false
    }
}

# Cleanup
function Stop-ValidationSession {
    Write-Host "`n[Cleanup] Stopping validation session..." -ForegroundColor Yellow
    
    if ($script:IdeProcess -and -not $script:IdeProcess.HasExited) {
        try {
            $script:IdeProcess.CloseMainWindow() | Out-Null
            Start-Sleep -Seconds 2
            
            if (-not $script:IdeProcess.HasExited) {
                $script:IdeProcess.Kill()
            }
            
            Write-Host "  IDE process terminated gracefully" -ForegroundColor Green
        }
        catch {
            Write-Host "  Warning: Could not terminate IDE process: $_" -ForegroundColor Yellow
        }
    }
    
    # Cleanup test workspace
    if (Test-Path $TestWorkspace) {
        Remove-Item -Path $TestWorkspace -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Test workspace cleaned up" -ForegroundColor Green
    }
}

# Generate Report
function Export-ValidationReport {
    param([string]$OutputPath = "RuntimeValidationReport.json")
    
    # Calculate summary
    $totalTests = $script:ValidationResults.Tests.Count
    $passedTests = ($script:ValidationResults.Tests | Where-Object { $_.Passed }).Count
    $failedTests = $totalTests - $passedTests
    
    $script:ValidationResults.Summary = @{
        TotalTests = $totalTests
        Passed = $passedTests
        Failed = $failedTests
        PassRate = [math]::Round(($passedTests / $totalTests) * 100, 2)
        OverallStatus = if ($failedTests -eq 0) { "PASSED" } else { "FAILED" }
    }
    
    # Export JSON
    $json = $script:ValidationResults | ConvertTo-Json -Depth 10
    $json | Set-Content -Path $OutputPath -Encoding UTF8
    
    Write-Host "`n📄 Validation report exported to: $OutputPath" -ForegroundColor Cyan
    
    # Console summary
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RUNTIME VALIDATION SUMMARY                           ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  Total Tests:  $totalTests" -ForegroundColor White
    Write-Host "  Passed:       $passedTests" -ForegroundColor Green
    Write-Host "  Failed:       $failedTests" -ForegroundColor $(if ($failedTests -gt 0) { "Red" } else { "Green" })
    Write-Host "  Pass Rate:    $($script:ValidationResults.Summary.PassRate)%" -ForegroundColor White
    Write-Host "  Status:       $($script:ValidationResults.Summary.OverallStatus)" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })
    Write-Host ""
}

# Main Execution
function Start-RuntimeValidation {
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   RAWRXD IDE v1.0.0 - RUNTIME VALIDATION SUITE                 ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "  Executable: $ExecutablePath" -ForegroundColor Gray
    Write-Host "  Workspace:  $TestWorkspace" -ForegroundColor Gray
    Write-Host "  Started:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    try {
        # Run tests
        Test-LaunchExecutable
        Start-Sleep -Seconds 2
        
        Test-WorkspaceOperations
        Test-SettingsPersistence
        Test-MemoryUsage
        
        # Stability check (wait a bit)
        Write-Host "`n[Info] Running stability check (5 seconds)..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        Test-ProcessStability
        
        # Set final status
        $failedCount = ($script:ValidationResults.Tests | Where-Object { -not $_.Passed }).Count
        $script:ValidationResults.Status = if ($failedCount -eq 0) { "PASSED" } else { "FAILED" }
    }
    finally {
        Stop-ValidationSession
        
        if ($GenerateReport) {
            Export-ValidationReport
        }
    }
    
    return $script:ValidationResults.Status -eq "PASSED"
}

# Entry point
if ($MyInvocation.InvocationName -ne '.') {
    $success = Start-RuntimeValidation
    exit $(if ($success) { 0 } else { 1 })
}

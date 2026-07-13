#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Smoke Test Script for RawrXD

.DESCRIPTION
    Quick smoke tests to verify basic functionality:
    - Binary existence and execution
    - Configuration loading
    - Model loading (basic)
    - API endpoints (if server mode)
    - Basic inference

.EXAMPLE
    .\scripts\smoke_test.ps1
    .\scripts\smoke_test.ps1 -Quick
    .\scripts\smoke_test.ps1 -WithModel model.gguf

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BinaryPath = ".\bin\RawrXD.exe",

    [Parameter()]
    [string]$ModelPath = "",

    [Parameter()]
    [switch]$Quick,

    [Parameter()]
    [switch]$ServerMode,

    [Parameter()]
    [int]$Timeout = 30,

    [Parameter()]
    [string]$OutputFile = "smoke-test-results.json"
)

# ============================================================================
# Configuration
# ============================================================================

$Tests = @{
    BinaryExists = @{ Name = "Binary Exists"; Weight = 10 }
    BinaryRuns = @{ Name = "Binary Executes"; Weight = 20 }
    VersionWorks = @{ Name = "Version Command"; Weight = 10 }
    HelpWorks = @{ Name = "Help Command"; Weight = 10 }
    ConfigLoads = @{ Name = "Configuration Loading"; Weight = 15 }
    ModelLoads = @{ Name = "Model Loading"; Weight = 20 }
    InferenceWorks = @{ Name = "Basic Inference"; Weight = 15 }
}

$script:Results = @()
$script:Passed = 0
$script:Failed = 0

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Add-Result {
    param([string]$Test, [bool]$Passed, [string]$Message, [int]$Duration = 0)
    
    $result = [PSCustomObject]@{
        Test = $Test
        Passed = $Passed
        Message = $Message
        Duration = $Duration
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    }
    
    $script:Results += $result
    
    if ($Passed) {
        $script:Passed++
        Write-Status "$Test`: PASSED ($Duration ms)" "Success"
    } else {
        $script:Failed++
        Write-Status "$Test`: FAILED - $Message" "Error"
    }
}

# ============================================================================
# Smoke Tests
# ============================================================================

function Test-BinaryExists {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    if (Test-Path $BinaryPath) {
        $fileInfo = Get-Item $BinaryPath
        Add-Result "BinaryExists" $true "Found: $($fileInfo.Name) ($($fileInfo.Length) bytes)" $sw.ElapsedMilliseconds
    } else {
        Add-Result "BinaryExists" $false "Binary not found: $BinaryPath" $sw.ElapsedMilliseconds
    }
}

function Test-BinaryRuns {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $process = Start-Process -FilePath $BinaryPath -ArgumentList "--version" -PassThru -NoNewWindow -RedirectStandardOutput "test_out.txt" -RedirectStandardError "test_err.txt"
        
        if ($process.WaitForExit($Timeout * 1000)) {
            if ($process.ExitCode -eq 0) {
                Add-Result "BinaryRuns" $true "Exit code: $($process.ExitCode)" $sw.ElapsedMilliseconds
            } else {
                $stderr = Get-Content "test_err.txt" -Raw -ErrorAction SilentlyContinue
                Add-Result "BinaryRuns" $false "Exit code: $($process.ExitCode) - $stderr" $sw.ElapsedMilliseconds
            }
        } else {
            $process.Kill()
            Add-Result "BinaryRuns" $false "Process timed out after $Timeout seconds" $sw.ElapsedMilliseconds
        }
    } catch {
        Add-Result "BinaryRuns" $false $_.Exception.Message $sw.ElapsedMilliseconds
    } finally {
        Remove-Item "test_out.txt", "test_err.txt" -ErrorAction SilentlyContinue
    }
}

function Test-VersionCommand {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $output = & $BinaryPath --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $output -match "\d+\.\d+\.\d+") {
            Add-Result "VersionCommand" $true "Version: $output" $sw.ElapsedMilliseconds
        } else {
            Add-Result "VersionCommand" $false "Unexpected output: $output" $sw.ElapsedMilliseconds
        }
    } catch {
        Add-Result "VersionCommand" $false $_.Exception.Message $sw.ElapsedMilliseconds
    }
}

function Test-HelpCommand {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $output = & $BinaryPath --help 2>&1
        if ($LASTEXITCODE -eq 0 -and $output -match "(usage|help|options)") {
            Add-Result "HelpCommand" $true "Help text available" $sw.ElapsedMilliseconds
        } else {
            Add-Result "HelpCommand" $false "Help text not found" $sw.ElapsedMilliseconds
        }
    } catch {
        Add-Result "HelpCommand" $false $_.Exception.Message $sw.ElapsedMilliseconds
    }
}

function Test-ConfigLoading {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    # Create temporary config
    $tempConfig = "test_config_$([Guid]::NewGuid().ToString().Substring(0,8)).json"
    @'{"test": true}'@ | Out-File -FilePath $tempConfig -Encoding UTF8
    
    try {
        # Test with config file
        $output = & $BinaryPath --config $tempConfig --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-Result "ConfigLoading" $true "Config file accepted" $sw.ElapsedMilliseconds
        } else {
            Add-Result "ConfigLoading" $false "Config file rejected" $sw.ElapsedMilliseconds
        }
    } catch {
        Add-Result "ConfigLoading" $false $_.Exception.Message $sw.ElapsedMilliseconds
    } finally {
        Remove-Item $tempConfig -ErrorAction SilentlyContinue
    }
}

function Test-ModelLoading {
    if ([string]::IsNullOrEmpty($ModelPath) -or -not (Test-Path $ModelPath)) {
        Add-Result "ModelLoading" $false "No model file provided or not found" 0
        return
    }
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $output = & $BinaryPath -m $ModelPath --check 2>&1
        if ($LASTEXITCODE -eq 0) {
            Add-Result "ModelLoading" $true "Model loaded successfully" $sw.ElapsedMilliseconds
        } else {
            Add-Result "ModelLoading" $false "Failed to load model" $sw.ElapsedMilliseconds
        }
    } catch {
        Add-Result "ModelLoading" $false $_.Exception.Message $sw.ElapsedMilliseconds
    }
}

function Test-BasicInference {
    if ([string]::IsNullOrEmpty($ModelPath) -or -not (Test-Path $ModelPath)) {
        Add-Result "BasicInference" $false "Skipping - no model file" 0
        return
    }
    
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $output = & $BinaryPath -m $ModelPath -p "Hello" -n 10 2>&1
        if ($LASTEXITCODE -eq 0 -and $output.Length -gt 0) {
            Add-Result "BasicInference" $true "Generated output: $($output.Length) chars" $sw.ElapsedMilliseconds
        } else {
            Add-Result "BasicInference" $false "No output generated" $sw.ElapsedMilliseconds
        }
    } catch {
        Add-Result "BasicInference" $false $_.Exception.Message $sw.ElapsedMilliseconds
    }
}

# ============================================================================
# Report Generation
# ============================================================================

function Write-Report {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Smoke Test Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "`nResults:" -ForegroundColor White
    Write-Host "  Passed: $script:Passed" -ForegroundColor Green
    Write-Host "  Failed: $script:Failed" -ForegroundColor $(if ($script:Failed -eq 0) { "Green" } else { "Red" })
    
    $totalDuration = ($script:Results | Measure-Object -Property Duration -Sum).Sum
    Write-Host "  Total Duration: $totalDuration ms" -ForegroundColor White
    
    if ($script:Failed -gt 0) {
        Write-Host "`nFailed Tests:" -ForegroundColor Red
        $script:Results | Where-Object { -not $_.Passed } | ForEach-Object {
            Write-Host "  - $($_.Test): $($_.Message)" -ForegroundColor Red
        }
    }
    
    # Save JSON report
    $report = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        binary = $BinaryPath
        model = $ModelPath
        results = $script:Results
        summary = @{
            total = $script:Results.Count
            passed = $script:Passed
            failed = $script:Failed
            success_rate = [math]::Round(($script:Passed / $script:Results.Count) * 100, 2)
        }
        passed = ($script:Failed -eq 0)
    }
    
    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Report saved to $OutputFile" "Success"
    
    # Exit code
    if ($script:Failed -eq 0) {
        Write-Host "`n✅ All smoke tests passed!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`n❌ Some smoke tests failed!" -ForegroundColor Red
        exit 1
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Smoke Tests" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Binary: $BinaryPath" "Info"
    Write-Status "Model: $(if ($ModelPath) { $ModelPath } else { 'None' })" "Info"
    Write-Status "Quick mode: $Quick" "Info"
    Write-Status ""
    
    # Run tests
    Test-BinaryExists
    Test-BinaryRuns
    
    if (-not $Quick) {
        Test-VersionCommand
        Test-HelpCommand
        Test-ConfigLoading
        Test-ModelLoading
        Test-BasicInference
    }
    
    Write-Report
}

# Run main
Main

#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Log Analyzer for RawrXD

.DESCRIPTION
    Analyzes log files for patterns and issues:
    - Error pattern detection
    - Performance trend analysis
    - Log aggregation
    - Alert generation

.EXAMPLE
    .\scripts\log_analyzer.ps1 -LogFile logs/rawrxd.log
    .\scripts\log_analyzer.ps1 -LogDir logs/ -Pattern "ERROR"

.NOTES
    Part of RawrXD Phase AD: Advanced Features & Integration
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$LogFile = "",

    [Parameter()]
    [string]$LogDir = "logs",

    [Parameter()]
    [string]$Pattern = "",

    [Parameter()]
    [ValidateSet("errors", "warnings", "info", "all")]
    [string]$Level = "all",

    [Parameter()]
    [string]$OutputFile = "log-analysis.json"
)

# ============================================================================
# Configuration
# ============================================================================

$script:Results = @{
    TotalLines = 0
    Errors = 0
    Warnings = 0
    Info = 0
    Patterns = @{}
    Timeline = @()
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-LogFiles {
    if ($LogFile -and (Test-Path $LogFile)) {
        return @($LogFile)
    }

    if (Test-Path $LogDir) {
        return Get-ChildItem -Path $LogDir -Filter "*.log" | Select-Object -ExpandProperty FullName
    }

    return @()
}

# ============================================================================
# Analysis
# ============================================================================

function Start-LogAnalysis {
    $files = Get-LogFiles

    if ($files.Count -eq 0) {
        Write-Status "No log files found" "Error"
        return
    }

    Write-Status "Analyzing $($files.Count) log file(s)..." "Info"

    foreach ($file in $files) {
        Write-Status "Processing: $(Split-Path $file -Leaf)" "Info"

        $lines = Get-Content -Path $file -ErrorAction SilentlyContinue
        $script:Results.TotalLines += $lines.Count

        foreach ($line in $lines) {
            # Count by level
            if ($line -match "\[ERROR\]|ERROR|Error") {
                $script:Results.Errors++
            } elseif ($line -match "\[WARN\]|WARNING|Warning") {
                $script:Results.Warnings++
            } elseif ($line -match "\[INFO\]|INFO|Info") {
                $script:Results.Info++
            }

            # Pattern matching
            if ($Pattern -and ($line -match $Pattern)) {
                if (-not $script:Results.Patterns[$Pattern]) {
                    $script:Results.Patterns[$Pattern] = 0
                }
                $script:Results.Patterns[$Pattern]++
            }
        }
    }
}

# ============================================================================
# Report
# ============================================================================

function Write-Report {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Log Analysis Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nSummary:" -ForegroundColor White
    Write-Host "  Total Lines: $($script:Results.TotalLines)" -ForegroundColor Gray
    Write-Host "  Errors:      $($script:Results.Errors)" -ForegroundColor $(if ($script:Results.Errors -gt 0) { "Red" } else { "Green" })
    Write-Host "  Warnings:    $($script:Results.Warnings)" -ForegroundColor $(if ($script:Results.Warnings -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Info:        $($script:Results.Info)" -ForegroundColor Gray

    if ($script:Results.Patterns.Count -gt 0) {
        Write-Host "`nPattern Matches:" -ForegroundColor White
        foreach ($pattern in $script:Results.Patterns.Keys) {
            Write-Host "  $pattern`: $($script:Results.Patterns[$pattern])" -ForegroundColor Gray
        }
    }

    # Save report
    $script:Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Report saved to $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Log Analyzer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Start-LogAnalysis
    Write-Report
}

# Run main
Main

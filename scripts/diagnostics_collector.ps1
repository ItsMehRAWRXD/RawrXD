#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Diagnostics Collector for RawrXD

.DESCRIPTION
    Collects diagnostic information for troubleshooting:
    - System information
    - Configuration dumps
    - Log collection
    - Performance snapshots

.EXAMPLE
    .\scripts\diagnostics_collector.ps1
    .\scripts\diagnostics_collector.ps1 -Output diagnostics.zip

.NOTES
    Part of RawrXD Phase AD: Advanced Features & Integration
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFile = "diagnostics_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip",

    [Parameter()]
    [switch]$IncludeLogs,

    [Parameter()]
    [switch]$IncludeMemoryDump
)

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-SystemInfo {
    return [PSCustomObject]@{
        OS = $PSVersionTable.OS
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Processor = $env:PROCESSOR_IDENTIFIER
        Cores = $env:NUMBER_OF_PROCESSORS
        TotalMemory = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    }
}

# ============================================================================
# Collection
# ============================================================================

function Start-DiagnosticsCollection {
    Write-Status "Starting diagnostics collection..." "Info"

    $tempDir = "diagnostics_temp_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        # System info
        Write-Status "Collecting system information..." "Info"
        $sysInfo = Get-SystemInfo
        $sysInfo | ConvertTo-Json -Depth 5 | Out-File -FilePath "$tempDir\system_info.json" -Encoding UTF8

        # Configuration
        Write-Status "Collecting configuration..." "Info"
        if (Test-Path "config") {
            Copy-Item -Path "config" -Destination "$tempDir\config" -Recurse -ErrorAction SilentlyContinue
        }

        # Logs
        if ($IncludeLogs) {
            Write-Status "Collecting logs..." "Info"
            if (Test-Path "logs") {
                Copy-Item -Path "logs" -Destination "$tempDir\logs" -Recurse -ErrorAction SilentlyContinue
            }
        }

        # Process info
        Write-Status "Collecting process information..." "Info"
        $processes = Get-Process | Where-Object { $_.ProcessName -like "*RawrXD*" } | Select-Object Name, Id, WorkingSet, CPU
        $processes | ConvertTo-Json | Out-File -FilePath "$tempDir\processes.json" -Encoding UTF8

        # Create archive
        Write-Status "Creating archive: $OutputFile" "Info"
        Compress-Archive -Path "$tempDir\*" -DestinationPath $OutputFile -Force

        Write-Status "Diagnostics collected: $OutputFile" "Success"

    } finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Diagnostics Collector" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Start-DiagnosticsCollection
}

# Run main
Main

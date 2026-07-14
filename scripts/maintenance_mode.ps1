#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Maintenance Mode Script for RawrXD

.DESCRIPTION
    Enable/disable maintenance mode for planned downtime.

.EXAMPLE
    .\scripts\maintenance_mode.ps1 -Enable -Message "System upgrade in progress"
    .\scripts\maintenance_mode.ps1 -Disable
    .\scripts\maintenance_mode.ps1 -Status

.NOTES
    Part of RawrXD Phase AV: Production Hardening
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName = "Enable")]
    [switch]$Enable,

    [Parameter(ParameterSetName = "Disable")]
    [switch]$Disable,

    [Parameter(ParameterSetName = "Status")]
    [switch]$Status,

    [Parameter()]
    [string]$Message = "System maintenance in progress",

    [Parameter()]
    [int]$RetryAfter = 300  # Seconds
)

# ============================================================================
# Configuration
# ============================================================================

$MaintenanceFile = "maintenance.flag"
$MaintenanceMessageFile = "maintenance.json"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Enable-MaintenanceMode {
    Write-Status "Enabling maintenance mode..."
    
    # Create maintenance flag
    $flag = @{
        enabled = $true
        message = $Message
        retry_after = $RetryAfter
        started_at = (Get-Date -Format "o")
    }
    
    $flag | ConvertTo-Json | Out-File $MaintenanceMessageFile
    New-Item -ItemType File -Path $MaintenanceFile -Force | Out-Null
    
    Write-Status "Maintenance mode enabled" "Success"
    Write-Status "Message: $Message"
    Write-Status "Retry-After: $RetryAfter seconds"
}

function Disable-MaintenanceMode {
    Write-Status "Disabling maintenance mode..."
    
    if (Test-Path $MaintenanceFile) {
        Remove-Item $MaintenanceFile -Force
    }
    
    if (Test-Path $MaintenanceMessageFile) {
        Remove-Item $MaintenanceMessageFile -Force
    }
    
    Write-Status "Maintenance mode disabled" "Success"
}

function Get-MaintenanceStatus {
    $enabled = Test-Path $MaintenanceFile
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Maintenance Mode Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    if ($enabled) {
        Write-Status "Status: ENABLED" "Warning"
        
        if (Test-Path $MaintenanceMessageFile) {
            $info = Get-Content $MaintenanceMessageFile | ConvertFrom-Json
            Write-Host "Message: $($info.message)"
            Write-Host "Started: $($info.started_at)"
            Write-Host "Retry-After: $($info.retry_after) seconds"
        }
    } else {
        Write-Status "Status: DISABLED" "Success"
    }
}

# ============================================================================
# Main
# ============================================================================

if ($Enable) {
    Enable-MaintenanceMode
} elseif ($Disable) {
    Disable-MaintenanceMode
} elseif ($Status) {
    Get-MaintenanceStatus
} else {
    Get-MaintenanceStatus
}

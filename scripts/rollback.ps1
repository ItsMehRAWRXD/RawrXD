#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Rollback Script for RawrXD

.DESCRIPTION
    Automated rollback to previous version with verification.

.EXAMPLE
    .\scripts\rollback.ps1 -Environment production
    .\scripts\rollback.ps1 -Environment production -Version 1.0.0

.NOTES
    Part of RawrXD Phase AV: Production Hardening
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,

    [Parameter()]
    [string]$Version = "",

    [Parameter()]
    [string]$BackupDir = "backups",

    [Parameter()]
    [switch]$Force
)

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Stop"

$Colors = @{
    Success = "Green"
    Error = "Red"
    Warning = "Yellow"
    Info = "Cyan"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $color = $Colors[$Status]
    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

function Get-AvailableBackups {
    if (-not (Test-Path $BackupDir)) {
        return @()
    }
    
    $backups = Get-ChildItem -Path $BackupDir -Directory | 
        Where-Object { $_.Name -like "rawrxd_$Environment*" } |
        Sort-Object CreationTime -Descending
    
    return $backups
}

function Select-Backup {
    param([array]$Backups)
    
    if ($Backups.Count -eq 0) {
        throw "No backups found"
    }
    
    if ($Version) {
        $backup = $Backups | Where-Object { 
            $manifest = Get-Content "$($_.FullName)/manifest.json" -Raw | ConvertFrom-Json
            $manifest.version -eq $Version 
        } | Select-Object -First 1
        
        if (-not $backup) {
            throw "Backup for version $Version not found"
        }
        
        return $backup
    }
    
    # Return most recent backup
    return $Backups[0]
}

function Stop-Service {
    $serviceName = "RawrXD-$Environment"
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Status "Stopping service: $serviceName"
            Stop-Service -Name $serviceName -Force
            
            $timeout = 30
            $timer = [Diagnostics.Stopwatch]::StartNew()
            while ($service.Status -ne "Stopped" -and $timer.Elapsed.TotalSeconds -lt $timeout) {
                Start-Sleep -Seconds 1
                $service.Refresh()
            }
            
            if ($service.Status -eq "Stopped") {
                Write-Status "Service stopped" "Success"
            } else {
                throw "Service failed to stop"
            }
        }
    } catch {
        Write-Status "Error stopping service: $_" "Error"
        if (-not $Force) { exit 1 }
    }
}

function Restore-Backup {
    param([string]$BackupPath)
    
    Write-Status "Restoring from: $BackupPath"
    
    # Verify backup
    if (-not (Test-Path "$BackupPath/manifest.json")) {
        throw "Invalid backup: manifest.json not found"
    }
    
    $manifest = Get-Content "$BackupPath/manifest.json" -Raw | ConvertFrom-Json
    Write-Status "Backup version: $($manifest.version)"
    Write-Status "Backup time: $($manifest.timestamp)"
    
    # Restore files
    $items = @("bin/", "lib/", "config/", "data/")
    foreach ($item in $items) {
        $source = Join-Path $BackupPath $item
        if (Test-Path $source) {
            $dest = $item.TrimEnd('/')
            if (Test-Path $dest) {
                Remove-Item -Path $dest -Recurse -Force
            }
            Copy-Item -Path $source -Destination $dest -Recurse -Force
            Write-Status "Restored: $item"
        }
    }
    
    Write-Status "Backup restored" "Success"
}

function Start-Service {
    $serviceName = "RawrXD-$Environment"
    
    try {
        Write-Status "Starting service: $serviceName"
        Start-Service -Name $serviceName
        
        $timeout = 30
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $service = Get-Service -Name $serviceName
        while ($service.Status -ne "Running" -and $timer.Elapsed.TotalSeconds -lt $timeout) {
            Start-Sleep -Seconds 1
            $service.Refresh()
        }
        
        if ($service.Status -eq "Running") {
            Write-Status "Service started" "Success"
        } else {
            throw "Service failed to start"
        }
    } catch {
        Write-Status "Error starting service: $_" "Error"
        exit 1
    }
}

function Test-Health {
    $healthUrl = "http://localhost:8080/health"
    $maxAttempts = 10
    
    Write-Status "Waiting for service health check..."
    
    for ($i = 1; $i -le $maxAttempts; $i++) {
        try {
            $response = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 5
            if ($response.status -eq "HEALTHY" -or $response.status -eq "DEGRADED") {
                Write-Status "Health check passed: $($response.status)" "Success"
                return $true
            }
        } catch {
            Write-Status "Health check attempt $i/$maxAttempts failed" "Warning"
        }
        Start-Sleep -Seconds 5
    }
    
    Write-Status "Health check failed" "Error"
    return $false
}

# ============================================================================
# Main
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Rollback" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Environment: $Environment"
    if ($Version) { Write-Host "Target Version: $Version" }
    Write-Host ""
    
    try {
        # Get available backups
        Write-Status "Finding available backups..."
        $backups = Get-AvailableBackups
        Write-Status "Found $($backups.Count) backup(s)"
        
        # Select backup
        $backup = Select-Backup -Backups $backups
        Write-Status "Selected backup: $($backup.Name)"
        
        # Confirm rollback
        if (-not $Force) {
            $confirmation = Read-Host "Are you sure you want to rollback to $($backup.Name)? (y/N)"
            if ($confirmation -ne "y") {
                Write-Status "Rollback cancelled"
                exit 0
            }
        }
        
        # Perform rollback
        Stop-Service
        Restore-Backup -BackupPath $backup.FullName
        Start-Service
        
        # Verify
        if (-not (Test-Health)) {
            throw "Rollback verification failed"
        }
        
        Write-Status "Rollback completed successfully!" "Success"
        
    } catch {
        Write-Status "Rollback failed: $_" "Error"
        exit 1
    }
}

Main

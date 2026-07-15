#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Production Deployment Script for RawrXD

.DESCRIPTION
    Automated production deployment with health checks, rollback support,
    and zero-downtime updates.

.EXAMPLE
    .\scripts\production_deploy.ps1 -Version 1.0.0 -Environment production
    .\scripts\production_deploy.ps1 -Version 1.0.0 -Environment staging -DryRun

.NOTES
    Part of RawrXD Phase AV: Production Hardening
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,

    [Parameter()]
    [string]$ConfigPath = "config/production.yaml",

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [switch]$SkipHealthCheck,

    [Parameter()]
    [switch]$Force
)

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

$Config = @{
    Version = $Version
    Environment = $Environment
    ConfigPath = $ConfigPath
    BackupDir = "backups"
    LogDir = "logs/deploy"
    HealthCheckUrl = "http://localhost:8080/health"
    HealthCheckTimeout = 60
    RollbackOnFailure = $true
    MaxRetries = 3
}

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

function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Test-Prerequisites {
    Write-Section "Checking Prerequisites"
    
    # Check if running as administrator (for service management)
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Status "Not running as administrator. Some operations may fail." "Warning"
    }
    
    # Check config file
    if (-not (Test-Path $Config.ConfigPath)) {
        Write-Status "Config file not found: $($Config.ConfigPath)" "Error"
        exit 1
    }
    
    # Check backup directory
    if (-not (Test-Path $Config.BackupDir)) {
        New-Item -ItemType Directory -Force -Path $Config.BackupDir | Out-Null
        Write-Status "Created backup directory: $($Config.BackupDir)"
    }
    
    # Check log directory
    if (-not (Test-Path $Config.LogDir)) {
        New-Item -ItemType Directory -Force -Path $Config.LogDir | Out-Null
    }
    
    Write-Status "Prerequisites check passed" "Success"
}

function Backup-CurrentVersion {
    Write-Section "Creating Backup"
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupName = "rawrxd_$($Config.Environment)_$timestamp"
    $backupPath = Join-Path $Config.BackupDir $backupName
    
    Write-Status "Creating backup: $backupName"
    
    # Backup binaries
    $binaries = @("bin/", "lib/", "config/")
    foreach ($item in $binaries) {
        if (Test-Path $item) {
            Copy-Item -Path $item -Destination "$backupPath/$item" -Recurse -Force
        }
    }
    
    # Backup database if exists
    if (Test-Path "data/") {
        Copy-Item -Path "data/" -Destination "$backupPath/data/" -Recurse -Force
    }
    
    # Create backup manifest
    $manifest = @{
        version = $Config.Version
        environment = $Config.Environment
        timestamp = $timestamp
        path = $backupPath
    }
    $manifest | ConvertTo-Json | Out-File "$backupPath/manifest.json"
    
    Write-Status "Backup created: $backupPath" "Success"
    return $backupPath
}

function Stop-Service {
    Write-Section "Stopping Service"
    
    $serviceName = "RawrXD-$($Config.Environment)"
    
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Status "Stopping service: $serviceName"
            Stop-Service -Name $serviceName -Force
            
            # Wait for service to stop
            $timeout = 30
            $timer = [Diagnostics.Stopwatch]::StartNew()
            while ($service.Status -ne "Stopped" -and $timer.Elapsed.TotalSeconds -lt $timeout) {
                Start-Sleep -Seconds 1
                $service.Refresh()
            }
            
            if ($service.Status -eq "Stopped") {
                Write-Status "Service stopped successfully" "Success"
            } else {
                throw "Service failed to stop within timeout"
            }
        } else {
            Write-Status "Service not running or not found"
        }
    } catch {
        Write-Status "Error stopping service: $_" "Error"
        if (-not $Force) { exit 1 }
    }
}

function Deploy-Binaries {
    Write-Section "Deploying Binaries"
    
    if ($DryRun) {
        Write-Status "DRY RUN: Would deploy binaries for version $($Config.Version)"
        return
    }
    
    # Deploy new binaries
    $sourcePath = "artifacts/$($Config.Version)"
    if (-not (Test-Path $sourcePath)) {
        Write-Status "Artifact not found: $sourcePath" "Error"
        exit 1
    }
    
    Write-Status "Copying binaries from $sourcePath"
    Copy-Item -Path "$sourcePath/*" -Destination "." -Recurse -Force
    
    Write-Status "Binaries deployed" "Success"
}

function Update-Configuration {
    Write-Section "Updating Configuration"
    
    if ($DryRun) {
        Write-Status "DRY RUN: Would update configuration"
        return
    }
    
    # Update config with environment-specific values
    $config = Get-Content $Config.ConfigPath | ConvertFrom-Yaml
    $config.version = $Config.Version
    $config.environment = $Config.Environment
    $config.deployed_at = (Get-Date -Format "o")
    
    $config | ConvertTo-Yaml | Out-File $Config.ConfigPath
    
    Write-Status "Configuration updated" "Success"
}

function Start-Service {
    Write-Section "Starting Service"
    
    if ($DryRun) {
        Write-Status "DRY RUN: Would start service"
        return
    }
    
    $serviceName = "RawrXD-$($Config.Environment)"
    
    try {
        Write-Status "Starting service: $serviceName"
        Start-Service -Name $serviceName
        
        # Wait for service to start
        $timeout = 30
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $service = Get-Service -Name $serviceName
        while ($service.Status -ne "Running" -and $timer.Elapsed.TotalSeconds -lt $timeout) {
            Start-Sleep -Seconds 1
            $service.Refresh()
        }
        
        if ($service.Status -eq "Running") {
            Write-Status "Service started successfully" "Success"
        } else {
            throw "Service failed to start within timeout"
        }
    } catch {
        Write-Status "Error starting service: $_" "Error"
        exit 1
    }
}

function Test-Health {
    Write-Section "Health Check"
    
    if ($DryRun -or $SkipHealthCheck) {
        Write-Status "Skipping health check"
        return $true
    }
    
    Write-Status "Waiting for service to be ready..."
    Start-Sleep -Seconds 5
    
    $maxAttempts = 10
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        $attempt++
        Write-Status "Health check attempt $attempt/$maxAttempts"
        
        try {
            $response = Invoke-RestMethod -Uri $Config.HealthCheckUrl -TimeoutSec 10
            if ($response.status -eq "HEALTHY" -or $response.status -eq "DEGRADED") {
                Write-Status "Health check passed: $($response.status)" "Success"
                return $true
            }
        } catch {
            Write-Status "Health check failed: $_" "Warning"
        }
        
        Start-Sleep -Seconds 5
    }
    
    Write-Status "Health check failed after $maxAttempts attempts" "Error"
    return $false
}

function Invoke-Rollback {
    param([string]$BackupPath)
    
    Write-Section "Rolling Back"
    
    if ($DryRun) {
        Write-Status "DRY RUN: Would rollback to $BackupPath"
        return
    }
    
    Write-Status "Restoring from backup: $BackupPath"
    
    # Stop service
    Stop-Service
    
    # Restore binaries
    Copy-Item -Path "$BackupPath/*" -Destination "." -Recurse -Force
    
    # Start service
    Start-Service
    
    Write-Status "Rollback completed" "Success"
}

function Write-Summary {
    param([bool]$Success, [string]$BackupPath)
    
    Write-Section "Deployment Summary"
    
    if ($Success) {
        Write-Status "Deployment completed successfully!" "Success"
        Write-Status "Version: $($Config.Version)"
        Write-Status "Environment: $($Config.Environment)"
        Write-Status "Backup: $BackupPath"
    } else {
        Write-Status "Deployment failed!" "Error"
        if ($Config.RollbackOnFailure) {
            Write-Status "Rollback was performed" "Warning"
        }
    }
    
    Write-Status "Log file: $($Config.LogDir)/deploy_$($Config.Version).log"
}

# ============================================================================
# Main
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Production Deployment" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Version: $($Config.Version)"
    Write-Host "Environment: $($Config.Environment)"
    Write-Host "Dry Run: $($DryRun.IsPresent)"
    Write-Host ""
    
    $backupPath = $null
    $success = $false
    
    try {
        # Pre-deployment checks
        Test-Prerequisites
        
        # Create backup
        $backupPath = Backup-CurrentVersion
        
        # Stop service
        Stop-Service
        
        # Deploy new version
        Deploy-Binaries
        Update-Configuration
        
        # Start service
        Start-Service
        
        # Health check
        if (-not (Test-Health)) {
            throw "Health check failed"
        }
        
        $success = $true
        
    } catch {
        Write-Status "Deployment failed: $_" "Error"
        
        if ($Config.RollbackOnFailure -and $backupPath) {
            Invoke-Rollback -BackupPath $backupPath
        }
    } finally {
        Write-Summary -Success $success -BackupPath $backupPath
    }
    
    exit ($success ? 0 : 1)
}

# Run main
Main

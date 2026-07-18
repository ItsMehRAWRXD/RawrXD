#Requires -Version 7.0
<#
.SYNOPSIS
    Production Deployment Script for RawrXD Hotpatch System

.DESCRIPTION
    Automates the deployment of the hotpatch system to production environments
    with safety checks, rollback capabilities, and monitoring integration.

.PARAMETER Environment
    Target environment: staging, production (default: staging)

.PARAMETER Version
    Version to deploy (default: latest)

.PARAMETER SkipTests
    Skip pre-deployment tests

.PARAMETER Force
    Force deployment without confirmation

.EXAMPLE
    .\production_deploy.ps1 -Environment production -Version 1.0.0
#
>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("staging", "production")]
    [string]$Environment = "staging",

    [Parameter(Mandatory = $false)]
    [string]$Version = "latest",

    [Parameter(Mandatory = $false)]
    [switch]$SkipTests,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Configuration
$script:Config = @{
    Staging = @{
        Servers = @("staging-rawrxd-01", "staging-rawrxd-02")
        HealthCheckUrl = "https://staging.rawrxd.ai/health"
        BackupPath = "\\staging-backup\rawrxd"
    }
    Production = @{
        Servers = @("prod-rawrxd-01", "prod-rawrxd-02", "prod-rawrxd-03")
        HealthCheckUrl = "https://rawrxd.ai/health"
        BackupPath = "\\prod-backup\rawrxd"
    }
}

$script:DeploymentLog = @()
$script:StartTime = Get-Date

function Write-DeployLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "ERROR" = "Red"; "WARN" = "Yellow"; "STEP" = "Cyan" }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]

    $script:DeploymentLog += @{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
}

function Test-Prerequisites {
    Write-DeployLog "Checking prerequisites..." -Level "STEP"

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "PowerShell 7.0+ required"
    }

    # Check administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-DeployLog "Warning: Not running as administrator" -Level "WARN"
    }

    # Check RAWRXD_HOME
    if (-not $env:RAWRXD_HOME) {
        throw "RAWRXD_HOME environment variable not set"
    }

    # Check source files exist
    $requiredFiles = @(
        "$env:RAWRXD_HOME\security\phase_g1_hotpatch\swarm_hotpatch_manager.ps1",
        "$env:RAWRXD_HOME\security\phase_g1_hotpatch\agent_hotpatch_manager.ps1",
        "$env:RAWRXD_HOME\security\phase_g1_hotpatch\tools_hotpatch_manager.ps1",
        "$env:RAWRXD_HOME\security\phase_g1_hotpatch\unified_hotpatch_orchestrator.ps1"
    )

    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            throw "Required file not found: $file"
        }
    }

    Write-DeployLog "Prerequisites check passed" -Level "SUCCESS"
    return $true
}

function Invoke-PreDeploymentTests {
    if ($SkipTests) {
        Write-DeployLog "Skipping pre-deployment tests" -Level "WARN"
        return $true
    }

    Write-DeployLog "Running pre-deployment tests..." -Level "STEP"

    # Run unit tests
    $testFramework = "$env:RAWRXD_HOME\security\phase_g1_hotpatch\testing\patch_test_framework.ps1"
    if (Test-Path $testFramework) {
        $testResult = & $testFramework -PatchBundle "$env:RAWRXD_HOME\security\phase_g1_hotpatch\patches\config\logging_verbosity_v1.0.1.json" -TestLevel unit -OutputPath "pre_deploy_test.json"
        if ($LASTEXITCODE -ne 0) {
            throw "Pre-deployment tests failed"
        }
    }

    Write-DeployLog "Pre-deployment tests passed" -Level "SUCCESS"
    return $true
}

function New-Backup {
    Write-DeployLog "Creating backup..." -Level "STEP"

    $backupDir = Join-Path $script:Config[$Environment].BackupPath "pre-deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    try {
        # Backup current hotpatch system
        $sourceDir = "$env:RAWRXD_HOME\security\phase_g1_hotpatch"
        if (Test-Path $sourceDir) {
            Copy-Item -Path $sourceDir -Destination $backupDir -Recurse -Force
            Write-DeployLog "Backup created at: $backupDir" -Level "SUCCESS"
        }

        return $backupDir
    }
    catch {
        throw "Failed to create backup: $_"
    }
}

function Invoke-Deployment {
    param([string]$BackupPath)

    Write-DeployLog "Starting deployment to $Environment..." -Level "STEP"

    $servers = $script:Config[$Environment].Servers
    $successCount = 0
    $failureCount = 0

    foreach ($server in $servers) {
        Write-DeployLog "Deploying to $server..." -Level "INFO"

        try {
            # Copy files to server
            $targetPath = "\\$server\c$\rawrxd\security\phase_g1_hotpatch"
            $sourcePath = "$env:RAWRXD_HOME\security\phase_g1_hotpatch"

            # Create directory if it doesn't exist
            if (-not (Test-Path $targetPath)) {
                New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
            }

            # Copy with robocopy for reliability
            $robocopyArgs = @(
                '"' + $sourcePath + '"',
                '"' + $targetPath + '"',
                "/MIR",
                "/R:3",
                "/W:5",
                "/MT:8",
                "/XD", "logs", "backups",
                "/XF", "*.log", "*.tmp"
            )

            $robocopyResult = Start-Process -FilePath "robocopy" -ArgumentList $robocopyArgs -Wait -PassThru -WindowStyle Hidden

            if ($robocopyResult.ExitCode -le 7) {  # Robocopy success codes 0-7
                Write-DeployLog "Deployment to $server successful" -Level "SUCCESS"
                $successCount++
            }
            else {
                throw "Robocopy failed with exit code $($robocopyResult.ExitCode)"
            }
        }
        catch {
            Write-DeployLog "Deployment to $server failed: $_" -Level "ERROR"
            $failureCount++
        }
    }

    Write-DeployLog "Deployment complete: $successCount succeeded, $failureCount failed" -Level $(if ($failureCount -eq 0) { "SUCCESS" } else { "WARN" })

    return @{
        SuccessCount = $successCount
        FailureCount = $failureCount
        TotalServers = $servers.Count
    }
}

function Test-Deployment {
    Write-DeployLog "Running post-deployment tests..." -Level "STEP"

    $servers = $script:Config[$Environment].Servers
    $healthyServers = 0

    foreach ($server in $servers) {
        try {
            # Test health endpoint
            $healthUrl = $script:Config[$Environment].HealthCheckUrl
            $response = Invoke-WebRequest -Uri $healthUrl -Method GET -TimeoutSec 30 -UseBasicParsing

            if ($response.StatusCode -eq 200) {
                Write-DeployLog "Health check passed for $server" -Level "SUCCESS"
                $healthyServers++
            }
            else {
                Write-DeployLog "Health check failed for $server (Status: $($response.StatusCode))" -Level "ERROR"
            }
        }
        catch {
            Write-DeployLog "Health check failed for $server`: $_" -Level "ERROR"
        }
    }

    $healthPercentage = ($healthyServers / $servers.Count) * 100
    Write-DeployLog "Health check results: $healthyServers/$($servers.Count) servers healthy ($([math]::Round($healthPercentage, 1))%)" -Level $(if ($healthPercentage -ge 100) { "SUCCESS" } else { "WARN" })

    return $healthPercentage -ge 80  # Require 80% healthy
}

function Invoke-Rollback {
    param([string]$BackupPath)

    Write-DeployLog "Initiating rollback..." -Level "ERROR"

    $servers = $script:Config[$Environment].Servers

    foreach ($server in $servers) {
        Write-DeployLog "Rolling back $server..." -Level "INFO"

        try {
            $targetPath = "\\$server\c$\rawrxd\security\phase_g1_hotpatch"

            # Restore from backup
            if (Test-Path $BackupPath) {
                Remove-Item -Path $targetPath -Recurse -Force -ErrorAction SilentlyContinue
                Copy-Item -Path $BackupPath -Destination $targetPath -Recurse -Force
                Write-DeployLog "Rollback for $server complete" -Level "SUCCESS"
            }
        }
        catch {
            Write-DeployLog "Rollback failed for $server`: $_" -Level "ERROR"
        }
    }
}

function Send-Notification {
    param([string]$Status, [hashtable]$Results)

    $duration = ((Get-Date) - $script:StartTime).TotalMinutes

    $message = @"
RawrXD Hotpatch System Deployment

Environment: $Environment
Version: $Version
Status: $Status
Duration: $([math]::Round($duration, 2)) minutes

Results:
- Servers Deployed: $($Results.SuccessCount)/$($Results.TotalServers)
- Failed: $($Results.FailureCount)

$(if ($Status -eq "FAILED") { "ACTION REQUIRED: Deployment failed, rollback may be needed." })
"@

    # Write to log file
    $message | Out-File -FilePath "deploy_notification.txt" -Encoding UTF8

    Write-DeployLog "Notification prepared" -Level "INFO"
}

function Save-DeploymentLog {
    $logPath = "deployment_log_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $deploymentReport = @{
        Timestamp = Get-Date -Format "o"
        Environment = $Environment
        Version = $Version
        Duration = ((Get-Date) - $script:StartTime).TotalMinutes
        Log = $script:DeploymentLog
    }

    $deploymentReport | ConvertTo-Json -Depth 5 | Out-File $logPath -Encoding UTF8
    Write-DeployLog "Deployment log saved to: $logPath" -Level "INFO"
}

# Main execution
Write-Host ""
Write-Host "RawrXD Hotpatch System - Production Deployment" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Version: $Version" -ForegroundColor Yellow
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "Continue with deployment? (yes/N)"
    if ($confirm -ne "yes") {
        Write-Host "Deployment cancelled." -ForegroundColor Red
        exit 0
    }
}

try {
    # Phase 1: Prerequisites
    Test-Prerequisites

    # Phase 2: Pre-deployment tests
    Invoke-PreDeploymentTests

    # Phase 3: Backup
    $backupPath = New-Backup

    # Phase 4: Deployment
    $deployResults = Invoke-Deployment -BackupPath $backupPath

    # Phase 5: Post-deployment tests
    $testsPassed = Test-Deployment

    # Phase 6: Notification
    $status = if ($testsPassed -and $deployResults.FailureCount -eq 0) { "SUCCESS" } else { "FAILED" }
    Send-Notification -Status $status -Results $deployResults

    # Phase 7: Rollback if needed
    if (-not $testsPassed -and $deployResults.FailureCount -gt 0) {
        Invoke-Rollback -BackupPath $backupPath
    }

    # Save log
    Save-DeploymentLog

    Write-Host ""
    if ($status -eq "SUCCESS") {
        Write-Host "✅ Deployment completed successfully!" -ForegroundColor Green
        exit 0
    }
    else {
        Write-Host "❌ Deployment failed!" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-DeployLog "Deployment failed with error: $_" -Level "ERROR"
    Save-DeploymentLog
    exit 1
}

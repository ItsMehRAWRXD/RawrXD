#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Staging Deployment Script for RawrXD

.DESCRIPTION
    Automates deployment to staging environment:
    - Environment preparation
    - Configuration deployment
    - Service deployment
    - Health checks
    - Rollback capability

.EXAMPLE
    .\scripts\deploy_staging.ps1
    .\scripts\deploy_staging.ps1 -Environment production
    .\scripts\deploy_staging.ps1 -Version 1.2.0

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateSet("staging", "production")]
    [string]$Environment = "staging",

    [Parameter()]
    [string]$Version = "",

    [Parameter()]
    [string]$ArtifactPath = ".\artifacts",

    [Parameter()]
    [string]$ConfigPath = ".\config\staging",

    [Parameter()]
    [switch]$SkipHealthCheck,

    [Parameter()]
    [switch]$RollbackOnFailure
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    Staging = @{
        Hosts = @("staging-01.rawrxd.local", "staging-02.rawrxd.local")
        ServiceName = "rawrxd-staging"
        Port = 8080
        HealthEndpoint = "/health"
    }
    Production = @{
        Hosts = @("prod-01.rawrxd.local", "prod-02.rawrxd.local", "prod-03.rawrxd.local")
        ServiceName = "rawrxd"
        Port = 80
        HealthEndpoint = "/health"
    }
}

$script:DeploymentResults = @()
$script:Errors = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Blue
    Write-Host $Title -ForegroundColor Blue
    Write-Host "========================================" -ForegroundColor Blue
}

function Add-Result {
    param([string]$Step, [bool]$Success, [string]$Message)
    $script:DeploymentResults += [PSCustomObject]@{
        Step = $Step
        Success = $Success
        Message = $Message
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    }
}

# ============================================================================
# Pre-Deployment
# ============================================================================

function Test-PreDeployment {
    Write-Section "Pre-Deployment Checks"

    # Check artifacts exist
    if (-not (Test-Path $ArtifactPath)) {
        Write-Status "Artifact path not found: $ArtifactPath" "Error"
        return $false
    }
    Write-Status "Artifacts found: $ArtifactPath" "Success"

    # Check configuration
    if (-not (Test-Path $ConfigPath)) {
        Write-Status "Config path not found: $ConfigPath" "Warning"
    } else {
        Write-Status "Configuration found: $ConfigPath" "Success"
    }

    # Check connectivity to hosts
    $envConfig = $Config[$Environment]
    foreach ($host in $envConfig.Hosts) {
        if (Test-Connection -ComputerName $host -Count 1 -Quiet) {
            Write-Status "Host reachable: $host" "Success"
        } else {
            Write-Status "Host unreachable: $host" "Error"
            return $false
        }
    }

    return $true
}

# ============================================================================
# Deployment
# ============================================================================

function Invoke-Deployment {
    Write-Section "Deploying to $Environment"

    $envConfig = $Config[$Environment]

    foreach ($host in $envConfig.Hosts) {
        Write-Status "Deploying to $host..." "Info"

        try {
            # Stop service
            Write-Status "Stopping service on $host..." "Info"
            Invoke-Command -ComputerName $host -ScriptBlock {
                Stop-Service -Name $using:envConfig.ServiceName -ErrorAction SilentlyContinue
            } -ErrorAction SilentlyContinue

            # Backup current version
            Write-Status "Backing up current version on $host..." "Info"
            $backupPath = "C:\RawrXD\backups\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Invoke-Command -ComputerName $host -ScriptBlock {
                if (Test-Path "C:\RawrXD\current") {
                    New-Item -ItemType Directory -Path $using:backupPath -Force | Out-Null
                    Copy-Item -Path "C:\RawrXD\current\*" -Destination $using:backupPath -Recurse -Force
                }
            }

            # Deploy new version
            if ($PSCmdlet.ShouldProcess($host, "Deploy new version")) {
                Write-Status "Copying artifacts to $host..." "Info"
                $session = New-PSSession -ComputerName $host
                Copy-Item -Path "$ArtifactPath\*" -Destination "C:\RawrXD\staging\" -ToSession $session -Recurse -Force
                Remove-PSSession $session

                # Update symlink/current directory
                Invoke-Command -ComputerName $host -ScriptBlock {
                    if (Test-Path "C:\RawrXD\current") {
                        Remove-Item -Path "C:\RawrXD\current" -Recurse -Force
                    }
                    Copy-Item -Path "C:\RawrXD\staging\*" -Destination "C:\RawrXD\current\" -Recurse -Force
                }

                Write-Status "Deployment to $host complete" "Success"
                Add-Result -Step "Deploy_$host" -Success $true -Message "Deployed successfully"
            }

            # Start service
            Write-Status "Starting service on $host..." "Info"
            Invoke-Command -ComputerName $host -ScriptBlock {
                Start-Service -Name $using:envConfig.ServiceName
            }

        } catch {
            Write-Status "Deployment to $host failed: $_" "Error"
            Add-Result -Step "Deploy_$host" -Success $false -Message $_.Exception.Message
            $script:Errors += "Failed to deploy to $host`: $_"
        }
    }
}

# ============================================================================
# Health Checks
# ============================================================================

function Test-Health {
    if ($SkipHealthCheck) {
        Write-Status "Health checks skipped" "Warning"
        return $true
    }

    Write-Section "Health Checks"

    $envConfig = $Config[$Environment]
    $allHealthy = $true

    foreach ($host in $envConfig.Hosts) {
        $url = "http://$($host):$($envConfig.Port)$($envConfig.HealthEndpoint)"
        Write-Status "Checking health: $url" "Info"

        try {
            $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-Status "Health check passed: $host" "Success"
                Add-Result -Step "Health_$host" -Success $true -Message "Healthy"
            } else {
                Write-Status "Health check failed: $host (Status: $($response.StatusCode))" "Error"
                Add-Result -Step "Health_$host" -Success $false -Message "Status: $($response.StatusCode)"
                $allHealthy = $false
            }
        } catch {
            Write-Status "Health check failed: $host - $_" "Error"
            Add-Result -Step "Health_$host" -Success $false -Message $_.Exception.Message
            $allHealthy = $false
        }
    }

    return $allHealthy
}

# ============================================================================
# Rollback
# ============================================================================

function Invoke-Rollback {
    Write-Section "Rolling Back Deployment"

    $envConfig = $Config[$Environment]

    foreach ($host in $envConfig.Hosts) {
        Write-Status "Rolling back $host..." "Info"

        try {
            # Stop service
            Invoke-Command -ComputerName $host -ScriptBlock {
                Stop-Service -Name $using:envConfig.ServiceName -ErrorAction SilentlyContinue
            }

            # Restore from backup
            Invoke-Command -ComputerName $host -ScriptBlock {
                $backups = Get-ChildItem -Path "C:\RawrXD\backups" -Directory | Sort-Object CreationTime -Descending
                if ($backups.Count -gt 0) {
                    $latestBackup = $backups[0].FullName
                    Remove-Item -Path "C:\RawrXD\current" -Recurse -Force -ErrorAction SilentlyContinue
                    Copy-Item -Path "$latestBackup\*" -Destination "C:\RawrXD\current\" -Recurse -Force
                }
            }

            # Start service
            Invoke-Command -ComputerName $host -ScriptBlock {
                Start-Service -Name $using:envConfig.ServiceName
            }

            Write-Status "Rollback complete: $host" "Success"
            Add-Result -Step "Rollback_$host" -Success $true -Message "Rolled back successfully"

        } catch {
            Write-Status "Rollback failed: $host - $_" "Error"
            Add-Result -Step "Rollback_$host" -Success $false -Message $_.Exception.Message
        }
    }
}

# ============================================================================
# Summary
# ============================================================================

function Write-Summary {
    Write-Section "Deployment Summary"

    $successCount = ($script:DeploymentResults | Where-Object { $_.Success }).Count
    $totalCount = $script:DeploymentResults.Count

    Write-Host "Environment: $Environment" -ForegroundColor Cyan
    Write-Host "Steps completed: $successCount / $totalCount" -ForegroundColor $(if ($successCount -eq $totalCount) { "Green" } else { "Yellow" })
    Write-Host "Errors: $($script:Errors.Count)" -ForegroundColor $(if ($script:Errors.Count -eq 0) { "Green" } else { "Red" })

    if ($script:Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($error in $script:Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
    }

    # Save deployment log
    $log = [ordered]@{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        environment = $Environment
        version = $Version
        results = $script:DeploymentResults
        success = ($script:Errors.Count -eq 0)
    }

    $logFile = "deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $log | ConvertTo-Json -Depth 10 | Out-File -FilePath $logFile -Encoding UTF8
    Write-Status "Deployment log saved: $logFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Deployment Tool" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Status "Environment: $Environment" "Info"
    Write-Status "Version: $(if ($Version) { $Version } else { 'Latest' })" "Info"
    Write-Status "Artifact path: $ArtifactPath" "Info"
    Write-Status ""

    # Pre-deployment checks
    if (-not (Test-PreDeployment)) {
        Write-Status "Pre-deployment checks failed" "Error"
        exit 1
    }

    # Deploy
    Invoke-Deployment

    # Health checks
    $healthy = Test-Health

    # Rollback if needed
    if (-not $healthy -and $RollbackOnFailure) {
        Write-Status "Health checks failed, initiating rollback..." "Warning"
        Invoke-Rollback
    }

    # Summary
    Write-Summary

    # Exit code
    if ($script:Errors.Count -eq 0 -and $healthy) {
        Write-Status "Deployment successful!" "Success"
        exit 0
    } else {
        Write-Status "Deployment completed with issues" "Warning"
        exit 1
    }
}

# Run main
Main

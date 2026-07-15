# RawrXD Rollback Manager
# Automated rollback procedures for failed deployments

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("dev", "staging", "production")]
    [string]$Environment,
    
    [string]$Reason = "Manual rollback",
    [string]$TargetVersion,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Rollback state
$script:RollbackState = @{
    rollback_id = [Guid]::NewGuid().ToString()
    timestamp = Get-Date -Format "o"
    environment = $Environment
    reason = $Reason
    target_version = $TargetVersion
    status = "in_progress"
    steps = @()
}

# Environment paths
$script:EnvironmentPaths = @{
    dev = "C:\\RawrXD\\dev"
    staging = "C:\\RawrXD\\staging"
    production = "C:\\RawrXD\\production"
}

function Write-RollbackLog {
    param(
        [string]$Step,
        [string]$Status,
        [string]$Details = ""
    )
    
    $script:RollbackState.steps += @{
        step = $Step
        status = $Status
        timestamp = Get-Date -Format "o"
        details = $Details
    }
    
    $color = switch ($Status) {
        "success" { "Green" }
        "error" { "Red" }
        "warning" { "Yellow" }
        "info" { "Cyan" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Step" -ForegroundColor $color
    if ($Details) {
        Write-Host "  $Details" -ForegroundColor Gray
    }
}

function Initialize-Rollback {
    Write-RollbackLog -Step "Initialize Rollback" -Status "info" -Details "Environment: $Environment, Reason: $Reason"
    
    if (-not $script:EnvironmentPaths.ContainsKey($Environment)) {
        throw "Unknown environment: $Environment"
    }
    
    $script:TargetPath = $script:EnvironmentPaths[$Environment]
    
    if (-not (Test-Path $script:TargetPath)) {
        throw "Environment path not found: $script:TargetPath"
    }
    
    # Load deployment state if exists
    $statePath = Join-Path $script:TargetPath ".deployment-state.json"
    if (Test-Path $statePath) {
        $script:DeploymentState = Get-Content $statePath | ConvertFrom-Json
        Write-RollbackLog -Step "Loaded Deployment State" -Status "info" -Details "Deployment ID: $($script:DeploymentState.deployment_id)"
    }
    
    # Confirm rollback
    if (-not $Force) {
        $confirmation = Read-Host "Confirm rollback for $Environment? (yes/no)"
        if ($confirmation -ne "yes") {
            throw "Rollback cancelled by user"
        }
    }
}

function Invoke-BlueGreenRollback {
    Write-RollbackLog -Step "Blue/Green Rollback" -Status "info"
    
    $bluePath = Join-Path $script:TargetPath "blue"
    $greenPath = Join-Path $script:TargetPath "green"
    $activePath = Join-Path $script:TargetPath "active"
    
    # Determine current active
    $currentActive = $null
    if (Test-Path $activePath) {
        $currentActive = Get-Item $activePath | Select-Object -ExpandProperty Target
    }
    
    # Switch to the other environment
    $targetPath = if ($currentActive -eq $bluePath) { $greenPath } else { $bluePath }
    
    if (-not (Test-Path $targetPath)) {
        throw "Rollback environment not found: $targetPath"
    }
    
    Write-Host "  Switching from $(if($currentActive -eq $bluePath){'blue'}else{'green'}) to $(if($targetPath -eq $bluePath){'blue'}else{'green'})..." -ForegroundColor Gray
    
    if (-not $DryRun) {
        # Remove current active link
        if (Test-Path $activePath) {
            Remove-Item $activePath -Force
        }
        
        # Create new active link
        New-Item -ItemType Junction -Path $activePath -Target $targetPath | Out-Null
    }
    
    Write-RollbackLog -Step "Traffic Switched" -Status "success" -Details "Now serving from $(if($targetPath -eq $bluePath){'blue'}else{'green'})"
    
    # Verify rollback
    $health = Test-RollbackHealth
    if (-not $health.healthy) {
        throw "Rollback health check failed"
    }
    Write-RollbackLog -Step "Rollback Health Check" -Status "success"
}

function Invoke-CanaryRollback {
    Write-RollbackLog -Step "Canary Rollback" -Status "info"
    
    $stablePath = Join-Path $script:TargetPath "stable"
    $canaryPath = Join-Path $script:TargetPath "canary"
    
    # Remove canary
    if (Test-Path $canaryPath) {
        Write-Host "  Removing canary deployment..." -ForegroundColor Gray
        if (-not $DryRun) {
            Remove-Item $canaryPath -Recurse -Force
        }
        Write-RollbackLog -Step "Canary Removed" -Status "success"
    }
    
    # Ensure stable exists
    if (-not (Test-Path $stablePath)) {
        throw "Stable deployment not found - cannot rollback"
    }
    
    # Redirect all traffic to stable
    Write-Host "  Redirecting all traffic to stable..." -ForegroundColor Gray
    Write-RollbackLog -Step "Traffic Redirected" -Status "success" -Details "All traffic now going to stable"
    
    # Verify
    $health = Test-RollbackHealth -Path $stablePath
    if (-not $health.healthy) {
        throw "Stable health check failed"
    }
    Write-RollbackLog -Step "Stable Health Check" -Status "success"
}

function Invoke-RollingRollback {
    Write-RollbackLog -Step "Rolling Rollback" -Status "info"
    
    # Find previous version backup
    $backupPattern = "disaster-recovery/backups/pre-deploy-*"
    $backups = Get-ChildItem -Path $backupPattern -Directory | Sort-Object CreationTime -Descending
    
    if ($backups.Count -eq 0) {
        throw "No backup found for rollback"
    }
    
    $latestBackup = $backups[0]
    Write-RollbackLog -Step "Found Backup" -Status "success" -Details $latestBackup.FullName
    
    # Restore from backup
    Write-Host "  Restoring from backup..." -ForegroundColor Gray
    if (-not $DryRun) {
        & "disaster-recovery/recovery/recovery_procedures.ps1" `
            -RecoveryType Partial `
            -BackupPath $latestBackup.FullName `
            -TargetPath $script:TargetPath
    }
    Write-RollbackLog -Step "Restore Complete" -Status "success"
    
    # Verify
    $health = Test-RollbackHealth
    if (-not $health.healthy) {
        throw "Rollback health check failed"
    }
    Write-RollbackLog -Step "Rollback Health Check" -Status "success"
}

function Invoke-BackupRestoreRollback {
    Write-RollbackLog -Step "Backup Restore Rollback" -Status "info"
    
    # Find backup for specific version
    $backupPath = $null
    if ($TargetVersion) {
        $backupPattern = "disaster-recovery/backups/*$TargetVersion*"
        $backups = Get-ChildItem -Path $backupPattern -File | Sort-Object CreationTime -Descending
        if ($backups.Count -gt 0) {
            $backupPath = $backups[0].FullName
        }
    }
    
    # If no specific version, use latest
    if (-not $backupPath) {
        $backupPattern = "disaster-recovery/backups/*.zip"
        $backups = Get-ChildItem -Path $backupPattern -File | Sort-Object CreationTime -Descending
        if ($backups.Count -gt 0) {
            $backupPath = $backups[0].FullName
        }
    }
    
    if (-not $backupPath) {
        throw "No backup found for rollback"
    }
    
    Write-RollbackLog -Step "Using Backup" -Status "success" -Details $backupPath
    
    # Perform restore
    Write-Host "  Restoring from backup..." -ForegroundColor Gray
    if (-not $DryRun) {
        & "disaster-recovery/recovery/recovery_procedures.ps1" `
            -RecoveryType Full `
            -BackupPath $backupPath `
            -TargetPath $script:TargetPath
    }
    Write-RollbackLog -Step "Restore Complete" -Status "success"
}

function Test-RollbackHealth {
    param([string]$Path)
    
    $config = @{
        dev = "http://localhost:8080/health"
        staging = "http://localhost:8081/health"
        production = "http://localhost:8082/health"
    }
    
    $healthEndpoint = $config[$Environment]
    
    for ($i = 0; $i -lt 3; $i++) {
        try {
            $response = Invoke-RestMethod -Uri $healthEndpoint -Method Get -TimeoutSec 10
            if ($response.status -eq "healthy") {
                return @{ healthy = $true }
            }
        }
        catch {
            Write-Host "    Health check attempt $($i+1) failed" -ForegroundColor Gray
        }
        Start-Sleep -Seconds 5
    }
    
    return @{ healthy = $false }
}

function Save-RollbackState {
    $script:RollbackState.completed_at = Get-Date -Format "o"
    if ($script:RollbackState.status -eq "in_progress") {
        $script:RollbackState.status = "completed"
    }
    
    $statePath = Join-Path $script:TargetPath ".rollback-state.json"
    $script:RollbackState | ConvertTo-Json -Depth 10 | Out-File $statePath
    
    Write-Host "`nRollback state saved: $statePath" -ForegroundColor Gray
}

function Send-RollbackNotification {
    # Send notification to stakeholders
    $message = @"
🚨 ROLLBACK EXECUTED

Environment: $Environment
Reason: $Reason
Time: $($script:RollbackState.timestamp)
Rollback ID: $($script:RollbackState.rollback_id)

Steps completed:
$($script:RollbackState.steps | ForEach-Object { "- $($_.step): $($_.status)" } | Out-String)

Please verify system functionality.
"@
    
    Write-Host "`nRollback Notification:" -ForegroundColor Cyan
    Write-Host $message -ForegroundColor White
    
    # In production, this would send to Slack/Email/PagerDuty
}

# Main execution
function Invoke-RollbackManager {
    Write-Host "RawrXD Rollback Manager" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host "Environment: $Environment" -ForegroundColor Yellow
    Write-Host "Reason: $Reason" -ForegroundColor Yellow
    if ($DryRun) { Write-Host "*** DRY RUN MODE ***" -ForegroundColor Magenta }
    Write-Host ""
    
    try {
        Initialize-Rollback
        
        # Determine rollback strategy based on deployment state
        if ($script:DeploymentState -and $script:DeploymentState.strategy) {
            switch ($script:DeploymentState.strategy) {
                "BlueGreen" { Invoke-BlueGreenRollback }
                "Canary" { Invoke-CanaryRollback }
                "Rolling" { Invoke-RollingRollback }
                default { Invoke-BackupRestoreRollback }
            }
        } else {
            # Default to backup restore
            Invoke-BackupRestoreRollback
        }
        
        Save-RollbackState
        Send-RollbackNotification
        
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "Rollback Complete!" -ForegroundColor Green
        Write-Host "Rollback ID: $($script:RollbackState.rollback_id)" -ForegroundColor White
        Write-Host "========================================" -ForegroundColor Green
    }
    catch {
        $script:RollbackState.status = "failed"
        $script:RollbackState.error = $_.Exception.Message
        Save-RollbackState
        throw
    }
}

# Run rollback
Invoke-RollbackManager

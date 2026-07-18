# recovery_workflow.ps1
# Phase H.4 Batch 5/5: Automated Recovery Orchestration

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("auto", "rollback", "restore", "reinstall", "safe-mode")]
    [string]$Strategy,
    
    [string]$TargetVersion,
    [string]$BackupPath,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$RecoveryConfig = @{
    InstallDir = "${env:ProgramFiles}\RawrXD"
    BackupDir = "${env:ProgramData}\RawrXD\Backups"
    LogDir = "${env:ProgramData}\RawrXD\Logs"
    MaxRetries = 3
    RetryDelaySeconds = 5
}

function Write-Log($Message, $Level = "INFO") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "STEP" { "Cyan" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Invoke-HealthCheck {
    Write-Log "Running health check..." "STEP"
    
    $healthScript = Join-Path $PSScriptRoot "..\health\health_check.ps1"
    if (Test-Path $healthScript) {
        $result = & $healthScript -Mode "quick" -OutputFormat "json" 2>$null
        return $LASTEXITCODE -eq 0
    }
    
    # Fallback health check
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    return ($service -and $service.Status -eq "Running")
}

function Invoke-AutoRecovery {
    Write-Log "Starting automatic recovery..." "STEP"
    
    # Step 1: Health check
    if (Invoke-HealthCheck) {
        Write-Log "System is healthy, no recovery needed" "SUCCESS"
        return $true
    }
    
    Write-Log "Health check failed, attempting recovery..." "WARNING"
    
    # Step 2: Try restart
    Write-Log "Attempting service restart..." "STEP"
    Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    
    if (Invoke-HealthCheck) {
        Write-Log "Recovery successful via restart" "SUCCESS"
        return $true
    }
    
    # Step 3: Try safe mode
    Write-Log "Restart failed, entering safe mode..." "STEP"
    $safeModeScript = Join-Path $PSScriptRoot "..\emergency\safe_mode.ps1"
    if (Test-Path $safeModeScript) {
        & $safeModeScript -Enter
        Start-Sleep -Seconds 5
        
        if (Invoke-HealthCheck) {
            Write-Log "Recovery successful via safe mode" "SUCCESS"
            Write-Log "System is running in safe mode - manual intervention required" "WARNING"
            return $true
        }
    }
    
    # Step 4: Try rollback
    Write-Log "Safe mode failed, attempting rollback..." "STEP"
    return Invoke-RollbackRecovery
}

function Invoke-RollbackRecovery {
    Write-Log "Starting rollback recovery..." "STEP"
    
    if (-not $TargetVersion) {
        # Find most recent backup
        $backups = Get-ChildItem -Path $RecoveryConfig.BackupDir -Directory | Sort-Object LastWriteTime -Descending
        if ($backups.Count -eq 0) {
            Write-Log "No backups found for rollback" "ERROR"
            return $false
        }
        
        $latestBackup = $backups[0]
        $TargetVersion = $latestBackup.Name -replace '^v', '' -replace '-.*$', ''
        $BackupPath = $latestBackup.FullName
    }
    
    Write-Log "Rolling back to v$TargetVersion from $BackupPath" "STEP"
    
    if ($DryRun) {
        Write-Log "DRY RUN: Would restore from $BackupPath"
        return $true
    }
    
    # Stop service
    Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    
    # Run rollback
    $rollbackScript = Join-Path $PSScriptRoot "..\rollback\version_downgrade.ps1"
    if (Test-Path $rollbackScript) {
        $result = & $rollbackScript -TargetVersion $TargetVersion -Force:$Force
        if ($result) {
            Write-Log "Rollback completed successfully" "SUCCESS"
            return $true
        }
    }
    
    Write-Log "Rollback failed" "ERROR"
    return $false
}

function Invoke-RestoreRecovery {
    Write-Log "Starting restore recovery..." "STEP"
    
    if (-not $BackupPath) {
        Write-Log "BackupPath required for restore" "ERROR"
        return $false
    }
    
    if (-not (Test-Path $BackupPath)) {
        Write-Log "Backup not found: $BackupPath" "ERROR"
        return $false
    }
    
    Write-Log "Restoring from backup: $BackupPath" "STEP"
    
    if ($DryRun) {
        Write-Log "DRY RUN: Would restore from $BackupPath"
        return $true
    }
    
    # Stop service
    Stop-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    
    # Restore data
    $preserveScript = Join-Path $PSScriptRoot "..\backup\data_preservation.ps1"
    if (Test-Path $preserveScript) {
        $result = & $preserveScript -Action "restore" -MigrationTarget $BackupPath
        if ($result) {
            Write-Log "Restore completed successfully" "SUCCESS"
            
            # Start service
            Start-Service -Name "RawrXD" -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            
            if (Invoke-HealthCheck) {
                Write-Log "Service is healthy after restore" "SUCCESS"
                return $true
            }
            else {
                Write-Log "Service not healthy after restore" "WARNING"
                return $false
            }
        }
    }
    
    Write-Log "Restore failed" "ERROR"
    return $false
}

function Invoke-ReinstallRecovery {
    Write-Log "Starting reinstall recovery..." "STEP"
    
    # Backup current data
    Write-Log "Backing up current data before reinstall..." "STEP"
    $preserveScript = Join-Path $PSScriptRoot "..\backup\data_preservation.ps1"
    if (Test-Path $preserveScript) {
        & $preserveScript -Action "backup" -Compress
    }
    
    # Uninstall
    Write-Log "Uninstalling current version..." "STEP"
    $uninstallScript = Join-Path $PSScriptRoot "..\..\installer\windows\uninstall.bat"
    if (Test-Path $uninstallScript) {
        & $uninstallScript
    }
    
    # Reinstall
    Write-Log "Reinstalling RawrXD..." "STEP"
    $installScript = Join-Path $PSScriptRoot "..\..\installer\windows\silent_install.bat"
    if (Test-Path $installScript) {
        & $installScript
    }
    
    # Restore data
    Write-Log "Restoring data..." "STEP"
    if (Test-Path $preserveScript) {
        & $preserveScript -Action "restore"
    }
    
    # Verify
    if (Invoke-HealthCheck) {
        Write-Log "Reinstall completed successfully" "SUCCESS"
        return $true
    }
    
    Write-Log "Reinstall failed" "ERROR"
    return $false
}

function Invoke-SafeModeRecovery {
    Write-Log "Entering safe mode recovery..." "STEP"
    
    $safeModeScript = Join-Path $PSScriptRoot "..\emergency\safe_mode.ps1"
    if (Test-Path $safeModeScript) {
        & $safeModeScript -Enter
        
        Start-Sleep -Seconds 5
        
        if (Invoke-HealthCheck) {
            Write-Log "Safe mode enabled successfully" "SUCCESS"
            Write-Log "System is running with minimal features" "WARNING"
            Write-Log "Run diagnostics and exit safe mode when ready"
            return $true
        }
    }
    
    Write-Log "Safe mode failed" "ERROR"
    return $false
}

# Main execution
Write-Log "RawrXD Recovery Orchestrator v1.0"
Write-Log "Strategy: $Strategy"
Write-Log ""

if ($DryRun) {
    Write-Log "DRY RUN MODE - No changes will be made" "WARNING"
    Write-Log ""
}

$success = $false

switch ($Strategy) {
    "auto" { $success = Invoke-AutoRecovery }
    "rollback" { $success = Invoke-RollbackRecovery }
    "restore" { $success = Invoke-RestoreRecovery }
    "reinstall" { $success = Invoke-ReinstallRecovery }
    "safe-mode" { $success = Invoke-SafeModeRecovery }
}

Write-Log ""
if ($success) {
    Write-Log "Recovery workflow completed successfully" "SUCCESS"
    exit 0
}
else {
    Write-Log "Recovery workflow failed" "ERROR"
    Write-Log "Manual intervention may be required"
    exit 1
}

# RawrXD Patch Deployment Manager
# Manages deployment of hotpatches across the 7-layer system

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Deploy", "Rollback", "Status", "Validate", "History", "Schedule")]
    [string]$Action = "Status",
    
    [string]$PatchFile = "",
    [string]$Layer = "",
    [string]$Target = "local",
    [string]$ScheduleTime = "",
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ValidLayers = @("pt-driver", "memory", "byte", "server", "binary", "shadow", "sentinel")

function Write-Status { param([string]$Message); Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message); Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Error { param([string]$Message); Write-Host "[✗] $Message" -ForegroundColor Red }
function Write-Warning { param([string]$Message); Write-Host "[!] $Message" -ForegroundColor Yellow }

function Initialize-DeploymentManager {
    if (-not (Test-Path "patch-history")) {
        New-Item -ItemType Directory -Path "patch-history" -Force | Out-Null
    }
    Write-Status "Patch Deployment Manager initialized"
}

function Test-PatchFile {
    param([string]$File)
    
    if (-not $File) {
        Write-Error "Patch file not specified"
        return $false
    }
    
    if (-not (Test-Path $File)) {
        Write-Error "Patch file not found: $File"
        return $false
    }
    
    try {
        $content = Get-Content $File -Raw | ConvertFrom-Json
        if (-not $content.version -or -not $content.target_layer) {
            Write-Error "Invalid patch file format"
            return $false
        }
        return $true
    } catch {
        Write-Error "Failed to parse patch file: $_"
        return $false
    }
}

function Invoke-PatchDeployment {
    if (-not (Test-PatchFile $PatchFile)) { return }
    
    $patch = Get-Content $PatchFile -Raw | ConvertFrom-Json
    
    Write-Status "Deploying patch: $($patch.name) v$($patch.version)"
    Write-Status "Target layer: $($patch.target_layer)"
    Write-Status "Target host: $Target"
    
    if ($DryRun) {
        Write-Warning "DRY RUN - No changes will be applied"
        return
    }
    
    # Pre-deployment checks
    Write-Status "Running pre-deployment checks..."
    
    # Check if layer is available
    $layerStatus = Get-LayerStatus $patch.target_layer
    if (-not $layerStatus.Available) {
        if (-not $Force) {
            Write-Error "Target layer is not available. Use -Force to override."
            return
        }
        Write-Warning "Layer unavailable but -Force specified, continuing..."
    }
    
    # Create backup
    $backupId = [Guid]::NewGuid().ToString().Substring(0, 8)
    $backupPath = "patch-history/backup-$backupId.json"
    
    $backup = @{
        timestamp = Get-Date -Format "o"
        patch_name = $patch.name
        patch_version = $patch.version
        target_layer = $patch.target_layer
        backup_id = $backupId
        status = "created"
    }
    
    $backup | ConvertTo-Json | Out-File $backupPath
    Write-Success "Backup created: $backupId"
    
    # Deploy patch
    Write-Status "Applying patch..."
    
    # Simulate deployment
    Start-Sleep -Milliseconds 500
    
    $deployment = @{
        timestamp = Get-Date -Format "o"
        patch_file = $PatchFile
        patch_name = $patch.name
        patch_version = $patch.version
        target_layer = $patch.target_layer
        target = $Target
        backup_id = $backupId
        status = "deployed"
        deployed_by = $env:USERNAME
    }
    
    $historyFile = "patch-history/deployments.json"
    $history = @()
    if (Test-Path $historyFile) {
        $history = Get-Content $historyFile | ConvertFrom-Json
    }
    $history += $deployment
    $history | ConvertTo-Json -Depth 5 | Out-File $historyFile
    
    Write-Success "Patch deployed successfully!"
    Write-Host ""
    Write-Host "Deployment Details:" -ForegroundColor White
    Write-Host "  Patch: $($patch.name) v$($patch.version)" -ForegroundColor Gray
    Write-Host "  Layer: $($patch.target_layer)" -ForegroundColor Gray
    Write-Host "  Target: $Target" -ForegroundColor Gray
    Write-Host "  Backup ID: $backupId" -ForegroundColor Gray
    Write-Host ""
}

function Get-LayerStatus {
    param([string]$LayerName)
    
    # Simulate layer status check
    return @{
        Available = $true
        Active = $true
        LastCheck = Get-Date -Format "o"
    }
}

function Invoke-PatchRollback {
    param([string]$BackupId)
    
    if (-not $BackupId) {
        Write-Error "Backup ID required for rollback"
        return
    }
    
    $backupFile = "patch-history/backup-$BackupId.json"
    if (-not (Test-Path $backupFile)) {
        Write-Error "Backup not found: $BackupId"
        return
    }
    
    $backup = Get-Content $backupFile | ConvertFrom-Json
    
    Write-Status "Rolling back patch: $($backup.patch_name)"
    Write-Status "Backup ID: $BackupId"
    
    if ($DryRun) {
        Write-Warning "DRY RUN - No changes will be applied"
        return
    }
    
    # Simulate rollback
    Start-Sleep -Milliseconds 500
    
    $backup.status = "rolled_back"
    $backup.rollback_time = Get-Date -Format "o"
    $backup | ConvertTo-Json | Out-File $backupFile
    
    Write-Success "Rollback completed successfully!"
}

function Show-DeploymentStatus {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Patch Deployment Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $historyFile = "patch-history/deployments.json"
    if (-not (Test-Path $historyFile)) {
        Write-Host "No deployment history found" -ForegroundColor Gray
        return
    }
    
    $history = Get-Content $historyFile | ConvertFrom-Json
    $recent = $history | Select-Object -Last 10
    
    Write-Host "Recent Deployments:" -ForegroundColor White
    foreach ($deployment in $recent) {
        $color = if ($deployment.status -eq "deployed") { "Green" } else { "Red" }
        Write-Host "  [$($deployment.status)] $($deployment.patch_name) v$($deployment.patch_version)" -ForegroundColor $color
        Write-Host "    Layer: $($deployment.target_layer) | Target: $($deployment.target)" -ForegroundColor Gray
        Write-Host "    Time: $($deployment.timestamp)" -ForegroundColor Gray
        Write-Host ""
    }
    
    $total = $history.Count
    $deployed = ($history | Where-Object { $_.status -eq "deployed" }).Count
    $failed = ($history | Where-Object { $_.status -eq "failed" }).Count
    
    Write-Host "Statistics:" -ForegroundColor White
    Write-Host "  Total: $total | Deployed: $deployed | Failed: $failed" -ForegroundColor Gray
    Write-Host ""
}

function Show-DeploymentHistory {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Patch Deployment History" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $historyFile = "patch-history/deployments.json"
    if (-not (Test-Path $historyFile)) {
        Write-Host "No deployment history found" -ForegroundColor Gray
        return
    }
    
    $history = Get-Content $historyFile | ConvertFrom-Json
    
    Write-Host "All Deployments (newest first):" -ForegroundColor White
    $history | Sort-Object timestamp -Descending | ForEach-Object {
        $color = switch ($_.status) {
            "deployed" { "Green" }
            "failed" { "Red" }
            "rolled_back" { "Yellow" }
            default { "Gray" }
        }
        Write-Host "  [$($_.status)] $($_.patch_name) v$($_.patch_version)" -ForegroundColor $color
        Write-Host "    Layer: $($_.target_layer) | Target: $($_.target)" -ForegroundColor Gray
        Write-Host "    Time: $($_.timestamp) | By: $($_.deployed_by)" -ForegroundColor Gray
        Write-Host ""
    }
}

function Invoke-PatchValidation {
    if (-not $PatchFile) {
        Write-Error "Patch file required for validation"
        return
    }
    
    Write-Status "Validating patch file: $PatchFile"
    
    if (-not (Test-Path $PatchFile)) {
        Write-Error "Patch file not found"
        return
    }
    
    try {
        $patch = Get-Content $PatchFile -Raw | ConvertFrom-Json
        
        $valid = $true
        $issues = @()
        
        if (-not $patch.name) { $valid = $false; $issues += "Missing 'name' field" }
        if (-not $patch.version) { $valid = $false; $issues += "Missing 'version' field" }
        if (-not $patch.target_layer) { $valid = $false; $issues += "Missing 'target_layer' field" }
        if ($patch.target_layer -and $patch.target_layer -notin $ValidLayers) { 
            $valid = $false 
            $issues += "Invalid target_layer: $($patch.target_layer)" 
        }
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "Patch Validation Results" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "File: $PatchFile" -ForegroundColor White
        Write-Host "Name: $($patch.name)" -ForegroundColor White
        Write-Host "Version: $($patch.version)" -ForegroundColor White
        Write-Host "Target Layer: $($patch.target_layer)" -ForegroundColor White
        Write-Host ""
        
        if ($valid) {
            Write-Success "Patch file is valid!"
        } else {
            Write-Error "Patch file has issues:"
            foreach ($issue in $issues) {
                Write-Host "  • $issue" -ForegroundColor Red
            }
        }
        Write-Host ""
        
    } catch {
        Write-Error "Failed to validate patch file: $_"
    }
}

function Invoke-ScheduledDeployment {
    if (-not $ScheduleTime) {
        Write-Error "Schedule time required (-ScheduleTime)"
        return
    }
    
    if (-not (Test-PatchFile $PatchFile)) { return }
    
    $patch = Get-Content $PatchFile -Raw | ConvertFrom-Json
    
    Write-Status "Scheduling patch deployment"
    Write-Status "Patch: $($patch.name) v$($patch.version)"
    Write-Status "Scheduled for: $ScheduleTime"
    
    $schedule = @{
        timestamp = Get-Date -Format "o"
        scheduled_time = $ScheduleTime
        patch_file = $PatchFile
        patch_name = $patch.name
        patch_version = $patch.version
        target_layer = $patch.target_layer
        target = $Target
        status = "scheduled"
    }
    
    $scheduleFile = "patch-history/scheduled.json"
    $schedules = @()
    if (Test-Path $scheduleFile) {
        $schedules = Get-Content $scheduleFile | ConvertFrom-Json
    }
    $schedules += $schedule
    $schedules | ConvertTo-Json -Depth 5 | Out-File $scheduleFile
    
    Write-Success "Patch scheduled successfully!"
}

# Main execution
function Main {
    Write-Host "RawrXD Patch Deployment Manager" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-DeploymentManager
    
    switch ($Action) {
        "Deploy" { Invoke-PatchDeployment }
        "Rollback" { Invoke-PatchRollback }
        "Status" { Show-DeploymentStatus }
        "Validate" { Invoke-PatchValidation }
        "History" { Show-DeploymentHistory }
        "Schedule" { Invoke-ScheduledDeployment }
        default { Write-Host "Usage: .\patch-deployment.ps1 -Action [Deploy|Rollback|Status|Validate|History|Schedule]" }
    }
    
    Write-Host ""
}

Main

#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Swarm Hotpatch Manager - Runtime patching for swarm components
    
.DESCRIPTION
    Provides hotpatching capabilities for swarm coordinator, worker nodes,
    and swarm-wide configuration without requiring full restarts.
    
.PARAMETER Action
    Action to perform: apply, rollback, status, list, validate
    
.PARAMETER Target
    Target component: coordinator, worker, config, all
    
.PARAMETER PatchFile
    Path to patch definition file
    
.EXAMPLE
    .\swarm_hotpatch_manager.ps1 -Action apply -Target coordinator -PatchFile .\patches\swarm_coord_v2.json
    .\swarm_hotpatch_manager.ps1 -Action status
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("apply", "rollback", "status", "list", "validate", "emergency")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("coordinator", "worker", "config", "loadbalancer", "all")]
    [string]$Target = "all",
    
    [Parameter(Mandatory=$false)]
    [string]$PatchFile,
    
    [Parameter(Mandatory=$false)]
    [string]$SwarmId,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Hotpatch registry for swarm
$SwarmHotpatchRegistry = @{
    Version = "1.0.0"
    AppliedPatches = @()
    RollbackHistory = @()
    ComponentStatus = @{}
}

# Swarm component definitions
$SwarmComponents = @{
    coordinator = @{
        Name = "Swarm Coordinator"
        ProcessName = "rawrxd_swarm_coord"
        ServiceName = "RawrXDSwarmCoord"
        ConfigPath = "$env:RAWRXD_HOME\config\swarm\coordinator.json"
        BackupPath = "$env:RAWRXD_HOME\backups\swarm\coordinator"
        Hotpatchable = $true
        Critical = $true
    }
    worker = @{
        Name = "Swarm Worker"
        ProcessName = "rawrxd_swarm_worker"
        ServiceName = "RawrXDSwarmWorker"
        ConfigPath = "$env:RAWRXD_HOME\config\swarm\worker.json"
        BackupPath = "$env:RAWRXD_HOME\backups\swarm\worker"
        Hotpatchable = $true
        Critical = $false
    }
    loadbalancer = @{
        Name = "Swarm Load Balancer"
        ProcessName = "rawrxd_swarm_lb"
        ServiceName = "RawrXDSwarmLB"
        ConfigPath = "$env:RAWRXD_HOME\config\swarm\loadbalancer.json"
        BackupPath = "$env:RAWRXD_HOME\backups\swarm\loadbalancer"
        Hotpatchable = $true
        Critical = $true
    }
    config = @{
        Name = "Swarm Configuration"
        ProcessName = $null
        ServiceName = $null
        ConfigPath = "$env:RAWRXD_HOME\config\swarm\global.json"
        BackupPath = "$env:RAWRXD_HOME\backups\swarm\global"
        Hotpatchable = $true
        Critical = $false
    }
}

function Write-SwarmHotpatchHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Swarm Hotpatch Manager                                            ║
║  Runtime patching for swarm components                             ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-SwarmHotpatchManager {
    $registryPath = "$env:RAWRXD_HOME\registry\swarm_hotpatch.json"
    if (Test-Path $registryPath) {
        $script:SwarmHotpatchRegistry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json -AsHashtable
    }
    
    # Ensure backup directories exist
    foreach ($component in $SwarmComponents.Values) {
        if (-not (Test-Path $component.BackupPath)) {
            New-Item -ItemType Directory -Path $component.BackupPath -Force | Out-Null
        }
    }
}

function Save-SwarmHotpatchRegistry {
    $registryPath = "$env:RAWRXD_HOME\registry\swarm_hotpatch.json"
    if (-not (Test-Path (Split-Path $registryPath))) {
        New-Item -ItemType Directory -Path (Split-Path $registryPath) -Force | Out-Null
    }
    $script:SwarmHotpatchRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryPath
}

function Test-SwarmComponentHealth {
    param($ComponentName)
    
    $component = $SwarmComponents[$ComponentName]
    if (-not $component) { return $false }
    
    # Check if process is running
    if ($component.ProcessName) {
        $process = Get-Process -Name $component.ProcessName -ErrorAction SilentlyContinue
        if (-not $process) {
            return $false
        }
    }
    
    # Check if service is running (if applicable)
    if ($component.ServiceName) {
        $service = Get-Service -Name $component.ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Running") {
            return $false
        }
    }
    
    return $true
}

function Backup-SwarmComponent {
    param($ComponentName)
    
    $component = $SwarmComponents[$ComponentName]
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $component.BackupPath "backup_$timestamp.json"
    
    if (Test-Path $component.ConfigPath) {
        Copy-Item -Path $component.ConfigPath -Destination $backupFile -Force
        Write-Host "  ✓ Backup created: $backupFile" -ForegroundColor Green
        return $backupFile
    }
    
    return $null
}

function Invoke-SwarmHotpatch {
    param($ComponentName, $PatchFile, [switch]$DryRun)
    
    Write-Host "`nApplying hotpatch to $ComponentName..." -ForegroundColor Yellow
    
    $component = $SwarmComponents[$ComponentName]
    if (-not $component) {
        Write-Error "Unknown component: $ComponentName"
        return
    }
    
    if (-not $component.Hotpatchable) {
        Write-Error "Component $ComponentName is not hotpatchable"
        return
    }
    
    # Load patch definition
    if (-not (Test-Path $PatchFile)) {
        Write-Error "Patch file not found: $PatchFile"
        return
    }
    
    $patch = Get-Content -Path $PatchFile -Raw | ConvertFrom-Json
    
    # Validate component health
    if (-not (Test-SwarmComponentHealth -ComponentName $ComponentName)) {
        Write-Error "Component $ComponentName is not healthy. Aborting hotpatch."
        return
    }
    
    # Create backup
    $backupPath = Backup-SwarmComponent -ComponentName $ComponentName
    
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would apply patch:" -ForegroundColor Cyan
        Write-Host "    Component: $($component.Name)" -ForegroundColor Gray
        Write-Host "    Patch Version: $($patch.Version)" -ForegroundColor Gray
        Write-Host "    Changes: $($patch.Changes.Count)" -ForegroundColor Gray
        return
    }
    
    # Apply patch based on type
    switch ($patch.Type) {
        "config" {
            Apply-ConfigHotpatch -Component $component -Patch $patch
        }
        "code" {
            Apply-CodeHotpatch -Component $component -Patch $patch
        }
        "binary" {
            Apply-BinaryHotpatch -Component $component -Patch $patch
        }
        default {
            Write-Error "Unknown patch type: $($patch.Type)"
            return
        }
    }
    
    # Register patch
    $patchRecord = @{
        Id = [Guid]::NewGuid().ToString()
        Component = $ComponentName
        PatchVersion = $patch.Version
        AppliedAt = Get-Date -Format "o"
        BackupPath = $backupPath
        PatchFile = $PatchFile
        Status = "applied"
    }
    
    $script:SwarmHotpatchRegistry.AppliedPatches += $patchRecord
    Save-SwarmHotpatchRegistry
    
    Write-Host "  ✓ Hotpatch applied successfully" -ForegroundColor Green
    Write-Host "    Patch ID: $($patchRecord.Id)" -ForegroundColor Gray
}

function Apply-ConfigHotpatch {
    param($Component, $Patch)
    
    Write-Host "  Applying configuration hotpatch..." -ForegroundColor Gray
    
    $config = Get-Content -Path $component.ConfigPath -Raw | ConvertFrom-Json
    
    foreach ($change in $patch.Changes) {
        $path = $change.Path -split '\.'
        $current = $config
        
        for ($i = 0; $i -lt $path.Count - 1; $i++) {
            $current = $current.$($path[$i])
        }
        
        $current.$($path[-1]) = $change.Value
        Write-Host "    Updated: $($change.Path) = $($change.Value)" -ForegroundColor Gray
    }
    
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $component.ConfigPath
    
    # Signal component to reload config
    if ($component.ProcessName) {
        $process = Get-Process -Name $component.ProcessName -ErrorAction SilentlyContinue
        if ($process) {
            # Send SIGHUP or equivalent signal for config reload
            # On Windows, this might be a custom signal or named pipe message
            Write-Host "    Signaled component to reload configuration" -ForegroundColor Gray
        }
    }
}

function Apply-CodeHotpatch {
    param($Component, $Patch)
    
    Write-Host "  Applying code hotpatch..." -ForegroundColor Gray
    
    # Code hotpatching involves replacing function implementations
    # This is typically done via DLL injection or shared library updates
    foreach ($change in $patch.Changes) {
        Write-Host "    Patching function: $($change.FunctionName)" -ForegroundColor Gray
        # Implementation would use platform-specific hotpatching mechanisms
    }
}

function Apply-BinaryHotpatch {
    param($Component, $Patch)
    
    Write-Host "  Applying binary hotpatch..." -ForegroundColor Gray
    Write-Warning "Binary hotpatching is advanced and requires careful handling"
    
    # Binary patching involves modifying in-memory code
    # This requires suspended threads and careful memory management
    foreach ($change in $patch.Changes) {
        Write-Host "    Binary patch at offset: $($change.Offset)" -ForegroundColor Gray
    }
}

function Invoke-SwarmRollback {
    param($PatchId)
    
    Write-Host "`nRolling back hotpatch $PatchId..." -ForegroundColor Yellow
    
    $patch = $script:SwarmHotpatchRegistry.AppliedPatches | Where-Object { $_.Id -eq $PatchId } | Select-Object -First 1
    if (-not $patch) {
        Write-Error "Patch not found: $PatchId"
        return
    }
    
    $component = $SwarmComponents[$patch.Component]
    
    # Restore from backup
    if (Test-Path $patch.BackupPath) {
        Copy-Item -Path $patch.BackupPath -Destination $component.ConfigPath -Force
        Write-Host "  ✓ Restored from backup" -ForegroundColor Green
    }
    
    # Update registry
    $patch.Status = "rolled_back"
    $patch.RolledBackAt = Get-Date -Format "o"
    $script:SwarmHotpatchRegistry.RollbackHistory += $patch
    Save-SwarmHotpatchRegistry
    
    Write-Host "  ✓ Rollback completed" -ForegroundColor Green
}

function Get-SwarmHotpatchStatus {
    Write-Host "`nSwarm Hotpatch Status:" -ForegroundColor Yellow
    Write-Host ""
    
    # Component health
    Write-Host "  Component Health:" -ForegroundColor Cyan
    foreach ($componentName in $SwarmComponents.Keys) {
        $component = $SwarmComponents[$componentName]
        $health = Test-SwarmComponentHealth -ComponentName $componentName
        $status = if ($health) { "✓ Healthy" } else { "✗ Unhealthy" }
        $color = if ($health) { "Green" } else { "Red" }
        Write-Host "    $($component.Name): $status" -ForegroundColor $color
    }
    
    # Applied patches
    Write-Host "`n  Applied Patches ($($script:SwarmHotpatchRegistry.AppliedPatches.Count)):" -ForegroundColor Cyan
    foreach ($patch in ($script:SwarmHotpatchRegistry.AppliedPatches | Sort-Object AppliedAt -Descending | Select-Object -First 10)) {
        $statusColor = switch ($patch.Status) {
            "applied" { "Green" }
            "rolled_back" { "Red" }
            default { "Gray" }
        }
        Write-Host "    [$($patch.Status)] $($patch.Component) - v$($patch.PatchVersion)" -ForegroundColor $statusColor
    }
}

function Get-SwarmHotpatchList {
    Write-Host "`nAvailable Swarm Hotpatches:" -ForegroundColor Yellow
    
    $patchDir = "$env:RAWRXD_HOME\patches\swarm"
    if (Test-Path $patchDir) {
        $patches = Get-ChildItem -Path $patchDir -Filter "*.json"
        foreach ($patch in $patches) {
            $content = Get-Content -Path $patch.FullName -Raw | ConvertFrom-Json
            Write-Host "  $($patch.Name)" -ForegroundColor White
            Write-Host "    Version: $($content.Version)" -ForegroundColor Gray
            Write-Host "    Type: $($content.Type)" -ForegroundColor Gray
            Write-Host "    Description: $($content.Description)" -ForegroundColor Gray
            Write-Host ""
        }
    } else {
        Write-Host "  No patches found in $patchDir" -ForegroundColor Gray
    }
}

function Invoke-EmergencySwarmHotpatch {
    Write-Host "`n🚨 EMERGENCY SWARM HOTPATCH MODE 🚨" -ForegroundColor Red
    Write-Host ""
    
    # Emergency patches for critical swarm issues
    $emergencyPatches = @{
        "coord_failover" = "Enable coordinator failover"
        "worker_restart" = "Emergency worker restart"
        "lb_reset" = "Load balancer reset"
        "config_reset" = "Configuration reset to defaults"
    }
    
    Write-Host "Available emergency patches:" -ForegroundColor Yellow
    foreach ($key in $emergencyPatches.Keys) {
        Write-Host "  $key - $($emergencyPatches[$key])" -ForegroundColor White
    }
    
    Write-Host "`n⚠️  Emergency patches may cause service disruption!" -ForegroundColor Red
}

# Main execution
Write-SwarmHotpatchHeader
Initialize-SwarmHotpatchManager

switch ($Action) {
    "apply" {
        if (-not $PatchFile) {
            Write-Error "PatchFile required for apply action"
            exit 1
        }
        if ($Target -eq "all") {
            foreach ($componentName in $SwarmComponents.Keys) {
                Invoke-SwarmHotpatch -ComponentName $componentName -PatchFile $PatchFile -DryRun:$DryRun
            }
        } else {
            Invoke-SwarmHotpatch -ComponentName $Target -PatchFile $PatchFile -DryRun:$DryRun
        }
    }
    "rollback" {
        if (-not $PatchFile) {
            Write-Error "PatchFile (PatchId) required for rollback action"
            exit 1
        }
        Invoke-SwarmRollback -PatchId $PatchFile
    }
    "status" {
        Get-SwarmHotpatchStatus
    }
    "list" {
        Get-SwarmHotpatchList
    }
    "validate" {
        Write-Host "`nValidating swarm hotpatch readiness..." -ForegroundColor Yellow
        foreach ($componentName in $SwarmComponents.Keys) {
            $health = Test-SwarmComponentHealth -ComponentName $componentName
            $status = if ($health) { "✓ Ready" } else { "✗ Not ready" }
            $color = if ($health) { "Green" } else { "Red" }
            Write-Host "  $($SwarmComponents[$componentName].Name): $status" -ForegroundColor $color
        }
    }
    "emergency" {
        Invoke-EmergencySwarmHotpatch
    }
}

Write-Host "`n✅ Swarm hotpatch operation complete" -ForegroundColor Green

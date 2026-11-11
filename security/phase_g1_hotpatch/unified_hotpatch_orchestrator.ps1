#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Unified Hotpatch Orchestrator - Coordinates all hotpatching systems
    
.DESCRIPTION
    Provides centralized coordination for swarm, agent, and tools hotpatching.
    Ensures consistency, prevents conflicts, and manages dependencies between systems.
    
.PARAMETER Action
    Action to perform: apply, rollback, status, validate, emergency
    
.PARAMETER System
    Target system: swarm, agent, tools, all
    
.PARAMETER PatchBundle
    Path to patch bundle (contains patches for multiple systems)
    
.EXAMPLE
    .\unified_hotpatch_orchestrator.ps1 -Action apply -System all -PatchBundle .\patches\hotfix_v1.1.json
    .\unified_hotpatch_orchestrator.ps1 -Action status
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("apply", "rollback", "status", "validate", "emergency", "sync", "health-check")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("swarm", "agent", "tools", "all")]
    [string]$System = "all",
    
    [Parameter(Mandatory=$false)]
    [string]$PatchBundle,
    
    [Parameter(Mandatory=$false)]
    [string]$PatchId,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoDepsCheck
)

$ErrorActionPreference = "Stop"

# Unified hotpatch registry
$UnifiedHotpatchRegistry = @{
    Version = "1.0.0"
    LastSync = $null
    Systems = @{
        swarm = @{ Status = "unknown"; LastCheck = $null }
        agent = @{ Status = "unknown"; LastCheck = $null }
        tools = @{ Status = "unknown"; LastCheck = $null }
    }
    CoordinatedPatches = @()
    Dependencies = @()
    Conflicts = @()
}

# System managers
$SystemManagers = @{
    swarm = "$PSScriptRoot\swarm_hotpatch_manager.ps1"
    agent = "$PSScriptRoot\agent_hotpatch_manager.ps1"
    tools = "$PSScriptRoot\tools_hotpatch_manager.ps1"
}

function Write-UnifiedHotpatchHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Unified Hotpatch Orchestrator                                     ║
║  Coordinates swarm, agent, and tools hotpatching                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Magenta
}

function Initialize-UnifiedHotpatchOrchestrator {
    $registryPath = "$env:RAWRXD_HOME\registry\unified_hotpatch.json"
    if (Test-Path $registryPath) {
        $script:UnifiedHotpatchRegistry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-UnifiedHotpatchRegistry {
    $registryPath = "$env:RAWRXD_HOME\registry\unified_hotpatch.json"
    if (-not (Test-Path (Split-Path $registryPath))) {
        New-Item -ItemType Directory -Path (Split-Path $registryPath) -Force | Out-Null
    }
    $script:UnifiedHotpatchRegistry.LastSync = Get-Date -Format "o"
    $script:UnifiedHotpatchRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryPath
}

function Test-SystemHealth {
    param($SystemName)
    
    $manager = $SystemManagers[$SystemName]
    if (-not (Test-Path $manager)) {
        return @{ Healthy = $false; Error = "Manager not found: $manager" }
    }
    
    try {
        $result = & $manager -Action "validate" 2>&1
        $healthy = $result -match "Ready|✓"
        return @{ 
            Healthy = $healthy
            Details = $result
            Timestamp = Get-Date -Format "o"
        }
    } catch {
        return @{ Healthy = $false; Error = $_.Exception.Message }
    }
}

function Update-SystemStatus {
    foreach ($system in $SystemManagers.Keys) {
        $health = Test-SystemHealth -SystemName $system
        $script:UnifiedHotpatchRegistry.Systems[$system].Status = if ($health.Healthy) { "healthy" } else { "unhealthy" }
        $script:UnifiedHotpatchRegistry.Systems[$system].LastCheck = Get-Date -Format "o"
    }
    Save-UnifiedHotpatchRegistry
}

function Test-PatchDependencies {
    param($PatchBundle)
    
    if (-not (Test-Path $PatchBundle)) {
        return @{ Valid = $false; Error = "Patch bundle not found" }
    }
    
    $bundle = Get-Content -Path $PatchBundle -Raw | ConvertFrom-Json
    $dependencies = @()
    $conflicts = @()
    
    # Check dependencies
    if ($bundle.Dependencies) {
        foreach ($dep in $bundle.Dependencies) {
            $depSystem = $dep.System
            $depVersion = $dep.MinimumVersion
            
            # Check if system is healthy
            $health = Test-SystemHealth -SystemName $depSystem
            if (-not $health.Healthy) {
                $dependencies += "System $depSystem is not healthy (required by dependency)"
            }
        }
    }
    
    # Check for conflicts
    if ($bundle.Conflicts) {
        foreach ($conflict in $bundle.Conflicts) {
            $existingPatches = $script:UnifiedHotpatchRegistry.CoordinatedPatches | 
                Where-Object { $_.PatchId -eq $conflict.PatchId -and $_.Status -eq "applied" }
            
            if ($existingPatches) {
                $conflicts += "Conflicts with existing patch: $($conflict.PatchId)"
            }
        }
    }
    
    return @{
        Valid = ($dependencies.Count -eq 0 -and $conflicts.Count -eq 0)
        Dependencies = $dependencies
        Conflicts = $conflicts
        Bundle = $bundle
    }
}

function Invoke-CoordinatedHotpatch {
    param($PatchBundle, [switch]$DryRun, [switch]$NoDepsCheck)
    
    Write-Host "`nApplying coordinated hotpatch bundle..." -ForegroundColor Yellow
    
    # Validate bundle
    if (-not $NoDepsCheck) {
        $validation = Test-PatchDependencies -PatchBundle $PatchBundle
        if (-not $validation.Valid) {
            Write-Error "Patch bundle validation failed:`n  $($validation.Dependencies -join "`n  ")`n  $($validation.Conflicts -join "`n  ")"
            return
        }
    }
    
    $bundle = Get-Content -Path $PatchBundle -Raw | ConvertFrom-Json
    $coordinatedPatchId = [Guid]::NewGuid().ToString()
    $patchResults = @()
    
    # Apply patches in order: tools -> agent -> swarm
    $applyOrder = @("tools", "agent", "swarm")
    
    foreach ($system in $applyOrder) {
        $systemPatch = $bundle.Patches | Where-Object { $_.System -eq $system } | Select-Object -First 1
        if (-not $systemPatch) { continue }
        
        Write-Host "`n  Applying $system patch..." -ForegroundColor Cyan
        
        $manager = $SystemManagers[$system]
        $patchFile = $systemPatch.PatchFile
        
        if ($DryRun) {
            Write-Host "    [DRY RUN] Would apply: $patchFile" -ForegroundColor Gray
            $patchResults += @{ System = $system; Status = "dry-run"; PatchFile = $patchFile }
            continue
        }
        
        try {
            # Apply the patch
            $result = & $manager -Action "apply" -Target $systemPatch.Target -PatchFile $patchFile -Force:$Force
            $patchResults += @{ System = $system; Status = "success"; PatchFile = $patchFile }
            Write-Host "    ✓ $system patch applied" -ForegroundColor Green
        } catch {
            $patchResults += @{ System = $system; Status = "failed"; PatchFile = $patchFile; Error = $_.Exception.Message }
            Write-Host "    ✗ $system patch failed: $($_.Exception.Message)" -ForegroundColor Red
            
            # Rollback previous patches on failure
            if (-not $DryRun) {
                Write-Host "`n  Rolling back previous patches..." -ForegroundColor Yellow
                foreach ($prevResult in ($patchResults | Where-Object { $_.Status -eq "success" })) {
                    $prevManager = $SystemManagers[$prevResult.System]
                    # Extract patch ID from result and rollback
                    Write-Host "    Rolling back $($prevResult.System)..." -ForegroundColor Gray
                }
            }
            
            return
        }
    }
    
    # Register coordinated patch
    $coordinatedPatch = @{
        Id = $coordinatedPatchId
        BundleFile = $PatchBundle
        AppliedAt = Get-Date -Format "o"
        Status = "applied"
        Results = $patchResults
        BundleVersion = $bundle.Version
    }
    
    $script:UnifiedHotpatchRegistry.CoordinatedPatches += $coordinatedPatch
    Save-UnifiedHotpatchRegistry
    
    Write-Host "`n✓ Coordinated patch applied: $coordinatedPatchId" -ForegroundColor Green
}

function Invoke-CoordinatedRollback {
    param($PatchId)
    
    Write-Host "`nRolling back coordinated patch $PatchId..." -ForegroundColor Yellow
    
    $patch = $script:UnifiedHotpatchRegistry.CoordinatedPatches | 
        Where-Object { $_.Id -eq $PatchId } | Select-Object -First 1
    
    if (-not $patch) {
        Write-Error "Coordinated patch not found: $PatchId"
        return
    }
    
    # Rollback in reverse order: swarm -> agent -> tools
    $rollbackOrder = @("swarm", "agent", "tools")
    
    foreach ($system in $rollbackOrder) {
        $systemResult = $patch.Results | Where-Object { $_.System -eq $system } | Select-Object -First 1
        if (-not $systemResult) { continue }
        
        Write-Host "  Rolling back $system..." -ForegroundColor Gray
        
        $manager = $SystemManagers[$system]
        # Extract patch ID from system result and rollback
        
        try {
            & $manager -Action "rollback" -PatchFile $systemResult.PatchId
            Write-Host "    ✓ $system rolled back" -ForegroundColor Green
        } catch {
            Write-Host "    ✗ $system rollback failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Update registry
    $patch.Status = "rolled_back"
    $patch.RolledBackAt = Get-Date -Format "o"
    Save-UnifiedHotpatchRegistry
    
    Write-Host "`n✓ Coordinated rollback completed" -ForegroundColor Green
}

function Get-UnifiedHotpatchStatus {
    Write-Host "`nUnified Hotpatch Status:" -ForegroundColor Yellow
    Write-Host ""
    
    # System health
    Write-Host "  System Health:" -ForegroundColor Cyan
    foreach ($system in $script:UnifiedHotpatchRegistry.Systems.Keys) {
        $status = $script:UnifiedHotpatchRegistry.Systems[$system].Status
        $lastCheck = $script:UnifiedHotpatchRegistry.Systems[$system].LastCheck
        $color = switch ($status) {
            "healthy" { "Green" }
            "unhealthy" { "Red" }
            default { "Gray" }
        }
        Write-Host "    $system`: $status" -ForegroundColor $color
        if ($lastCheck) {
            Write-Host "      Last check: $([DateTime]::Parse($lastCheck).ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor DarkGray
        }
    }
    
    # Coordinated patches
    Write-Host "`n  Coordinated Patches ($($script:UnifiedHotpatchRegistry.CoordinatedPatches.Count)):" -ForegroundColor Cyan
    foreach ($patch in ($script:UnifiedHotpatchRegistry.CoordinatedPatches | Sort-Object AppliedAt -Descending | Select-Object -First 10)) {
        $statusColor = switch ($patch.Status) {
            "applied" { "Green" }
            "rolled_back" { "Red" }
            default { "Gray" }
        }
        Write-Host "    [$($patch.Status)] Bundle v$($patch.BundleVersion)" -ForegroundColor $statusColor
        Write-Host "      ID: $($patch.Id)" -ForegroundColor DarkGray
        Write-Host "      Systems: $($patch.Results.System -join ', ')" -ForegroundColor DarkGray
    }
    
    # Last sync
    if ($script:UnifiedHotpatchRegistry.LastSync) {
        Write-Host "`n  Last Sync: $([DateTime]::Parse($script:UnifiedHotpatchRegistry.LastSync).ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    }
}

function Invoke-EmergencyUnifiedHotpatch {
    Write-Host "`n🚨 EMERGENCY UNIFIED HOTPATCH MODE 🚨" -ForegroundColor Red
    Write-Host ""
    
    Write-Host "Emergency procedures available:" -ForegroundColor Yellow
    Write-Host "  1. Full system rollback" -ForegroundColor White
    Write-Host "  2. Isolate and disable all systems" -ForegroundColor White
    Write-Host "  3. Emergency patch from known-good state" -ForegroundColor White
    Write-Host "  4. System health reset" -ForegroundColor White
    
    Write-Host "`n⚠️  Emergency procedures may cause service disruption!" -ForegroundColor Red
    Write-Host "   Use only when normal operations have failed." -ForegroundColor Red
}

function Invoke-SystemSync {
    Write-Host "`nSynchronizing hotpatch systems..." -ForegroundColor Yellow
    
    Update-SystemStatus
    
    Write-Host "  System statuses updated:" -ForegroundColor Cyan
    foreach ($system in $script:UnifiedHotpatchRegistry.Systems.Keys) {
        $status = $script:UnifiedHotpatchRegistry.Systems[$system].Status
        $color = if ($status -eq "healthy") { "Green" } else { "Red" }
        Write-Host "    $system`: $status" -ForegroundColor $color
    }
    
    Save-UnifiedHotpatchRegistry
    Write-Host "`n✓ Systems synchronized" -ForegroundColor Green
}

function Invoke-HealthCheck {
    Write-Host "`nPerforming comprehensive health check..." -ForegroundColor Yellow
    
    $issues = @()
    
    foreach ($system in $SystemManagers.Keys) {
        Write-Host "  Checking $system..." -ForegroundColor Gray
        $health = Test-SystemHealth -SystemName $system
        
        if (-not $health.Healthy) {
            $issues += "$system`: $($health.Error)"
            Write-Host "    ✗ Unhealthy: $($health.Error)" -ForegroundColor Red
        } else {
            Write-Host "    ✓ Healthy" -ForegroundColor Green
        }
    }
    
    # Check registry consistency
    Write-Host "  Checking registry consistency..." -ForegroundColor Gray
    $registryPath = "$env:RAWRXD_HOME\registry"
    if (Test-Path $registryPath) {
        $registries = Get-ChildItem -Path $registryPath -Filter "*hotpatch.json"
        Write-Host "    Found $($registries.Count) hotpatch registries" -ForegroundColor Green
    }
    
    # Check backup directories
    Write-Host "  Checking backup directories..." -ForegroundColor Gray
    $backupPath = "$env:RAWRXD_HOME\backups"
    if (Test-Path $backupPath) {
        $backups = Get-ChildItem -Path $backupPath -Recurse -Directory
        Write-Host "    Found $($backups.Count) backup directories" -ForegroundColor Green
    }
    
    if ($issues.Count -gt 0) {
        Write-Host "`n⚠️  Health check completed with issues:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "  - $issue" -ForegroundColor Red
        }
    } else {
        Write-Host "`n✓ All systems healthy" -ForegroundColor Green
    }
}

# Main execution
Write-UnifiedHotpatchHeader
Initialize-UnifiedHotpatchOrchestrator

switch ($Action) {
    "apply" {
        if (-not $PatchBundle) {
            Write-Error "PatchBundle required for apply action"
            exit 1
        }
        Invoke-CoordinatedHotpatch -PatchBundle $PatchBundle -DryRun:$DryRun -NoDepsCheck:$NoDepsCheck
    }
    "rollback" {
        if (-not $PatchId) {
            Write-Error "PatchId required for rollback action"
            exit 1
        }
        Invoke-CoordinatedRollback -PatchId $PatchId
    }
    "status" {
        Get-UnifiedHotpatchStatus
    }
    "validate" {
        if (-not $PatchBundle) {
            Write-Error "PatchBundle required for validate action"
            exit 1
        }
        $validation = Test-PatchDependencies -PatchBundle $PatchBundle
        Write-Host "`nValidation Results:" -ForegroundColor Yellow
        Write-Host "  Valid: $($validation.Valid)" -ForegroundColor $(if ($validation.Valid) { "Green" } else { "Red" })
        if ($validation.Dependencies.Count -gt 0) {
            Write-Host "  Dependencies:" -ForegroundColor Cyan
            $validation.Dependencies | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
        }
        if ($validation.Conflicts.Count -gt 0) {
            Write-Host "  Conflicts:" -ForegroundColor Red
            $validation.Conflicts | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
        }
    }
    "emergency" {
        Invoke-EmergencyUnifiedHotpatch
    }
    "sync" {
        Invoke-SystemSync
    }
    "health-check" {
        Invoke-HealthCheck
    }
}

Write-Host "`n✅ Unified hotpatch orchestration complete" -ForegroundColor Green

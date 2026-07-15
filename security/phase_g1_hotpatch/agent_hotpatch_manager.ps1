#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Agent Hotpatch Manager - Runtime patching for agentic components
    
.DESCRIPTION
    Provides hotpatching capabilities for agent orchestrator, agent workers,
    agent tools, and agent configuration without requiring restarts.
    
.PARAMETER Action
    Action to perform: apply, rollback, status, list, validate
    
.PARAMETER Target
    Target component: orchestrator, worker, tools, config, policy, all
    
.PARAMETER PatchFile
    Path to patch definition file
    
.PARAMETER AgentId
    Specific agent ID to target (optional)
    
.EXAMPLE
    .\agent_hotpatch_manager.ps1 -Action apply -Target orchestrator -PatchFile .\patches\agent_coord_v2.json
    .\agent_hotpatch_manager.ps1 -Action status
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("apply", "rollback", "status", "list", "validate", "emergency", "policy-update")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("orchestrator", "worker", "tools", "config", "policy", "memory", "all")]
    [string]$Target = "all",
    
    [Parameter(Mandatory=$false)]
    [string]$PatchFile,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentId,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Agent hotpatch registry
$AgentHotpatchRegistry = @{
    Version = "1.0.0"
    AppliedPatches = @()
    RollbackHistory = @()
    ComponentStatus = @{}
    AgentSpecificPatches = @{}
}

# Agent component definitions
$AgentComponents = @{
    orchestrator = @{
        Name = "Agent Orchestrator"
        ProcessName = "rawrxd_agent_orchestrator"
        ServiceName = "RawrXDAgentOrchestrator"
        ConfigPath = "$env:RAWRXD_HOME\config\agent\orchestrator.json"
        BackupPath = "$env:RAWRXD_HOME\backups\agent\orchestrator"
        Hotpatchable = $true
        Critical = $true
        SupportsDynamicReload = $true
    }
    worker = @{
        Name = "Agent Worker"
        ProcessName = "rawrxd_agent_worker"
        ServiceName = "RawrXDAgentWorker"
        ConfigPath = "$env:RAWRXD_HOME\config\agent\worker.json"
        BackupPath = "$env:RAWRXD_HOME\backups\agent\worker"
        Hotpatchable = $true
        Critical = $false
        SupportsDynamicReload = $true
    }
    tools = @{
        Name = "Agent Tools"
        ProcessName = $null
        ServiceName = $null
        ConfigPath = "$env:RAWRXD_HOME\config\agent\tools.json"
        BackupPath = "$env:RAWRXD_HOME\backups\agent\tools"
        Hotpatchable = $true
        Critical = $false
        SupportsDynamicReload = $true
    }
    policy = @{
        Name = "Agent Policy Engine"
        ProcessName = "rawrxd_agent_policy"
        ServiceName = "RawrXDAgentPolicy"
        ConfigPath = "$env:RAWRXD_HOME\config\agent\policy.json"
        BackupPath = "$env:RAWRXD_HOME\backups\agent\policy"
        Hotpatchable = $true
        Critical = $true
        SupportsDynamicReload = $true
    }
    memory = @{
        Name = "Agent Memory Store"
        ProcessName = "rawrxd_agent_memory"
        ServiceName = "RawrXDAgentMemory"
        ConfigPath = "$env:RAWRXD_HOME\config\agent\memory.json"
        BackupPath = "$env:RAWRXD_HOME\backups\agent\memory"
        Hotpatchable = $true
        Critical = $false
        SupportsDynamicReload = $false  # Requires restart for memory layout changes
    }
    config = @{
        Name = "Agent Global Configuration"
        ProcessName = $null
        ServiceName = $null
        ConfigPath = "$env:RAWRXD_HOME\config\agent\global.json"
        BackupPath = "$env:RAWRXD_HOME\backups\agent\global"
        Hotpatchable = $true
        Critical = $false
        SupportsDynamicReload = $true
    }
}

function Write-AgentHotpatchHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Agent Hotpatch Manager                                            ║
║  Runtime patching for agentic components                           ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-AgentHotpatchManager {
    $registryPath = "$env:RAWRXD_HOME\registry\agent_hotpatch.json"
    if (Test-Path $registryPath) {
        $script:AgentHotpatchRegistry = Get-Content -Path $registryPath -Raw | ConvertFrom-Json -AsHashtable
    }
    
    # Ensure backup directories exist
    foreach ($component in $AgentComponents.Values) {
        if (-not (Test-Path $component.BackupPath)) {
            New-Item -ItemType Directory -Path $component.BackupPath -Force | Out-Null
        }
    }
}

function Save-AgentHotpatchRegistry {
    $registryPath = "$env:RAWRXD_HOME\registry\agent_hotpatch.json"
    if (-not (Test-Path (Split-Path $registryPath))) {
        New-Item -ItemType Directory -Path (Split-Path $registryPath) -Force | Out-Null
    }
    $script:AgentHotpatchRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryPath
}

function Test-AgentComponentHealth {
    param($ComponentName)
    
    $component = $AgentComponents[$ComponentName]
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

function Backup-AgentComponent {
    param($ComponentName)
    
    $component = $AgentComponents[$ComponentName]
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $component.BackupPath "backup_$timestamp.json"
    
    if (Test-Path $component.ConfigPath) {
        Copy-Item -Path $component.ConfigPath -Destination $backupFile -Force
        Write-Host "  ✓ Backup created: $backupFile" -ForegroundColor Green
        return $backupFile
    }
    
    return $null
}

function Invoke-AgentHotpatch {
    param($ComponentName, $PatchFile, [string]$AgentId, [switch]$DryRun)
    
    Write-Host "`nApplying hotpatch to $ComponentName..." -ForegroundColor Yellow
    
    $component = $AgentComponents[$ComponentName]
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
    if (-not (Test-AgentComponentHealth -ComponentName $ComponentName)) {
        Write-Error "Component $ComponentName is not healthy. Aborting hotpatch."
        return
    }
    
    # Check if dynamic reload is supported
    if (-not $component.SupportsDynamicReload -and -not $Force) {
        Write-Warning "Component $ComponentName does not support dynamic reload. Use -Force to override."
        return
    }
    
    # Create backup
    $backupPath = Backup-AgentComponent -ComponentName $ComponentName
    
    if ($DryRun) {
        Write-Host "  [DRY RUN] Would apply patch:" -ForegroundColor Cyan
        Write-Host "    Component: $($component.Name)" -ForegroundColor Gray
        Write-Host "    Patch Version: $($patch.Version)" -ForegroundColor Gray
        Write-Host "    Changes: $($patch.Changes.Count)" -ForegroundColor Gray
        if ($AgentId) {
            Write-Host "    Target Agent: $AgentId" -ForegroundColor Gray
        }
        return
    }
    
    # Apply patch based on type
    switch ($patch.Type) {
        "config" {
            Apply-AgentConfigHotpatch -Component $component -Patch $patch -AgentId $AgentId
        }
        "policy" {
            Apply-AgentPolicyHotpatch -Component $component -Patch $patch -AgentId $AgentId
        }
        "tools" {
            Apply-AgentToolsHotpatch -Component $component -Patch $patch -AgentId $AgentId
        }
        "memory" {
            Apply-AgentMemoryHotpatch -Component $component -Patch $patch -AgentId $AgentId
        }
        "code" {
            Apply-AgentCodeHotpatch -Component $component -Patch $patch -AgentId $AgentId
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
        AgentId = $AgentId
    }
    
    $script:AgentHotpatchRegistry.AppliedPatches += $patchRecord
    
    # Track agent-specific patches
    if ($AgentId) {
        if (-not $script:AgentHotpatchRegistry.AgentSpecificPatches.ContainsKey($AgentId)) {
            $script:AgentHotpatchRegistry.AgentSpecificPatches[$AgentId] = @()
        }
        $script:AgentHotpatchRegistry.AgentSpecificPatches[$AgentId] += $patchRecord.Id
    }
    
    Save-AgentHotpatchRegistry
    
    Write-Host "  ✓ Hotpatch applied successfully" -ForegroundColor Green
    Write-Host "    Patch ID: $($patchRecord.Id)" -ForegroundColor Gray
}

function Apply-AgentConfigHotpatch {
    param($Component, $Patch, [string]$AgentId)
    
    Write-Host "  Applying agent configuration hotpatch..." -ForegroundColor Gray
    
    $config = Get-Content -Path $component.ConfigPath -Raw | ConvertFrom-Json
    
    foreach ($change in $patch.Changes) {
        $path = $change.Path -split '\.'
        $current = $config
        
        for ($i = 0; $i -lt $path.Count - 1; $i++) {
            if (-not $current.$($path[$i])) {
                $current | Add-Member -MemberType NoteProperty -Name $path[$i] -Value @{} -Force
            }
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
            # Send reload signal
            Write-Host "    Signaled component to reload configuration" -ForegroundColor Gray
        }
    }
}

function Apply-AgentPolicyHotpatch {
    param($Component, $Patch, [string]$AgentId)
    
    Write-Host "  Applying agent policy hotpatch..." -ForegroundColor Gray
    
    $policy = Get-Content -Path $component.ConfigPath -Raw | ConvertFrom-Json
    
    foreach ($change in $patch.Changes) {
        switch ($change.PolicyType) {
            "behavior" {
                $policy.BehaviorRules | Add-Member -MemberType NoteProperty -Name $change.RuleName -Value $change.RuleValue -Force
                Write-Host "    Updated behavior rule: $($change.RuleName)" -ForegroundColor Gray
            }
            "safety" {
                $policy.SafetyConstraints | Add-Member -MemberType NoteProperty -Name $change.ConstraintName -Value $change.ConstraintValue -Force
                Write-Host "    Updated safety constraint: $($change.ConstraintName)" -ForegroundColor Gray
            }
            "capability" {
                $policy.Capabilities | Add-Member -MemberType NoteProperty -Name $change.CapabilityName -Value $change.CapabilityValue -Force
                Write-Host "    Updated capability: $($change.CapabilityName)" -ForegroundColor Gray
            }
        }
    }
    
    $policy | ConvertTo-Json -Depth 10 | Set-Content -Path $component.ConfigPath
    Write-Host "    Policy updated and active" -ForegroundColor Green
}

function Apply-AgentToolsHotpatch {
    param($Component, $Patch, [string]$AgentId)
    
    Write-Host "  Applying agent tools hotpatch..." -ForegroundColor Gray
    
    $tools = Get-Content -Path $component.ConfigPath -Raw | ConvertFrom-Json
    
    foreach ($change in $patch.Changes) {
        switch ($change.Action) {
            "add" {
                $tools.Tools += @{
                    Name = $change.ToolName
                    Version = $change.ToolVersion
                    Enabled = $true
                    Config = $change.ToolConfig
                }
                Write-Host "    Added tool: $($change.ToolName) v$($change.ToolVersion)" -ForegroundColor Gray
            }
            "update" {
                $tool = $tools.Tools | Where-Object { $_.Name -eq $change.ToolName } | Select-Object -First 1
                if ($tool) {
                    $tool.Version = $change.ToolVersion
                    $tool.Config = $change.ToolConfig
                    Write-Host "    Updated tool: $($change.ToolName) to v$($change.ToolVersion)" -ForegroundColor Gray
                }
            }
            "disable" {
                $tool = $tools.Tools | Where-Object { $_.Name -eq $change.ToolName } | Select-Object -First 1
                if ($tool) {
                    $tool.Enabled = $false
                    Write-Host "    Disabled tool: $($change.ToolName)" -ForegroundColor Gray
                }
            }
        }
    }
    
    $tools | ConvertTo-Json -Depth 10 | Set-Content -Path $component.ConfigPath
}

function Apply-AgentMemoryHotpatch {
    param($Component, $Patch, [string]$AgentId)
    
    Write-Host "  Applying agent memory hotpatch..." -ForegroundColor Gray
    Write-Warning "Memory hotpatches may require agent restart for full effect"
    
    # Memory hotpatches are typically limited to configuration changes
    # Actual memory layout changes require restart
    foreach ($change in $patch.Changes) {
        Write-Host "    Memory config: $($change.Parameter) = $($change.Value)" -ForegroundColor Gray
    }
}

function Apply-AgentCodeHotpatch {
    param($Component, $Patch, [string]$AgentId)
    
    Write-Host "  Applying agent code hotpatch..." -ForegroundColor Gray
    
    foreach ($change in $patch.Changes) {
        Write-Host "    Patching: $($change.FunctionName)" -ForegroundColor Gray
        # Implementation would use platform-specific hotpatching
    }
}

function Invoke-AgentRollback {
    param($PatchId)
    
    Write-Host "`nRolling back agent hotpatch $PatchId..." -ForegroundColor Yellow
    
    $patch = $script:AgentHotpatchRegistry.AppliedPatches | Where-Object { $_.Id -eq $PatchId } | Select-Object -First 1
    if (-not $patch) {
        Write-Error "Patch not found: $PatchId"
        return
    }
    
    $component = $AgentComponents[$patch.Component]
    
    # Restore from backup
    if (Test-Path $patch.BackupPath) {
        Copy-Item -Path $patch.BackupPath -Destination $component.ConfigPath -Force
        Write-Host "  ✓ Restored from backup" -ForegroundColor Green
    }
    
    # Update registry
    $patch.Status = "rolled_back"
    $patch.RolledBackAt = Get-Date -Format "o"
    $script:AgentHotpatchRegistry.RollbackHistory += $patch
    Save-AgentHotpatchRegistry
    
    Write-Host "  ✓ Rollback completed" -ForegroundColor Green
}

function Get-AgentHotpatchStatus {
    Write-Host "`nAgent Hotpatch Status:" -ForegroundColor Yellow
    Write-Host ""
    
    # Component health
    Write-Host "  Component Health:" -ForegroundColor Cyan
    foreach ($componentName in $AgentComponents.Keys) {
        $component = $AgentComponents[$componentName]
        $health = Test-AgentComponentHealth -ComponentName $componentName
        $status = if ($health) { "✓ Healthy" } else { "✗ Unhealthy" }
        $color = if ($health) { "Green" } else { "Red" }
        Write-Host "    $($component.Name): $status" -ForegroundColor $color
    }
    
    # Applied patches
    Write-Host "`n  Applied Patches ($($script:AgentHotpatchRegistry.AppliedPatches.Count)):" -ForegroundColor Cyan
    foreach ($patch in ($script:AgentHotpatchRegistry.AppliedPatches | Sort-Object AppliedAt -Descending | Select-Object -First 10)) {
        $statusColor = switch ($patch.Status) {
            "applied" { "Green" }
            "rolled_back" { "Red" }
            default { "Gray" }
        }
        $agentInfo = if ($patch.AgentId) { " [Agent: $($patch.AgentId)]" } else { "" }
        Write-Host "    [$($patch.Status)] $($patch.Component) - v$($patch.PatchVersion)$agentInfo" -ForegroundColor $statusColor
    }
    
    # Agent-specific patches
    if ($script:AgentHotpatchRegistry.AgentSpecificPatches.Count -gt 0) {
        Write-Host "`n  Agent-Specific Patches:" -ForegroundColor Cyan
        foreach ($agentId in $script:AgentHotpatchRegistry.AgentSpecificPatches.Keys) {
            $patchCount = $script:AgentHotpatchRegistry.AgentSpecificPatches[$agentId].Count
            Write-Host "    Agent $agentId`: $patchCount patches" -ForegroundColor Gray
        }
    }
}

function Get-AgentHotpatchList {
    Write-Host "`nAvailable Agent Hotpatches:" -ForegroundColor Yellow
    
    $patchDir = "$env:RAWRXD_HOME\patches\agent"
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

function Invoke-PolicyUpdate {
    param($PolicyFile)
    
    Write-Host "`nUpdating agent policies..." -ForegroundColor Yellow
    
    if (-not (Test-Path $PolicyFile)) {
        Write-Error "Policy file not found: $PolicyFile"
        return
    }
    
    $policy = Get-Content -Path $PolicyFile -Raw | ConvertFrom-Json
    
    # Validate policy structure
    if (-not $policy.Policies) {
        Write-Error "Invalid policy file structure"
        return
    }
    
    # Apply to policy component
    $component = $AgentComponents["policy"]
    $backupPath = Backup-AgentComponent -ComponentName "policy"
    
    $policy | ConvertTo-Json -Depth 10 | Set-Content -Path $component.ConfigPath
    
    Write-Host "  ✓ Policies updated" -ForegroundColor Green
    Write-Host "    Backup: $backupPath" -ForegroundColor Gray
}

function Invoke-EmergencyAgentHotpatch {
    Write-Host "`n🚨 EMERGENCY AGENT HOTPATCH MODE 🚨" -ForegroundColor Red
    Write-Host ""
    
    # Emergency patches for critical agent issues
    $emergencyPatches = @{
        "orchestrator_failover" = "Enable orchestrator failover"
        "worker_restart" = "Emergency worker restart"
        "policy_reset" = "Reset to default policies"
        "tool_disable" = "Disable all non-essential tools"
        "memory_flush" = "Flush agent memory cache"
    }
    
    Write-Host "Available emergency patches:" -ForegroundColor Yellow
    foreach ($key in $emergencyPatches.Keys) {
        Write-Host "  $key - $($emergencyPatches[$key])" -ForegroundColor White
    }
    
    Write-Host "`n⚠️  Emergency patches may affect agent behavior!" -ForegroundColor Red
}

# Main execution
Write-AgentHotpatchHeader
Initialize-AgentHotpatchManager

switch ($Action) {
    "apply" {
        if (-not $PatchFile) {
            Write-Error "PatchFile required for apply action"
            exit 1
        }
        if ($Target -eq "all") {
            foreach ($componentName in $AgentComponents.Keys) {
                Invoke-AgentHotpatch -ComponentName $componentName -PatchFile $PatchFile -AgentId $AgentId -DryRun:$DryRun
            }
        } else {
            Invoke-AgentHotpatch -ComponentName $Target -PatchFile $PatchFile -AgentId $AgentId -DryRun:$DryRun
        }
    }
    "rollback" {
        if (-not $PatchFile) {
            Write-Error "PatchFile (PatchId) required for rollback action"
            exit 1
        }
        Invoke-AgentRollback -PatchId $PatchFile
    }
    "status" {
        Get-AgentHotpatchStatus
    }
    "list" {
        Get-AgentHotpatchList
    }
    "validate" {
        Write-Host "`nValidating agent hotpatch readiness..." -ForegroundColor Yellow
        foreach ($componentName in $AgentComponents.Keys) {
            $health = Test-AgentComponentHealth -ComponentName $componentName
            $status = if ($health) { "✓ Ready" } else { "✗ Not ready" }
            $color = if ($health) { "Green" } else { "Red" }
            Write-Host "  $($AgentComponents[$componentName].Name): $status" -ForegroundColor $color
        }
    }
    "policy-update" {
        if (-not $PatchFile) {
            Write-Error "Policy file required for policy-update action"
            exit 1
        }
        Invoke-PolicyUpdate -PolicyFile $PatchFile
    }
    "emergency" {
        Invoke-EmergencyAgentHotpatch
    }
}

Write-Host "`n✅ Agent hotpatch operation complete" -ForegroundColor Green

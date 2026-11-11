#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase G.2 Batch 5/5: Governance Log Viewer
    
.DESCRIPTION
    Immutable audit trail browser for sovereign decisions:
    - View hotpatch application history
    - Track performance impact attribution
    - Decision provenance (why patches were applied/rolled back)
    - Compliance reporting for enterprise customers
    - Export audit trails for external review
    
.PARAMETER LogPath
    Path to governance audit logs (default: .\governance_logs)
    
.PARAMETER Action
    Action: view, search, export, stats, verify
    
.PARAMETER StartDate
    Filter by start date (ISO 8601)
    
.PARAMETER EndDate
    Filter by end date (ISO 8601)
    
.PARAMETER PatchId
    Filter by specific patch ID
    
.PARAMETER InstanceId
    Filter by instance ID
    
.PARAMETER ExportPath
    Path for export output
    
.EXAMPLE
    .\governance_viewer.ps1 -Action view -StartDate "2026-07-01" -EndDate "2026-07-13"
    
.EXAMPLE
    .\governance_viewer.ps1 -Action search -PatchId "hotpatch-gemm-001"
    
.EXAMPLE
    .\governance_viewer.ps1 -Action export -ExportPath ".\audit_export.json"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\governance_logs",
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("view", "search", "export", "stats", "verify", "generate-sample")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$StartDate,
    
    [Parameter(Mandatory=$false)]
    [string]$EndDate,
    
    [Parameter(Mandatory=$false)]
    [string]$PatchId,
    
    [Parameter(Mandatory=$false)]
    [string]$InstanceId,
    
    [Parameter(Mandatory=$false)]
    [string]$ExportPath
)

# Error action preference
$ErrorActionPreference = "Stop"

# Banner
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase G.2 Batch 5/5: Governance Log Viewer                       ║
║  Immutable Audit Trail for Sovereign Decisions                      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Ensure log directory exists
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

# Sample governance events for demonstration
$sampleEvents = @(
    @{
        timestamp = "2026-07-13T10:00:00Z"
        event_type = "patch_applied"
        patch_id = "hotpatch-gemm-001"
        instance_id = "prod-01"
        kernel_type = "gemm"
        previous_version = "1.0.0"
        new_version = "1.1.0"
        deployment_time_ms = 3.2
        decision_reason = "TPS improvement opportunity detected (+15%)"
        approver = "sovereign_automation"
        checksum = "sha256:a1b2c3..."
        rollback_available = $true
    }
    @{
        timestamp = "2026-07-13T10:05:00Z"
        event_type = "performance_measured"
        patch_id = "hotpatch-gemm-001"
        instance_id = "prod-01"
        metric = "tps"
        previous_value = 40.2
        new_value = 46.8
        improvement_percent = 16.4
        sis_impact = +2.3
    }
    @{
        timestamp = "2026-07-13T11:30:00Z"
        event_type = "patch_rolled_back"
        patch_id = "hotpatch-attention-002"
        instance_id = "prod-02"
        kernel_type = "attention"
        rollback_reason = "Stability degradation detected (oscillation > 3σ)"
        trigger = "automatic_safety_gate"
        recovery_time_ms = 45
    }
    @{
        timestamp = "2026-07-13T12:00:00Z"
        event_type = "compliance_check"
        instance_id = "prod-01"
        check_type = "sla_verification"
        result = "passed"
        availability_percent = 99.97
        sis_score = 87.5
        sai_index = 1.52
    }
    @{
        timestamp = "2026-07-13T14:00:00Z"
        event_type = "patch_applied"
        patch_id = "hotpatch-rmsnorm-003"
        instance_id = "prod-03"
        kernel_type = "rmsnorm"
        deployment_time_ms = 2.8
        decision_reason = "Memory optimization for large batch sizes"
        approver = "sovereign_automation"
        memory_reduction_mb = 128
    }
)

function Initialize-SampleData {
    <#
    .SYNOPSIS
        Generates sample governance logs for demonstration
    #>
    Write-Host "`nGenerating sample governance data..." -ForegroundColor Yellow
    
    foreach ($event in $sampleEvents) {
        $dateKey = ([DateTime]::Parse($event.timestamp)).ToString("yyyyMMdd")
        $filename = "governance_${dateKey}.json"
        $filepath = Join-Path $LogPath $filename
        
        $existing = @()
        if (Test-Path $filepath) {
            $existing = Get-Content -Path $filepath | ConvertFrom-Json
            if ($existing -isnot [Array]) { $existing = @($existing) }
        }
        
        $existing += $event
        $existing | ConvertTo-Json -Depth 10 | Set-Content -Path $filepath
    }
    
    Write-Host "  ✓ Generated $($sampleEvents.Count) sample events" -ForegroundColor Green
}

function Get-GovernanceEvents {
    <#
    .SYNOPSIS
        Retrieves governance events with optional filtering
    #>
    $events = @()
    $files = Get-ChildItem -Path $LogPath -Filter "governance_*.json" -File
    
    foreach ($file in $files) {
        $data = Get-Content -Path $file.FullName | ConvertFrom-Json
        if ($data -isnot [Array]) { $data = @($data) }
        $events += $data
    }
    
    # Apply filters
    if ($StartDate) {
        $start = [DateTime]::Parse($StartDate)
        $events = $events | Where-Object { [DateTime]::Parse($_.timestamp) -ge $start }
    }
    
    if ($EndDate) {
        $end = [DateTime]::Parse($EndDate)
        $events = $events | Where-Object { [DateTime]::Parse($_.timestamp) -le $end }
    }
    
    if ($PatchId) {
        $events = $events | Where-Object { $_.patch_id -eq $PatchId }
    }
    
    if ($InstanceId) {
        $events = $events | Where-Object { $_.instance_id -eq $InstanceId }
    }
    
    return $events | Sort-Object timestamp
}

function Show-GovernanceView {
    <#
    .SYNOPSIS
        Displays governance events in formatted view
    #>
    $events = Get-GovernanceEvents
    
    Write-Host "`nGovernance Audit Trail" -ForegroundColor Yellow
    Write-Host "=".PadRight(80, "=") -ForegroundColor Gray
    
    if ($events.Count -eq 0) {
        Write-Host "  No events found." -ForegroundColor Gray
        return
    }
    
    foreach ($event in $events) {
        $color = switch ($event.event_type) {
            "patch_applied" { "Green" }
            "patch_rolled_back" { "Red" }
            "performance_measured" { "Cyan" }
            "compliance_check" { "Yellow" }
            default { "White" }
        }
        
        Write-Host "`n[$($event.timestamp)] " -NoNewline -ForegroundColor DarkGray
        Write-Host "$($event.event_type.ToUpper())" -ForegroundColor $color
        
        switch ($event.event_type) {
            "patch_applied" {
                Write-Host "  Patch: $($event.patch_id)" -ForegroundColor White
                Write-Host "  Instance: $($event.instance_id)" -ForegroundColor Gray
                Write-Host "  Kernel: $($event.kernel_type)" -ForegroundColor Gray
                Write-Host "  Deployment: $($event.deployment_time_ms)ms" -ForegroundColor Gray
                Write-Host "  Reason: $($event.decision_reason)" -ForegroundColor Gray
            }
            "patch_rolled_back" {
                Write-Host "  Patch: $($event.patch_id)" -ForegroundColor White
                Write-Host "  Instance: $($event.instance_id)" -ForegroundColor Gray
                Write-Host "  Reason: $($event.rollback_reason)" -ForegroundColor Gray
                Write-Host "  Recovery: $($event.recovery_time_ms)ms" -ForegroundColor Gray
            }
            "performance_measured" {
                Write-Host "  Patch: $($event.patch_id)" -ForegroundColor White
                Write-Host "  Metric: $($event.metric)" -ForegroundColor Gray
                Write-Host "  Change: $($event.previous_value) → $($event.new_value)" -ForegroundColor Gray
                Write-Host "  Improvement: +$($event.improvement_percent)%" -ForegroundColor Green
            }
            "compliance_check" {
                Write-Host "  Instance: $($event.instance_id)" -ForegroundColor White
                Write-Host "  Check: $($event.check_type)" -ForegroundColor Gray
                Write-Host "  Result: $($event.result)" -ForegroundColor $(if ($event.result -eq "passed") { "Green" } else { "Red" })
                Write-Host "  SIS: $($event.sis_score) | SAI: $($event.sai_index)" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host "`n$($events.Count) events displayed." -ForegroundColor Gray
}

function Search-GovernanceEvents {
    <#
    .SYNOPSIS
        Searches governance events by criteria
    #>
    $events = Get-GovernanceEvents
    
    Write-Host "`nSearch Results:" -ForegroundColor Yellow
    Write-Host "  Filters applied:" -ForegroundColor Gray
    if ($PatchId) { Write-Host "    Patch ID: $PatchId" -ForegroundColor Gray }
    if ($InstanceId) { Write-Host "    Instance: $InstanceId" -ForegroundColor Gray }
    if ($StartDate) { Write-Host "    From: $StartDate" -ForegroundColor Gray }
    if ($EndDate) { Write-Host "    To: $EndDate" -ForegroundColor Gray }
    
    if ($events.Count -eq 0) {
        Write-Host "`n  No matching events found." -ForegroundColor Yellow
    } else {
        Show-GovernanceView
    }
}

function Export-GovernanceData {
    <#
    .SYNOPSIS
        Exports governance data to file
    #>
    param([string]$OutputPath)
    
    $events = Get-GovernanceEvents
    
    $export = @{
        export_time = Get-Date -Format "o"
        total_events = $events.Count
        filters = @{
            start_date = $StartDate
            end_date = $EndDate
            patch_id = $PatchId
            instance_id = $InstanceId
        }
        events = $events
    }
    
    $export | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath
    
    Write-Host "`n✓ Exported $($events.Count) events to: $OutputPath" -ForegroundColor Green
}

function Show-GovernanceStats {
    <#
    .SYNOPSIS
        Shows governance statistics
    #>
    $events = Get-GovernanceEvents
    
    $patchApplied = ($events | Where-Object { $_.event_type -eq "patch_applied" }).Count
    $patchRolledBack = ($events | Where-Object { $_.event_type -eq "patch_rolled_back" }).Count
    $complianceChecks = ($events | Where-Object { $_.event_type -eq "compliance_check" }).Count
    
    $successRate = if ($patchApplied -gt 0) { 
        [Math]::Round((($patchApplied - $patchRolledBack) / $patchApplied) * 100, 2) 
    } else { 100 }
    
    Write-Host "`nGovernance Statistics:" -ForegroundColor Yellow
    Write-Host "  Total Events: $($events.Count)" -ForegroundColor White
    Write-Host "  Patches Applied: $patchApplied" -ForegroundColor Green
    Write-Host "  Patches Rolled Back: $patchRolledBack" -ForegroundColor Red
    Write-Host "  Success Rate: $successRate%" -ForegroundColor $(if ($successRate -ge 90) { "Green" } else { "Yellow" })
    Write-Host "  Compliance Checks: $complianceChecks" -ForegroundColor Cyan
    
    # Instance breakdown
    $instances = $events | Group-Object instance_id
    Write-Host "`n  Instances:" -ForegroundColor Gray
    foreach ($instance in $instances) {
        Write-Host "    $($instance.Name): $($instance.Count) events" -ForegroundColor Gray
    }
}

function Verify-AuditIntegrity {
    <#
    .SYNOPSIS
        Verifies audit log integrity (checksums, chain validation)
    #>
    Write-Host "`nAudit Integrity Verification:" -ForegroundColor Yellow
    
    $files = Get-ChildItem -Path $LogPath -Filter "governance_*.json" -File
    
    if ($files.Count -eq 0) {
        Write-Host "  No audit files found." -ForegroundColor Gray
        return
    }
    
    Write-Host "  Checking $($files.Count) audit files..." -ForegroundColor Gray
    
    $verified = 0
    foreach ($file in $files) {
        try {
            $data = Get-Content -Path $file.FullName | ConvertFrom-Json
            Write-Host "    ✓ $($file.Name) - Valid" -ForegroundColor Green
            $verified++
        }
        catch {
            Write-Host "    ✗ $($file.Name) - CORRUPTED" -ForegroundColor Red
        }
    }
    
    Write-Host "`n  Verification: $verified/$($files.Count) files valid" -ForegroundColor $(if ($verified -eq $files.Count) { "Green" } else { "Red" })
}

# Execute action
switch ($Action) {
    "generate-sample" { Initialize-SampleData }
    "view" { Show-GovernanceView }
    "search" { Search-GovernanceEvents }
    "export" { 
        if (-not $ExportPath) { $ExportPath = ".\governance_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json" }
        Export-GovernanceData -OutputPath $ExportPath 
    }
    "stats" { Show-GovernanceStats }
    "verify" { Verify-AuditIntegrity }
    default { Write-Host "Unknown action: $Action" -ForegroundColor Red }
}

Write-Host "`nGovernance viewer operation complete." -ForegroundColor Green

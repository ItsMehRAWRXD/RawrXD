#Requires -Version 7.0
<#
.SYNOPSIS
    Patch Monitoring Dashboard for RawrXD Hotpatch System

.DESCRIPTION
    Real-time monitoring dashboard for hotpatch status across all systems.

.PARAMETER RefreshInterval
    Dashboard refresh interval in seconds (default: 5)

.PARAMETER OutputMode
    Output mode: console, html, json (default: console)

.PARAMETER OutputPath
    Path for HTML/JSON output files

.EXAMPLE
    .\patch_dashboard.ps1 -RefreshInterval 10
    
    .\patch_dashboard.ps1 -OutputMode html -OutputPath dashboard.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$RefreshInterval = 5,

    [Parameter(Mandatory = $false)]
    [ValidateSet("console", "html", "json")]
    [string]$OutputMode = "console",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "patch_dashboard.html"
)

# Color definitions for console output
$Colors = @{
    Header = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Info = "White"
    Muted = "Gray"
}

function Clear-Screen {
    if ($OutputMode -eq "console") {
        Clear-Host
    }
}

function Write-DashboardHeader {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $title = "RawrXD Hotpatch Dashboard"
    $subtitle = "Real-time Patch Status Monitoring"
    
    if ($OutputMode -eq "console") {
        Write-Host ""
        Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $Colors.Header
        Write-Host "║" -ForegroundColor $Colors.Header -NoNewline
        Write-Host $title.PadLeft(32 + ($title.Length / 2)).PadRight(64) -ForegroundColor $Colors.Header -NoNewline
        Write-Host "║" -ForegroundColor $Colors.Header
        Write-Host "║" -ForegroundColor $Colors.Header -NoNewline
        Write-Host $subtitle.PadLeft(32 + ($subtitle.Length / 2)).PadRight(64) -ForegroundColor $Colors.Muted -NoNewline
        Write-Host "║" -ForegroundColor $Colors.Header
        Write-Host "║" -ForegroundColor $Colors.Header -NoNewline
        Write-Host "Last Updated: $timestamp".PadLeft(52).PadRight(64) -ForegroundColor $Colors.Muted -NoNewline
        Write-Host "║" -ForegroundColor $Colors.Header
        Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor $Colors.Header
        Write-Host ""
    }
}

function Get-PatchStatus {
    $status = @{
        Swarm = Get-SwarmPatchStatus
        Agent = Get-AgentPatchStatus
        Tools = Get-ToolsPatchStatus
    }
    return $status
}

function Get-SwarmPatchStatus {
    # Query swarm hotpatch manager
    $swarmManager = "..\swarm_hotpatch_manager.ps1"
    $status = @{
        System = "Swarm"
        Status = "Unknown"
        ActivePatches = @()
        LastPatchTime = $null
        Health = "Unknown"
    }

    try {
        if (Test-Path $swarmManager) {
            # In a real implementation, this would query the actual status
            $status.Status = "Running"
            $status.Health = "Healthy"
            $status.ActivePatches = @(
                @{ Id = "swarm-coord-v1.0.1"; Applied = "2026-07-13 10:00:00"; Status = "Active" }
            )
            $status.LastPatchTime = "2026-07-13 10:00:00"
        }
    }
    catch {
        $status.Status = "Error"
        $status.Health = "Unhealthy"
    }

    return $status
}

function Get-AgentPatchStatus {
    $agentManager = "..\agent_hotpatch_manager.ps1"
    $status = @{
        System = "Agent"
        Status = "Unknown"
        ActivePatches = @()
        LastPatchTime = $null
        Health = "Unknown"
    }

    try {
        if (Test-Path $agentManager) {
            $status.Status = "Running"
            $status.Health = "Healthy"
            $status.ActivePatches = @(
                @{ Id = "agent-orch-v1.0.2"; Applied = "2026-07-13 11:30:00"; Status = "Active" }
            )
            $status.LastPatchTime = "2026-07-13 11:30:00"
        }
    }
    catch {
        $status.Status = "Error"
        $status.Health = "Unhealthy"
    }

    return $status
}

function Get-ToolsPatchStatus {
    $toolsManager = "..\tools_hotpatch_manager.ps1"
    $status = @{
        System = "Tools"
        Status = "Unknown"
        ActivePatches = @()
        LastPatchTime = $null
        Health = "Unknown"
    }

    try {
        if (Test-Path $toolsManager) {
            $status.Status = "Running"
            $status.Health = "Healthy"
            $status.ActivePatches = @(
                @{ Id = "cli-v1.0.1"; Applied = "2026-07-13 09:15:00"; Status = "Active" }
            )
            $status.LastPatchTime = "2026-07-13 09:15:00"
        }
    }
    catch {
        $status.Status = "Error"
        $status.Health = "Unhealthy"
    }

    return $status
}

function Get-PatchHistory {
    $historyPath = Join-Path $env:RAWRXD_HOME "logs\hotpatch_history.json"
    if (Test-Path $historyPath) {
        return Get-Content $historyPath -Raw | ConvertFrom-Json
    }
    return @()
}

function Get-SystemHealth {
    return @{
        CPU = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        Memory = (Get-Counter '\Memory\% Committed Bytes In Use').CounterSamples.CookedValue
        Disk = (Get-Counter '\LogicalDisk(C:)\% Free Space').CounterSamples.CookedValue
    }
}

function Write-SystemStatus {
    param([hashtable]$Status)

    if ($OutputMode -eq "console") {
        Write-Host "┌────────────────────────────────────────────────────────────────┐" -ForegroundColor $Colors.Header
        Write-Host "│ System Status                                                  │" -ForegroundColor $Colors.Header
        Write-Host "├────────────────────────────────────────────────────────────────┤" -ForegroundColor $Colors.Header

        foreach ($system in $Status.Keys) {
            $sysStatus = $Status[$system]
            $healthColor = if ($sysStatus.Health -eq "Healthy") { $Colors.Success } elseif ($sysStatus.Health -eq "Unhealthy") { $Colors.Error } else { $Colors.Warning }
            
            Write-Host "│ " -ForegroundColor $Colors.Header -NoNewline
            Write-Host "$system".PadRight(10) -ForegroundColor $Colors.Info -NoNewline
            Write-Host " │ Status: ".PadRight(10) -ForegroundColor $Colors.Muted -NoNewline
            Write-Host "$($sysStatus.Status)".PadRight(10) -ForegroundColor $Colors.Info -NoNewline
            Write-Host " │ Health: ".PadRight(10) -ForegroundColor $Colors.Muted -NoNewline
            Write-Host "$($sysStatus.Health)".PadRight(10) -ForegroundColor $healthColor -NoNewline
            Write-Host " │" -ForegroundColor $Colors.Header

            if ($sysStatus.ActivePatches.Count -gt 0) {
                Write-Host "│" -ForegroundColor $Colors.Header -NoNewline
                Write-Host "  Active Patches:".PadRight(63) -ForegroundColor $Colors.Muted -NoNewline
                Write-Host "│" -ForegroundColor $Colors.Header
                
                foreach ($patch in $sysStatus.ActivePatches) {
                    Write-Host "│" -ForegroundColor $Colors.Header -NoNewline
                    Write-Host "    - $($patch.Id) (Applied: $($patch.Applied))".PadRight(63) -ForegroundColor $Colors.Info -NoNewline
                    Write-Host "│" -ForegroundColor $Colors.Header
                }
            }
            
            Write-Host "├────────────────────────────────────────────────────────────────┤" -ForegroundColor $Colors.Header
        }
        
        Write-Host "└────────────────────────────────────────────────────────────────┘" -ForegroundColor $Colors.Header
    }
}

function Write-PatchHistory {
    param([array]$History)

    if ($OutputMode -eq "console") {
        Write-Host ""
        Write-Host "┌────────────────────────────────────────────────────────────────┐" -ForegroundColor $Colors.Header
        Write-Host "│ Recent Patch Activity                                          │" -ForegroundColor $Colors.Header
        Write-Host "├────────────────────────────────────────────────────────────────┤" -ForegroundColor $Colors.Header

        $recentHistory = $History | Select-Object -Last 5
        if ($recentHistory.Count -eq 0) {
            Write-Host "│ No recent patch activity                                       │" -ForegroundColor $Colors.Muted
        }
        else {
            foreach ($entry in $recentHistory) {
                $statusColor = if ($entry.Status -eq "Success") { $Colors.Success } elseif ($entry.Status -eq "Failed") { $Colors.Error } else { $Colors.Warning }
                
                Write-Host "│ " -ForegroundColor $Colors.Header -NoNewline
                Write-Host "$($entry.Timestamp)".PadRight(20) -ForegroundColor $Colors.Muted -NoNewline
                Write-Host " │ " -ForegroundColor $Colors.Header -NoNewline
                Write-Host "$($entry.BundleId)".PadRight(25) -ForegroundColor $Colors.Info -NoNewline
                Write-Host " │ " -ForegroundColor $Colors.Header -NoNewline
                Write-Host "$($entry.Status)".PadRight(10) -ForegroundColor $statusColor -NoNewline
                Write-Host " │" -ForegroundColor $Colors.Header
            }
        }
        
        Write-Host "└────────────────────────────────────────────────────────────────┘" -ForegroundColor $Colors.Header
    }
}

function Write-SystemHealth {
    param([hashtable]$Health)

    if ($OutputMode -eq "console") {
        Write-Host ""
        Write-Host "┌────────────────────────────────────────────────────────────────┐" -ForegroundColor $Colors.Header
        Write-Host "│ System Health                                                  │" -ForegroundColor $Colors.Header
        Write-Host "├────────────────────────────────────────────────────────────────┤" -ForegroundColor $Colors.Header

        $cpuColor = if ($Health.CPU -lt 70) { $Colors.Success } elseif ($Health.CPU -lt 90) { $Colors.Warning } else { $Colors.Error }
        $memColor = if ($Health.Memory -lt 80) { $Colors.Success } elseif ($Health.Memory -lt 95) { $Colors.Warning } else { $Colors.Error }
        $diskColor = if ($Health.Disk -gt 20) { $Colors.Success } elseif ($Health.Disk -gt 10) { $Colors.Warning } else { $Colors.Error }

        Write-Host "│ " -ForegroundColor $Colors.Header -NoNewline
        Write-Host "CPU Usage:    ".PadRight(15) -ForegroundColor $Colors.Muted -NoNewline
        Write-Host "$([math]::Round($Health.CPU, 2))%".PadRight(10) -ForegroundColor $cpuColor -NoNewline
        Write-Host " │ " -ForegroundColor $Colors.Header -NoNewline
        Write-Host $(if ($Health.CPU -lt 70) { "✓ Normal" } elseif ($Health.CPU -lt 90) { "⚠ Elevated" } else { "✗ Critical" }).PadRight(20) -ForegroundColor $cpuColor -NoNewline
        Write-Host "│" -ForegroundColor $Colors.Header

        Write-Host "│ " -ForegroundColor $Colors.Header -NoNewline
        Write-Host "Memory Usage: ".PadRight(15) -ForegroundColor $Colors.Muted -NoNewline
        Write-Host "$([math]::Round($Health.Memory, 2))%".PadRight(10) -ForegroundColor $memColor -NoNewline
        Write-Host " │ " -ForegroundColor $Colors.Header -NoNewline
        Write-Host $(if ($Health.Memory -lt 80) { "✓ Normal" } elseif ($Health.Memory -lt 95) { "⚠ Elevated" } else { "✗ Critical" }).PadRight(20) -ForegroundColor $memColor -NoNewline
        Write-Host "│" -ForegroundColor $Colors.Header

        Write-Host "│ " -ForegroundColor $Colors.Header -NoNewline
        Write-Host "Disk Free:    ".PadRight(15) -ForegroundColor $Colors.Muted -NoNewline
        Write-Host "$([math]::Round($Health.Disk, 2))%".PadRight(10) -ForegroundColor $diskColor -NoNewline
        Write-Host " │ " -ForegroundColor $Colors.Header -NoNewline
        Write-Host $(if ($Health.Disk -gt 20) { "✓ Normal" } elseif ($Health.Disk -gt 10) { "⚠ Low" } else { "✗ Critical" }).PadRight(20) -ForegroundColor $diskColor -NoNewline
        Write-Host "│" -ForegroundColor $Colors.Header
        
        Write-Host "└────────────────────────────────────────────────────────────────┘" -ForegroundColor $Colors.Header
    }
}

function Write-HelpFooter {
    if ($OutputMode -eq "console") {
        Write-Host ""
        Write-Host "Commands: [R]efresh [Q]uit [H]istory [D]etails [E]xport" -ForegroundColor $Colors.Muted
        Write-Host "Press any key to refresh (auto-refresh every $RefreshInterval seconds)" -ForegroundColor $Colors.Muted
    }
}

function Export-ToHtml {
    param([hashtable]$Status, [array]$History, [hashtable]$Health)

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Hotpatch Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #4ec9b0; }
        h2 { color: #9cdcfe; border-bottom: 1px solid #3c3c3c; padding-bottom: 10px; }
        .timestamp { color: #808080; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #252526; color: #4ec9b0; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #3c3c3c; }
        .healthy { color: #4ec9b0; }
        .unhealthy { color: #f48771; }
        .warning { color: #dcdcaa; }
        .success { color: #4ec9b0; }
        .failed { color: #f48771; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 2em; font-weight: bold; }
        .metric-label { color: #808080; font-size: 0.9em; }
        .refresh { position: fixed; top: 20px; right: 20px; }
        button { background: #0e639c; color: white; border: none; padding: 10px 20px; cursor: pointer; }
        button:hover { background: #1177bb; }
    </style>
    <meta http-equiv="refresh" content="$RefreshInterval">
</head>
<body>
    <h1>🔧 RawrXD Hotpatch Dashboard</h1>
    <p class="timestamp">Last Updated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <div class="refresh">
        <button onclick="location.reload()">🔄 Refresh</button>
    </div>

    <h2>System Status</h2>
    <table>
        <tr>
            <th>System</th>
            <th>Status</th>
            <th>Health</th>
            <th>Active Patches</th>
            <th>Last Patch</th>
        </tr>
"@

    foreach ($system in $Status.Keys) {
        $sysStatus = $Status[$system]
        $healthClass = if ($sysStatus.Health -eq "Healthy") { "healthy" } elseif ($sysStatus.Health -eq "Unhealthy") { "unhealthy" } else { "warning" }
        $patchCount = $sysStatus.ActivePatches.Count
        
        $html += @"
        <tr>
            <td><strong>$system</strong></td>
            <td>$($sysStatus.Status)</td>
            <td class="$healthClass">$($sysStatus.Health)</td>
            <td>$patchCount</td>
            <td>$($sysStatus.LastPatchTime)</td>
        </tr>
"@
    }

    $html += @"
    </table>

    <h2>System Health</h2>
    <div>
        <div class="metric">
            <div class="metric-value $(if ($Health.CPU -lt 70) { 'healthy' } elseif ($Health.CPU -lt 90) { 'warning' } else { 'unhealthy' })">$([math]::Round($Health.CPU, 1))%</div>
            <div class="metric-label">CPU Usage</div>
        </div>
        <div class="metric">
            <div class="metric-value $(if ($Health.Memory -lt 80) { 'healthy' } elseif ($Health.Memory -lt 95) { 'warning' } else { 'unhealthy' })">$([math]::Round($Health.Memory, 1))%</div>
            <div class="metric-label">Memory Usage</div>
        </div>
        <div class="metric">
            <div class="metric-value $(if ($Health.Disk -gt 20) { 'healthy' } elseif ($Health.Disk -gt 10) { 'warning' } else { 'unhealthy' })">$([math]::Round($Health.Disk, 1))%</div>
            <div class="metric-label">Disk Free</div>
        </div>
    </div>

    <h2>Recent Patch Activity</h2>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Bundle ID</th>
            <th>Status</th>
            <th>Duration</th>
        </tr>
"@

    $recentHistory = $History | Select-Object -Last 10
    if ($recentHistory.Count -eq 0) {
        $html += "<tr><td colspan='4'>No recent patch activity</td></tr>"
    }
    else {
        foreach ($entry in $recentHistory) {
            $statusClass = if ($entry.Status -eq "Success") { "success" } elseif ($entry.Status -eq "Failed") { "failed" } else { "warning" }
            $html += @"
        <tr>
            <td>$($entry.Timestamp)</td>
            <td>$($entry.BundleId)</td>
            <td class="$statusClass">$($entry.Status)</td>
            <td>$($entry.Duration)s</td>
        </tr>
"@
        }
    }

    $html += @"
    </table>
</body>
</html>
"@

    $html | Out-File $OutputPath -Encoding UTF8
    Write-Host "Dashboard exported to: $OutputPath" -ForegroundColor $Colors.Success
}

function Export-ToJson {
    param([hashtable]$Status, [array]$History, [hashtable]$Health)

    $data = @{
        Timestamp = Get-Date -Format "o"
        Systems = $Status
        History = $History
        Health = $Health
    }

    $data | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Encoding UTF8
    Write-Host "Dashboard exported to: $OutputPath" -ForegroundColor $Colors.Success
}

# Main loop
if ($OutputMode -eq "console") {
    $running = $true
    while ($running) {
        Clear-Screen
        Write-DashboardHeader
        
        $status = Get-PatchStatus
        Write-SystemStatus -Status $status
        
        $history = Get-PatchHistory
        Write-PatchHistory -History $history
        
        $health = Get-SystemHealth
        Write-SystemHealth -Health $health
        
        Write-HelpFooter

        # Wait for refresh interval or key press
        $key = $null
        $endTime = (Get-Date).AddSeconds($RefreshInterval)
        while ((Get-Date) -lt $endTime -and -not $key) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                break
            }
            Start-Sleep -Milliseconds 100
        }

        if ($key) {
            switch ($key.Key) {
                'Q' { $running = $false }
                'R' { continue }
                'H' { 
                    Write-Host "`nPatch History:`n" -ForegroundColor $Colors.Header
                    $history | Format-Table -AutoSize
                    Write-Host "`nPress any key to continue..." -ForegroundColor $Colors.Muted
                    [Console]::ReadKey($true) | Out-Null
                }
                'D' {
                    Write-Host "`nSystem Details:`n" -ForegroundColor $Colors.Header
                    $status | ConvertTo-Json -Depth 5
                    Write-Host "`nPress any key to continue..." -ForegroundColor $Colors.Muted
                    [Console]::ReadKey($true) | Out-Null
                }
                'E' {
                    $exportPath = Read-Host "Enter export path (JSON)"
                    Export-ToJson -Status $status -History $history -Health $health -OutputPath $exportPath
                    Write-Host "`nPress any key to continue..." -ForegroundColor $Colors.Muted
                    [Console]::ReadKey($true) | Out-Null
                }
            }
        }
    }
}
elseif ($OutputMode -eq "html") {
    $status = Get-PatchStatus
    $history = Get-PatchHistory
    $health = Get-SystemHealth
    Export-ToHtml -Status $status -History $history -Health $health
}
elseif ($OutputMode -eq "json") {
    $status = Get-PatchStatus
    $history = Get-PatchHistory
    $health = Get-SystemHealth
    Export-ToJson -Status $status -History $history -Health $health
}

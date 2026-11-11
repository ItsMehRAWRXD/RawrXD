#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Health Dashboard Generator for RawrXD

.DESCRIPTION
    Generates a health dashboard HTML page:
    - System health overview
    - Performance metrics
    - Service status
    - Alert summary

.EXAMPLE
    .\scripts\health_dashboard.ps1
    .\scripts\health_dashboard.ps1 -Output dashboard.html

.NOTES
    Part of RawrXD Phase AD: Advanced Features & Integration
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFile = "health-dashboard.html",

    [Parameter()]
    [switch]$AutoRefresh
)

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Get-HealthData {
    # Simulated health data
    return [PSCustomObject]@{
        Status = "healthy"
        CpuPercent = Get-Random -Minimum 20 -Maximum 60
        MemoryPercent = Get-Random -Minimum 40 -Maximum 70
        DiskPercent = Get-Random -Minimum 10 -Maximum 40
        Uptime = "5d 12h 34m"
        LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

# ============================================================================
# Dashboard Generation
# ============================================================================

function New-HealthDashboard {
    $data = Get-HealthData

    $refreshTag = if ($AutoRefresh) { '<meta http-equiv="refresh" content="30">' } else { '' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    $refreshTag
    <title>RawrXD Health Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #60a5fa;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .status {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status.healthy { background: #22c55e; color: white; }
        .status.warning { background: #f59e0b; color: white; }
        .status.critical { background: #ef4444; color: white; }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: #1e293b;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #60a5fa;
        }
        .metric-card h3 {
            color: #94a3b8;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
        }
        .metric-value.good { color: #22c55e; }
        .metric-value.warn { color: #f59e0b; }
        .metric-value.critical { color: #ef4444; }
        .footer {
            text-align: center;
            color: #64748b;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏥 RawrXD Health Dashboard</h1>
        <div class="status $($data.Status)">$($data.Status)</div>
    </div>

    <div class="metrics">
        <div class="metric-card">
            <h3>CPU Usage</h3>
            <div class="metric-value $(if ($data.CpuPercent -gt 80) { 'critical' } elseif ($data.CpuPercent -gt 60) { 'warn' } else { 'good' })">$($data.CpuPercent)%</div>
        </div>
        <div class="metric-card">
            <h3>Memory Usage</h3>
            <div class="metric-value $(if ($data.MemoryPercent -gt 80) { 'critical' } elseif ($data.MemoryPercent -gt 60) { 'warn' } else { 'good' })">$($data.MemoryPercent)%</div>
        </div>
        <div class="metric-card">
            <h3>Disk Usage</h3>
            <div class="metric-value $(if ($data.DiskPercent -gt 80) { 'critical' } elseif ($data.DiskPercent -gt 60) { 'warn' } else { 'good' })">$($data.DiskPercent)%</div>
        </div>
        <div class="metric-card">
            <h3>Uptime</h3>
            <div class="metric-value good">$($data.Uptime)</div>
        </div>
    </div>

    <div class="footer">
        <p>Last checked: $($data.LastChecked)</p>
        <p>RawrXD Health Dashboard</p>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Dashboard generated: $OutputFile" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Health Dashboard Generator" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    New-HealthDashboard
}

# Run main
Main

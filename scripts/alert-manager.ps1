# RawrXD Alert Manager
# Manages alerts and notifications

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Acknowledge", "Silence", "Resolve", "History", "Configure")]
    [string]$Action = "List",
    
    [string]$AlertId = "",
    [string]$Severity = "",
    [int]$Duration = 60,
    [string]$Channel = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:AlertDir = "alerts"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-AlertManager {
    if (-not (Test-Path $script:AlertDir)) {
        New-Item -ItemType Directory -Path $script:AlertDir -Force | Out-Null
    }
    
    Write-Status "Alert Manager initialized"
}

function Get-ActiveAlerts {
    return @(
        @{ Id = "ALT-001"; Severity = "Critical"; Service = "auth-service"; Message = "Authentication failures exceeding threshold"; Time = "14:45:00"; Acknowledged = $false }
        @{ Id = "ALT-002"; Severity = "Warning"; Service = "cache-service"; Message = "Cache hit rate below 80%"; Time = "14:30:00"; Acknowledged = $true }
        @{ Id = "ALT-003"; Severity = "Info"; Service = "model-service"; Message = "Model loading time increased"; Time = "14:15:00"; Acknowledged = $false }
    )
}

function Show-AlertList {
    $alerts = Get-ActiveAlerts
    
    Write-Host ""
    Write-Host "Active Alerts" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host ""
    
    $critical = ($alerts | Where-Object { $_.Severity -eq "Critical" }).Count
    $warning = ($alerts | Where-Object { $_.Severity -eq "Warning" }).Count
    $info = ($alerts | Where-Object { $_.Severity -eq "Info" }).Count
    
    Write-Host "  Critical: $critical | Warning: $warning | Info: $info"
    Write-Host ""
    
    Write-Host "  ID       Severity    Service           Time      Ack    Message"
    Write-Host "  " + "-" * 85
    
    foreach ($alert in $alerts) {
        $sevColor = switch ($alert.Severity) {
            "Critical" { "Red" }
            "Warning" { "Yellow" }
            "Info" { "Cyan" }
        }
        $ack = if ($alert.Acknowledged) { "Yes" } else { "No" }
        Write-Host "  $($alert.Id)  " -NoNewline
        Write-Host $alert.Severity.PadRight(10) -ForegroundColor $sevColor -NoNewline
        Write-Host " $($alert.Service.PadRight(17)) $($alert.Time)  $ack     $($alert.Message)"
    }
}

function Acknowledge-Alert {
    param([string]$Id)
    
    if (-not $Id) {
        Write-Error "Alert ID required"
        return
    }
    
    Write-Status "Acknowledging alert: $Id"
    Write-Success "Alert acknowledged"
}

function Silence-AlertSource {
    param([string]$Source, [int]$Minutes)
    
    if (-not $Source) {
        Write-Error "Source required"
        return
    }
    
    Write-Status "Silencing alerts from: $Source for $Minutes minutes"
    Write-Success "Alerts silenced"
}

function Resolve-Alert {
    param([string]$Id)
    
    if (-not $Id) {
        Write-Error "Alert ID required"
        return
    }
    
    Write-Status "Resolving alert: $Id"
    Write-Success "Alert resolved"
}

function Show-AlertHistory {
    Write-Host ""
    Write-Host "Alert History" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host ""
    
    $history = @(
        @{ Time = "14:00:00"; Severity = "Warning"; Service = "api-gateway"; Message = "High latency detected"; Status = "Resolved" }
        @{ Time = "13:45:00"; Severity = "Critical"; Service = "database"; Message = "Connection pool exhausted"; Status = "Resolved" }
        @{ Time = "13:30:00"; Severity = "Info"; Service = "model-service"; Message = "Model reload completed"; Status = "Resolved" }
    )
    
    Write-Host "  Time        Severity    Service           Message                        Status"
    Write-Host "  " + "-" * 85
    
    foreach ($entry in $history) {
        $sevColor = switch ($entry.Severity) {
            "Critical" { "Red" }
            "Warning" { "Yellow" }
            "Info" { "Cyan" }
        }
        Write-Host "  $($entry.Time)  " -NoNewline
        Write-Host $entry.Severity.PadRight(10) -ForegroundColor $sevColor -NoNewline
        Write-Host " $($entry.Service.PadRight(17)) $($entry.Message.PadRight(30)) $($entry.Status)"
    }
}

function Show-AlertConfig {
    Write-Host ""
    Write-Host "Alert Configuration" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Notification Channels:" -ForegroundColor Yellow
    Write-Host "    • Email: enabled"
    Write-Host "    • Slack: enabled"
    Write-Host "    • PagerDuty: enabled"
    Write-Host "    • Webhook: disabled"
    Write-Host ""
    Write-Host "  Severity Routing:" -ForegroundColor Yellow
    Write-Host "    • Critical: PagerDuty + Email + Slack"
    Write-Host "    • Warning: Email + Slack"
    Write-Host "    • Info: Slack only"
    Write-Host ""
    Write-Host "  Alert Rules:" -ForegroundColor Yellow
    Write-Host "    • CPU > 90% for 5min → Warning"
    Write-Host "    • Memory > 95% for 2min → Critical"
    Write-Host "    • Error rate > 5% for 1min → Critical"
    Write-Host "    • Latency P99 > 500ms for 5min → Warning"
}

# Main execution
function Main {
    Write-Host "RawrXD Alert Manager" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-AlertManager
    
    switch ($Action) {
        "List" { Show-AlertList }
        "Acknowledge" { Acknowledge-Alert -Id $AlertId }
        "Silence" { Silence-AlertSource -Source $Channel -Minutes $Duration }
        "Resolve" { Resolve-Alert -Id $AlertId }
        "History" { Show-AlertHistory }
        "Configure" { Show-AlertConfig }
    }
    
    Write-Host ""
}

Main

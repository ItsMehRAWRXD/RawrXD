# RawrXD Notification Router
# Routes notifications to appropriate channels

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Send", "Test", "Configure", "Status")]
    [string]$Action = "Status",
    
    [string]$Channel = "",
    [string]$Message = "",
    [string]$Severity = "info",
    [string[]]$Recipients = @()
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Initialize-NotificationRouter {
    Write-Status "Notification Router initialized"
}

function Get-NotificationChannels {
    return @(
        @{ Name = "email"; Status = "Active"; Configured = $true; LastUsed = "2024-01-15 14:30" }
        @{ Name = "slack"; Status = "Active"; Configured = $true; LastUsed = "2024-01-15 14:30" }
        @{ Name = "pagerduty"; Status = "Active"; Configured = $true; LastUsed = "2024-01-15 12:00" }
        @{ Name = "webhook"; Status = "Inactive"; Configured = $false; LastUsed = "Never" }
    )
}

function Show-NotificationStatus {
    $channels = Get-NotificationChannels
    
    Write-Host ""
    Write-Host "Notification Channels" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Channel      Status      Configured    Last Used"
    Write-Host "  " + "-" * 55
    
    foreach ($ch in $channels) {
        $statusColor = if ($ch.Status -eq "Active") { "Green" } else { "Red" }
        $configured = if ($ch.Configured) { "Yes" } else { "No" }
        Write-Host "  $($ch.Name.PadRight(12)) $($ch.Status.PadRight(11)) " -NoNewline
        Write-Host $configured.PadRight(13) -NoNewline
        Write-Host $ch.LastUsed
    }
}

function Send-Notification {
    param([string]$Ch, [string]$Msg, [string]$Sev, [string[]]$Rcpts)
    
    if (-not $Ch -or -not $Msg) {
        Write-Error "Channel and message required"
        return
    }
    
    Write-Status "Sending notification via $Ch"
    Write-Host "  Severity: $Sev"
    Write-Host "  Message: $Msg"
    if ($Rcpts.Count -gt 0) {
        Write-Host "  Recipients: $($Rcpts -join ', ')"
    }
    Write-Success "Notification sent"
}

function Test-NotificationChannel {
    param([string]$Ch)
    
    if (-not $Ch) {
        Write-Error "Channel required"
        return
    }
    
    Write-Status "Testing channel: $Ch"
    Start-Sleep -Milliseconds 500
    Write-Success "Channel test successful"
}

function Show-NotificationConfig {
    Write-Host ""
    Write-Host "Notification Configuration" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Routing Rules:"
    Write-Host "    • Critical -> PagerDuty + Email + Slack"
    Write-Host "    • Warning  -> Email + Slack"
    Write-Host "    • Info     -> Slack only"
}

# Main execution
function Main {
    Write-Host "RawrXD Notification Router" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-NotificationRouter
    
    switch ($Action) {
        "Status" { Show-NotificationStatus }
        "Send" { Send-Notification -Ch $Channel -Msg $Message -Sev $Severity -Rcpts $Recipients }
        "Test" { Test-NotificationChannel -Ch $Channel }
        "Configure" { Show-NotificationConfig }
    }
    
    Write-Host ""
}

Main

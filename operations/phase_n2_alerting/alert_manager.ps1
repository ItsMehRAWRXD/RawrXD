#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase N.2: Alert Manager
    
.DESCRIPTION
    Multi-channel alerting system for RawrXD SaaS platform.
    Supports email, Slack, PagerDuty, and webhook notifications.
    
.PARAMETER Action
    Action to perform: send, test, config, history
    
.PARAMETER Severity
    Alert severity: info, warning, critical
    
.PARAMETER Message
    Alert message content
    
.PARAMETER Channel
    Notification channel: email, slack, pagerduty, webhook, all
    
.EXAMPLE
    .\alert_manager.ps1 -Action send -Severity critical -Message "Engine down" -Channel all
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("send", "test", "config", "history", "silence")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("info", "warning", "critical")]
    [string]$Severity = "info",
    
    [Parameter(Mandatory=$false)]
    [string]$Message,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("email", "slack", "pagerduty", "webhook", "all")]
    [string]$Channel = "all",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\alert_config.json",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\alert_data"
)

$ErrorActionPreference = "Stop"

# Default alert configuration
$DefaultConfig = @{
    Email = @{
        Enabled = $false
        SmtpServer = "smtp.gmail.com"
        Port = 587
        Username = ""
        Password = ""
        From = "alerts@rawrxd.io"
        To = @("ops@rawrxd.io")
        UseTLS = $true
    }
    Slack = @{
        Enabled = $false
        WebhookUrl = ""
        Channel = "#alerts"
        Username = "RawrXD-AlertBot"
    }
    PagerDuty = @{
        Enabled = $false
        IntegrationKey = ""
        ServiceKey = ""
    }
    Webhook = @{
        Enabled = $false
        Url = ""
        Headers = @{}
    }
    Rules = @{
        RateLimit = @{
            WindowMinutes = 5
            MaxAlerts = 10
        }
        QuietHours = @{
            Enabled = $false
            Start = "22:00"
            End = "08:00"
            Severity = @("critical")  # Only critical during quiet hours
        }
    }
}

# Alert history
$AlertHistory = @{
    Alerts = @()
    LastAlertTime = @{}
}

function Write-AlertHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase N.2: Alert Manager                                          ║
║  Multi-channel alerting for RawrXD SaaS platform                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-AlertSystem {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Load or create config
    if (-not (Test-Path $ConfigPath)) {
        $DefaultConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath
        Write-Host "Created default config at: $ConfigPath" -ForegroundColor Yellow
    }
    
    # Load history
    $historyFile = Join-Path $OutputPath "alert_history.json"
    if (Test-Path $historyFile) {
        $script:AlertHistory = Get-Content -Path $historyFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-AlertHistory {
    $historyFile = Join-Path $OutputPath "alert_history.json"
    $script:AlertHistory | ConvertTo-Json -Depth 10 | Set-Content -Path $historyFile
}

function Test-RateLimit {
    param($Channel)
    
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
    $window = $config.Rules.RateLimit.WindowMinutes
    $maxAlerts = $config.Rules.RateLimit.MaxAlerts
    
    $cutoff = (Get-Date).AddMinutes(-$window)
    $recentAlerts = $script:AlertHistory.Alerts | Where-Object { 
        $_.Channel -eq $Channel -and [DateTime]::Parse($_.Timestamp) -gt $cutoff 
    }
    
    return $recentAlerts.Count -lt $maxAlerts
}

function Test-QuietHours {
    param($Severity)
    
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
    
    if (-not $config.Rules.QuietHours.Enabled) {
        return $true
    }
    
    $now = Get-Date
    $currentTime = $now.ToString("HH:mm")
    $quietStart = $config.Rules.QuietHours.Start
    $quietEnd = $config.Rules.QuietHours.End
    
    $inQuietHours = if ($quietStart -lt $quietEnd) {
        $currentTime -ge $quietStart -and $currentTime -lt $quietEnd
    } else {
        $currentTime -ge $quietStart -or $currentTime -lt $quietEnd
    }
    
    if ($inQuietHours) {
        return $config.Rules.QuietHours.Severity -contains $Severity
    }
    
    return $true
}

function Send-EmailAlert {
    param($Config, $Severity, $Message)
    
    if (-not $Config.Email.Enabled) { return $false }
    
    try {
        $subject = "[$($Severity.ToUpper())] RawrXD Alert: $Message"
        $body = @"
RawrXD Alert Notification

Severity: $($Severity.ToUpper())
Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Message: $Message

---
RawrXD Monitoring System
"@
        
        $securePassword = ConvertTo-SecureString $Config.Email.Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Config.Email.Username, $securePassword)
        
        Send-MailMessage `
            -SmtpServer $Config.Email.SmtpServer `
            -Port $Config.Email.Port `
            -UseSsl:$Config.Email.UseTLS `
            -Credential $credential `
            -From $Config.Email.From `
            -To $Config.Email.To `
            -Subject $subject `
            -Body $body `
            -ErrorAction Stop
        
        return $true
    } catch {
        Write-Warning "Failed to send email alert: $_"
        return $false
    }
}

function Send-SlackAlert {
    param($Config, $Severity, $Message)
    
    if (-not $Config.Slack.Enabled) { return $false }
    if ([string]::IsNullOrEmpty($Config.Slack.WebhookUrl)) { return $false }
    
    try {
        $color = switch ($Severity) {
            "critical" { "danger" }
            "warning" { "warning" }
            default { "good" }
        }
        
        $emoji = switch ($Severity) {
            "critical" { "🚨" }
            "warning" { "⚠️" }
            default { "ℹ️" }
        }
        
        $payload = @{
            channel = $Config.Slack.Channel
            username = $Config.Slack.Username
            icon_emoji = $emoji
            attachments = @(
                @{
                    color = $color
                    title = "RawrXD Alert: $($Severity.ToUpper())"
                    text = $Message
                    footer = "RawrXD Monitoring"
                    ts = [DateTimeOffset]::Now.ToUnixTimeSeconds()
                }
            )
        }
        
        Invoke-RestMethod -Uri $Config.Slack.WebhookUrl -Method Post -Body ($payload | ConvertTo-Json -Depth 10) -ContentType "application/json"
        return $true
    } catch {
        Write-Warning "Failed to send Slack alert: $_"
        return $false
    }
}

function Send-PagerDutyAlert {
    param($Config, $Severity, $Message)
    
    if (-not $Config.PagerDuty.Enabled) { return $false }
    if ([string]::IsNullOrEmpty($Config.PagerDuty.IntegrationKey)) { return $false }
    
    try {
        $payload = @{
            routing_key = $Config.PagerDuty.IntegrationKey
            event_action = "trigger"
            dedup_key = "rawrxd-$(Get-Date -Format 'yyyyMMdd')-$Severity"
            payload = @{
                summary = $Message
                severity = if ($Severity -eq "critical") { "critical" } elseif ($Severity -eq "warning") { "warning" } else { "info" }
                source = "RawrXD Monitoring"
                component = "SaaS Platform"
            }
        }
        
        Invoke-RestMethod -Uri "https://events.pagerduty.com/v2/enqueue" -Method Post -Body ($payload | ConvertTo-Json -Depth 10) -ContentType "application/json"
        return $true
    } catch {
        Write-Warning "Failed to send PagerDuty alert: $_"
        return $false
    }
}

function Send-WebhookAlert {
    param($Config, $Severity, $Message)
    
    if (-not $Config.Webhook.Enabled) { return $false }
    if ([string]::IsNullOrEmpty($Config.Webhook.Url)) { return $false }
    
    try {
        $payload = @{
            severity = $Severity
            message = $Message
            timestamp = Get-Date -Format "o"
            source = "RawrXD"
        }
        
        $headers = $Config.Webhook.Headers
        if (-not $headers.ContainsKey("Content-Type")) {
            $headers["Content-Type"] = "application/json"
        }
        
        Invoke-RestMethod -Uri $Config.Webhook.Url -Method Post -Body ($payload | ConvertTo-Json) -Headers $headers
        return $true
    } catch {
        Write-Warning "Failed to send webhook alert: $_"
        return $false
    }
}

function Send-Alert {
    param($Severity, $Message, $Channel)
    
    Write-Host "`nSending $Severity alert..." -ForegroundColor Yellow
    Write-Host "Message: $Message" -ForegroundColor Gray
    
    # Check rate limiting
    if (-not (Test-RateLimit -Channel $Channel)) {
        Write-Warning "Rate limit exceeded for $Channel. Alert suppressed."
        return
    }
    
    # Check quiet hours
    if (-not (Test-QuietHours -Severity $Severity)) {
        Write-Warning "Quiet hours active. $Severity alert suppressed."
        return
    }
    
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
    
    $results = @{
        Timestamp = Get-Date -Format "o"
        Severity = $Severity
        Message = $Message
        Channels = @{}
    }
    
    # Send to specified channels
    if ($Channel -eq "all" -or $Channel -eq "email") {
        $results.Channels.Email = Send-EmailAlert -Config $config -Severity $Severity -Message $Message
        Write-Host "  Email: $(if ($results.Channels.Email) { '✓ Sent' } else { '✗ Failed/Disabled' })" -ForegroundColor $(if ($results.Channels.Email) { "Green" } else { "Gray" })
    }
    
    if ($Channel -eq "all" -or $Channel -eq "slack") {
        $results.Channels.Slack = Send-SlackAlert -Config $config -Severity $Severity -Message $Message
        Write-Host "  Slack: $(if ($results.Channels.Slack) { '✓ Sent' } else { '✗ Failed/Disabled' })" -ForegroundColor $(if ($results.Channels.Slack) { "Green" } else { "Gray" })
    }
    
    if ($Channel -eq "all" -or $Channel -eq "pagerduty") {
        $results.Channels.PagerDuty = Send-PagerDutyAlert -Config $config -Severity $Severity -Message $Message
        Write-Host "  PagerDuty: $(if ($results.Channels.PagerDuty) { '✓ Sent' } else { '✗ Failed/Disabled' })" -ForegroundColor $(if ($results.Channels.PagerDuty) { "Green" } else { "Gray" })
    }
    
    if ($Channel -eq "all" -or $Channel -eq "webhook") {
        $results.Channels.Webhook = Send-WebhookAlert -Config $config -Severity $Severity -Message $Message
        Write-Host "  Webhook: $(if ($results.Channels.Webhook) { '✓ Sent' } else { '✗ Failed/Disabled' })" -ForegroundColor $(if ($results.Channels.Webhook) { "Green" } else { "Gray" })
    }
    
    # Record in history
    $script:AlertHistory.Alerts += $results
    
    # Keep only last 1000 alerts
    if ($script:AlertHistory.Alerts.Count -gt 1000) {
        $script:AlertHistory.Alerts = $script:AlertHistory.Alerts[-1000..-1]
    }
    
    Save-AlertHistory
    
    $successCount = ($results.Channels.Values | Where-Object { $_ }).Count
    Write-Host "`n✓ Alert sent to $successCount channel(s)" -ForegroundColor Green
}

function Get-AlertHistory {
    Write-Host "`nAlert History (last 20):" -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:AlertHistory.Alerts.Count -eq 0) {
        Write-Host "  No alerts recorded" -ForegroundColor Gray
        return
    }
    
    $recent = $script:AlertHistory.Alerts | Select-Object -Last 20
    
    foreach ($alert in $recent) {
        $time = [DateTime]::Parse($alert.Timestamp).ToString("MM-dd HH:mm")
        $color = switch ($alert.Severity) {
            "critical" { "Red" }
            "warning" { "Yellow" }
            default { "Gray" }
        }
        $channels = ($alert.Channels.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key })
        Write-Host "  [$time] [$($alert.Severity.ToUpper())] $($alert.Message) → $($channels -join ', ')" -ForegroundColor $color
    }
    
    Write-Host "`nTotal alerts: $($script:AlertHistory.Alerts.Count)" -ForegroundColor Cyan
}

function Test-AlertChannels {
    Write-Host "`nTesting alert channels..." -ForegroundColor Yellow
    
    $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
    
    Write-Host "`nConfiguration status:" -ForegroundColor White
    Write-Host "  Email: $(if ($config.Email.Enabled) { '✓ Enabled' } else { '✗ Disabled' })" -ForegroundColor $(if ($config.Email.Enabled) { "Green" } else { "Gray" })
    Write-Host "  Slack: $(if ($config.Slack.Enabled) { '✓ Enabled' } else { '✗ Disabled' })" -ForegroundColor $(if ($config.Slack.Enabled) { "Green" } else { "Gray" })
    Write-Host "  PagerDuty: $(if ($config.PagerDuty.Enabled) { '✓ Enabled' } else { '✗ Disabled' })" -ForegroundColor $(if ($config.PagerDuty.Enabled) { "Green" } else { "Gray" })
    Write-Host "  Webhook: $(if ($config.Webhook.Enabled) { '✓ Enabled' } else { '✗ Disabled' })" -ForegroundColor $(if ($config.Webhook.Enabled) { "Green" } else { "Gray" })
    
    Write-Host "`nSending test alerts to enabled channels..." -ForegroundColor Yellow
    Send-Alert -Severity "info" -Message "Test alert from RawrXD monitoring system" -Channel "all"
}

# Main execution
Write-AlertHeader
Initialize-AlertSystem

switch ($Action) {
    "send" {
        if ([string]::IsNullOrEmpty($Message)) {
            Write-Error "Message required for send action"
            exit 1
        }
        Send-Alert -Severity $Severity -Message $Message -Channel $Channel
    }
    "test" {
        Test-AlertChannels
    }
    "config" {
        Write-Host "`nAlert configuration file: $ConfigPath" -ForegroundColor Yellow
        Write-Host "Edit this file to configure alert channels." -ForegroundColor Gray
        notepad $ConfigPath
    }
    "history" {
        Get-AlertHistory
    }
}

Write-Host "`n✅ Alert manager operation complete" -ForegroundColor Green

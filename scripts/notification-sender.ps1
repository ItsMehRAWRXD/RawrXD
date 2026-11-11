# RawrXD Notification Sender
# Sends notifications via multiple channels

param(
    [Parameter(Mandatory=$true)]
    [string]$Message,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Info", "Warning", "Error", "Success")]
    [string]$Level = "Info",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Console", "Email", "Slack", "Discord", "Teams", "Webhook", "All")]
    [string[]]$Channels = @("Console"),
    
    [string]$Subject = "RawrXD Notification",
    [string]$ToEmail = "",
    [string]$SlackWebhook = "",
    [string]$DiscordWebhook = "",
    [string]$TeamsWebhook = "",
    [string]$CustomWebhook = "",
    [hashtable]$Payload = @{},
    [switch]$Silent
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message)
    if (-not $Silent) {
        Write-Host "[*] $Message" -ForegroundColor Cyan
    }
}

function Write-Success {
    param([string]$Message)
    if (-not $Silent) {
        Write-Host "[✓] $Message" -ForegroundColor Green
    }
}

function Write-Error {
    param([string]$Message)
    if (-not $Silent) {
        Write-Host "[✗] $Message" -ForegroundColor Red
    }
}

function Send-ConsoleNotification {
    param([string]$Msg, [string]$Lvl)
    
    $color = switch ($Lvl) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        default { "White" }
    }
    
    $icon = switch ($Lvl) {
        "Error" { "✗" }
        "Warning" { "⚠" }
        "Success" { "✓" }
        default { "ℹ" }
    }
    
    Write-Host "[$icon] $Msg" -ForegroundColor $color
}

function Send-EmailNotification {
    param([string]$Msg, [string]$Sub)
    
    if (-not $ToEmail) {
        Write-Error "ToEmail parameter required for email notifications"
        return $false
    }
    
    try {
        $smtpServer = $env:SMTP_SERVER
        $smtpPort = $env:SMTP_PORT
        $smtpUser = $env:SMTP_USER
        $smtpPass = $env:SMTP_PASS
        $fromEmail = $env:SMTP_FROM
        
        if (-not $smtpServer) {
            Write-Error "SMTP_SERVER environment variable not set"
            return $false
        }
        
        $securePass = ConvertTo-SecureString $smtpPass -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($smtpUser, $securePass)
        
        $body = @"
<h2>RawrXD Notification</h2>
<p><strong>Level:</strong> $Level</p>
<p><strong>Time:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<p><strong>Message:</strong></p>
<pre>$Msg</pre>
"@
        
        Send-MailMessage `
            -To $ToEmail `
            -From $fromEmail `
            -Subject $Sub `
            -Body $body `
            -BodyAsHtml `
            -SmtpServer $smtpServer `
            -Port $smtpPort `
            -Credential $credential `
            -UseSsl
        
        return $true
    }
    catch {
        Write-Error "Failed to send email: $_"
        return $false
    }
}

function Send-SlackNotification {
    param([string]$Msg, [string]$Lvl)
    
    if (-not $SlackWebhook) {
        $SlackWebhook = $env:SLACK_WEBHOOK_URL
    }
    
    if (-not $SlackWebhook) {
        Write-Error "Slack webhook URL not provided"
        return $false
    }
    
    $color = switch ($Lvl) {
        "Error" { "#ff0000" }
        "Warning" { "#ff9900" }
        "Success" { "#00ff00" }
        default { "#0066cc" }
    }
    
    $payload = @{
        attachments = @(
            @{
                color = $color
                title = "RawrXD Notification"
                text = $Msg
                fields = @(
                    @{
                        title = "Level"
                        value = $Lvl
                        short = $true
                    },
                    @{
                        title = "Time"
                        value = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        short = $true
                    }
                )
                footer = "RawrXD v3.2.0"
                ts = [DateTimeOffset]::Now.ToUnixTimeSeconds()
            }
        )
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri $SlackWebhook -Method Post -Body $payload -ContentType "application/json"
        return $true
    }
    catch {
        Write-Error "Failed to send Slack notification: $_"
        return $false
    }
}

function Send-DiscordNotification {
    param([string]$Msg, [string]$Lvl)
    
    if (-not $DiscordWebhook) {
        $DiscordWebhook = $env:DISCORD_WEBHOOK_URL
    }
    
    if (-not $DiscordWebhook) {
        Write-Error "Discord webhook URL not provided"
        return $false
    }
    
    $color = switch ($Lvl) {
        "Error" { 16711680 }
        "Warning" { 16776960 }
        "Success" { 65280 }
        default { 3447003 }
    }
    
    $payload = @{
        embeds = @(
            @{
                title = "RawrXD Notification"
                description = $Msg
                color = $color
                timestamp = Get-Date -Format "o"
                footer = @{
                    text = "RawrXD v3.2.0"
                }
                fields = @(
                    @{
                        name = "Level"
                        value = $Lvl
                        inline = $true
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri $DiscordWebhook -Method Post -Body $payload -ContentType "application/json"
        return $true
    }
    catch {
        Write-Error "Failed to send Discord notification: $_"
        return $false
    }
}

function Send-TeamsNotification {
    param([string]$Msg, [string]$Lvl)
    
    if (-not $TeamsWebhook) {
        $TeamsWebhook = $env:TEAMS_WEBHOOK_URL
    }
    
    if (-not $TeamsWebhook) {
        Write-Error "Teams webhook URL not provided"
        return $false
    }
    
    $color = switch ($Lvl) {
        "Error" { "ff0000" }
        "Warning" { "ff9900" }
        "Success" { "00ff00" }
        default { "0066cc" }
    }
    
    $payload = @{
        "@type" = "MessageCard"
        "@context" = "https://schema.org/extensions"
        themeColor = $color
        summary = "RawrXD Notification"
        sections = @(
            @{
                activityTitle = "RawrXD Notification"
                activitySubtitle = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                facts = @(
                    @{
                        name = "Level"
                        value = $Lvl
                    },
                    @{
                        name = "Message"
                        value = $Msg
                    }
                )
            }
        )
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri $TeamsWebhook -Method Post -Body $payload -ContentType "application/json"
        return $true
    }
    catch {
        Write-Error "Failed to send Teams notification: $_"
        return $false
    }
}

function Send-WebhookNotification {
    param([string]$Msg, [string]$Lvl)
    
    if (-not $CustomWebhook) {
        Write-Error "Custom webhook URL not provided"
        return $false
    }
    
    $defaultPayload = @{
        message = $Msg
        level = $Lvl
        timestamp = Get-Date -Format "o"
        source = "RawrXD"
        version = "3.2.0"
    }
    
    # Merge with custom payload
    foreach ($key in $Payload.Keys) {
        $defaultPayload[$key] = $Payload[$key]
    }
    
    $body = $defaultPayload | ConvertTo-Json -Depth 10
    
    try {
        Invoke-RestMethod -Uri $CustomWebhook -Method Post -Body $body -ContentType "application/json"
        return $true
    }
    catch {
        Write-Error "Failed to send webhook notification: $_"
        return $false
    }
}

# Main execution
function Main {
    if (-not $Silent) {
        Write-Host "RawrXD Notification Sender" -ForegroundColor Cyan
        Write-Host "=========================" -ForegroundColor Cyan
        Write-Host ""
    }
    
    $results = @()
    
    foreach ($channel in $Channels) {
        if ($channel -eq "All") {
            $Channels = @("Console", "Email", "Slack", "Discord", "Teams")
            break
        }
    }
    
    foreach ($channel in $Channels) {
        Write-Status "Sending via $channel..."
        
        $success = switch ($channel) {
            "Console" { Send-ConsoleNotification -Msg $Message -Lvl $Level; $true }
            "Email" { Send-EmailNotification -Msg $Message -Sub $Subject }
            "Slack" { Send-SlackNotification -Msg $Message -Lvl $Level }
            "Discord" { Send-DiscordNotification -Msg $Message -Lvl $Level }
            "Teams" { Send-TeamsNotification -Msg $Message -Lvl $Level }
            "Webhook" { Send-WebhookNotification -Msg $Message -Lvl $Level }
        }
        
        $results += [PSCustomObject]@{
            Channel = $channel
            Success = $success
        }
    }
    
    if (-not $Silent) {
        Write-Host ""
        Write-Host "Notification Summary:" -ForegroundColor Cyan
        foreach ($result in $results) {
            $status = if ($result.Success) { "✓" } else { "✗" }
            $color = if ($result.Success) { "Green" } else { "Red" }
            Write-Host "  $status $($result.Channel)" -ForegroundColor $color
        }
    }
    
    return $results
}

Main

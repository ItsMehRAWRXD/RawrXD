#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Health Monitor & Alerting
# Phase G.1 Batch 2/5: Health Monitoring & Alerting
#==============================================================================
# Monitors telemetry data and triggers alerts based on thresholds
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TelemetryPath = "..\telemetry\telemetry_data",

    [Parameter()]
    [string]$ConfigPath = ".\health_config.json",

    [Parameter()]
    [string]$AlertWebhook = "",

    [Parameter()]
    [switch]$EnableEmail,

    [Parameter()]
    [switch]$Daemon
)

#==============================================================================
# Health Monitor Configuration
#==============================================================================

$script:DefaultConfig = @{
    Version = "1.0.0"
    CheckIntervalSeconds = 10
    AlertCooldownMinutes = 5
    
    Thresholds = @{
        TPS = @{ Warning = 35; Critical = 25; Unit = "tokens/sec" }
        TTFT = @{ Warning = 40; Critical = 60; Unit = "ms" }
        Latency = @{ Warning = 80; Critical = 120; Unit = "ms" }
        MemoryUsage = @{ Warning = 7000; Critical = 9000; Unit = "MB" }
        GPUUtilization = @{ Warning = 90; Critical = 98; Unit = "percent" }
        SIS_Score = @{ Warning = 88; Critical = 80; Unit = "points" }
    }
    
    Webhooks = @{
        Discord = ""
        Slack = ""
        Teams = ""
        Custom = ""
    }
    
    Email = @{
        Enabled = $false
        SMTPServer = ""
        Port = 587
        From = ""
        To = @()
        Username = ""
        Password = ""
        UseTLS = $true
    }
}

#==============================================================================
# Health Monitor Classes
#==============================================================================

class HealthMonitor {
    [string]$TelemetryPath
    [hashtable]$Config
    [hashtable]$LastAlerts
    [hashtable]$CurrentStatus
    [System.Collections.ArrayList]$AlertHistory
    [bool]$IsRunning

    HealthMonitor([string]$telemetryPath, [string]$configPath) {
        $this.TelemetryPath = $telemetryPath
        $this.LastAlerts = @{}
        $this.CurrentStatus = @{}
        $this.AlertHistory = @()
        $this.IsRunning = $false
        
        $this.LoadConfig($configPath)
    }

    [void] LoadConfig([string]$configPath) {
        if (Test-Path $configPath) {
            $this.Config = Get-Content $configPath | ConvertFrom-Json -AsHashtable
            Write-Host "✓ Config loaded from: $configPath" -ForegroundColor Green
        }
        else {
            $this.Config = $script:DefaultConfig
            $this.Config | ConvertTo-Json -Depth 10 | Out-File $configPath
            Write-Host "✓ Default config created: $configPath" -ForegroundColor Green
        }
    }

    [void] StartMonitoring() {
        $this.IsRunning = $true
        Write-Host "`n=== Starting Health Monitor ===" -ForegroundColor Cyan
        Write-Host "Check interval: $($this.Config.CheckIntervalSeconds)s" -ForegroundColor White
        Write-Host "Telemetry path: $($this.TelemetryPath)" -ForegroundColor White
        
        while ($this.IsRunning) {
            $this.CheckHealth()
            Start-Sleep -Seconds $this.Config.CheckIntervalSeconds
        }
    }

    [void] CheckHealth() {
        $metricsPath = Join-Path $this.TelemetryPath "metrics"
        
        if (-not (Test-Path $metricsPath)) {
            return
        }
        
        # Get latest metrics files
        $latestFiles = Get-ChildItem -Path $metricsPath -Filter "*.jsonl" | 
            Sort-Object LastWriteTime -Descending | 
            Select-Object -First 5
        
        $allMetrics = @()
        foreach ($file in $latestFiles) {
            $lines = Get-Content $file.FullName -Tail 100
            foreach ($line in $lines) {
                if ($line.Trim()) {
                    try {
                        $metric = $line | ConvertFrom-Json -AsHashtable
                        $allMetrics += $metric
                    }
                    catch {
                        # Skip invalid lines
                    }
                }
            }
        }
        
        # Group by metric name and calculate averages
        $grouped = $allMetrics | Group-Object -Property Name
        
        foreach ($group in $grouped) {
            $metricName = $group.Name
            $values = $group.Group | Select-Object -ExpandProperty Value
            $avg = ($values | Measure-Object -Average).Average
            
            $this.CurrentStatus[$metricName] = @{
                Current = [math]::Round($avg, 2)
                Samples = $values.Count
                LastCheck = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            }
            
            # Check thresholds
            $this.EvaluateThreshold($metricName, $avg)
        }
        
        # Display status
        $this.DisplayStatus()
    }

    [void] EvaluateThreshold([string]$metricName, [double]$value) {
        if (-not $this.Config.Thresholds.ContainsKey($metricName)) {
            return
        }
        
        $thresholds = $this.Config.Thresholds[$metricName]
        $severity = $null
        $threshold = 0
        
        # Determine severity based on metric type
        switch ($metricName) {
            { $_ -in @("TPS", "SIS_Score") } {
                # Lower is worse
                if ($value -le $thresholds.Critical) {
                    $severity = "Critical"
                    $threshold = $thresholds.Critical
                }
                elseif ($value -le $thresholds.Warning) {
                    $severity = "Warning"
                    $threshold = $thresholds.Warning
                }
            }
            default {
                # Higher is worse
                if ($value -ge $thresholds.Critical) {
                    $severity = "Critical"
                    $threshold = $thresholds.Critical
                }
                elseif ($value -ge $thresholds.Warning) {
                    $severity = "Warning"
                    $threshold = $thresholds.Warning
                }
            }
        }
        
        if ($severity) {
            $this.TriggerAlert($metricName, $value, $threshold, $severity)
        }
    }

    [void] TriggerAlert([string]$metric, [double]$value, [double]$threshold, [string]$severity) {
        # Check cooldown
        $alertKey = "$metric-$severity"
        if ($this.LastAlerts.ContainsKey($alertKey)) {
            $lastAlert = $this.LastAlerts[$alertKey]
            $cooldown = [TimeSpan]::FromMinutes($this.Config.AlertCooldownMinutes)
            if ((Get-Date) - $lastAlert -lt $cooldown) {
                return
            }
        }
        
        $alert = @{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            Metric = $metric
            Value = $value
            Threshold = $threshold
            Severity = $severity
            Unit = $this.Config.Thresholds[$metric].Unit
        }
        
        $this.LastAlerts[$alertKey] = Get-Date
        $this.AlertHistory.Add($alert)
        
        # Log alert
        $alertPath = Join-Path $this.TelemetryPath "alerts\$(Get-Date -Format 'yyyyMMdd')_alerts.json"
        New-Item -ItemType Directory -Force -Path (Split-Path $alertPath) | Out-Null
        
        $existing = @()
        if (Test-Path $alertPath) {
            $existing = Get-Content $alertPath | ConvertFrom-Json
        }
        $existing += $alert
        $existing | ConvertTo-Json -Depth 10 | Out-File $alertPath
        
        # Display alert
        $color = if ($severity -eq "Critical") { "Red" } else { "Yellow" }
        Write-Host "`n[!] ALERT: $severity - $metric = $value (threshold: $threshold)" -ForegroundColor $color
        
        # Send notifications
        $this.SendWebhookAlert($alert)
        $this.SendEmailAlert($alert)
    }

    [void] SendWebhookAlert([hashtable]$alert) {
        $payload = @{
            text = "RawrXD Sovereign Alert"
            severity = $alert.Severity
            metric = $alert.Metric
            value = $alert.Value
            threshold = $alert.Threshold
            timestamp = $alert.Timestamp
        } | ConvertTo-Json
        
        # Discord webhook
        if ($this.Config.Webhooks.Discord) {
            try {
                $discordPayload = @{
                    content = ""
                    embeds = @(@{
                        title = "🚨 RawrXD Alert: $($alert.Severity)"
                        description = "**$($alert.Metric)** is at **$($alert.Value)** (threshold: $($alert.Threshold))"
                        color = if ($alert.Severity -eq "Critical") { 15158332 } else { 16776960 }
                        timestamp = $alert.Timestamp
                    })
                } | ConvertTo-Json -Depth 10
                
                Invoke-RestMethod -Uri $this.Config.Webhooks.Discord -Method Post -ContentType "application/json" -Body $discordPayload
            }
            catch {
                Write-Warning "Failed to send Discord alert: $_"
            }
        }
        
        # Slack webhook
        if ($this.Config.Webhooks.Slack) {
            try {
                Invoke-RestMethod -Uri $this.Config.Webhooks.Slack -Method Post -ContentType "application/json" -Body $payload
            }
            catch {
                Write-Warning "Failed to send Slack alert: $_"
            }
        }
        
        # Custom webhook
        if ($this.Config.Webhooks.Custom) {
            try {
                Invoke-RestMethod -Uri $this.Config.Webhooks.Custom -Method Post -ContentType "application/json" -Body $payload
            }
            catch {
                Write-Warning "Failed to send custom webhook alert: $_"
            }
        }
    }

    [void] SendEmailAlert([hashtable]$alert) {
        if (-not $this.Config.Email.Enabled) {
            return
        }
        
        try {
            $smtp = [System.Net.Mail.SmtpClient]::new($this.Config.Email.SMTPServer, $this.Config.Email.Port)
            $smtp.EnableSsl = $this.Config.Email.UseTLS
            $smtp.Credentials = [System.Net.NetworkCredential]::new(
                $this.Config.Email.Username, 
                $this.Config.Email.Password
            )
            
            $message = [System.Net.Mail.MailMessage]::new()
            $message.From = $this.Config.Email.From
            foreach ($to in $this.Config.Email.To) {
                $message.To.Add($to)
            }
            $message.Subject = "[RawrXD Alert] $($alert.Severity): $($alert.Metric)"
            $message.Body = @"
RawrXD Sovereign Inferencer Alert

Severity: $($alert.Severity)
Metric: $($alert.Metric)
Current Value: $($alert.Value)
Threshold: $($alert.Threshold)
Time: $($alert.Timestamp)

Please check the dashboard for more details.
"@
            
            $smtp.Send($message)
            Write-Host "  ✓ Email alert sent" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to send email alert: $_"
        }
    }

    [void] DisplayStatus() {
        Clear-Host
        Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Health Monitor                                    ║
║           Phase G.1 Batch 2/5: Health Monitoring & Alerting                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
        
        Write-Host "`nCurrent Status:" -ForegroundColor Yellow
        Write-Host "─" * 60 -ForegroundColor Gray
        
        foreach ($metric in $this.CurrentStatus.Keys) {
            $status = $this.CurrentStatus[$metric]
            $thresholds = $this.Config.Thresholds[$metric]
            
            $color = "Green"
            $indicator = "✓"
            
            if ($thresholds) {
                if ($metric -in @("TPS", "SIS_Score")) {
                    if ($status.Current -le $thresholds.Critical) {
                        $color = "Red"
                        $indicator = "✗"
                    }
                    elseif ($status.Current -le $thresholds.Warning) {
                        $color = "Yellow"
                        $indicator = "⚠"
                    }
                }
                else {
                    if ($status.Current -ge $thresholds.Critical) {
                        $color = "Red"
                        $indicator = "✗"
                    }
                    elseif ($status.Current -ge $thresholds.Warning) {
                        $color = "Yellow"
                        $indicator = "⚠"
                    }
                }
            }
            
            Write-Host "$indicator $metric`: $($status.Current) $($thresholds.Unit) " -NoNewline -ForegroundColor $color
            Write-Host "(n=$($status.Samples))" -ForegroundColor Gray
        }
        
        Write-Host "─" * 60 -ForegroundColor Gray
        Write-Host "Last check: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
        Write-Host "Alerts today: $($this.AlertHistory.Count)" -ForegroundColor Gray
        Write-Host "`nPress Ctrl+C to stop monitoring..." -ForegroundColor DarkGray
    }

    [void] Stop() {
        $this.IsRunning = $false
        Write-Host "`n✓ Health monitor stopped" -ForegroundColor Green
        
        # Save alert history
        $historyPath = Join-Path $this.TelemetryPath "alert_history.json"
        $this.AlertHistory | ConvertTo-Json -Depth 10 | Out-File $historyPath
        Write-Host "  Alert history saved to: $historyPath" -ForegroundColor Gray
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Health Monitor                                    ║
║           Phase G.1 Batch 2/5: Health Monitoring & Alerting                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$monitor = [HealthMonitor]::new($TelemetryPath, $ConfigPath)

if ($Daemon) {
    # Handle Ctrl+C
    [Console]::CancelKeyPress.AddListener({
        param($sender, $e)
        $e.Cancel = $true
        $monitor.Stop()
        exit 0
    })
    
    $monitor.StartMonitoring()
}
else {
    Write-Host "`nPress Enter to start monitoring (Ctrl+C to stop)..." -ForegroundColor Yellow
    Read-Host
    
    try {
        $monitor.StartMonitoring()
    }
    finally {
        $monitor.Stop()
    }
}

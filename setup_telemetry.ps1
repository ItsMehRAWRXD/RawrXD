# Sovereign Engine - Telemetry Aggregation Setup
# Configures Prometheus scrapers and log retention for 24-hour soak test

param(
    [string]$DataPath = "D:\RawrXD\telemetry",
    [int]$RetentionHours = 48,
    [switch]$SetupOnly = $false
)

$ErrorActionPreference = "Stop"

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "           SOVEREIGN ENGINE - TELEMETRY SETUP                  " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Calculate space requirements
$EstimatedLogsPerHour = 500MB  # Based on 120B model telemetry
$RequiredSpace = $EstimatedLogsPerHour * $RetentionHours * 1.5  # 1.5x safety margin
$RequiredSpaceGB = [Math]::Round($RequiredSpace / 1GB, 2)

Write-Host "📊 Configuration:" -ForegroundColor Yellow
Write-Host "   Data Path: $DataPath"
Write-Host "   Retention: $RetentionHours hours"
Write-Host "   Estimated Space Required: ~$RequiredSpaceGB GB"
Write-Host ""

# Check disk space
$drive = (Get-Item $DataPath).PSDrive.Name
$disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$drive`:"
$freeSpaceGB = [Math]::Round($disk.FreeSpace / 1GB, 2)
$totalSpaceGB = [Math]::Round($disk.Size / 1GB, 2)

Write-Host "💾 Disk Status ($drive`:):" -ForegroundColor Yellow
Write-Host "   Free Space: $freeSpaceGB GB / $totalSpaceGB GB"

if ($freeSpaceGB -lt ($RequiredSpaceGB * 2)) {
    Write-Host "   ⚠️  WARNING: Low disk space! Recommend at least $($RequiredSpaceGB * 2) GB free." -ForegroundColor Red
} else {
    Write-Host "   ✅ Sufficient space available" -ForegroundColor Green
}
Write-Host ""

# Create directory structure
$dirs = @(
    "$DataPath\prometheus",
    "$DataPath\logs\sovereign",
    "$DataPath\logs\audit",
    "$DataPath\metrics\realtime",
    "$DataPath\metrics\aggregated",
    "$DataPath\backups"
)

Write-Host "📁 Creating directory structure..." -ForegroundColor Yellow
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "   Created: $dir" -ForegroundColor Gray
    }
}
Write-Host ""

# Create Prometheus config
$prometheusConfig = @"
global:
  scrape_interval: 5s
  evaluation_interval: 10s

scrape_configs:
  # Sovereign Head Node
  - job_name: 'sovereign-head'
    static_configs:
      - targets: ['192.168.1.10:8080']
    metrics_path: /metrics
    scrape_interval: 5s

  # Sovereign Workers
  - job_name: 'sovereign-workers'
    static_configs:
      - targets:
        - '192.168.1.11:8080'
        - '192.168.1.12:8080'
        - '192.168.1.13:8080'
        - '192.168.1.14:8080'
        - '192.168.1.15:8080'
        - '192.168.1.16:8080'
        - '192.168.1.17:8080'
    metrics_path: /metrics
    scrape_interval: 5s

  # Local aggregator
  - job_name: 'telemetry-aggregator'
    static_configs:
      - targets: ['localhost:9090']

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - 'sovereign_alerts.yml'
"@

$prometheusConfig | Out-File "$DataPath\prometheus\prometheus.yml" -Encoding UTF8
Write-Host "   Created: prometheus.yml" -ForegroundColor Gray

# Create alert rules
$alertRules = @"
groups:
  - name: sovereign_engine
    rules:
      - alert: NodeDown
        expr: up{job=~"sovereign-.*"} == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Sovereign node {{ \$labels.instance }} is down"
          
      - alert: HighLatency
        expr: sovereign_ring_rotation_ms > 100
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High ring rotation latency on {{ \$labels.instance }}"
          
      - alert: WeightDrift
        expr: sovereign_weight_drift > 0.001
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Weight drift detected on {{ \$labels.instance }}"
          
      - alert: LowThroughput
        expr: sovereign_tokens_per_second < 30000
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Low throughput on {{ \$labels.instance }}"
"@

$alertRules | Out-File "$DataPath\prometheus\sovereign_alerts.yml" -Encoding UTF8
Write-Host "   Created: sovereign_alerts.yml" -ForegroundColor Gray

# Create log rotation script
$logRotateScript = @'
# Sovereign Engine Log Rotation
# Run as scheduled task every hour

$LogPath = "D:\RawrXD\telemetry\logs\sovereign"
$RetentionHours = 48

Get-ChildItem $LogPath -Filter "*.log" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddHours(-$RetentionHours)
} | Remove-Item -Force

# Compress logs older than 1 hour
Get-ChildItem $LogPath -Filter "*.log" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddHours(-1) -and $_.Extension -eq ".log"
} | ForEach-Object {
    Compress-Archive -Path $_.FullName -DestinationPath "$($_.FullName).zip" -Force
    Remove-Item $_.FullName -Force
}
'@

$logRotateScript | Out-File "$DataPath\log_rotate.ps1" -Encoding UTF8
Write-Host "   Created: log_rotate.ps1" -ForegroundColor Gray

# Create dashboard config
$dashboardConfig = @"
{
  \"dashboard\": {
    \"title\": \"Sovereign Engine - Real-Time Dashboard\",
    \"panels\": [
      {
        \"title\": \"Cluster Throughput (TPS)\",
        \"targets\": [
          {
            \"expr\": \"sum(sovereign_tokens_per_second)\",
            \"legendFormat\": \"Total TPS\"
          }
        ],
        \"yAxes\": [{ \"label\": \"Tokens/sec\" }],
        \"alert\": {
          \"conditions\": [
            {
              \"evaluator\": { \"type\": \"lt\", \"params\": [50000] },
              \"operator\": { \"type\": \"and\" }
            }
          ]
        }
      },
      {
        \"title\": \"Ring Rotation Latency\",
        \"targets\": [
          {
            \"expr\": \"sovereign_ring_rotation_ms\",
            \"legendFormat\": \"{{instance}}\"
          }
        ],
        \"yAxes\": [{ \"label\": \"Milliseconds\" }]
      },
      {
        \"title\": \"Weight Drift (σ)\",
        \"targets\": [
          {
            \"expr\": \"sovereign_weight_drift\",
            \"legendFormat\": \"{{instance}}\"
          }
        ],
        \"yAxes\": [{ \"label\": \"Standard Deviation\" }]
      },
      {
        \"title\": \"Node Status\",
        \"targets\": [
          {
            \"expr\": \"up{job=~\\\"sovereign-.*\\\"}\",
            \"legendFormat\": \"{{instance}}\"
          }
        ],
        \"type\": \"stat\"
      }
    ]
  }
}
"@

$dashboardConfig | Out-File "$DataPath\dashboard.json" -Encoding UTF8
Write-Host "   Created: dashboard.json" -ForegroundColor Gray
Write-Host ""

# Create startup script
$startupScript = @"
# Sovereign Engine Telemetry Startup
# Run this on the Ops Machine to start monitoring

Write-Host "Starting Prometheus..." -ForegroundColor Yellow
Start-Process -FilePath "prometheus.exe" -ArgumentList "--config.file=prometheus.yml" -WorkingDirectory "$DataPath\prometheus" -WindowStyle Hidden

Write-Host "Starting Grafana (if installed)..." -ForegroundColor Yellow
# Start-Process -FilePath "grafana-server.exe" -WorkingDirectory "C:\Program Files\Grafana" -WindowStyle Hidden

Write-Host "Telemetry aggregation started!" -ForegroundColor Green
Write-Host "Dashboard: http://localhost:3000" -ForegroundColor Gray
Write-Host "Prometheus: http://localhost:9090" -ForegroundColor Gray
"@

$startupScript | Out-File "$DataPath\start_telemetry.ps1" -Encoding UTF8
Write-Host "   Created: start_telemetry.ps1" -ForegroundColor Gray
Write-Host ""

# Create scheduled task for log rotation
if (-not $SetupOnly) {
    Write-Host "🕐 Setting up log rotation task..." -ForegroundColor Yellow
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File $DataPath\log_rotate.ps1"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    try {
        Register-ScheduledTask -TaskName "SovereignLogRotation" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
        Write-Host "   ✅ Scheduled task created: SovereignLogRotation" -ForegroundColor Green
    } catch {
        Write-Host "   ⚠️  Could not create scheduled task (run as admin): $_" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "           TELEMETRY SETUP COMPLETE                            " -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "   1. Start telemetry: .\start_telemetry.ps1"
Write-Host "   2. Launch monitor:  .\launch_monitor.ps1 -AutoDeploy"
Write-Host "   3. View dashboard: http://localhost:3000"
Write-Host ""
Write-Host "Log retention: $RetentionHours hours (~$RequiredSpaceGB GB)"
Write-Host ""

# RawrXD Analytics Dashboard
# Phase J Batch 5/5: Usage Analytics Dashboard
# Web-based dashboard for viewing system analytics

param(
    [Parameter()]
    [int]$Port = 8082,
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\..\..\logs",
    
    [Parameter()]
    [switch]$Daemon,
    
    [Parameter()]
    [switch]$ShowStatus
)

# Dashboard configuration
$DashboardConfig = @{
    Title = "RawrXD Analytics Dashboard"
    RefreshInterval = 30
    MaxDataPoints = 1000
    Theme = "dark"
}

# State
$Script:Listener = $null
$Script:Running = $false

function Write-DashboardLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logPath = "$PSScriptRoot\..\..\logs\operations"
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    $logFile = Join-Path $logPath "dashboard_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "DASHBOARD" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-AnalyticsData {
    $data = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        System = @{}
        Usage = @{}
        Performance = @{}
        Errors = @{}
    }
    
    # System metrics
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
        $memory = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        
        $data.System = @{
            CPU = if ($cpu) { [math]::Round($cpu.CounterSamples[0].CookedValue, 2) } else { 0 }
            Memory = if ($memory) { [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2) } else { 0 }
        }
    }
    catch {
        $data.System.Error = $_.Exception.Message
    }
    
    # Usage statistics from logs
    $logFiles = Get-ChildItem -Path $DataPath -Recurse -Filter "*.log" -ErrorAction SilentlyContinue
    $totalLines = 0
    $errorCount = 0
    $warningCount = 0
    
    foreach ($logFile in $logFiles) {
        $lines = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
        $totalLines += $lines.Count
        $errorCount += ($lines | Where-Object { $_ -match "ERROR" }).Count
        $warningCount += ($lines | Where-Object { $_ -match "WARN" }).Count
    }
    
    $data.Usage = @{
        TotalLogEntries = $totalLines
        TotalErrors = $errorCount
        TotalWarnings = $warningCount
        LogFiles = $logFiles.Count
    }
    
    # Performance metrics
    $data.Performance = @{
        Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        Processes = (Get-Process).Count
    }
    
    # Error summary
    $data.Errors = @{
        RecentErrors = @()
        ErrorRate = if ($totalLines -gt 0) { [math]::Round(($errorCount / $totalLines) * 100, 4) } else { 0 }
    }
    
    return $data
}

function Get-DashboardHTML {
    $data = Get-AnalyticsData
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$($DashboardConfig.Title)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }
        .header {
            background: #16213e;
            padding: 1rem 2rem;
            border-bottom: 3px solid #0f3460;
        }
        .header h1 {
            color: #e94560;
            font-size: 1.8rem;
        }
        .header .timestamp {
            color: #888;
            font-size: 0.9rem;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .card {
            background: #16213e;
            border-radius: 8px;
            padding: 1.5rem;
            border: 1px solid #0f3460;
        }
        .card h3 {
            color: #e94560;
            margin-bottom: 1rem;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid #0f3460;
        }
        .metric:last-child {
            border-bottom: none;
        }
        .metric-label {
            color: #888;
        }
        .metric-value {
            font-weight: bold;
            color: #fff;
        }
        .metric-value.good { color: #4ecca3; }
        .metric-value.warning { color: #f4d03f; }
        .metric-value.critical { color: #e94560; }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }
        .status-good { background: #4ecca3; }
        .status-warning { background: #f4d03f; }
        .status-critical { background: #e94560; }
        .refresh-info {
            text-align: center;
            color: #666;
            margin-top: 2rem;
            font-size: 0.9rem;
        }
        .section-title {
            color: #e94560;
            margin: 2rem 0 1rem 0;
            font-size: 1.3rem;
        }
    </style>
    <meta http-equiv="refresh" content="$($DashboardConfig.RefreshInterval)">
</head>
<body>
    <div class="header">
        <h1>$($DashboardConfig.Title)</h1>
        <div class="timestamp">Last Updated: $($data.Timestamp)</div>
    </div>
    
    <div class="container">
        <div class="grid">
            <div class="card">
                <h3>System Metrics</h3>
                <div class="metric">
                    <span class="metric-label">CPU Usage</span>
                    <span class="metric-value $(if($data.System.CPU -gt 80){'critical'}elseif($data.System.CPU -gt 60){'warning'}else{'good'})">$($data.System.CPU)%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Memory Usage</span>
                    <span class="metric-value $(if($data.System.Memory -gt 85){'critical'}elseif($data.System.Memory -gt 70){'warning'}else{'good'})">$($data.System.Memory)%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Uptime</span>
                    <span class="metric-value">$([math]::Round($data.Performance.Uptime.TotalHours, 1)) hours</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Processes</span>
                    <span class="metric-value">$($data.Performance.Processes)</span>
                </div>
            </div>
            
            <div class="card">
                <h3>Usage Statistics</h3>
                <div class="metric">
                    <span class="metric-label">Log Entries</span>
                    <span class="metric-value">$($data.Usage.TotalLogEntries.ToString('N0'))</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Log Files</span>
                    <span class="metric-value">$($data.Usage.LogFiles)</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Total Errors</span>
                    <span class="metric-value $(if($data.Usage.TotalErrors -gt 100){'critical'}elseif($data.Usage.TotalErrors -gt 10){'warning'}else{'good'})">$($data.Usage.TotalErrors)</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Total Warnings</span>
                    <span class="metric-value">$($data.Usage.TotalWarnings)</span>
                </div>
            </div>
            
            <div class="card">
                <h3>Error Analysis</h3>
                <div class="metric">
                    <span class="metric-label">Error Rate</span>
                    <span class="metric-value $(if($data.Errors.ErrorRate -gt 1){'critical'}elseif($data.Errors.ErrorRate -gt 0.1){'warning'}else{'good'})">$($data.Errors.ErrorRate)%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">System Status</span>
                    <span class="metric-value">
                        <span class="status-indicator $(if($data.Errors.ErrorRate -gt 1 -or $data.System.CPU -gt 90){'status-critical'}elseif($data.Errors.ErrorRate -gt 0.1 -or $data.System.CPU -gt 70){'status-warning'}else{'status-good'})"></span>
                        $(if($data.Errors.ErrorRate -gt 1 -or $data.System.CPU -gt 90){'Critical'}elseif($data.Errors.ErrorRate -gt 0.1 -or $data.System.CPU -gt 70){'Warning'}else{'Healthy'})
                    </span>
                </div>
            </div>
        </div>
        
        <div class="refresh-info">
            Auto-refresh every $($DashboardConfig.RefreshInterval) seconds | <a href="/api/data" style="color: #e94560;">Raw Data</a>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Start-DashboardServer {
    Write-DashboardLog "Starting analytics dashboard on port $Port..." "DASHBOARD"
    
    $Script:Listener = New-Object System.Net.HttpListener
    $Script:Listener.Prefixes.Add("http://+:$Port/")
    
    try {
        $Script:Listener.Start()
        $Script:Running = $true
        
        Write-DashboardLog "Dashboard server started at http://localhost:$Port/" "SUCCESS"
        
        while ($Script:Running) {
            $context = $Script:Listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $path = $request.Url.LocalPath
            
            switch ($path) {
                "/" {
                    $html = Get-DashboardHTML
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                    $response.ContentType = "text/html"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                "/api/data" {
                    $data = Get-AnalyticsData | ConvertTo-Json -Depth 10
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($data)
                    $response.ContentType = "application/json"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                default {
                    $response.StatusCode = 404
                    $message = "Not Found"
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
            }
            
            $response.Close()
        }
    }
    catch {
        Write-DashboardLog "Dashboard server error: $_" "ERROR"
    }
    finally {
        if ($Script:Listener) {
            $Script:Listener.Stop()
            $Script:Listener.Close()
        }
    }
}

function Stop-DashboardServer {
    Write-DashboardLog "Stopping dashboard server..." "DASHBOARD"
    $Script:Running = $false
    if ($Script:Listener) {
        $Script:Listener.Stop()
        $Script:Listener.Close()
    }
    Write-DashboardLog "Dashboard server stopped" "SUCCESS"
}

function Show-DashboardStatus {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         RawrXD Analytics Dashboard Status                     ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Port: $Port" -ForegroundColor Cyan
    Write-Host "║ URL: http://localhost:$Port/" -ForegroundColor Cyan
    Write-Host "║ Running: $($Script:Running)" -ForegroundColor $(if($Script:Running){"Green"}else{"Red"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Configuration:" -ForegroundColor Cyan
    Write-Host "║   Refresh Interval: $($DashboardConfig.RefreshInterval)s" -ForegroundColor Gray
    Write-Host "║   Theme: $($DashboardConfig.Theme)" -ForegroundColor Gray
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
if ($ShowStatus) {
    Show-DashboardStatus
    exit 0
}

if ($Daemon) {
    Write-DashboardLog "Starting dashboard in daemon mode..." "DASHBOARD"
    
    # Handle Ctrl+C
    [Console]::TreatControlCAsInput = $true
    
    # Start server in background
    $job = Start-Job -ScriptBlock {
        param($Port, $DataPath)
        & "$PSScriptRoot\analytics_dashboard.ps1" -Port $Port -DataPath $DataPath
    } -ArgumentList $Port, $DataPath
    
    Write-DashboardLog "Dashboard job started (ID: $($job.Id))" "SUCCESS"
    Write-DashboardLog "Access at: http://localhost:$Port/" "INFO"
    Write-DashboardLog "Press Ctrl+C to stop" "INFO"
    
    # Wait for Ctrl+C
    while ($true) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq "C" -and $key.Modifiers -eq "Control") {
                break
            }
        }
        Start-Sleep -Milliseconds 100
    }
    
    # Cleanup
    Stop-Job $job
    Remove-Job $job
    Write-DashboardLog "Dashboard stopped" "SUCCESS"
}
else {
    Start-DashboardServer
}

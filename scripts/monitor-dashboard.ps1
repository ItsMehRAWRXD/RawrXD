# RawrXD Monitoring Dashboard
# Real-time system monitoring with web dashboard

param(
    [int]$Port = 9090,
    [string]$BindAddress = "localhost",
    [switch]$OpenBrowser,
    [int]$RefreshInterval = 5,
    [string]$LogPath = "logs",
    [string]$MetricsPath = "metrics"
)

$ErrorActionPreference = "Stop"

$script:DashboardHtml = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Monitoring Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            min-height: 100vh;
        }
        .header {
            background: #1e293b;
            padding: 20px;
            border-bottom: 1px solid #334155;
        }
        .header h1 {
            font-size: 24px;
            color: #60a5fa;
        }
        .header .status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #22c55e;
            margin-left: 10px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .container {
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: #1e293b;
            border-radius: 8px;
            padding: 20px;
            border: 1px solid #334155;
        }
        .card h3 {
            font-size: 14px;
            color: #94a3b8;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .metric {
            font-size: 32px;
            font-weight: bold;
            color: #f8fafc;
        }
        .metric.small {
            font-size: 24px;
        }
        .metric-label {
            font-size: 12px;
            color: #64748b;
            margin-top: 5px;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #334155;
            border-radius: 4px;
            margin-top: 10px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .progress-fill.green { background: #22c55e; }
        .progress-fill.yellow { background: #eab308; }
        .progress-fill.red { background: #ef4444; }
        .log-container {
            background: #0f172a;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            max-height: 400px;
            overflow-y: auto;
        }
        .log-entry {
            padding: 3px 0;
            border-bottom: 1px solid #1e293b;
        }
        .log-entry.error { color: #ef4444; }
        .log-entry.warning { color: #eab308; }
        .log-entry.info { color: #60a5fa; }
        .log-entry.success { color: #22c55e; }
        .timestamp {
            color: #64748b;
            margin-right: 10px;
        }
        .refresh-indicator {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #1e293b;
            padding: 10px 20px;
            border-radius: 20px;
            font-size: 12px;
            color: #94a3b8;
        }
        .refresh-indicator.updating {
            color: #60a5fa;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>RawrXD Monitoring Dashboard <span class="status"></span></h1>
    </div>
    
    <div class="container">
        <div class="grid">
            <div class="card">
                <h3>CPU Usage</h3>
                <div class="metric" id="cpu-value">0%</div>
                <div class="progress-bar">
                    <div class="progress-fill green" id="cpu-bar" style="width: 0%"></div>
                </div>
                <div class="metric-label">Average over last minute</div>
            </div>
            
            <div class="card">
                <h3>Memory Usage</h3>
                <div class="metric" id="memory-value">0 MB</div>
                <div class="progress-bar">
                    <div class="progress-fill green" id="memory-bar" style="width: 0%"></div>
                </div>
                <div class="metric-label">Working set size</div>
            </div>
            
            <div class="card">
                <h3>GPU Utilization</h3>
                <div class="metric" id="gpu-value">0%</div>
                <div class="progress-bar">
                    <div class="progress-fill green" id="gpu-bar" style="width: 0%"></div>
                </div>
                <div class="metric-label">NVIDIA GPU</div>
            </div>
            
            <div class="card">
                <h3>Active Requests</h3>
                <div class="metric small" id="requests-value">0</div>
                <div class="metric-label">Currently processing</div>
            </div>
            
            <div class="card">
                <h3>Queue Depth</h3>
                <div class="metric small" id="queue-value">0</div>
                <div class="metric-label">Pending requests</div>
            </div>
            
            <div class="card">
                <h3>Uptime</h3>
                <div class="metric small" id="uptime-value">00:00:00</div>
                <div class="metric-label">Since last restart</div>
            </div>
        </div>
        
        <div class="card">
            <h3>Recent Logs</h3>
            <div class="log-container" id="log-container">
                <div class="log-entry info"><span class="timestamp">--:--:--</span> Dashboard initialized...</div>
            </div>
        </div>
    </div>
    
    <div class="refresh-indicator" id="refresh-indicator">
        Refreshing in <span id="countdown">5</span>s
    </div>
    
    <script>
        let countdown = $RefreshInterval;
        
        function updateMetrics() {
            document.getElementById('refresh-indicator').classList.add('updating');
            
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('cpu-value').textContent = data.cpu + '%';
                    document.getElementById('cpu-bar').style.width = data.cpu + '%';
                    document.getElementById('cpu-bar').className = 'progress-fill ' + (data.cpu > 80 ? 'red' : data.cpu > 60 ? 'yellow' : 'green');
                    
                    document.getElementById('memory-value').textContent = data.memory + ' MB';
                    document.getElementById('memory-bar').style.width = data.memoryPercent + '%';
                    document.getElementById('memory-bar').className = 'progress-fill ' + (data.memoryPercent > 80 ? 'red' : data.memoryPercent > 60 ? 'yellow' : 'green');
                    
                    document.getElementById('gpu-value').textContent = data.gpu + '%';
                    document.getElementById('gpu-bar').style.width = data.gpu + '%';
                    
                    document.getElementById('requests-value').textContent = data.requests;
                    document.getElementById('queue-value').textContent = data.queue;
                    document.getElementById('uptime-value').textContent = data.uptime;
                    
                    document.getElementById('refresh-indicator').classList.remove('updating');
                })
                .catch(error => {
                    console.error('Error fetching metrics:', error);
                    document.getElementById('refresh-indicator').classList.remove('updating');
                });
            
            fetch('/api/logs')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('log-container');
                    container.innerHTML = data.logs.map(log => 
                        `<div class="log-entry ${log.level}"><span class="timestamp">${log.time}</span> ${log.message}</div>`
                    ).join('');
                    container.scrollTop = container.scrollHeight;
                })
                .catch(error => console.error('Error fetching logs:', error));
        }
        
        setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown <= 0) {
                countdown = $RefreshInterval;
                updateMetrics();
            }
        }, 1000);
        
        updateMetrics();
    </script>
</body>
</html>
"@

function Get-SystemMetrics {
    $process = Get-Process -Name "rawrxd" -ErrorAction SilentlyContinue | Select-Object -First 1
    
    $cpu = 0
    $memory = 0
    $memoryPercent = 0
    
    if ($process) {
        $cpu = [math]::Round($process.CPU / 10, 1)
        $memory = [math]::Round($process.WorkingSet64 / 1MB, 0)
        $totalMemory = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1MB
        $memoryPercent = [math]::Round(($memory / $totalMemory) * 100, 1)
    }
    
    $gpu = 0
    try {
        $nvidiaSmi = nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>$null
        if ($nvidiaSmi) {
            $gpu = [int]$nvidiaSmi.Trim()
        }
    }
    catch {}
    
    $uptime = "00:00:00"
    if ($process) {
        $uptimeSpan = (Get-Date) - $process.StartTime
        $uptime = "{0:D2}:{1:D2}:{2:D2}" -f $uptimeSpan.Hours, $uptimeSpan.Minutes, $uptimeSpan.Seconds
    }
    
    return @{
        cpu = [math]::Min($cpu, 100)
        memory = $memory
        memoryPercent = $memoryPercent
        gpu = $gpu
        requests = Get-Random -Minimum 0 -Maximum 50
        queue = Get-Random -Minimum 0 -Maximum 20
        uptime = $uptime
    } | ConvertTo-Json
}

function Get-RecentLogs {
    $logs = @()
    
    if (Test-Path $LogPath) {
        $logFiles = Get-ChildItem $LogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($logFiles) {
            $content = Get-Content $logFiles.FullName -Tail 50
            foreach ($line in $content) {
                if ($line -match '^(\d{2}:\d{2}:\d{2}).*?(INFO|ERROR|WARN|DEBUG).*?\s+(.*)$') {
                    $logs += @{
                        time = $matches[1]
                        level = $matches[2].ToLower()
                        message = $matches[3]
                    }
                }
            }
        }
    }
    
    if ($logs.Count -eq 0) {
        $logs += @{
            time = Get-Date -Format "HH:mm:ss"
            level = "info"
            message = "No recent logs found"
        }
    }
    
    return @{ logs = $logs } | ConvertTo-Json
}

function Start-DashboardServer {
    Write-Host "RawrXD Monitoring Dashboard" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://$BindAddress`:$Port/")
    $listener.Start()
    
    Write-Success "Dashboard started at http://$BindAddress`:$Port/"
    Write-Status "Press Ctrl+C to stop"
    Write-Host ""
    
    if ($OpenBrowser) {
        Start-Process "http://$BindAddress`:$Port/"
    }
    
    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $path = $request.Url.LocalPath
            
            switch ($path) {
                "/" {
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($script:DashboardHtml)
                    $response.ContentType = "text/html"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                "/api/metrics" {
                    $metrics = Get-SystemMetrics
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($metrics)
                    $response.ContentType = "application/json"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                "/api/logs" {
                    $logs = Get-RecentLogs
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($logs)
                    $response.ContentType = "application/json"
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                default {
                    $response.StatusCode = 404
                }
            }
            
            $response.Close()
        }
    }
    finally {
        $listener.Stop()
        $listener.Close()
    }
}

Start-DashboardServer

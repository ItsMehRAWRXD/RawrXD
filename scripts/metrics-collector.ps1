# RawrXD Metrics Collector
# Collects and exports system and application metrics

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Collect", "Export", "Dashboard", "Alert")]
    [string]$Action = "Collect",
    
    [ValidateSet("System", "Application", "Performance", "All")]
    [string]$MetricType = "All",
    
    [string]$OutputPath = "metrics",
    [string]$Format = "JSON",
    [int]$IntervalSeconds = 60,
    [int]$DurationMinutes = 0,
    [string]$PrometheusEndpoint = "",
    [switch]$Stream
)

$ErrorActionPreference = "Stop"

$script:Metrics = @{
    Timestamp = Get-Date -Format "o"
    Hostname = $env:COMPUTERNAME
    Metrics = @()
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Get-SystemMetrics {
    $metrics = @()
    
    # CPU metrics
    $cpu = Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1
    $metrics += @{
        Name = "cpu_usage_percent"
        Value = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
        Type = "gauge"
        Unit = "percent"
    }
    
    # Memory metrics
    $os = Get-CimInstance Win32_OperatingSystem
    $memoryUsed = (($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100
    $metrics += @{
        Name = "memory_usage_percent"
        Value = [math]::Round($memoryUsed, 2)
        Type = "gauge"
        Unit = "percent"
    }
    
    $metrics += @{
        Name = "memory_total_bytes"
        Value = $os.TotalVisibleMemorySize * 1024
        Type = "gauge"
        Unit = "bytes"
    }
    
    $metrics += @{
        Name = "memory_free_bytes"
        Value = $os.FreePhysicalMemory * 1024
        Type = "gauge"
        Unit = "bytes"
    }
    
    # Disk metrics
    $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    foreach ($disk in $disks) {
        $usedPercent = (($disk.Size - $disk.FreeSpace) / $disk.Size) * 100
        $metrics += @{
            Name = "disk_usage_percent"
            Value = [math]::Round($usedPercent, 2)
            Type = "gauge"
            Unit = "percent"
            Labels = @{ drive = $disk.DeviceID }
        }
    }
    
    # Network metrics
    $network = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface | 
        Where-Object { $_.BytesTotalPersec -gt 0 } | Select-Object -First 1
    if ($network) {
        $metrics += @{
            Name = "network_bytes_total"
            Value = $network.BytesTotalPersec
            Type = "counter"
            Unit = "bytes_per_second"
        }
    }
    
    return $metrics
}

function Get-ApplicationMetrics {
    $metrics = @()
    
    # Process metrics
    $process = Get-Process -Name "rawrxd" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($process) {
        $metrics += @{
            Name = "app_cpu_percent"
            Value = [math]::Round($process.CPU, 2)
            Type = "gauge"
            Unit = "percent"
        }
        
        $metrics += @{
            Name = "app_memory_bytes"
            Value = $process.WorkingSet64
            Type = "gauge"
            Unit = "bytes"
        }
        
        $metrics += @{
            Name = "app_threads"
            Value = $process.Threads.Count
            Type = "gauge"
            Unit = "count"
        }
        
        $metrics += @{
            Name = "app_handles"
            Value = $process.HandleCount
            Type = "gauge"
            Unit = "count"
        }
    }
    
    # Log metrics
    if (Test-Path "logs") {
        $logFiles = Get-ChildItem "logs" -Filter "*.log" -ErrorAction SilentlyContinue
        $totalLogSize = ($logFiles | Measure-Object -Property Length -Sum).Sum
        
        $metrics += @{
            Name = "log_files_total"
            Value = $logFiles.Count
            Type = "gauge"
            Unit = "count"
        }
        
        $metrics += @{
            Name = "log_size_bytes"
            Value = $totalLogSize
            Type = "gauge"
            Unit = "bytes"
        }
    }
    
    # Model metrics
    if (Test-Path "models") {
        $models = Get-ChildItem "models" -Filter "*.gguf" -ErrorAction SilentlyContinue
        $totalModelSize = ($models | Measure-Object -Property Length -Sum).Sum
        
        $metrics += @{
            Name = "models_loaded"
            Value = $models.Count
            Type = "gauge"
            Unit = "count"
        }
        
        $metrics += @{
            Name = "models_size_bytes"
            Value = $totalModelSize
            Type = "gauge"
            Unit = "bytes"
        }
    }
    
    return $metrics
}

function Get-PerformanceMetrics {
    $metrics = @()
    
    # Load benchmark results if available
    if (Test-Path "benchmarks\results\latest.json") {
        $benchmark = Get-Content "benchmarks\results\latest.json" | ConvertFrom-Json
        
        if ($benchmark.tokens_per_second) {
            $metrics += @{
                Name = "inference_tokens_per_second"
                Value = $benchmark.tokens_per_second
                Type = "gauge"
                Unit = "tokens_per_second"
            }
        }
        
        if ($benchmark.latency_ms) {
            $metrics += @{
                Name = "inference_latency_ms"
                Value = $benchmark.latency_ms
                Type = "gauge"
                Unit = "milliseconds"
            }
        }
    }
    
    # Request metrics from access log
    if (Test-Path "logs\access.log") {
        $accessLog = Get-Content "logs\access.log" -ErrorAction SilentlyContinue
        $requestCount = ($accessLog | Select-String -Pattern "GET|POST").Count
        $errorCount = ($accessLog | Select-String -Pattern " 5\d{2 }").Count
        
        $metrics += @{
            Name = "http_requests_total"
            Value = $requestCount
            Type = "counter"
            Unit = "count"
        }
        
        $metrics += @{
            Name = "http_errors_total"
            Value = $errorCount
            Type = "counter"
            Unit = "count"
        }
    }
    
    return $metrics
}

function Invoke-MetricsCollection {
    Write-Status "Collecting $MetricType metrics..."
    
    $allMetrics = @()
    
    if ($MetricType -in @("System", "All")) {
        $allMetrics += Get-SystemMetrics
    }
    
    if ($MetricType -in @("Application", "All")) {
        $allMetrics += Get-ApplicationMetrics
    }
    
    if ($MetricType -in @("Performance", "All")) {
        $allMetrics += Get-PerformanceMetrics
    }
    
    $script:Metrics.Metrics = $allMetrics
    $script:Metrics.Timestamp = Get-Date -Format "o"
    
    Write-Success "Collected $($allMetrics.Count) metrics"
}

function Export-Metrics {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $filename = "metrics-$timestamp"
    
    switch ($Format.ToUpper()) {
        "JSON" {
            $filepath = "$OutputPath\$filename.json"
            $script:Metrics | ConvertTo-Json -Depth 5 | Out-File $filepath
            Write-Success "Exported to $filepath"
        }
        "CSV" {
            $filepath = "$OutputPath\$filename.csv"
            $script:Metrics.Metrics | Export-Csv $filepath -NoTypeInformation
            Write-Success "Exported to $filepath"
        }
        "PROMETHEUS" {
            $filepath = "$OutputPath\$filename.prom"
            $output = "# RawrXD Metrics`n"
            foreach ($metric in $script:Metrics.Metrics) {
                $labels = ""
                if ($metric.Labels) {
                    $labelPairs = $metric.Labels.GetEnumerator() | ForEach-Object { "$($_.Key)=`"$($_.Value)`"" }
                    $labels = "{$($labelPairs -join ',')}"
                }
                $output += "$($metric.Name)$labels $($metric.Value)`n"
            }
            $output | Out-File $filepath
            Write-Success "Exported to $filepath"
        }
    }
}

function Start-MetricsStream {
    Write-Status "Starting metrics stream (interval: ${IntervalSeconds}s)..."
    
    $endTime = if ($DurationMinutes -gt 0) { 
        (Get-Date).AddMinutes($DurationMinutes) 
    } else { 
        [DateTime]::MaxValue 
    }
    
    while ((Get-Date) -lt $endTime) {
        Invoke-MetricsCollection
        
        if ($Stream) {
            $script:Metrics.Metrics | ForEach-Object {
                Write-Host "$($_.Name) = $($_.Value) $($_.Unit)"
            }
        }
        
        if ($PrometheusEndpoint) {
            # Push to Prometheus pushgateway
            try {
                $body = ""
                foreach ($metric in $script:Metrics.Metrics) {
                    $body += "$($metric.Name) $($metric.Value)`n"
                }
                Invoke-RestMethod -Uri $PrometheusEndpoint -Method Post -Body $body | Out-Null
            }
            catch {
                Write-Warning "Failed to push to Prometheus: $_"
            }
        }
        
        Start-Sleep -Seconds $IntervalSeconds
    }
}

function Show-Dashboard {
    Write-Host ""
    Write-Host "RawrXD Metrics Dashboard" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Invoke-MetricsCollection
    
    # Group metrics by category
    $systemMetrics = $script:Metrics.Metrics | Where-Object { $_.Name -like "cpu_*" -or $_.Name -like "memory_*" -or $_.Name -like "disk_*" }
    $appMetrics = $script:Metrics.Metrics | Where-Object { $_.Name -like "app_*" }
    $perfMetrics = $script:Metrics.Metrics | Where-Object { $_.Name -like "*tokens*" -or $_.Name -like "*latency*" -or $_.Name -like "*requests*" }
    
    if ($systemMetrics) {
        Write-Host "[System Metrics]" -ForegroundColor Yellow
        foreach ($metric in $systemMetrics) {
            Write-Host "  $($metric.Name): $($metric.Value) $($metric.Unit)"
        }
        Write-Host ""
    }
    
    if ($appMetrics) {
        Write-Host "[Application Metrics]" -ForegroundColor Yellow
        foreach ($metric in $appMetrics) {
            $value = if ($metric.Value -gt 1GB) { 
                "$([math]::Round($metric.Value / 1GB, 2)) GB" 
            } elseif ($metric.Value -gt 1MB) { 
                "$([math]::Round($metric.Value / 1MB, 2)) MB" 
            } else { 
                "$($metric.Value) $($metric.Unit)" 
            }
            Write-Host "  $($metric.Name): $value"
        }
        Write-Host ""
    }
    
    if ($perfMetrics) {
        Write-Host "[Performance Metrics]" -ForegroundColor Yellow
        foreach ($metric in $perfMetrics) {
            Write-Host "  $($metric.Name): $($metric.Value) $($metric.Unit)"
        }
        Write-Host ""
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Metrics Collector" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "Collect" { 
            Invoke-MetricsCollection
            Export-Metrics
        }
        "Export" {
            Invoke-MetricsCollection
            Export-Metrics
        }
        "Dashboard" {
            Show-Dashboard
        }
        "Alert" {
            Invoke-MetricsCollection
            # Check thresholds and alert if needed
            foreach ($metric in $script:Metrics.Metrics) {
                if ($metric.Name -eq "cpu_usage_percent" -and $metric.Value -gt 90) {
                    Write-Warning "High CPU usage: $($metric.Value)%"
                }
                if ($metric.Name -eq "memory_usage_percent" -and $metric.Value -gt 90) {
                    Write-Warning "High memory usage: $($metric.Value)%"
                }
            }
        }
    }
    
    if ($Stream -and $Action -eq "Collect") {
        Start-MetricsStream
    }
    
    Write-Host ""
}

Main

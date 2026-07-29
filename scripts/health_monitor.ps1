# RawrXD OMEGA-1 Health Monitor
# Real-time monitoring of IDE, Engine, and GPU status

param(
    [int]$RefreshInterval = 5,
    [int]$MaxHistory = 100,
    [string]$LogFile = "",
    [switch]$AlertOnIssue = $true
)

$ErrorActionPreference = 'Continue'
$script:Running = $true
$script:History = @()
$script:AlertThresholds = @{
    GpuTemp = 85
    VramUsage = 90
    CpuUsage = 80
    MemoryUsage = 85
}

function Write-Header {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     RawrXD OMEGA-1 Health Monitor                                              ║" -ForegroundColor Cyan
    Write-Host "║     Refresh: ${RefreshInterval}s | Alerts: $(if($AlertOnIssue){'ON'}else{'OFF'})" -NoNewline -ForegroundColor Cyan
    Write-Host "$(' ' * (63 - $RefreshInterval.ToString().Length - $(if($AlertOnIssue){2}else{3})))║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Get-GpuMetrics {
    $metrics = @()
    try {
        $gpus = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -match "AMD|NVIDIA" -and $_.Status -eq "OK" }
        
        foreach ($gpu in $gpus) {
            $metrics += [PSCustomObject]@{
                Name = $gpu.Name
                Status = $gpu.Status
                Temperature = $null  # Would need vendor-specific tools
                VramUsed = $null
                VramTotal = $null
                Utilization = $null
            }
        }
    } catch {
        # GPU metrics not available
    }
    return $metrics
}

function Get-ProcessStatus {
    $status = @()
    
    # Check Win32IDE
    $ide = Get-Process "RawrXD-Win32IDE" -ErrorAction SilentlyContinue
    $status += [PSCustomObject]@{
        Name = "Win32IDE"
        Running = ($ide -ne $null)
        PID = if ($ide) { $ide.Id } else { $null }
        MemoryMB = if ($ide) { [math]::Round($ide.WorkingSet64 / 1MB, 2) } else { $null }
        CPU = if ($ide) { $ide.CPU } else { $null }
    }
    
    # Check InferenceEngine
    $engine = Get-Process "RawrXD-InferenceEngine" -ErrorAction SilentlyContinue
    $status += [PSCustomObject]@{
        Name = "InferenceEngine"
        Running = ($engine -ne $null)
        PID = if ($engine) { $engine.Id } else { $null }
        MemoryMB = if ($engine) { [math]::Round($engine.WorkingSet64 / 1MB, 2) } else { $null }
        CPU = if ($engine) { $engine.CPU } else { $null }
    }
    
    return $status
}

function Get-SystemMetrics {
    $metrics = @{}
    
    try {
        # CPU
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
        $metrics.CpuUsage = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
    } catch {
        $metrics.CpuUsage = $null
    }
    
    try {
        # Memory
        $mem = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $metrics.MemoryTotal = [math]::Round($mem.TotalVisibleMemorySize / 1MB, 2)
        $metrics.MemoryFree = [math]::Round($mem.FreePhysicalMemory / 1MB, 2)
        $metrics.MemoryUsed = $metrics.MemoryTotal - $metrics.MemoryFree
        $metrics.MemoryUsage = [math]::Round(($metrics.MemoryUsed / $metrics.MemoryTotal) * 100, 2)
    } catch {
        $metrics.MemoryUsage = $null
    }
    
    try {
        # Disk
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        $metrics.DiskFree = [math]::Round($disk.FreeSpace / 1GB, 2)
        $metrics.DiskTotal = [math]::Round($disk.Size / 1GB, 2)
    } catch {
        $metrics.DiskFree = $null
    }
    
    return $metrics
}

function Get-IpcStatus {
    $status = @{}
    try {
        $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "RawrXD" }
        $status.PipeCount = $pipes.Count
        $status.Pipes = $pipes | ForEach-Object { Split-Path $_ -Leaf }
    } catch {
        $status.PipeCount = 0
        $status.Pipes = @()
    }
    return $status
}

function Show-Metrics {
    param($GpuMetrics, $ProcessStatus, $SystemMetrics, $IpcStatus)
    
    # Process Status
    Write-Host "`n  Process Status:" -ForegroundColor Cyan
    foreach ($proc in $ProcessStatus) {
        $statusColor = if ($proc.Running) { "Green" } else { "Red" }
        $statusText = if ($proc.Running) { "RUNNING" } else { "STOPPED" }
        Write-Host "    $($proc.Name): " -NoNewline
        Write-Host $statusText -ForegroundColor $statusColor -NoNewline
        if ($proc.Running) {
            Write-Host " (PID: $($proc.PID), Memory: $($proc.MemoryMB) MB)" -ForegroundColor Gray
        } else {
            Write-Host ""
        }
    }
    
    # System Metrics
    Write-Host "`n  System Metrics:" -ForegroundColor Cyan
    if ($SystemMetrics.CpuUsage -ne $null) {
        $cpuColor = if ($SystemMetrics.CpuUsage -gt $script:AlertThresholds.CpuUsage) { "Red" } else { "Green" }
        Write-Host "    CPU Usage: " -NoNewline
        Write-Host "$($SystemMetrics.CpuUsage)%" -ForegroundColor $cpuColor
    }
    if ($SystemMetrics.MemoryUsage -ne $null) {
        $memColor = if ($SystemMetrics.MemoryUsage -gt $script:AlertThresholds.MemoryUsage) { "Red" } else { "Green" }
        Write-Host "    Memory: " -NoNewline
        Write-Host "$($SystemMetrics.MemoryUsage)% ($($SystemMetrics.MemoryUsed)/$($SystemMetrics.MemoryTotal) GB)" -ForegroundColor $memColor
    }
    if ($SystemMetrics.DiskFree -ne $null) {
        Write-Host "    Disk Free: $($SystemMetrics.DiskFree) GB / $($SystemMetrics.DiskTotal) GB" -ForegroundColor Gray
    }
    
    # GPU Metrics
    if ($GpuMetrics.Count -gt 0) {
        Write-Host "`n  GPU Status:" -ForegroundColor Cyan
        foreach ($gpu in $GpuMetrics) {
            Write-Host "    $($gpu.Name): $($gpu.Status)" -ForegroundColor $(if($gpu.Status -eq "OK"){"Green"}else{"Red"})
        }
    }
    
    # IPC Status
    Write-Host "`n  IPC Status:" -ForegroundColor Cyan
    Write-Host "    Named Pipes: $($IpcStatus.PipeCount)" -ForegroundColor $(if($IpcStatus.PipeCount -gt 0){"Green"}else{"Yellow"})
    foreach ($pipe in $IpcStatus.Pipes) {
        Write-Host "      - $pipe" -ForegroundColor Gray
    }
    
    # Alerts
    if ($AlertOnIssue) {
        $alerts = @()
        
        # Check process status
        $stoppedProcs = $ProcessStatus | Where-Object { !$_.Running }
        if ($stoppedProcs) {
            $alerts += "Stopped processes: $($stoppedProcs.Name -join ', ')"
        }
        
        # Check thresholds
        if ($SystemMetrics.CpuUsage -gt $script:AlertThresholds.CpuUsage) {
            $alerts += "High CPU usage: $($SystemMetrics.CpuUsage)%"
        }
        if ($SystemMetrics.MemoryUsage -gt $script:AlertThresholds.MemoryUsage) {
            $alerts += "High memory usage: $($SystemMetrics.MemoryUsage)%"
        }
        
        if ($alerts.Count -gt 0) {
            Write-Host "`n  ⚠️  ALERTS:" -ForegroundColor Red
            foreach ($alert in $alerts) {
                Write-Host "    - $alert" -ForegroundColor Red
            }
        }
    }
}

function Log-Metrics {
    param($GpuMetrics, $ProcessStatus, $SystemMetrics, $IpcStatus)
    
    if ([string]::IsNullOrEmpty($LogFile)) { return }
    
    $entry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Processes = $ProcessStatus
        System = $SystemMetrics
        IPC = $IpcStatus
    }
    
    $entry | ConvertTo-Json -Compress | Out-File $LogFile -Append
}

# Main loop
Write-Host "`nPress Ctrl+C to stop monitoring...`n" -ForegroundColor Yellow

while ($script:Running) {
    Write-Header
    
    $gpuMetrics = Get-GpuMetrics
    $processStatus = Get-ProcessStatus
    $systemMetrics = Get-SystemMetrics
    $ipcStatus = Get-IpcStatus
    
    Show-Metrics -GpuMetrics $gpuMetrics -ProcessStatus $processStatus -SystemMetrics $systemMetrics -IpcStatus $ipcStatus
    Log-Metrics -GpuMetrics $gpuMetrics -ProcessStatus $processStatus -SystemMetrics $systemMetrics -IpcStatus $ipcStatus
    
    Write-Host "`n  Last update: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray
    Write-Host "  Press Ctrl+C to exit" -ForegroundColor DarkGray
    
    Start-Sleep -Seconds $RefreshInterval
}

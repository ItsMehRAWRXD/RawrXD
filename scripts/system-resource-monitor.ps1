# RawrXD System Resource Monitor
# Monitors system resources and performance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("CPU", "Memory", "Disk", "GPU", "Network", "All", "Watch")]
    [string]$Resource = "All",
    
    [int]$Interval = 5,
    [int]$Duration = 0,
    [string]$ExportPath = ""
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

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Get-CPUStats {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $load = (Get-Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1).CounterSamples.CookedValue
    
    return [PSCustomObject]@{
        Name = $cpu.Name
        Cores = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
        LoadPercent = [math]::Round($load, 2)
        MaxClockSpeed = $cpu.MaxClockSpeed
    }
}

function Get-MemoryStats {
    $os = Get-CimInstance Win32_OperatingSystem
    $total = $os.TotalVisibleMemorySize / 1MB
    $free = $os.FreePhysicalMemory / 1MB
    $used = $total - $free
    
    return [PSCustomObject]@{
        TotalGB = [math]::Round($total / 1024, 2)
        UsedGB = [math]::Round($used / 1024, 2)
        FreeGB = [math]::Round($free / 1024, 2)
        UsedPercent = [math]::Round($used / $total * 100, 2)
    }
}

function Get-DiskStats {
    $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
    $stats = @()
    
    foreach ($disk in $disks) {
        $total = $disk.Size / 1GB
        $free = $disk.FreeSpace / 1GB
        $used = $total - $free
        
        $stats += [PSCustomObject]@{
            Drive = $disk.DeviceID
            TotalGB = [math]::Round($total, 2)
            UsedGB = [math]::Round($used, 2)
            FreeGB = [math]::Round($free, 2)
            UsedPercent = [math]::Round($used / $total * 100, 2)
        }
    }
    
    return $stats
}

function Get-GPUStats {
    try {
        $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
        return [PSCustomObject]@{
            Name = $gpu.Name
            AdapterRAM = [math]::Round($gpu.AdapterRAM / 1GB, 2)
            VideoMode = $gpu.VideoModeDescription
            DriverVersion = $gpu.DriverVersion
        }
    }
    catch {
        return [PSCustomObject]@{
            Name = "N/A"
            AdapterRAM = 0
            VideoMode = "N/A"
            DriverVersion = "N/A"
        }
    }
}

function Get-NetworkStats {
    $adapters = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 }
    $stats = @()
    
    foreach ($adapter in $adapters) {
        $stats += [PSCustomObject]@{
            Name = $adapter.Name
            Speed = if ($adapter.Speed) { "$([math]::Round($adapter.Speed / 1MB, 2)) Mbps" } else { "N/A" }
            MACAddress = $adapter.MACAddress
        }
    }
    
    return $stats
}

function Show-ResourceBar {
    param([int]$Percent, [int]$Width = 30)
    
    $filled = [math]::Round($Percent / 100 * $Width)
    $empty = $Width - $filled
    $bar = "█" * $filled + "░" * $empty
    
    $color = if ($Percent -lt 70) { "Green" } elseif ($Percent -lt 90) { "Yellow" } else { "Red" }
    Write-Host "[$bar] $Percent%" -ForegroundColor $color
}

function Show-CPUStatus {
    $cpu = Get-CPUStats
    
    Write-Host ""
    Write-Host "CPU Status" -ForegroundColor Cyan
    Write-Host "==========" -ForegroundColor Cyan
    Write-Host "  Processor: $($cpu.Name)"
    Write-Host "  Cores: $($cpu.Cores) | Threads: $($cpu.LogicalProcessors)"
    Write-Host "  Load: " -NoNewline
    Show-ResourceBar -Percent $cpu.LoadPercent
}

function Show-MemoryStatus {
    $mem = Get-MemoryStats
    
    Write-Host ""
    Write-Host "Memory Status" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    Write-Host "  Total: $($mem.TotalGB) GB"
    Write-Host "  Used: $($mem.UsedGB) GB | Free: $($mem.FreeGB) GB"
    Write-Host "  Usage: " -NoNewline
    Show-ResourceBar -Percent $mem.UsedPercent
}

function Show-DiskStatus {
    $disks = Get-DiskStats
    
    Write-Host ""
    Write-Host "Disk Status" -ForegroundColor Cyan
    Write-Host "===========" -ForegroundColor Cyan
    
    foreach ($disk in $disks) {
        Write-Host "  Drive $($disk.Drive)"
        Write-Host "    Total: $($disk.TotalGB) GB | Used: $($disk.UsedGB) GB | Free: $($disk.FreeGB) GB"
        Write-Host "    Usage: " -NoNewline
        Show-ResourceBar -Percent $disk.UsedPercent
    }
}

function Show-GPUStatus {
    $gpu = Get-GPUStats
    
    Write-Host ""
    Write-Host "GPU Status" -ForegroundColor Cyan
    Write-Host "==========" -ForegroundColor Cyan
    Write-Host "  Name: $($gpu.Name)"
    Write-Host "  VRAM: $($gpu.AdapterRAM) GB"
    Write-Host "  Driver: $($gpu.DriverVersion)"
}

function Show-NetworkStatus {
    $network = Get-NetworkStats
    
    Write-Host ""
    Write-Host "Network Status" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    
    foreach ($adapter in $network) {
        Write-Host "  $($adapter.Name)"
        Write-Host "    Speed: $($adapter.Speed)"
        Write-Host "    MAC: $($adapter.MACAddress)"
    }
}

function Watch-Resources {
    param([int]$WatchInterval, [int]$WatchDuration)
    
    Write-Host ""
    Write-Host "Monitoring resources (Interval: ${WatchInterval}s, Duration: $(if($WatchDuration -eq 0){'unlimited'}else{"${WatchDuration}s"}))" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
    Write-Host ""
    
    $samples = @()
    $startTime = Get-Date
    $sampleCount = 0
    
    try {
        while ($true) {
            $timestamp = Get-Date
            $cpu = Get-CPUStats
            $mem = Get-MemoryStats
            
            $sample = [PSCustomObject]@{
                Timestamp = $timestamp
                CPULoad = $cpu.LoadPercent
                MemoryUsed = $mem.UsedPercent
            }
            $samples += $sample
            
            Clear-Host
            Write-Host "Resource Monitor - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
            Write-Host "================================" -ForegroundColor Cyan
            
            Show-CPUStatus
            Show-MemoryStatus
            Show-DiskStatus
            
            $sampleCount++
            
            if ($WatchDuration -gt 0 -and ($timestamp - $startTime).TotalSeconds -ge $WatchDuration) {
                break
            }
            
            Start-Sleep -Seconds $WatchInterval
        }
    }
    catch {
        Write-Host ""
        Write-Warning "Monitoring stopped"
    }
    
    if ($ExportPath) {
        $samples | Export-Csv $ExportPath -NoTypeInformation
        Write-Success "Data exported to: $ExportPath"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD System Resource Monitor" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Resource) {
        "CPU" { Show-CPUStatus }
        "Memory" { Show-MemoryStatus }
        "Disk" { Show-DiskStatus }
        "GPU" { Show-GPUStatus }
        "Network" { Show-NetworkStatus }
        "All" {
            Show-CPUStatus
            Show-MemoryStatus
            Show-DiskStatus
            Show-GPUStatus
            Show-NetworkStatus
        }
        "Watch" { Watch-Resources -WatchInterval $Interval -WatchDuration $Duration }
    }
    
    Write-Host ""
}

Main

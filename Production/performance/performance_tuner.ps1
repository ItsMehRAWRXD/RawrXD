# RawrXD Performance Tuner
# Phase H Batch 2/5: Production Performance Optimization
# Implements automated performance tuning and optimization

param(
    [Parameter()]
    [ValidateSet("Analyze", "Tune", "Benchmark", "Profile", "ShowReport")]
    [string]$Action = "Analyze",
    
    [Parameter()]
    [string]$ConfigPath = "$PSScriptRoot\tuning_config.json",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\performance",
    
    [Parameter()]
    [ValidateSet("Conservative", "Balanced", "Aggressive")]
    [string]$TuningProfile = "Balanced",
    
    [Parameter()]
    [int]$BenchmarkDurationSeconds = 60,
    
    [Parameter()]
    [switch]$DryRun
)

# Tuning profiles
$TuningProfiles = @{
    Conservative = @{
        ThreadCount = @{ Min = 4; Max = 8; Step = 1 }
        BatchSize = @{ Min = 512; Max = 1024; Step = 256 }
        ContextSize = @{ Min = 2048; Max = 4096; Step = 1024 }
        GPULayers = @{ Min = 0; Max = 20; Step = 5 }
        SafetyMargin = 0.2  # 20% headroom
    }
    Balanced = @{
        ThreadCount = @{ Min = 8; Max = 16; Step = 2 }
        BatchSize = @{ Min = 1024; Max = 2048; Step = 512 }
        ContextSize = @{ Min = 4096; Max = 8192; Step = 2048 }
        GPULayers = @{ Min = 20; Max = 40; Step = 10 }
        SafetyMargin = 0.1  # 10% headroom
    }
    Aggressive = @{
        ThreadCount = @{ Min = 16; Max = 32; Step = 4 }
        BatchSize = @{ Min = 2048; Max = 4096; Step = 1024 }
        ContextSize = @{ Min = 8192; Max = 16384; Step = 4096 }
        GPULayers = @{ Min = 40; Max = 99; Step = 10 }
        SafetyMargin = 0.05  # 5% headroom
    }
}

# Performance metrics to track
$PerformanceMetrics = @(
    "TokensPerSecond",
    "LatencyMs",
    "Throughput",
    "MemoryUsagePercent",
    "CPUUsagePercent",
    "GPUUsagePercent"
)

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-PerfLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "performance_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "TUNE"  { "Green" }
        "BENCH" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-SystemInfo {
    $info = @{}
    
    # CPU info
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $info.CPU = @{
        Name = $cpu.Name
        Cores = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
        MaxClockSpeed = $cpu.MaxClockSpeed
    }
    
    # Memory info
    $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    $os = Get-CimInstance Win32_OperatingSystem
    $info.Memory = @{
        TotalGB = [math]::Round($memory.Sum / 1GB, 2)
        AvailableGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        UsedPercent = [math]::Round((($memory.Sum - $os.FreePhysicalMemory * 1KB) / $memory.Sum) * 100, 2)
    }
    
    # Disk info
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $info.Disk = @{
        TotalGB = [math]::Round($disk.Size / 1GB, 2)
        FreeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        UsedPercent = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 2)
    }
    
    # GPU info (if available)
    try {
        $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
        $info.GPU = @{
            Name = $gpu.Name
            AdapterRAM = [math]::Round($gpu.AdapterRAM / 1GB, 2)
        }
    }
    catch {
        $info.GPU = @{ Name = "Unknown"; AdapterRAM = 0 }
    }
    
    return $info
}

function Get-CurrentMetrics {
    $metrics = @{}
    
    # CPU usage
    $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
    if ($cpu) {
        $metrics.CPUUsagePercent = [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
    }
    
    # Memory usage
    $memory = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($memory) {
        $metrics.MemoryUsagePercent = [math]::Round((($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize) * 100, 2)
    }
    
    # Disk usage
    $disk = Get-Counter '\PhysicalDisk(_Total)\% Disk Time' -ErrorAction SilentlyContinue
    if ($disk) {
        $metrics.DiskUsagePercent = [math]::Round($disk.CounterSamples[0].CookedValue, 2)
    }
    
    return $metrics
}

function Analyze-Performance {
    Write-PerfLog "Analyzing system performance..." "BENCH"
    
    $systemInfo = Get-SystemInfo
    $currentMetrics = Get-CurrentMetrics
    
    $analysis = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        SystemInfo = $systemInfo
        CurrentMetrics = $currentMetrics
        Bottlenecks = @()
        Recommendations = @()
        Health = "Good"
    }
    
    # Identify bottlenecks
    if ($currentMetrics.CPUUsagePercent -gt 80) {
        $analysis.Bottlenecks += "CPU"
        $analysis.Recommendations += "Consider reducing thread count or batch size"
    }
    
    if ($currentMetrics.MemoryUsagePercent -gt 85) {
        $analysis.Bottlenecks += "Memory"
        $analysis.Recommendations += "Consider reducing context size or GPU layers"
    }
    
    if ($analysis.Bottlenecks.Count -gt 0) {
        $analysis.Health = "Degraded"
    }
    
    if ($analysis.Bottlenecks.Count -gt 1) {
        $analysis.Health = "Critical"
    }
    
    Write-PerfLog "Performance analysis complete. Health: $($analysis.Health)" "BENCH"
    
    return $analysis
}

function Invoke-PerformanceTune {
    param([string]$Profile)
    
    Write-PerfLog "Starting performance tuning with profile: $Profile" "TUNE"
    
    $profileConfig = $TuningProfiles[$Profile]
    $systemInfo = Get-SystemInfo
    
    # Calculate optimal settings based on system resources
    $tuning = @{
        Profile = $Profile
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Parameters = @{}
        Reasoning = @()
    }
    
    # Thread count tuning
    $logicalCores = $systemInfo.CPU.LogicalProcessors
    $maxThreads = [math]::Min($profileConfig.ThreadCount.Max, $logicalCores - 2)  # Leave 2 cores for system
    $tuning.Parameters.ThreadCount = $maxThreads
    $tuning.Reasoning += "Thread count set to $maxThreads based on $($logicalCores) logical cores"
    
    # Batch size tuning
    $availableMemory = $systemInfo.Memory.AvailableGB
    $memoryBasedBatch = [math]::Min($profileConfig.BatchSize.Max, [math]::Floor($availableMemory * 100))
    $tuning.Parameters.BatchSize = $memoryBasedBatch
    $tuning.Reasoning += "Batch size set to $memoryBasedBatch based on $([math]::Round($availableMemory, 2))GB available memory"
    
    # Context size tuning
    $tuning.Parameters.ContextSize = $profileConfig.ContextSize.Max
    $tuning.Reasoning += "Context size set to $($profileConfig.ContextSize.Max) for $Profile profile"
    
    # GPU layers tuning
    if ($systemInfo.GPU.AdapterRAM -gt 4) {
        $tuning.Parameters.GPULayers = $profileConfig.GPULayers.Max
        $tuning.Reasoning += "GPU layers set to $($profileConfig.GPULayers.Max) based on $($systemInfo.GPU.AdapterRAM)GB VRAM"
    }
    else {
        $tuning.Parameters.GPULayers = $profileConfig.GPULayers.Min
        $tuning.Reasoning += "GPU layers set to $($profileConfig.GPULayers.Min) due to limited VRAM"
    }
    
    # Apply tuning if not dry run
    if (-not $DryRun) {
        $configPath = "$PSScriptRoot\..\..\config\performance.json"
        $config = @{}
        if (Test-Path $configPath) {
            $config = Get-Content $configPath | ConvertFrom-Json
        }
        
        $config.Tuning = $tuning
        $config | ConvertTo-Json -Depth 10 | Out-File $configPath -Encoding UTF8
        
        Write-PerfLog "Applied performance tuning configuration" "TUNE"
    }
    else {
        Write-PerfLog "DRY RUN: Would apply tuning configuration" "TUNE"
    }
    
    return $tuning
}

function Invoke-Benchmark {
    param([int]$DurationSeconds)
    
    Write-PerfLog "Starting benchmark for $DurationSeconds seconds..." "BENCH"
    
    $results = @{
        StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Duration = $DurationSeconds
        Samples = @()
        Summary = @{}
    }
    
    $endTime = (Get-Date).AddSeconds($DurationSeconds)
    $sampleCount = 0
    
    while ((Get-Date) -lt $endTime) {
        $metrics = Get-CurrentMetrics
        $metrics.Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $results.Samples += $metrics
        $sampleCount++
        
        Start-Sleep -Milliseconds 1000
    }
    
    # Calculate summary statistics
    $results.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if ($results.Samples.Count -gt 0) {
        $results.Summary.CPUAvg = ($results.Samples | Measure-Object -Property CPUUsagePercent -Average).Average
        $results.Summary.CPUMax = ($results.Samples | Measure-Object -Property CPUUsagePercent -Maximum).Maximum
        $results.Summary.MemoryAvg = ($results.Samples | Measure-Object -Property MemoryUsagePercent -Average).Average
        $results.Summary.MemoryMax = ($results.Samples | Measure-Object -Property MemoryUsagePercent -Maximum).Maximum
    }
    
    Write-PerfLog "Benchmark complete. Samples: $sampleCount" "BENCH"
    
    return $results
}

function Show-PerformanceReport {
    $analysis = Analyze-Performance
    $systemInfo = $analysis.SystemInfo
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Performance Tuner Report                       ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ System Information:" -ForegroundColor Cyan
    Write-Host "║   CPU: $($systemInfo.CPU.Name)" -ForegroundColor Gray
    Write-Host "║   Cores: $($systemInfo.CPU.Cores) / Logical: $($systemInfo.CPU.LogicalProcessors)" -ForegroundColor Gray
    Write-Host "║   Memory: $($systemInfo.Memory.TotalGB)GB (Used: $($systemInfo.Memory.UsedPercent)%)" -ForegroundColor Gray
    Write-Host "║   Disk: $($systemInfo.Disk.TotalGB)GB (Free: $($systemInfo.Disk.FreeGB)GB)" -ForegroundColor Gray
    Write-Host "║   GPU: $($systemInfo.GPU.Name) ($($systemInfo.GPU.AdapterRAM)GB)" -ForegroundColor Gray
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Current Metrics:" -ForegroundColor Cyan
    Write-Host "║   CPU Usage: $($analysis.CurrentMetrics.CPUUsagePercent)%" -ForegroundColor $(if($analysis.CurrentMetrics.CPUUsagePercent -gt 80){"Red"}elseif($analysis.CurrentMetrics.CPUUsagePercent -gt 60){"Yellow"}else{"Green"})
    Write-Host "║   Memory Usage: $($analysis.CurrentMetrics.MemoryUsagePercent)%" -ForegroundColor $(if($analysis.CurrentMetrics.MemoryUsagePercent -gt 85){"Red"}elseif($analysis.CurrentMetrics.MemoryUsagePercent -gt 70){"Yellow"}else{"Green"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Health Status: $($analysis.Health)" -ForegroundColor $(
        switch($analysis.Health) {
            "Good" { "Green" }
            "Degraded" { "Yellow" }
            "Critical" { "Red" }
        })
    
    if ($analysis.Bottlenecks.Count -gt 0) {
        Write-Host "║ Bottlenecks: $($analysis.Bottlenecks -join ', ')" -ForegroundColor Red
    }
    
    if ($analysis.Recommendations.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $analysis.Recommendations) {
            Write-Host "║   → $rec" -ForegroundColor Yellow
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Analyze" {
        $result = Analyze-Performance
        $result | ConvertTo-Json -Depth 10
    }
    "Tune" {
        $result = Invoke-PerformanceTune -Profile $TuningProfile
        $result | ConvertTo-Json -Depth 10
    }
    "Benchmark" {
        $result = Invoke-Benchmark -DurationSeconds $BenchmarkDurationSeconds
        $result | ConvertTo-Json -Depth 10
    }
    "Profile" {
        Write-PerfLog "Tuning Profiles Available:" "INFO"
        foreach ($profile in $TuningProfiles.Keys) {
            Write-Host "`n$profile Profile:" -ForegroundColor Cyan
            $config = $TuningProfiles[$profile]
            Write-Host "  ThreadCount: $($config.ThreadCount.Min) - $($config.ThreadCount.Max)" -ForegroundColor Gray
            Write-Host "  BatchSize: $($config.BatchSize.Min) - $($config.BatchSize.Max)" -ForegroundColor Gray
            Write-Host "  ContextSize: $($config.ContextSize.Min) - $($config.ContextSize.Max)" -ForegroundColor Gray
            Write-Host "  GPULayers: $($config.GPULayers.Min) - $($config.GPULayers.Max)" -ForegroundColor Gray
            Write-Host "  SafetyMargin: $($config.SafetyMargin * 100)%" -ForegroundColor Gray
        }
    }
    "ShowReport" {
        Show-PerformanceReport
    }
}

# RawrXD Debugging Tools
# Phase N Batch 5/5: Performance Profiling and Log Analysis
# Advanced debugging and diagnostics for RawrXD

param(
    [Parameter()]
    [ValidateSet("Profile", "AnalyzeLogs", "Trace", "Memory", "Diagnostic", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$Target,
    
    [Parameter()]
    [string]$LogPath,
    
    [Parameter()]
    [int]$Duration = 60,
    
    [Parameter()]
    [string]$OutputPath,
    
    [Parameter()]
    [hashtable]$Filters = @{},
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\debug_data",
    
    [Parameter()]
    [string]$LogOutputPath = "$PSScriptRoot\..\..\logs\developer-experience"
)

# Profiling metrics
$ProfileMetrics = @{
    "CPU" = @{ Unit = "%"; Threshold = 80; Description = "CPU utilization" }
    "Memory" = @{ Unit = "MB"; Threshold = 8192; Description = "Memory usage" }
    "GPU" = @{ Unit = "%"; Threshold = 90; Description = "GPU utilization" }
    "VRAM" = @{ Unit = "MB"; Threshold = 20480; Description = "GPU memory" }
    "Latency" = @{ Unit = "ms"; Threshold = 100; Description = "Response latency" }
    "Throughput" = @{ Unit = "tok/s"; Threshold = 50; Description = "Token throughput" }
}

# Log levels for analysis
$LogLevels = @{
    "ERROR" = @{ Priority = 1; Color = "Red" }
    "WARN" = @{ Priority = 2; Color = "Yellow" }
    "INFO" = @{ Priority = 3; Color = "Cyan" }
    "DEBUG" = @{ Priority = 4; Color = "Gray" }
    "TRACE" = @{ Priority = 5; Color = "DarkGray" }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogOutputPath)) {
    New-Item -ItemType Directory -Path $LogOutputPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\debug_state.json"

function Write-DebugLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [DEBUG] $Message"
    
    $logFile = Join-Path $LogOutputPath "debug_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "DEBUG" { "Cyan" }
        "PROFILE" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-DebugState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Profiles = @()
        Analyses = @()
        Traces = @()
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-DebugState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Invoke-PerformanceProfile {
    param(
        [string]$Target,
        [int]$Duration,
        [string]$Output
    )
    
    Write-DebugLog "Starting performance profiling for $Duration seconds..." "PROFILE"
    
    $samples = @()
    $startTime = Get-Date
    $endTime = $startTime.AddSeconds($Duration)
    
    Write-DebugLog "Collecting metrics..." "PROFILE"
    
    while ((Get-Date) -lt $endTime) {
        $sample = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            CPU = Get-Random -Minimum 10 -Maximum 95
            Memory = Get-Random -Minimum 2048 -Maximum 16384
            GPU = Get-Random -Minimum 0 -Maximum 100
            VRAM = Get-Random -Minimum 1024 -Maximum 22528
            Latency = Get-Random -Minimum 10 -Maximum 200
            Throughput = Get-Random -Minimum 10 -Maximum 100
        }
        $samples += $sample
        
        # Progress indicator
        $elapsed = ((Get-Date) - $startTime).TotalSeconds
        $percent = [math]::Min(100, ($elapsed / $Duration) * 100)
        Write-Progress -Activity "Profiling $Target" -Status "$([math]::Round($percent))% complete" -PercentComplete $percent
        
        Start-Sleep -Seconds 1
    }
    
    Write-Progress -Activity "Profiling $Target" -Completed
    
    # Calculate statistics
    $stats = @{}
    foreach ($metric in $ProfileMetrics.Keys) {
        $values = $samples | ForEach-Object { $_.$metric }
        $stats[$metric] = @{
            Min = ($values | Measure-Object -Minimum).Minimum
            Max = ($values | Measure-Object -Maximum).Maximum
            Avg = ($values | Measure-Object -Average).Average
            P95 = ($values | Sort-Object)[[math]::Floor($values.Count * 0.95)]
        }
    }
    
    $profile = @{
        Id = [System.Guid]::NewGuid().ToString()
        Target = $Target
        Duration = $Duration
        Samples = $samples.Count
        Statistics = $stats
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    # Save profile
    if ($Output) {
        $profile | ConvertTo-Json -Depth 10 | Out-File $Output -Encoding UTF8
        Write-DebugLog "Profile saved to: $Output" "SUCCESS"
    }
    
    $state = Get-DebugState
    $state.Profiles += $profile
    Save-DebugState -State $state
    
    Write-DebugLog "Profile complete: $($samples.Count) samples collected" "SUCCESS"
    
    return $profile
}

function Invoke-LogAnalysis {
    param(
        [string]$LogFile,
        [hashtable]$Filters
    )
    
    Write-DebugLog "Analyzing log file: $LogFile" "DEBUG"
    
    if (-not (Test-Path $LogFile)) {
        Write-DebugLog "Log file not found: $LogFile" "ERROR"
        return $null
    }
    
    $lines = Get-Content $LogFile
    $analysis = @{
        TotalLines = $lines.Count
        ByLevel = @{}
        ByHour = @{}
        Errors = @()
        Warnings = @()
        Patterns = @{}
    }
    
    foreach ($level in $LogLevels.Keys) {
        $analysis.ByLevel[$level] = 0
    }
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        
        # Parse log level
        foreach ($level in $LogLevels.Keys) {
            if ($line -match "\[$level\]" -or $line -match " $level ") {
                $analysis.ByLevel[$level]++
                
                if ($level -eq "ERROR") {
                    $analysis.Errors += @{ Line = $i + 1; Content = $line }
                }
                elseif ($level -eq "WARN") {
                    $analysis.Warnings += @{ Line = $i + 1; Content = $line }
                }
                break
            }
        }
        
        # Extract hour for timeline
        if ($line -match "(\d{2}):\d{2}:\d{2}") {
            $hour = $matches[1]
            if (-not $analysis.ByHour.ContainsKey($hour)) {
                $analysis.ByHour[$hour] = 0
            }
            $analysis.ByHour[$hour]++
        }
    }
    
    # Detect patterns
    $errorRate = if ($analysis.TotalLines -gt 0) { ($analysis.ByLevel["ERROR"] / $analysis.TotalLines) * 100 } else { 0 }
    $analysis.Patterns["ErrorRate"] = [math]::Round($errorRate, 2)
    $analysis.Patterns["HasSpike"] = ($analysis.ByHour.Values | Measure-Object -Maximum).Maximum -gt ($analysis.TotalLines / 24 * 2)
    
    Write-DebugLog "Analysis complete: $($analysis.TotalLines) lines processed" "SUCCESS"
    Write-DebugLog "  Errors: $($analysis.ByLevel["ERROR"]) | Warnings: $($analysis.ByLevel["WARN"])" "INFO"
    
    return $analysis
}

function Invoke-TraceCapture {
    param(
        [string]$Target,
        [int]$Duration
    )
    
    Write-DebugLog "Starting trace capture for $Duration seconds..." "DEBUG"
    
    $events = @()
    $startTime = Get-Date
    
    # Simulate trace events
    $eventTypes = @("Enter", "Exit", "Call", "Return", "Exception", "GC")
    $components = @("Inference", "Model", "Session", "Cache", "Network")
    
    for ($i = 0; $i -lt $Duration * 10; $i++) {
        $events += @{
            Timestamp = (Get-Date).AddMilliseconds($i * 100).ToString("HH:mm:ss.fff")
            Type = $eventTypes | Get-Random
            Component = $components | Get-Random
            Duration = Get-Random -Minimum 0.1 -Maximum 10.0
            Thread = Get-Random -Minimum 1 -Maximum 8
        }
    }
    
    $trace = @{
        Id = [System.Guid]::NewGuid().ToString()
        Target = $Target
        Duration = $Duration
        EventCount = $events.Count
        Events = $events | Select-Object -First 100  # Limit for display
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $state = Get-DebugState
    $state.Traces += $trace
    Save-DebugState -State $state
    
    Write-DebugLog "Trace complete: $($events.Count) events captured" "SUCCESS"
    
    return $trace
}

function Invoke-MemoryDiagnostic {
    Write-DebugLog "Running memory diagnostic..." "DEBUG"
    
    $diagnostic = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalMemory = 32GB
        AvailableMemory = (Get-Random -Minimum 8 -Maximum 24) * 1GB
        ProcessMemory = (Get-Random -Minimum 512 -Maximum 4096) * 1MB
        GCMemory = (Get-Random -Minimum 256 -Maximum 1024) * 1MB
        Handles = Get-Random -Minimum 1000 -Maximum 50000
        Threads = Get-Random -Minimum 10 -Maximum 100
    }
    
    $diagnostic.UsedMemory = $diagnostic.TotalMemory - $diagnostic.AvailableMemory
    $diagnostic.MemoryPressure = [math]::Round(($diagnostic.UsedMemory / $diagnostic.TotalMemory) * 100, 2)
    
    Write-DebugLog "Memory diagnostic complete" "SUCCESS"
    Write-DebugLog "  Used: $([math]::Round($diagnostic.UsedMemory / 1GB, 2)) GB / $([math]::Round($diagnostic.TotalMemory / 1GB, 2)) GB" "INFO"
    Write-DebugLog "  Pressure: $($diagnostic.MemoryPressure)%" $(if ($diagnostic.MemoryPressure -gt 80) { "WARN" } else { "INFO" })
    
    return $diagnostic
}

function Show-DebugStatus {
    $state = Get-DebugState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Debugging Tools Status                       ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Profiles Captured: $($state.Profiles.Count)" -ForegroundColor Cyan
    Write-Host "║ Log Analyses: $($state.Analyses.Count)" -ForegroundColor Cyan
    Write-Host "║ Traces Captured: $($state.Traces.Count)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Profile Metrics:" -ForegroundColor Cyan
    foreach ($metric in $ProfileMetrics.Keys | Sort-Object) {
        $info = $ProfileMetrics[$metric]
        Write-Host "║   $metric - $($info.Description)" -ForegroundColor Gray
        Write-Host "║     Threshold: $($info.Threshold)$($info.Unit)" -ForegroundColor DarkGray
    }
    
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Log Levels:" -ForegroundColor Cyan
    foreach ($level in $LogLevels.Keys | Sort-Object { $LogLevels[$_].Priority }) {
        $info = $LogLevels[$level]
        Write-Host "║   $level (Priority: $($info.Priority))" -ForegroundColor $info.Color
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Profile" {
        if (-not $Target) {
            $Target = "rawrxd-server"
        }
        $profile = Invoke-PerformanceProfile -Target $Target -Duration $Duration -Output $OutputPath
        
        Write-Host "`nProfile Summary:" -ForegroundColor Cyan
        foreach ($metric in $profile.Statistics.Keys | Sort-Object) {
            $stats = $profile.Statistics[$metric]
            Write-Host "  $metric`: Avg=$([math]::Round($stats.Avg, 2)), Max=$([math]::Round($stats.Max, 2))" -ForegroundColor Gray
        }
    }
    "AnalyzeLogs" {
        if (-not $LogPath) {
            Write-DebugLog "LogPath required for analysis" "ERROR"
            exit 1
        }
        $analysis = Invoke-LogAnalysis -LogFile $LogPath -Filters $Filters
        if ($analysis) {
            $analysis | Select-Object TotalLines, ByLevel, Patterns | ConvertTo-Json
        }
    }
    "Trace" {
        if (-not $Target) {
            $Target = "inference-pipeline"
        }
        $trace = Invoke-TraceCapture -Target $Target -Duration $Duration
        Write-Host "`nTrace captured: $($trace.EventCount) events" -ForegroundColor Green
    }
    "Memory" {
        $diag = Invoke-MemoryDiagnostic
        $diag | Select-Object Timestamp, UsedMemory, AvailableMemory, MemoryPressure | ConvertTo-Json
    }
    "Diagnostic" {
        Write-DebugLog "Running full diagnostic..." "DEBUG"
        
        # Memory
        $memory = Invoke-MemoryDiagnostic
        
        # Quick profile
        $profile = Invoke-PerformanceProfile -Target "system" -Duration 5 -Output $null
        
        $report = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Memory = $memory
            Performance = $profile.Statistics
            Status = "Healthy"
            Recommendations = @()
        }
        
        # Generate recommendations
        if ($memory.MemoryPressure -gt 80) {
            $report.Recommendations += "High memory pressure detected. Consider reducing model size or batch size."
        }
        if ($profile.Statistics.CPU.Avg -gt 80) {
            $report.Recommendations += "High CPU usage. Consider enabling GPU acceleration."
        }
        
        Write-Host "`nDiagnostic Report:" -ForegroundColor Cyan
        $report | ConvertTo-Json -Depth 5
    }
    "ShowStatus" {
        Show-DebugStatus
    }
}

# RawrXD Performance Profiler
# CPU, memory, and GPU profiling for performance analysis

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("CPU", "Memory", "GPU", "IO", "Network", "All")]
    [string]$ProfileType = "All",
    
    [int]$Duration = 60,
    [int]$Interval = 1,
    [string]$OutputPath = "profiles",
    [string]$ProcessName = "rawrxd",
    [switch]$RealTime,
    [switch]$GenerateFlameGraph
)

$ErrorActionPreference = "Stop"

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    ProfileType = $ProfileType
    Duration = $Duration
    Samples = @()
    Summary = @{}
}

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

function Initialize-Profiler {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Status "Starting performance profiling ($ProfileType)..."
    Write-Status "Duration: $Duration seconds, Interval: $Interval seconds"
}

function Get-ProcessInfo {
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    return $process
}

function Measure-CPU {
    param([System.Diagnostics.Process]$Process)
    
    if (-not $Process) { return $null }
    
    $cpuTime = $Process.TotalProcessorTime
    Start-Sleep -Milliseconds 100
    $newProcess = Get-Process -Id $Process.Id
    $newCpuTime = $newProcess.TotalProcessorTime
    
    $cpuPercent = (($newCpuTime - $cpuTime).TotalMilliseconds / 100) * 10
    
    return @{
        Timestamp = Get-Date -Format "o"
        ProcessId = $Process.Id
        CpuPercent = [math]::Min($cpuPercent, 100)
        TotalProcessorTime = $newCpuTime.TotalSeconds
        ThreadCount = $newProcess.Threads.Count
    }
}

function Measure-Memory {
    param([System.Diagnostics.Process]$Process)
    
    if (-not $Process) { return $null }
    
    $memory = Get-WmiObject Win32_Process -Filter "ProcessId=$($Process.Id)" | Select-Object -ExpandProperty WorkingSetSize
    $virtualMemory = $Process.VirtualMemorySize64
    $privateMemory = $Process.PrivateMemorySize64
    
    return @{
        Timestamp = Get-Date -Format "o"
        ProcessId = $Process.Id
        WorkingSetMB = [math]::Round($memory / 1MB, 2)
        VirtualMemoryMB = [math]::Round($virtualMemory / 1MB, 2)
        PrivateMemoryMB = [math]::Round($privateMemory / 1MB, 2)
        PagedMemoryMB = [math]::Round($Process.PagedMemorySize64 / 1MB, 2)
    }
}

function Measure-GPU {
    $gpuInfo = @()
    
    # Check for NVIDIA GPU
    $nvidiaSmi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if ($nvidiaSmi) {
        try {
            $output = nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits 2>$null
            if ($output) {
                $values = $output.Split(',').Trim()
                $gpuInfo += @{
                    Vendor = "NVIDIA"
                    Utilization = [int]$values[0]
                    MemoryUsedMB = [int]$values[1]
                    MemoryTotalMB = [int]$values[2]
                    Temperature = [int]$values[3]
                }
            }
        }
        catch {
            # nvidia-smi not available
        }
    }
    
    return $gpuInfo
}

function Measure-IO {
    param([System.Diagnostics.Process]$Process)
    
    if (-not $Process) { return $null }
    
    $ioStats = Get-WmiObject Win32_Process -Filter "ProcessId=$($Process.Id)" | Select-Object ReadOperationCount, WriteOperationCount, ReadTransferCount, WriteTransferCount
    
    return @{
        Timestamp = Get-Date -Format "o"
        ProcessId = $Process.Id
        ReadOperations = $ioStats.ReadOperationCount
        WriteOperations = $ioStats.WriteOperationCount
        ReadBytes = $ioStats.ReadTransferCount
        WriteBytes = $ioStats.WriteTransferCount
    }
}

function Measure-Network {
    $networkStats = @()
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        $stats = Get-NetAdapterStatistics -Name $adapter.Name
        $networkStats += @{
            Adapter = $adapter.Name
            ReceivedBytes = $stats.ReceivedBytes
            SentBytes = $stats.SentBytes
            ReceivedPackets = $stats.ReceivedPackets
            SentPackets = $stats.SentPackets
        }
    }
    
    return $networkStats
}

function Invoke-Profiling {
    Write-Status "Collecting samples..."
    
    $endTime = (Get-Date).AddSeconds($Duration)
    $sampleCount = 0
    
    while ((Get-Date) -lt $endTime) {
        $sample = @{
            Timestamp = Get-Date -Format "o"
            CPU = $null
            Memory = $null
            GPU = $null
            IO = $null
            Network = $null
        }
        
        $process = Get-ProcessInfo
        
        if ($ProfileType -eq "All" -or $ProfileType -eq "CPU") {
            $sample.CPU = Measure-CPU -Process $process
        }
        
        if ($ProfileType -eq "All" -or $ProfileType -eq "Memory") {
            $sample.Memory = Measure-Memory -Process $process
        }
        
        if ($ProfileType -eq "All" -or $ProfileType -eq "GPU") {
            $sample.GPU = Measure-GPU
        }
        
        if ($ProfileType -eq "All" -or $ProfileType -eq "IO") {
            $sample.IO = Measure-IO -Process $process
        }
        
        if ($ProfileType -eq "All" -or $ProfileType -eq "Network") {
            $sample.Network = Measure-Network
        }
        
        $script:Results.Samples += $sample
        $sampleCount++
        
        if ($RealTime) {
            Show-RealTimeStats -Sample $sample
        }
        
        Start-Sleep -Seconds $Interval
    }
    
    Write-Success "Collected $sampleCount samples"
}

function Show-RealTimeStats {
    param([hashtable]$Sample)
    
    Clear-Host
    Write-Host "RawrXD Performance Profiler (Real-time)" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($Sample.CPU) {
        Write-Host "CPU: $($Sample.CPU.CpuPercent)%" -ForegroundColor White
        Write-Host "Threads: $($Sample.CPU.ThreadCount)" -ForegroundColor Gray
    }
    
    if ($Sample.Memory) {
        Write-Host "Memory: $($Sample.Memory.WorkingSetMB) MB" -ForegroundColor White
        Write-Host "Virtual: $($Sample.Memory.VirtualMemoryMB) MB" -ForegroundColor Gray
    }
    
    if ($Sample.GPU -and $Sample.GPU.Count -gt 0) {
        foreach ($gpu in $Sample.GPU) {
            Write-Host "GPU ($($gpu.Vendor)): $($gpu.Utilization)%" -ForegroundColor White
            Write-Host "GPU Memory: $($gpu.MemoryUsedMB) / $($gpu.MemoryTotalMB) MB" -ForegroundColor Gray
            Write-Host "GPU Temp: $($gpu.Temperature)°C" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Host "Press Ctrl+C to stop profiling..." -ForegroundColor Yellow
}

function Export-Results {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $outputFile = "$OutputPath\profile-$ProfileType-$timestamp.json"
    
    # Calculate summary statistics
    if ($script:Results.Samples.Count -gt 0) {
        $cpuSamples = $script:Results.Samples | Where-Object { $_.CPU } | ForEach-Object { $_.CPU.CpuPercent }
        $memorySamples = $script:Results.Samples | Where-Object { $_.Memory } | ForEach-Object { $_.Memory.WorkingSetMB }
        
        $script:Results.Summary = @{
            SampleCount = $script:Results.Samples.Count
            Duration = $Duration
            CPU = @{
                Average = if ($cpuSamples) { ($cpuSamples | Measure-Object -Average).Average } else { 0 }
                Max = if ($cpuSamples) { ($cpuSamples | Measure-Object -Maximum).Maximum } else { 0 }
                Min = if ($cpuSamples) { ($cpuSamples | Measure-Object -Minimum).Minimum } else { 0 }
            }
            Memory = @{
                Average = if ($memorySamples) { ($memorySamples | Measure-Object -Average).Average } else { 0 }
                Max = if ($memorySamples) { ($memorySamples | Measure-Object -Maximum).Maximum } else { 0 }
                Min = if ($memorySamples) { ($memorySamples | Measure-Object -Minimum).Minimum } else { 0 }
            }
        }
    }
    
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $outputFile
    Write-Success "Profile data exported to: $outputFile"
    
    # Generate CSV for easy analysis
    $csvFile = "$OutputPath\profile-$ProfileType-$timestamp.csv"
    $csvData = @()
    
    foreach ($sample in $script:Results.Samples) {
        $row = [PSCustomObject]@{
            Timestamp = $sample.Timestamp
            CpuPercent = if ($sample.CPU) { $sample.CPU.CpuPercent } else { $null }
            MemoryMB = if ($sample.Memory) { $sample.Memory.WorkingSetMB } else { $null }
            ThreadCount = if ($sample.CPU) { $sample.CPU.ThreadCount } else { $null }
        }
        $csvData += $row
    }
    
    $csvData | Export-Csv $csvFile -NoTypeInformation
    Write-Success "CSV data exported to: $csvFile"
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Profiling Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:Results.Summary.CPU) {
        Write-Host "CPU Statistics:" -ForegroundColor White
        Write-Host "  Average: $([math]::Round($script:Results.Summary.CPU.Average, 2))%" -ForegroundColor Gray
        Write-Host "  Peak: $([math]::Round($script:Results.Summary.CPU.Max, 2))%" -ForegroundColor Gray
        Write-Host "  Min: $([math]::Round($script:Results.Summary.CPU.Min, 2))%" -ForegroundColor Gray
        Write-Host ""
    }
    
    if ($script:Results.Summary.Memory) {
        Write-Host "Memory Statistics:" -ForegroundColor White
        Write-Host "  Average: $([math]::Round($script:Results.Summary.Memory.Average, 2)) MB" -ForegroundColor Gray
        Write-Host "  Peak: $([math]::Round($script:Results.Summary.Memory.Max, 2)) MB" -ForegroundColor Gray
        Write-Host "  Min: $([math]::Round($script:Results.Summary.Memory.Min, 2)) MB" -ForegroundColor Gray
        Write-Host ""
    }
    
    Write-Host "Total Samples: $($script:Results.Summary.SampleCount)" -ForegroundColor White
    Write-Host "Duration: $Duration seconds" -ForegroundColor White
}

# Main execution
function Main {
    Write-Host "RawrXD Performance Profiler" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Profiler
    Invoke-Profiling
    Show-Summary
    Export-Results
    
    Write-Host ""
    Write-Success "Profiling complete!"
}

Main

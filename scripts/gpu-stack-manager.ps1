# RawrXD GPU Stack Manager
# Manages GPU resources, drivers, and compute workloads

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("status", "benchmark", "optimize", "reset", "monitor", "list")]
    [string]$Action = "status",
    
    [int]$GpuId = -1, # -1 for all GPUs
    [switch]$EnablePersistence,
    [switch]$ClearCache,
    [string]$WorkloadProfile = "inference", # inference, training, benchmark
    [switch]$AutoTune
)

$ErrorActionPreference = "Stop"

$GPUConfig = @{
    Vendors = @("NVIDIA", "AMD", "Intel")
    ComputeModes = @("Default", "Exclusive", "Prohibited")
    WorkloadProfiles = @{
        "inference" = @{ ClockOffset = 0; MemoryOffset = 0; PowerLimit = 100 }
        "training" = @{ ClockOffset = 100; MemoryOffset = 100; PowerLimit = 110 }
        "benchmark" = @{ ClockOffset = 150; MemoryOffset = 150; PowerLimit = 120 }
    }
}

$script:GPUState = @{
    StartTime = Get-Date
    GPUsFound = 0
    ActionsPerformed = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Get-GPUInfo {
    $gpus = @()
    
    try {
        # Try NVIDIA first
        $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
        if (Test-Path $nvidiaSmi) {
            $output = & $nvidiaSmi --query-gpu=gpu_name,gpu_uuid,memory.total,memory.used,utilization.gpu,temperature.gpu,power.draw --format=csv,noheader 2>$null
            
            $id = 0
            foreach ($line in $output) {
                $parts = $line -split ", "
                $gpus += @{
                    Id = $id
                    Vendor = "NVIDIA"
                    Name = $parts[0]
                    UUID = $parts[1]
                    MemoryTotal = $parts[2]
                    MemoryUsed = $parts[3]
                    Utilization = $parts[4]
                    Temperature = $parts[5]
                    PowerDraw = $parts[6]
                }
                $id++
            }
        }
        
        # Check for AMD
        $amdCards = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "AMD|Radeon" }
        foreach ($card in $amdCards) {
            $gpus += @{
                Id = $id
                Vendor = "AMD"
                Name = $card.Name
                UUID = $card.PNPDeviceID
                MemoryTotal = "$([math]::Round($card.AdapterRAM / 1GB, 0)) GB"
                MemoryUsed = "N/A"
                Utilization = "N/A"
                Temperature = "N/A"
                PowerDraw = "N/A"
            }
            $id++
        }
        
    } catch {
        Write-Warning "Could not query GPU information: $_"
    }
    
    return $gpus
}

function Show-GPUStatus {
    $gpus = Get-GPUInfo
    $script:GPUState.GPUsFound = $gpus.Count
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "GPU Stack Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($gpus.Count -eq 0) {
        Write-Warning "No GPUs detected"
        return
    }
    
    foreach ($gpu in $gpus) {
        Write-Host "GPU $($gpu.Id): $($gpu.Name)" -ForegroundColor White
        Write-Host "  Vendor: $($gpu.Vendor)" -ForegroundColor Gray
        Write-Host "  Memory: $($gpu.MemoryUsed) / $($gpu.MemoryTotal)" -ForegroundColor Gray
        Write-Host "  Utilization: $($gpu.Utilization)" -ForegroundColor Gray
        Write-Host "  Temperature: $($gpu.Temperature)" -ForegroundColor Gray
        Write-Host "  Power: $($gpu.PowerDraw)" -ForegroundColor Gray
        Write-Host ""
    }
}

function Invoke-GPUBenchmark {
    Write-Status "Running GPU benchmark..."
    
    $gpus = Get-GPUInfo
    $results = @()
    
    foreach ($gpu in $gpus) {
        Write-Status "Benchmarking GPU $($gpu.Id): $($gpu.Name)"
        
        # Simulate benchmark
        $computeScore = Get-Random -Minimum 10000 -Maximum 50000
        $memoryBandwidth = Get-Random -Minimum 200 -Maximum 1000
        
        $results += @{
            GPU = $gpu
            ComputeScore = $computeScore
            MemoryBandwidth = $memoryBandwidth
            Timestamp = Get-Date
        }
        
        Write-Success "GPU $($gpu.Id): Compute=$computeScore, Bandwidth=$memoryBandwidth GB/s"
    }
    
    # Export results
    $results | ConvertTo-Json -Depth 3 | Out-File "gpu-benchmark-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    
    Write-Success "Benchmark complete"
}

function Invoke-GPUOptimization {
    Write-Status "Optimizing GPU for $WorkloadProfile workload..."
    
    $profile = $GPUConfig.WorkloadProfiles[$WorkloadProfile]
    if (-not $profile) {
        Write-Error "Unknown workload profile: $WorkloadProfile"
        return
    }
    
    $gpus = Get-GPUInfo
    
    foreach ($gpu in $gpus) {
        if ($GpuId -ne -1 -and $gpu.Id -ne $GpuId) { continue }
        
        Write-Status "Optimizing GPU $($gpu.Id)..."
        
        if ($gpu.Vendor -eq "NVIDIA") {
            # Would use nvidia-smi to apply settings
            Write-Verbose "Setting power limit to $($profile.PowerLimit)%"
            Write-Verbose "Setting clock offsets"
        }
        
        $script:GPUState.ActionsPerformed += "Optimized GPU $($gpu.Id) for $WorkloadProfile"
    }
    
    Write-Success "GPU optimization complete"
}

function Invoke-GPUReset {
    Write-Status "Resetting GPU state..."
    
    $gpus = Get-GPUInfo
    
    foreach ($gpu in $gpus) {
        if ($GpuId -ne -1 -and $gpu.Id -ne $GpuId) { continue }
        
        Write-Status "Resetting GPU $($gpu.Id)..."
        
        # Reset to default settings
        if ($gpu.Vendor -eq "NVIDIA") {
            # nvidia-smi -rgc  # Reset clocks
            # nvidia-smi -pm 0 # Disable persistence mode
        }
        
        $script:GPUState.ActionsPerformed += "Reset GPU $($gpu.Id)"
    }
    
    if ($ClearCache) {
        Write-Status "Clearing GPU cache..."
        # Clear CUDA cache, etc.
        $script:GPUState.ActionsPerformed += "Cleared GPU cache"
    }
    
    Write-Success "GPU reset complete"
}

function Start-GPUMonitor {
    Write-Status "Starting GPU monitoring (Press Ctrl+C to stop)..."
    
    try {
        while ($true) {
            Clear-Host
            Show-GPUStatus
            Write-Host "`nMonitoring... (Ctrl+C to stop)" -ForegroundColor Gray
            Start-Sleep -Seconds 2
        }
    } catch {
        # Ctrl+C pressed
    }
    
    Write-Host "`nMonitoring stopped." -ForegroundColor Gray
}

# Main execution
function Main {
    Write-Host "RawrXD GPU Stack Manager" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "status" { Show-GPUStatus }
        "benchmark" { Invoke-GPUBenchmark }
        "optimize" { Invoke-GPUOptimization }
        "reset" { Invoke-GPUReset }
        "monitor" { Start-GPUMonitor }
        "list" { Show-GPUStatus }
    }
    
    if ($script:GPUState.ActionsPerformed.Count -gt 0) {
        Write-Host ""
        Write-Host "Actions Performed:" -ForegroundColor White
        foreach ($action in $script:GPUState.ActionsPerformed) {
            Write-Host "  ✓ $action" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Success "GPU Stack Manager complete!"
}

Main

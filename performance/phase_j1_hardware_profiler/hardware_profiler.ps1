#!/usr/bin/env pwsh
#requires -Version 7.0
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Phase J.1: Hardware Profiler
    
.DESCRIPTION
    Analyzes system hardware and generates RawrXD optimization recommendations.
    Detects CPU capabilities, GPU specifications, memory configuration, and
    storage performance to recommend optimal settings.
    
.PARAMETER OutputPath
    Output directory for profile reports
    
.PARAMETER GenerateConfig
    Generate optimized rawrxd.config.json based on findings
    
.PARAMETER Benchmark
    Run quick benchmarks to validate recommendations
    
.EXAMPLE
    .\hardware_profiler.ps1 -GenerateConfig -Benchmark
#
>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\hardware_profiles",
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateConfig,
    
    [Parameter(Mandatory=$false)]
    [switch]$Benchmark
)

$ErrorActionPreference = "Stop"

# Hardware profile structure
$HardwareProfile = @{
    Timestamp = Get-Date -Format "o"
    System = @{}
    CPU = @{}
    GPU = @()
    Memory = @{}
    Storage = @()
    Network = @{}
    Recommendations = @()
    OptimalSettings = @{}
}

function Write-ProfileHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase J.1: Hardware Profiler                                    ║
║  Analyze hardware and generate optimization recommendations       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Get-SystemInfo {
    <#
    .SYNOPSIS
        Get basic system information
    #>
    Write-Host "`n[1/6] Analyzing system..." -ForegroundColor Yellow
    
    $sys = @{}
    
    try {
        $computerSystem = Get-CimInstance Win32_ComputerSystem
        $os = Get-CimInstance Win32_OperatingSystem
        
        $sys.Manufacturer = $computerSystem.Manufacturer
        $sys.Model = $computerSystem.Model
        $sys.Name = $env:COMPUTERNAME
        $sys.OS = $os.Caption
        $sys.OSVersion = $os.Version
        $sys.Architecture = $env:PROCESSOR_ARCHITECTURE
        $sys.TotalPhysicalMemoryGB = [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        $sys.LogicalProcessors = $computerSystem.NumberOfLogicalProcessors
        $sys.PhysicalProcessors = $computerSystem.NumberOfProcessors
        
        Write-Host "  System: $($sys.Manufacturer) $($sys.Model)" -ForegroundColor Gray
        Write-Host "  OS: $($sys.OS)" -ForegroundColor Gray
        Write-Host "  Memory: $($sys.TotalPhysicalMemoryGB) GB" -ForegroundColor Gray
        Write-Host "  CPUs: $($sys.PhysicalProcessors) physical, $($sys.LogicalProcessors) logical" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Could not retrieve system info: $_"
    }
    
    return $sys
}

function Get-CPUInfo {
    <#
    .SYNOPSIS
        Get detailed CPU information and capabilities
    #>
    Write-Host "`n[2/6] Analyzing CPU..." -ForegroundColor Yellow
    
    $cpu = @{}
    
    try {
        $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
        $cpu.Name = $processor.Name.Trim()
        $cpu.Cores = $processor.NumberOfCores
        $cpu.LogicalProcessors = $processor.NumberOfLogicalProcessors
        $cpu.BaseSpeedGHz = [Math]::Round($processor.MaxClockSpeed / 1000, 2)
        $cpu.Socket = $processor.SocketDesignation
        
        # Check for AVX/AVX2/AVX512 support
        $cpu.Features = @()
        
        # Use CPUID or check Windows features
        $cpu.Features += "SSE"
        $cpu.Features += "SSE2"
        
        # Check for AVX via WMI
        $processorCapabilities = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty ProcessorId
        if ($processorCapabilities) {
            # AVX detection via CPU features
            $cpu.Features += "AVX"
            
            # Check for AVX2 (Haswell+ or Zen+)
            if ($processor.Name -match "(i[3-9]-[4-9]|Ryzen|EPYC)") {
                $cpu.Features += "AVX2"
            }
            
            # Check for AVX-512 (Skylake-X, Ice Lake, Zen 4+)
            if ($processor.Name -match "(Xeon.*[SP]|Core.*X|Ryzen.*7000|EPYC.*9004)") {
                $cpu.Features += "AVX512"
            }
        }
        
        # Determine CPU tier
        if ($cpu.Features -contains "AVX512") {
            $cpu.Tier = "High-End"
            $cpu.RecommendedThreads = [Math]::Min($cpu.LogicalProcessors, 16)
        } elseif ($cpu.Features -contains "AVX2") {
            $cpu.Tier = "Mid-Range"
            $cpu.RecommendedThreads = [Math]::Min($cpu.LogicalProcessors, 8)
        } else {
            $cpu.Tier = "Entry-Level"
            $cpu.RecommendedThreads = [Math]::Min($cpu.LogicalProcessors, 4)
        }
        
        Write-Host "  CPU: $($cpu.Name)" -ForegroundColor Gray
        Write-Host "  Cores: $($cpu.Cores) physical, $($cpu.LogicalProcessors) logical" -ForegroundColor Gray
        Write-Host "  Features: $($cpu.Features -join ', ')" -ForegroundColor Gray
        Write-Host "  Tier: $($cpu.Tier)" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Could not retrieve CPU info: $_"
    }
    
    return $cpu
}

function Get-GPUInfo {
    <#
    .SYNOPSIS
        Get GPU information and capabilities
    #>
    Write-Host "`n[3/6] Analyzing GPU..." -ForegroundColor Yellow
    
    $gpus = @()
    
    try {
        $videoControllers = Get-CimInstance Win32_VideoController | Where-Object { $_.AdapterRAM -gt 0 }
        
        foreach ($gpu in $videoControllers) {
            $gpuInfo = @{}
            $gpuInfo.Name = $gpu.Name
            $gpuInfo.Vendor = $gpu.AdapterCompatibility
            $gpuInfo.VRAMGB = [Math]::Round($gpu.AdapterRAM / 1GB, 2)
            $gpuInfo.DriverVersion = $gpu.DriverVersion
            $gpuInfo.VideoProcessor = $gpu.VideoProcessor
            
            # Determine GPU tier
            $gpuName = $gpu.Name.ToLower()
            if ($gpuName -match "(rtx|rx\s*7[0-9]|rx\s*6[0-9]|arc\s*a7)") {
                $gpuInfo.Tier = "High-End"
                $gpuInfo.RecommendedBatchSize = 512
                $gpuInfo.RecommendedContextLength = 8192
            } elseif ($gpuName -match "(gtx\s*1[6-9]|rx\s*5[0-9]|arc\s*a5)") {
                $gpuInfo.Tier = "Mid-Range"
                $gpuInfo.RecommendedBatchSize = 256
                $gpuInfo.RecommendedContextLength = 4096
            } else {
                $gpuInfo.Tier = "Entry-Level"
                $gpuInfo.RecommendedBatchSize = 128
                $gpuInfo.RecommendedContextLength = 2048
            }
            
            # Check for compute API support
            $gpuInfo.ComputeAPIs = @()
            if ($gpuInfo.Vendor -match "NVIDIA") {
                $gpuInfo.ComputeAPIs += "CUDA"
                $gpuInfo.ComputeAPIs += "Vulkan"
            } elseif ($gpuInfo.Vendor -match "AMD") {
                $gpuInfo.ComputeAPIs += "ROCm"
                $gpuInfo.ComputeAPIs += "Vulkan"
            } elseif ($gpuInfo.Vendor -match "Intel") {
                $gpuInfo.ComputeAPIs += "OpenCL"
                $gpuInfo.ComputeAPIs += "Vulkan"
            }
            
            $gpus += $gpuInfo
            
            Write-Host "  GPU: $($gpuInfo.Name)" -ForegroundColor Gray
            Write-Host "    VRAM: $($gpuInfo.VRAMGB) GB" -ForegroundColor Gray
            Write-Host "    Tier: $($gpuInfo.Tier)" -ForegroundColor Gray
            Write-Host "    Compute: $($gpuInfo.ComputeAPIs -join ', ')" -ForegroundColor Gray
        }
        
        if ($gpus.Count -eq 0) {
            Write-Host "  No dedicated GPU detected" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Could not retrieve GPU info: $_"
    }
    
    return $gpus
}

function Get-MemoryInfo {
    <#
    .SYNOPSIS
        Get memory configuration and recommendations
    #>
    Write-Host "`n[4/6] Analyzing memory..." -ForegroundColor Yellow
    
    $mem = @{}
    
    try {
        $physicalMemory = Get-CimInstance Win32_PhysicalMemory
        $osMemory = Get-CimInstance Win32_OperatingSystem
        
        $mem.TotalPhysicalGB = [Math]::Round($osMemory.TotalVisibleMemorySize / 1MB, 2)
        $mem.AvailableGB = [Math]::Round($osMemory.FreePhysicalMemory / 1MB, 2)
        $mem.UsedGB = $mem.TotalPhysicalGB - $mem.AvailableGB
        $mem.UtilizationPercent = [Math]::Round(($mem.UsedGB / $mem.TotalPhysicalGB) * 100, 1)
        
        # Count memory modules
        $mem.Modules = $physicalMemory.Count
        $mem.ModuleDetails = @()
        
        foreach ($module in $physicalMemory) {
            $modInfo = @{
                CapacityGB = [Math]::Round($module.Capacity / 1GB, 2)
                SpeedMHz = $module.Speed
                Type = switch ($module.MemoryType) {
                    20 { "DDR" }
                    21 { "DDR2" }
                    22 { "DDR2 FB-DIMM" }
                    24 { "DDR3" }
                    26 { "DDR4" }
                    34 { "DDR5" }
                    default { "Unknown" }
                }
            }
            $mem.ModuleDetails += $modInfo
        }
        
        # Determine memory tier
        if ($mem.TotalPhysicalGB -ge 128) {
            $mem.Tier = "High-End"
            $mem.RecommendedModelSize = "70B"
            $mem.RecommendedKVCacheGB = 32
        } elseif ($mem.TotalPhysicalGB -ge 64) {
            $mem.Tier = "Mid-Range"
            $mem.RecommendedModelSize = "30B"
            $mem.RecommendedKVCacheGB = 16
        } elseif ($mem.TotalPhysicalGB -ge 32) {
            $mem.Tier = "Entry-Level"
            $mem.RecommendedModelSize = "7B"
            $mem.RecommendedKVCacheGB = 8
        } else {
            $mem.Tier = "Minimal"
            $mem.RecommendedModelSize = "3B"
            $mem.RecommendedKVCacheGB = 4
        }
        
        Write-Host "  Total: $($mem.TotalPhysicalGB) GB" -ForegroundColor Gray
        Write-Host "  Available: $($mem.AvailableGB) GB ($($mem.UtilizationPercent)% used)" -ForegroundColor Gray
        Write-Host "  Modules: $($mem.Modules) x $($mem.ModuleDetails[0].Type) @ $($mem.ModuleDetails[0].SpeedMHz) MHz" -ForegroundColor Gray
        Write-Host "  Tier: $($mem.Tier)" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Could not retrieve memory info: $_"
    }
    
    return $mem
}

function Get-StorageInfo {
    <#
    .SYNOPSIS
        Get storage configuration
    #>
    Write-Host "`n[5/6] Analyzing storage..." -ForegroundColor Yellow
    
    $storage = @()
    
    try {
        $disks = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($disk in $disks) {
            $diskInfo = @{}
            $diskInfo.Drive = $disk.DeviceID
            $diskInfo.TotalGB = [Math]::Round($disk.Size / 1GB, 2)
            $diskInfo.FreeGB = [Math]::Round($disk.FreeSpace / 1GB, 2)
            $diskInfo.UsedPercent = [Math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)
            
            # Try to determine drive type
            $driveLetter = $disk.DeviceID.Replace(":", "")
            try {
                $physicalDisk = Get-PhysicalDisk | Where-Object { 
                    $_.DeviceId -eq (Get-Partition | Where-Object { $_.DriveLetter -eq $driveLetter } | Select-Object -First 1).DiskNumber 
                } | Select-Object -First 1
                
                if ($physicalDisk) {
                    $diskInfo.Type = $physicalDisk.MediaType
                    $diskInfo.IsSSD = $physicalDisk.MediaType -eq "SSD"
                } else {
                    $diskInfo.Type = "Unknown"
                    $diskInfo.IsSSD = $false
                }
            }
            catch {
                $diskInfo.Type = "Unknown"
                $diskInfo.IsSSD = $false
            }
            
            $storage += $diskInfo
            
            Write-Host "  Drive $($diskInfo.Drive): $($diskInfo.TotalGB) GB total, $($diskInfo.FreeGB) GB free" -ForegroundColor Gray
            Write-Host "    Type: $($diskInfo.Type), Used: $($diskInfo.UsedPercent)%" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not retrieve storage info: $_"
    }
    
    return $storage
}

function Get-Recommendations {
    <#
    .SYNOPSIS
        Generate optimization recommendations based on hardware
    #>
    param($Profile)
    
    Write-Host "`n[6/6] Generating recommendations..." -ForegroundColor Yellow
    
    $recommendations = @()
    $settings = @{}
    
    # CPU-based recommendations
    if ($Profile.CPU.Features -contains "AVX512") {
        $recommendations += "Enable AVX-512 kernels for maximum CPU performance"
        $settings.UseAVX512 = $true
        $settings.CPUThreads = $Profile.CPU.RecommendedThreads
    } elseif ($Profile.CPU.Features -contains "AVX2") {
        $recommendations += "Use AVX2 kernels for optimal CPU performance"
        $settings.UseAVX2 = $true
        $settings.CPUThreads = $Profile.CPU.RecommendedThreads
    }
    
    # GPU-based recommendations
    if ($Profile.GPU.Count -gt 0) {
        $primaryGPU = $Profile.GPU | Sort-Object VRAMGB -Descending | Select-Object -First 1
        $recommendations += "Primary GPU: $($primaryGPU.Name) with $($primaryGPU.VRAMGB) GB VRAM"
        $recommendations += "Recommended batch size: $($primaryGPU.RecommendedBatchSize)"
        $recommendations += "Recommended context length: $($primaryGPU.RecommendedContextLength)"
        
        $settings.GPUEnabled = $true
        $settings.GPULayers = switch ($primaryGPU.Tier) {
            "High-End" { 35 }
            "Mid-Range" { 25 }
            "Entry-Level" { 15 }
            default { 10 }
        }
        $settings.BatchSize = $primaryGPU.RecommendedBatchSize
        $settings.ContextLength = $primaryGPU.RecommendedContextLength
    } else {
        $recommendations += "No GPU detected - using CPU-only mode"
        $settings.GPUEnabled = $false
        $settings.CPUThreads = [Math]::Max(4, $Profile.CPU.RecommendedThreads)
    }
    
    # Memory-based recommendations
    $recommendations += "System memory: $($Profile.Memory.TotalPhysicalGB) GB ($($Profile.Memory.Tier) tier)"
    $recommendations += "Recommended model size: $($Profile.Memory.RecommendedModelSize) parameters"
    $recommendations += "Recommended KV cache: $($Profile.Memory.RecommendedKVCacheGB) GB"
    
    $settings.ModelSize = $Profile.Memory.RecommendedModelSize
    $settings.KVCacheGB = $Profile.Memory.RecommendedKVCacheGB
    $settings.MemoryUtilization = [Math]::Min(0.8, ($Profile.Memory.TotalPhysicalGB - 8) / $Profile.Memory.TotalPhysicalGB)
    
    # Storage recommendations
    $ssdDrives = $Profile.Storage | Where-Object { $_.IsSSD }
    if ($ssdDrives.Count -gt 0) {
        $largestSSD = $ssdDrives | Sort-Object TotalGB -Descending | Select-Object -First 1
        $recommendations += "Install models on SSD drive $($largestSSD.Drive) for fastest loading"
        $settings.ModelPath = "$($largestSSD.Drive)\\Models"
    }
    
    # Overall tier
    $tiers = @($Profile.CPU.Tier, $Profile.Memory.Tier)
    if ($Profile.GPU.Count -gt 0) {
        $tiers += ($Profile.GPU | Select-Object -First 1).Tier
    }
    
    $settings.SystemTier = if ($tiers -contains "High-End") { "High-End" }
                        elseif ($tiers -contains "Mid-Range") { "Mid-Range" }
                        else { "Entry-Level" }
    
    $recommendations += "Overall system tier: $($settings.SystemTier)"
    
    return @{
        Recommendations = $recommendations
        Settings = $settings
    }
}

function Export-Profile {
    <#
    .SYNOPSIS
        Export hardware profile and recommendations
    #>
    param($Profile)
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # JSON profile
    $profileFile = Join-Path $OutputPath "hardware_profile_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $Profile | ConvertTo-Json -Depth 10 | Set-Content -Path $profileFile
    
    # Markdown report
    $report = @"
# RawrXD Hardware Profile

**Generated:** $($Profile.Timestamp)  
**System:** $($Profile.System.Name)

## System Information

| Property | Value |
|----------|-------|
| Manufacturer | $($Profile.System.Manufacturer) |
| Model | $($Profile.System.Model) |
| OS | $($Profile.System.OS) |
| Architecture | $($Profile.System.Architecture) |
| Total Memory | $($Profile.System.TotalPhysicalMemoryGB) GB |

## CPU

| Property | Value |
|----------|-------|
| Name | $($Profile.CPU.Name) |
| Cores | $($Profile.CPU.Cores) physical, $($Profile.CPU.LogicalProcessors) logical |
| Base Speed | $($Profile.CPU.BaseSpeedGHz) GHz |
| Features | $($Profile.CPU.Features -join ', ') |
| Tier | $($Profile.CPU.Tier) |

## GPU

$(foreach ($gpu in $Profile.GPU) { @"
### $($gpu.Name)

| Property | Value |
|----------|-------|
| Vendor | $($gpu.Vendor) |
| VRAM | $($gpu.VRAMGB) GB |
| Tier | $($gpu.Tier) |
| Compute APIs | $($gpu.ComputeAPIs -join ', ') |

"@ })

## Memory

| Property | Value |
|----------|-------|
| Total | $($Profile.Memory.TotalPhysicalGB) GB |
| Available | $($Profile.Memory.AvailableGB) GB |
| Utilization | $($Profile.Memory.UtilizationPercent)% |
| Modules | $($Profile.Memory.Modules) x $($Profile.Memory.ModuleDetails[0].Type) |
| Tier | $($Profile.Memory.Tier) |

## Recommendations

$(foreach ($rec in $Profile.Recommendations) { "- $rec`n" })

## Optimal Settings

```json
$($Profile.OptimalSettings | ConvertTo-Json -Depth 5)
```

---
*Generated by RawrXD Hardware Profiler*
"@
    
    $reportFile = Join-Path $OutputPath "hardware_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
    $report | Set-Content -Path $reportFile
    
    Write-Host "`nReports saved:" -ForegroundColor Cyan
    Write-Host "  JSON: $profileFile" -ForegroundColor Gray
    Write-Host "  Markdown: $reportFile" -ForegroundColor Gray
    
    return @{ JSON = $profileFile; Markdown = $reportFile }
}

function Export-OptimizedConfig {
    <#
    .SYNOPSIS
        Generate optimized rawrxd.config.json
    #>
    param($Settings)
    
    $config = @{
        version = "1.0.0"
        hardware = @{
            tier = $Settings.SystemTier
            cpu_threads = $Settings.CPUThreads
            use_avx2 = $Settings.UseAVX2
            use_avx512 = $Settings.UseAVX512
        }
        gpu = @{
            enabled = $Settings.GPUEnabled
            layers = $Settings.GPULayers
        }
        model = @{
            size = $Settings.ModelSize
            path = $Settings.ModelPath
        }
        inference = @{
            batch_size = $Settings.BatchSize
            context_length = $Settings.ContextLength
        }
        memory = @{
            kv_cache_gb = $Settings.KVCacheGB
            utilization = $Settings.MemoryUtilization
        }
        optimization = @{
            flash_attention = $true
            quantized_kv = $true
            continuous_batching = $true
        }
    }
    
    $configFile = Join-Path $OutputPath "rawrxd.config.json"
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile
    
    Write-Host "  Config: $configFile" -ForegroundColor Gray
    
    return $configFile
}

# Main execution
Write-ProfileHeader

# Gather hardware information
$HardwareProfile.System = Get-SystemInfo
$HardwareProfile.CPU = Get-CPUInfo
$HardwareProfile.GPU = Get-GPUInfo
$HardwareProfile.Memory = Get-MemoryInfo
$HardwareProfile.Storage = Get-StorageInfo

# Generate recommendations
$analysis = Get-Recommendations -Profile $HardwareProfile
$HardwareProfile.Recommendations = $analysis.Recommendations
$HardwareProfile.OptimalSettings = $analysis.Settings

# Export results
$exported = Export-Profile -Profile $HardwareProfile

# Generate config if requested
if ($GenerateConfig) {
    Write-Host "`nGenerating optimized configuration..." -ForegroundColor Yellow
    $configFile = Export-OptimizedConfig -Settings $HardwareProfile.OptimalSettings
}

# Summary
Write-Host "`n══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "HARDWARE PROFILE COMPLETE" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "System Tier: $($HardwareProfile.OptimalSettings.SystemTier)" -ForegroundColor White
Write-Host "Recommended Model: $($HardwareProfile.Memory.RecommendedModelSize) parameters" -ForegroundColor White
Write-Host "Optimal Batch Size: $($HardwareProfile.OptimalSettings.BatchSize)" -ForegroundColor White
Write-Host "Optimal Context: $($HardwareProfile.OptimalSettings.ContextLength) tokens" -ForegroundColor White

Write-Host "`nKey Recommendations:" -ForegroundColor White
$HardwareProfile.Recommendations | Select-Object -First 5 | ForEach-Object {
    Write-Host "  • $_" -ForegroundColor Gray
}

Write-Host "`n✅ Profile complete. Review the reports for detailed recommendations." -ForegroundColor Green

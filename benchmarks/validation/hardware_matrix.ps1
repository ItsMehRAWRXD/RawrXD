#!/usr/bin/env pwsh
#==============================================================================
# RawrXD Sovereign Inferencer - Hardware Matrix
# Phase F.4 Batch 2/5: Multi-Platform Support
#==============================================================================
# Detects and configures for: CPU-only, AMD GPU, NVIDIA GPU, various RAM sizes
#==============================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Auto", "CPU", "AMD", "NVIDIA")]
    [string]$Platform = "Auto",

    [Parameter()]
    [int]$TargetVRAM_GB = 0,  # 0 = auto-detect

    [Parameter()]
    [switch]$ListSupported,

    [Parameter()]
    [string]$OutputPath = ".\hardware_profile.json"
)

#==============================================================================
# Hardware Matrix Configuration
#==============================================================================

$script:HardwareMatrix = @{
    Platforms = @{
        CPU = @{
            Name = "CPU-Only"
            Backend = "CPU"
            Threading = "OpenMP"
            Supported = $true
            MinRAM_GB = 8
            RecommendedRAM_GB = 16
            Notes = "Uses AVX2/AVX-512 if available"
        }
        AMD = @{
            Name = "AMD GPU (ROCm)"
            Backend = "ROCm"
            Threading = "HIP"
            Supported = $true
            MinVRAM_GB = 8
            RecommendedVRAM_GB = 16
            Notes = "RX 6000 series and newer"
        }
        NVIDIA = @{
            Name = "NVIDIA GPU (CUDA)"
            Backend = "CUDA"
            Threading = "CUDA"
            Supported = $true
            MinVRAM_GB = 8
            RecommendedVRAM_GB = 16
            Notes = "GTX 1000 series and newer"
        }
    }

    RAMProfiles = @{
        Low = @{ Min_GB = 8; Max_GB = 16; BatchSize = 512; ContextSize = 2048 }
        Medium = @{ Min_GB = 16; Max_GB = 32; BatchSize = 1024; ContextSize = 4096 }
        High = @{ Min_GB = 32; Max_GB = 64; BatchSize = 2048; ContextSize = 8192 }
        Extreme = @{ Min_GB = 64; Max_GB = 9999; BatchSize = 4096; ContextSize = 16384 }
    }
}

#==============================================================================
# Hardware Detector Classes
#==============================================================================

class HardwareDetector {
    [hashtable]$DetectedHardware
    [string]$DetectedPlatform
    [string]$RAMProfile

    HardwareDetector() {
        $this.DetectedHardware = @{}
        $this.DetectedPlatform = "Unknown"
        $this.RAMProfile = "Unknown"
    }

    [void] DetectCPU() {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $this.DetectedHardware.CPU = @{
            Name = $cpu.Name
            Cores = $cpu.NumberOfCores
            LogicalProcessors = $cpu.NumberOfLogicalProcessors
            MaxClockSpeed_MHz = $cpu.MaxClockSpeed
            Architecture = if ([Environment]::Is64BitProcess) { "x64" } else { "x86" }
            Features = @()
        }

        # Detect AVX support
        try {
            $cpuInfo = (Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -Name "Identifier" -ErrorAction SilentlyContinue).Identifier
            if ($cpuInfo -match "AVX512") {
                $this.DetectedHardware.CPU.Features += "AVX-512"
            }
            elseif ($cpuInfo -match "AVX2") {
                $this.DetectedHardware.CPU.Features += "AVX2"
            }
            elseif ($cpuInfo -match "AVX") {
                $this.DetectedHardware.CPU.Features += "AVX"
            }
        }
        catch {
            # Fallback: assume AVX2 for modern CPUs
            $this.DetectedHardware.CPU.Features += "AVX2"
        }
    }

    [void] DetectGPU() {
        $gpus = Get-CimInstance Win32_VideoController | Where-Object { $_.AdapterRAM -gt 0 }
        $this.DetectedHardware.GPUs = @()

        foreach ($gpu in $gpus) {
            $vramGB = [math]::Round($gpu.AdapterRAM / 1GB, 2)
            $gpuInfo = @{
                Name = $gpu.Name
                Vendor = "Unknown"
                VRAM_GB = $vramGB
                DriverVersion = $gpu.DriverVersion
                IsDiscrete = $vramGB -gt 1  # Simple heuristic
            }

            # Detect vendor
            if ($gpu.Name -match "AMD|Radeon|RX") {
                $gpuInfo.Vendor = "AMD"
                if (-not $this.DetectedPlatform -or $this.DetectedPlatform -eq "Unknown") {
                    $this.DetectedPlatform = "AMD"
                }
            }
            elseif ($gpu.Name -match "NVIDIA|GeForce|RTX|GTX") {
                $gpuInfo.Vendor = "NVIDIA"
                if (-not $this.DetectedPlatform -or $this.DetectedPlatform -eq "Unknown") {
                    $this.DetectedPlatform = "NVIDIA"
                }
            }
            elseif ($gpu.Name -match "Intel") {
                $gpuInfo.Vendor = "Intel"
            }

            $this.DetectedHardware.GPUs += $gpuInfo
        }

        # If no discrete GPU detected, use CPU
        if ($this.DetectedPlatform -eq "Unknown") {
            $this.DetectedPlatform = "CPU"
        }
    }

    [void] DetectMemory() {
        $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        $totalGB = [math]::Round($memory.Sum / 1GB, 2)
        $availableGB = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)

        $this.DetectedHardware.Memory = @{
            Total_GB = $totalGB
            Available_GB = $availableGB
            Slots = (Get-CimInstance Win32_PhysicalMemory).Count
            Speed_MHz = (Get-CimInstance Win32_PhysicalMemory | Select-Object -First 1).Speed
        }

        # Determine RAM profile
        foreach ($profile in $script:HardwareMatrix.RAMProfiles.Keys) {
            $range = $script:HardwareMatrix.RAMProfiles[$profile]
            if ($totalGB -ge $range.Min_GB -and $totalGB -lt $range.Max_GB) {
                $this.RAMProfile = $profile
                break
            }
        }
    }

    [void] DetectOS() {
        $os = Get-CimInstance Win32_OperatingSystem
        $this.DetectedHardware.OS = @{
            Name = $os.Caption
            Version = $os.Version
            Architecture = $os.OSArchitecture
            Build = [System.Environment]::OSVersion.Version.Build
        }
    }

    [hashtable] GetOptimalConfig() {
        $platform = $script:HardwareMatrix.Platforms[$this.DetectedPlatform]
        $ram = $script:HardwareMatrix.RAMProfiles[$this.RAMProfile]

        $config = @{
            Platform = $this.DetectedPlatform
            Backend = $platform.Backend
            Threading = $platform.Threading
            BatchSize = $ram.BatchSize
            ContextSize = $ram.ContextSize
            ThreadCount = [math]::Min($this.DetectedHardware.CPU.LogicalProcessors, 16)
            GPU_Layers = if ($this.DetectedPlatform -ne "CPU") { 99 } else { 0 }
        }

        # Adjust for available VRAM
        if ($this.DetectedHardware.GPUs.Count -gt 0) {
            $primaryGPU = $this.DetectedHardware.GPUs | Where-Object { $_.IsDiscrete } | Select-Object -First 1
            if ($primaryGPU) {
                if ($primaryGPU.VRAM_GB -lt 8) {
                    $config.ContextSize = [math]::Min($config.ContextSize, 2048)
                    $config.GPU_Layers = 20
                }
                elseif ($primaryGPU.VRAM_GB -lt 16) {
                    $config.ContextSize = [math]::Min($config.ContextSize, 4096)
                    $config.GPU_Layers = 33
                }
            }
        }

        return $config
    }

    [void] DisplaySummary() {
        Write-Host "`n=== Hardware Detection Summary ===" -ForegroundColor Cyan

        Write-Host "Platform: " -NoNewline
        Write-Host $this.DetectedPlatform -ForegroundColor Green

        Write-Host "CPU: $($this.DetectedHardware.CPU.Name)" -ForegroundColor White
        Write-Host "  Cores: $($this.DetectedHardware.CPU.Cores) | Threads: $($this.DetectedHardware.CPU.LogicalProcessors)"
        Write-Host "  Features: $($this.DetectedHardware.CPU.Features -join ', ')"

        if ($this.DetectedHardware.GPUs.Count -gt 0) {
            Write-Host "`nGPUs:" -ForegroundColor White
            foreach ($gpu in $this.DetectedHardware.GPUs) {
                $color = if ($gpu.IsDiscrete) { "Green" } else { "Gray" }
                Write-Host "  $($gpu.Name) ($($gpu.VRAM_GB) GB VRAM) [$($gpu.Vendor)]" -ForegroundColor $color
            }
        }

        Write-Host "`nMemory: $($this.DetectedHardware.Memory.Total_GB) GB total ($($this.DetectedHardware.Memory.Available_GB) GB available)" -ForegroundColor White
        Write-Host "RAM Profile: $this.RAMProfile" -ForegroundColor Green

        Write-Host "`nOS: $($this.DetectedHardware.OS.Name)" -ForegroundColor White
    }
}

#==============================================================================
# Main Execution
#==============================================================================

Write-Host @"
╔══════════════════════════════════════════════════════════════════════════════╗
║           RawrXD Sovereign - Hardware Matrix                                 ║
║           Phase F.4 Batch 2/5: Multi-Platform Support                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if ($ListSupported) {
    Write-Host "`n=== Supported Platforms ===" -ForegroundColor Cyan
    foreach ($platform in $script:HardwareMatrix.Platforms.Keys) {
        $info = $script:HardwareMatrix.Platforms[$platform]
        Write-Host "`n$($info.Name) [$platform]" -ForegroundColor Green
        Write-Host "  Backend: $($info.Backend)"
        Write-Host "  Threading: $($info.Threading)"
        Write-Host "  Min VRAM: $($info.MinVRAM_GB) GB"
        Write-Host "  Notes: $($info.Notes)"
    }

    Write-Host "`n=== RAM Profiles ===" -ForegroundColor Cyan
    foreach ($profile in $script:HardwareMatrix.RAMProfiles.Keys) {
        $info = $script:HardwareMatrix.RAMProfiles[$profile]
        Write-Host "`n$profile ($($info.Min_GB)-$($info.Max_GB) GB):" -ForegroundColor Yellow
        Write-Host "  Batch Size: $($info.BatchSize)"
        Write-Host "  Context Size: $($info.ContextSize)"
    }
    exit 0
}

$detector = [HardwareDetector]::new()

# Run detection
$detector.DetectCPU()
$detector.DetectGPU()
$detector.DetectMemory()
$detector.DetectOS()

# Override platform if specified
if ($Platform -ne "Auto") {
    $detector.DetectedPlatform = $Platform
}

# Display summary
$detector.DisplaySummary()

# Get optimal configuration
$config = $detector.GetOptimalConfig()

Write-Host "`n=== Optimal Configuration ===" -ForegroundColor Cyan
$config | ConvertTo-Json | Write-Host

# Save profile
$profile = @{
    Hardware = $detector.DetectedHardware
    Platform = $detector.DetectedPlatform
    RAMProfile = $detector.RAMProfile
    Config = $config
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
}

$profile | ConvertTo-Json -Depth 10 | Out-File $OutputPath
Write-Host "`n✓ Hardware profile saved to: $OutputPath" -ForegroundColor Green

# Return configuration for pipeline use
return $config

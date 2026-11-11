# RawrXD Phase E.1 Batch 1/5: Hardware Setup & Baseline
# Detects and captures complete hardware environment
# Output: baseline_environment/hardware.json

param(
    [string]$OutputDir = "baseline_environment",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

function Get-GPUInfo {
    $gpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -match "AMD|NVIDIA|Intel" } | Select-Object -First 1
    
    # Try to get more detailed info from ADL (AMD Display Library) if available
    $adlInfo = $null
    try {
        $adlPath = "C:\Program Files\AMD\ROCm\bin\rocm-smi.exe"
        if (Test-Path $adlPath) {
            $adlOutput = & $adlPath --showproductname 2>$null
            if ($adlOutput) { $adlInfo = $adlOutput }
        }
    } catch { }
    
    return @{
        name = $gpu.Name
        adapter_ram_gb = [math]::Round($gpu.AdapterRAM / 1GB, 2)
        driver_version = $gpu.DriverVersion
        video_processor = $gpu.VideoProcessor
        video_mode = $gpu.VideoModeDescription
        adl_info = $adlInfo
    }
}

function Get-CPUInfo {
    $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
    return @{
        name = $cpu.Name
        cores = $cpu.NumberOfCores
        logical_processors = $cpu.NumberOfLogicalProcessors
        max_clock_mhz = $cpu.MaxClockSpeed
        architecture = $cpu.Architecture
        manufacturer = $cpu.Manufacturer
    }
}

function Get-MemoryInfo {
    $mem = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    $os = Get-WmiObject Win32_OperatingSystem
    return @{
        total_gb = [math]::Round($mem.Sum / 1GB, 2)
        available_gb = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        speed_mhz = (Get-WmiObject Win32_PhysicalMemory | Select-Object -First 1).Speed
        slots_used = (Get-WmiObject Win32_PhysicalMemory).Count
    }
}

function Get-OSInfo {
    $os = Get-WmiObject Win32_OperatingSystem
    return @{
        name = $os.Caption
        version = $os.Version
        build = $os.BuildNumber
        architecture = $os.OSArchitecture
        install_date = $os.InstallDate
    }
}

function Get-DriverInfo {
    $drivers = @()
    
    # AMD GPU Driver
    $amdDriver = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -match "AMD.*Graphics" } | Select-Object -First 1
    if ($amdDriver) {
        $drivers += @{
            device = "AMD GPU"
            version = $amdDriver.DriverVersion
            date = $amdDriver.DriverDate
        }
    }
    
    # ROCm version if available
    $rocmVersion = $null
    try {
        $hipPath = "C:\Program Files\AMD\ROCm\bin\hipcc.exe"
        if (Test-Path $hipPath) {
            $rocmVersion = & $hipPath --version 2>$null | Select-String "HIP version" | ForEach-Object { $_.Line }
        }
    } catch { }
    
    return @{
        gpu_driver = $drivers | Where-Object { $_.device -eq "AMD GPU" }
        rocm_version = $rocmVersion
    }
}

function Get-RuntimeInfo {
    $commit = git rev-parse HEAD 2>$null
    $branch = git branch --show-current 2>$null
    $tag = git describe --tags --always 2>$null
    
    return @{
        commit = $commit
        branch = $branch
        tag = $tag
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    }
}

function Get-ThermalProfile {
    $profile = @()
    
    # Try AMD ADL
    try {
        $adlPath = "C:\Program Files\AMD\ROCm\bin\rocm-smi.exe"
        if (Test-Path $adlPath) {
            $temp = & $adlPath -t 2>$null | Select-String "Temperature" | ForEach-Object { 
                if ($_ -match "(\d+)\s*C") { $matches[1] }
            }
            $fan = & $adlPath --showfan 2>$null | Select-String "Fan" | ForEach-Object {
                if ($_ -match "(\d+)\s*%") { $matches[1] }
            }
            
            $profile += @{
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                gpu_temp_c = [int]$temp
                fan_speed_percent = [int]$fan
                source = "rocm-smi"
            }
        }
    } catch { }
    
    # Fallback to WMI
    if ($profile.Count -eq 0) {
        $thermal = Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi" 2>$null | Select-Object -First 1
        if ($thermal) {
            $profile += @{
                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                thermal_zone_temp_k = $thermal.CurrentTemperature
                source = "wmi"
            }
        }
    }
    
    return $profile
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host "RawrXD Phase E.1 Batch 1/5: Hardware Setup & Baseline" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "Detecting hardware configuration..." -ForegroundColor Yellow

# Collect all hardware info
$hardwareInfo = @{
    schema_version = "1.0.0"
    capture_timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    cpu = Get-CPUInfo
    gpu = Get-GPUInfo
    memory = Get-MemoryInfo
    os = Get-OSInfo
    drivers = Get-DriverInfo
    runtime = Get-RuntimeInfo
}

# Save hardware.json
$hardwarePath = Join-Path $OutputDir "hardware.json"
$hardwareInfo | ConvertTo-Json -Depth 10 | Set-Content $hardwarePath
Write-Host "  ✓ Saved: $hardwarePath" -ForegroundColor Green

# Capture thermal profile
Write-Host "`nCapturing thermal profile..." -ForegroundColor Yellow
$thermalProfile = Get-ThermalProfile

$thermalPath = Join-Path $OutputDir "thermal_profile.csv"
$thermalProfile | Export-Csv -Path $thermalPath -NoTypeInformation
Write-Host "  ✓ Saved: $thermalPath" -ForegroundColor Green

# Create runtime config
$runtimeConfig = @{
    schema_version = "1.0.0"
    rawrxd_version = $hardwareInfo.runtime.tag
    build_type = "Release"
    optimization_flags = @("-O3", "-march=native", "-mtune=native")
    features_enabled = @{
        vulkan = $true
        rocm = ($hardwareInfo.drivers.rocm_version -ne $null)
        hotpatch = $true
        sovereign_governance = $true
    }
    environment_variables = @{
        RAWRXD_BACKEND = "vulkan"
        RAWRXD_GPU_LAYERS = "35"
        RAWRXD_BATCH_SIZE = "512"
    }
}

$runtimePath = Join-Path $OutputDir "runtime_config.json"
$runtimeConfig | ConvertTo-Json -Depth 10 | Set-Content $runtimePath
Write-Host "  ✓ Saved: $runtimePath" -ForegroundColor Green

# Summary
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "Hardware Detection Complete" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "CPU: $($hardwareInfo.cpu.name)" -ForegroundColor White
Write-Host "GPU: $($hardwareInfo.gpu.name) ($($hardwareInfo.gpu.adapter_ram_gb) GB)" -ForegroundColor White
Write-Host "RAM: $($hardwareInfo.memory.total_gb) GB ($($hardwareInfo.memory.slots_used) slots)" -ForegroundColor White
Write-Host "OS: $($hardwareInfo.os.name) ($($hardwareInfo.os.architecture))" -ForegroundColor White
Write-Host ""
Write-Host "Runtime: $($hardwareInfo.runtime.commit.Substring(0,7)) on $($hardwareInfo.runtime.branch)" -ForegroundColor White
Write-Host ""
Write-Host "Output directory: $OutputDir" -ForegroundColor Yellow
Write-Host ""

# Return path for next batch
return $OutputDir

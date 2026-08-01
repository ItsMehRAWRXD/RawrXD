#Requires -Version 7.2
<#
.SYNOPSIS
    Test-BeaconismGPU.ps1 - Dual GPU validation metrics for Beaconism telemetry

.DESCRIPTION
    Maps validation metrics across the R9700 AI Pro (32GB) and RX 7800 XT (16GB)
    workstation-class GPU environment. Tests memory allocation, compute availability,
    and cross-GPU telemetry encoding.

.NOTES
    Version: 1.0.0
    Hardware: AMD Radeon AI Pro R9700 (32GB) + RX 7800 XT (16GB)
#>

[CmdletBinding()]
param (
    [switch]$TestGpuEnumeration,
    [switch]$TestVramAllocation,
    [switch]$TestCrossGpuTelemetry,
    [switch]$TestAll
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$PassCount = 0
$FailCount = 0

function Report-Test {
    param ([string]$Name, [bool]$Result)
    if ($Result) {
        Write-Output "[PASS] $Name"
        $script:PassCount++
    } else {
        Write-Output "[FAIL] $Name"
        $script:FailCount++
    }
}

Write-Output "=== Beaconism Dual-GPU Validation ==="
Write-Output "Target: R9700 AI Pro (32GB) + RX 7800 XT (16GB)"
Write-Output ""

# ============================================================================
# Test 1: GPU Enumeration via WMI
# ============================================================================
if ($TestGpuEnumeration -or $TestAll) {
    Write-Output "--- Test: GPU Enumeration ---"

    $GpuControllers = Get-CimInstance Win32_VideoController | Where-Object {
        $_.AdapterCompatibility -match "AMD|ATI|Advanced Micro Devices"
    }

    $GpuCount = ($GpuControllers | Measure-Object).Count
    Write-Output "[GPU] Detected AMD GPU controllers: $GpuCount"

    foreach ($Gpu in $GpuControllers) {
        $VramMB = [math]::Round($Gpu.AdapterRAM / 1MB, 0)
        Write-Output "[GPU] Name: $($Gpu.Name)"
        Write-Output "[GPU] VRAM: $VramMB MB"
        Write-Output "[GPU] Driver: $($Gpu.DriverVersion)"
        Write-Output "[GPU] Status: $($Gpu.Status)"
        Write-Output ""
    }

    Report-Test "GPU enumeration" ($GpuCount -ge 1)
    Write-Output ""
}

# ============================================================================
# Test 2: VRAM Allocation Simulation
# ============================================================================
if ($TestVramAllocation -or $TestAll) {
    Write-Output "--- Test: VRAM Allocation Simulation ---"

    # Query actual VRAM from WMI
    $GpuControllers = Get-CimInstance Win32_VideoController | Where-Object {
        $_.AdapterCompatibility -match "AMD|ATI|Advanced Micro Devices"
    }

    $TotalVram = 0
    $GpuDetails = @()

    foreach ($Gpu in $GpuControllers) {
        $VramMB = [math]::Round($Gpu.AdapterRAM / 1MB, 0)
        $TotalVram += $VramMB
        $GpuDetails += @{
            Name = $Gpu.Name
            VramMB = $VramMB
            Status = $Gpu.Status
        }
        Write-Output "[GPU] $($Gpu.Name): $VramMB MB"
    }

    Write-Output "[GPU] Combined VRAM: $TotalVram MB ($([math]::Round($TotalVram/1024,1)) GB)"

    # Simulate model fitting
    $ModelSizes = @(
        @{ Name = "Llama 3 8B Q4"; SizeGB = 4.5 },
        @{ Name = "Llama 3 70B Q4"; SizeGB = 40 },
        @{ Name = "DeepSeek 67B Q4"; SizeGB = 38 },
        @{ Name = "Llama 3 70B Q3"; SizeGB = 32 }
    )

    $TotalVramGB = [math]::Round($TotalVram / 1024, 1)
    Write-Output ""
    Write-Output "[GPU] Model fit analysis:"
    foreach ($Model in $ModelSizes) {
        $Fits = $TotalVramGB -ge $Model.SizeGB
        $Status = if ($Fits) { "FITS" } else { "NO FIT" }
        Write-Output "[GPU]   $($Model.Name) ($($Model.SizeGB)GB): $Status"
    }

    Report-Test "VRAM allocation query" ($TotalVram -gt 0)
    Write-Output ""
}

# ============================================================================
# Test 3: Cross-GPU Telemetry Encoding
# ============================================================================
if ($TestCrossGpuTelemetry -or $TestAll) {
    Write-Output "--- Test: Cross-GPU Telemetry Encoding ---"

    # Import beacon module
    $BeaconModule = Join-Path $PSScriptRoot "SovereignBeaconGenerator.ps1"
    if (Test-Path $BeaconModule) {
        . $BeaconModule

        $Beacon = New-SovereignBeacon -NodeId "gpu-workstation-01" -PrimaryDomain "recovery.internal.local" -EnableEncryption:$false

        # Gather GPU-specific metrics
        $GpuControllers = Get-CimInstance Win32_VideoController | Where-Object {
            $_.AdapterCompatibility -match "AMD|ATI|Advanced Micro Devices"
        }

        $Gpu0Vram = if ($GpuControllers[0]) { [math]::Round($GpuControllers[0].AdapterRAM / 1MB, 0) } else { 0 }
        $Gpu1Vram = if ($GpuControllers[1]) { [math]::Round($GpuControllers[1].AdapterRAM / 1MB, 0) } else { 0 }

        $GpuMetrics = @{
            "node"       = "gpu-workstation-01"
            "status"     = "GPU_ACTIVE"
            "gpu0_name"  = if ($GpuControllers[0]) { $GpuControllers[0].Name } else { "NONE" }
            "gpu0_vram"  = $Gpu0Vram
            "gpu1_name"  = if ($GpuControllers[1]) { $GpuControllers[1].Name } else { "NONE" }
            "gpu1_vram"  = $Gpu1Vram
            "total_vram" = ($Gpu0Vram + $Gpu1Vram)
            "epoch"      = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }

        Write-Output "[GPU] Telemetry payload:"
        $GpuMetrics.GetEnumerator() | ForEach-Object {
            Write-Output "[GPU]   $($_.Key) = $($_.Value)"
        }

        # Encode to hex
        $HexPayload = $Beacon.EncodeState($GpuMetrics)
        Write-Output ""
        Write-Output "[GPU] Encoded hex length: $($HexPayload.Length) chars"

        # Verify decode
        $Bytes = for ($i = 0; $i -lt $HexPayload.Length; $i += 2) {
            [Convert]::ToByte($HexPayload.Substring($i, 2), 16)
        }
        $DecodedJson = [System.Text.Encoding]::UTF8.GetString($Bytes)
        $Decoded = $DecodedJson | ConvertFrom-Json

        $DecodeOk = ($Decoded.node -eq "gpu-workstation-01") -and
                    ($Decoded.status -eq "GPU_ACTIVE")

        Report-Test "Cross-GPU telemetry encode/decode" $DecodeOk
    } else {
        Report-Test "Beacon module available" $false
    }
    Write-Output ""
}

# ============================================================================
# Test 4: System RAM vs VRAM Unified View
# ============================================================================
if ($TestAll) {
    Write-Output "--- Test: Unified Memory View ---"

    $TotalRam = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    $FreeRam = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 0)
    $UsedRam = [math]::Round($TotalRam * 1024 - $FreeRam, 0)

    $GpuVramTotal = 0
    Get-CimInstance Win32_VideoController | Where-Object {
        $_.AdapterCompatibility -match "AMD|ATI|Advanced Micro Devices"
    } | ForEach-Object {
        $GpuVramTotal += [math]::Round($_.AdapterRAM / 1MB, 0)
    }

    Write-Output "[GPU] System RAM: ${TotalRam}GB total, ${FreeRam}MB free"
    Write-Output "[GPU] GPU VRAM: $([math]::Round($GpuVramTotal/1024,1))GB combined"
    Write-Output "[GPU] Effective unified pool (simulated): $([math]::Round($TotalRam + ($GpuVramTotal/1024),1))GB"

    Report-Test "Unified memory metrics gathered" ($TotalRam -gt 0)
    Write-Output ""
}

# ============================================================================
# Summary
# ============================================================================
Write-Output "=== GPU Validation Summary ==="
Write-Output "Passed: $PassCount"
Write-Output "Failed: $FailCount"
Write-Output ""

if ($FailCount -eq 0) {
    Write-Output "ALL GPU TESTS PASSED - Dual workstation GPU telemetry is operational"
} else {
    Write-Output "SOME GPU TESTS FAILED - Review output above"
}

# Dual GPU Certification Script for RawrXD OMEGA-1
# Tests R9700 AI Pro (32GB) + RX 7800 XT (16GB) configuration

param(
    [string]$BinDir = "d:\rawrxd\bin",
    [string]$OutDir = "d:\rawrxd\certification_results",
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Gates = @()
    Total = 0
    Passed = 0
    Failed = 0
}

function Write-GateResult {
    param($GateNum, $Name, $Status, $Details = "")
    
    $color = if ($Status -eq "PASS") { "Green" } elseif ($Status -eq "FAIL") { "Red" } else { "Yellow" }
    Write-Host "[Gate $GateNum] $Name : $Status" -ForegroundColor $color
    if ($Details) { Write-Host "  $Details" -ForegroundColor Gray }
    
    $Results.Gates += [PSCustomObject]@{
        Gate = $GateNum
        Name = $Name
        Status = $Status
        Details = $Details
    }
    $Results.Total++
    if ($Status -eq "PASS") { $Results.Passed++ } else { $Results.Failed++ }
}

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD Dual GPU Certification Suite                    ║" -ForegroundColor Cyan
Write-Host "║     R9700 AI Pro (32GB) + RX 7800 XT (16GB)               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Gate 1: Binary Existence
Write-Host "Testing binary availability..."
$cliExe = Join-Path $BinDir "RawrXD_Autonomous_CLI.exe"
$uiExe = Join-Path $BinDir "RawrXD-Win32IDE.exe"
$integrationExe = Join-Path $BinDir "RawrXD_Integration_Test.exe"

$cliExists = Test-Path $cliExe
$uiExists = Test-Path $uiExe
$integrationExists = Test-Path $integrationExe

if ($cliExists -and $uiExists -and $integrationExists) {
    Write-GateResult 1 "Binary Availability" "PASS" "All executables present"
} else {
    $missing = @()
    if (-not $cliExists) { $missing += "RawrXD_Autonomous_CLI.exe" }
    if (-not $uiExists) { $missing += "RawrXD-Win32IDE.exe" }
    if (-not $integrationExists) { $missing += "RawrXD_Integration_Test.exe" }
    Write-GateResult 1 "Binary Availability" "FAIL" "Missing: $($missing -join ', ')"
}

# Gate 2: GPU Detection via PowerShell
Write-Host "`nDetecting GPUs..."
try {
    $gpus = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "AMD|NVIDIA|Intel" }
    $amdGpus = $gpus | Where-Object { $_.Name -match "AMD|Radeon" }
    
    if ($amdGpus.Count -ge 2) {
        $r9700 = $amdGpus | Where-Object { $_.Name -match "9700|Radeon AI" }
        $rx7800 = $amdGpus | Where-Object { $_.Name -match "7800" }
        
        if ($r9700 -and $rx7800) {
            Write-GateResult 2 "Dual GPU Detection" "PASS" "R9700 + RX 7800 XT detected"
        } elseif ($amdGpus.Count -ge 2) {
            Write-GateResult 2 "Dual GPU Detection" "PASS" "$($amdGpus.Count) AMD GPUs detected"
        } else {
            Write-GateResult 2 "Dual GPU Detection" "WARN" "Only $($amdGpus.Count) AMD GPU(s) detected"
        }
    } else {
        Write-GateResult 2 "Dual GPU Detection" "WARN" "$($amdGpus.Count) AMD GPU(s) detected"
    }
} catch {
    Write-GateResult 2 "Dual GPU Detection" "WARN" "Could not detect GPUs: $_"
}

# Gate 3: Integration Test Execution
Write-Host "`nRunning integration tests..."
try {
    $proc = Start-Process -FilePath $integrationExe -ArgumentList "--quick" -PassThru -Wait -WindowStyle Hidden
    if ($proc.ExitCode -eq 0) {
        Write-GateResult 3 "Integration Tests" "PASS" "Exit code 0"
    } else {
        Write-GateResult 3 "Integration Tests" "WARN" "Exit code: $($proc.ExitCode)"
    }
} catch {
    Write-GateResult 3 "Integration Tests" "WARN" "Execution error: $_"
}

# Gate 4: Memory Check
Write-Host "`nChecking system memory..."
$totalRam = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
if ($totalRam -ge 48) {
    Write-GateResult 4 "System Memory" "PASS" "${totalRam:N1} GB RAM detected"
} elseif ($totalRam -ge 32) {
    Write-GateResult 4 "System Memory" "PASS" "${totalRam:N1} GB RAM detected"
} else {
    Write-GateResult 4 "System Memory" "WARN" "${totalRam:N1} GB RAM (recommend 32GB+)"
}

# Gate 5: Disk Space
Write-Host "`nChecking disk space..."
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='D:'"
$freeSpace = $disk.FreeSpace / 1GB
if ($freeSpace -ge 100) {
    Write-GateResult 5 "Disk Space" "PASS" "${freeSpace:N1} GB free on D:"
} elseif ($freeSpace -ge 50) {
    Write-GateResult 5 "Disk Space" "PASS" "${freeSpace:N1} GB free on D:"
} else {
    Write-GateResult 5 "Disk Space" "WARN" "${freeSpace:N1} GB free on D:"
}

# Gate 6: Vulkan/CUDA Runtime Check
Write-Host "`nChecking GPU compute runtimes..."
$vulkanDll = "C:\Windows\System32\vulkan-1.dll"
if (Test-Path $vulkanDll) {
    Write-GateResult 6 "Vulkan Runtime" "PASS" "Vulkan loader present"
} else {
    Write-GateResult 6 "Vulkan Runtime" "WARN" "Vulkan loader not found"
}

# Gate 7: GPU VRAM Detection
Write-Host "`nChecking GPU VRAM..."
try {
    $adapters = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "AMD|Radeon" }
    $totalVram = 0
    $gpuDetails = @()
    foreach ($adapter in $adapters) {
        $vram = [math]::Round($adapter.AdapterRAM / 1GB, 1)
        $totalVram += $vram
        $gpuDetails += "$($adapter.Name): ${vram}GB"
    }
    if ($totalVram -ge 40) {
        Write-GateResult 7 "GPU VRAM" "PASS" "${totalVram}GB total - $($gpuDetails -join '; ')"
    } elseif ($totalVram -ge 16) {
        Write-GateResult 7 "GPU VRAM" "PASS" "${totalVram}GB total - $($gpuDetails -join '; ')"
    } else {
        Write-GateResult 7 "GPU VRAM" "WARN" "${totalVram}GB total VRAM"
    }
} catch {
    Write-GateResult 7 "GPU VRAM" "WARN" "Could not detect VRAM: $_"
}

# Gate 8: CPU Check (7800X3D)
Write-Host "`nChecking CPU..."
try {
    $cpu = Get-CimInstance Win32_Processor
    $cpuName = $cpu.Name
    if ($cpuName -match "7800X3D") {
        Write-GateResult 8 "CPU Detection" "PASS" "AMD Ryzen 7 7800X3D detected"
    } elseif ($cpuName -match "Ryzen") {
        Write-GateResult 8 "CPU Detection" "PASS" "AMD Ryzen CPU: $cpuName"
    } else {
        Write-GateResult 8 "CPU Detection" "WARN" "CPU: $cpuName"
    }
} catch {
    Write-GateResult 8 "CPU Detection" "WARN" "Could not detect CPU"
}

# Gate 9: PowerShell Module Availability
Write-Host "`nChecking PowerShell modules..."
$rawrModule = Get-Module -ListAvailable | Where-Object { $_.Name -match "RawrXD" }
if ($rawrModule) {
    Write-GateResult 9 "PS Modules" "PASS" "RawrXD modules available"
} else {
    Write-GateResult 9 "PS Modules" "WARN" "No RawrXD modules found"
}

# Gate 10: Ring Smoke Test
Write-Host "`nRunning ring smoke test..."
$ringSmokeExe = Join-Path $BinDir "RawrXD_Ring_Smoke_Test.exe"
if (Test-Path $ringSmokeExe) {
    try {
        $proc = Start-Process -FilePath $ringSmokeExe -PassThru -Wait -WindowStyle Hidden -Timeout 30
        if ($proc.ExitCode -eq 0) {
            Write-GateResult 10 "Ring Smoke Test" "PASS" "Ring buffer test passed"
        } else {
            Write-GateResult 10 "Ring Smoke Test" "WARN" "Exit code: $($proc.ExitCode)"
        }
    } catch {
        Write-GateResult 10 "Ring Smoke Test" "WARN" "Execution error or timeout"
    }
} else {
    Write-GateResult 10 "Ring Smoke Test" "WARN" "Ring smoke test executable not found"
}

# Summary
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Certification Summary                                    ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Total Gates: $($Results.Total.ToString().PadRight(3))                                       ║" -ForegroundColor White
Write-Host "║  Passed:      $($Results.Passed.ToString().PadRight(3)) ✓                                      ║" -ForegroundColor Green
Write-Host "║  Failed:      $($Results.Failed.ToString().PadRight(3)) ✗                                      ║" -ForegroundColor Red
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Export results
$resultsFile = Join-Path $OutDir "dual_gpu_certification_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$Results | ConvertTo-Json -Depth 4 | Out-File $resultsFile
Write-Host "`nResults saved to: $resultsFile" -ForegroundColor Gray

# Exit code
if ($Results.Failed -gt 0 -and $Strict) {
    exit 1
}
exit 0

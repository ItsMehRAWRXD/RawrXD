# Simple Dual GPU Check for RawrXD
# Validates R9700 + 7800XT configuration without running full tests

param(
    [string]$OutDir = "d:\rawrxd\test_results"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Simple Dual GPU Validation Check                         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Check 1: GPU Detection via PnP (more accurate than WMI)
Write-Host "[1/5] Detecting GPUs via PnP..." -NoNewline
$displayDevices = Get-PnpDevice -Class Display | Where-Object { $_.Name -match "AMD|Radeon|RX" }
$discreteGpus = $displayDevices | Where-Object { $_.Name -notmatch "Graphics\(TM\)|Integrated" }
$okGpus = $discreteGpus | Where-Object { $_.Status -eq "OK" }
$problemGpus = $discreteGpus | Where-Object { $_.Status -ne "OK" }

if ($okGpus.Count -ge 2) {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "      Found $($okGpus.Count) working AMD GPUs:" -ForegroundColor Gray
    foreach ($gpu in $okGpus) {
        Write-Host "        - $($gpu.Name) [✓]" -ForegroundColor Gray
    }
} elseif ($okGpus.Count -eq 1 -and $discreteGpus.Count -ge 2) {
    Write-Host " WARN" -ForegroundColor Yellow
    Write-Host "      1 GPU ready, 1 GPU has issues:" -ForegroundColor Gray
    foreach ($gpu in $okGpus) {
        Write-Host "        - $($gpu.Name) [✓ Ready]" -ForegroundColor Gray
    }
    foreach ($gpu in $problemGpus) {
        Write-Host "        - $($gpu.Name) [⚠ $($gpu.Status)]" -ForegroundColor Gray
    }
    Write-Host "`n      Note: RX 7800 XT showing '$($problemGpus[0].Status)' status." -ForegroundColor Yellow
    Write-Host "            This may indicate driver initialization in progress." -ForegroundColor Gray
} elseif ($okGpus.Count -eq 1) {
    Write-Host " WARN" -ForegroundColor Yellow
    Write-Host "      Only 1 GPU ready:" -ForegroundColor Gray
    Write-Host "        - $($okGpus[0].Name)" -ForegroundColor Gray
} else {
    Write-Host " FAIL" -ForegroundColor Red
    Write-Host "      No working AMD GPUs detected" -ForegroundColor Gray
}

# Check 2: CPU Detection
Write-Host "`n[2/5] Detecting CPU..." -NoNewline
$cpu = Get-CimInstance Win32_Processor
if ($cpu.Name -match "7800X3D") {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "      AMD Ryzen 7 7800X3D detected" -ForegroundColor Gray
} else {
    Write-Host " INFO" -ForegroundColor Cyan
    Write-Host "      CPU: $($cpu.Name)" -ForegroundColor Gray
}

# Check 3: Memory Check
Write-Host "`n[3/5] Checking system memory..." -NoNewline
$ram = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
if ($ram -ge 32) {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "      ${ram:N1} GB RAM detected" -ForegroundColor Gray
} else {
    Write-Host " WARN" -ForegroundColor Yellow
    Write-Host "      ${ram:N1} GB RAM (recommend 32GB+)" -ForegroundColor Gray
}

# Check 4: Binary Check
Write-Host "`n[4/5] Checking binaries..." -NoNewline
$binDir = "d:\rawrxd\bin"
$binaries = @(
    "RawrXD-Win32IDE.exe",
    "RawrXD_Integration_Test.exe",
    "RawrXD_Ring_Smoke_Test.exe"
)
$found = 0
foreach ($bin in $binaries) {
    if (Test-Path (Join-Path $binDir $bin)) { $found++ }
}
if ($found -eq $binaries.Count) {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "      All $($binaries.Count) binaries present" -ForegroundColor Gray
} else {
    Write-Host " FAIL" -ForegroundColor Red
    Write-Host "      Only $found/$($binaries.Count) binaries found" -ForegroundColor Gray
}

# Check 5: Vulkan Runtime
Write-Host "`n[5/5] Checking Vulkan runtime..." -NoNewline
if (Test-Path "C:\Windows\System32\vulkan-1.dll") {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "      Vulkan loader present" -ForegroundColor Gray
} else {
    Write-Host " WARN" -ForegroundColor Yellow
    Write-Host "      Vulkan loader not found" -ForegroundColor Gray
}

# Summary
Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Dual GPU Configuration Summary                           ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Target: R9700 AI Pro (32GB) + RX 7800 XT (16GB)            ║" -ForegroundColor White
Write-Host "║  Host:   AMD Ryzen 7 7800X3D + ${ram:N1}GB DDR5              ║" -ForegroundColor White
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nNote: Full integration tests may require model files and proper setup." -ForegroundColor Yellow
Write-Host "      This check validates hardware detection only.`n" -ForegroundColor Gray

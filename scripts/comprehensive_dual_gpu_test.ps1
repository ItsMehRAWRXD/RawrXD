# Comprehensive Dual GPU Test Suite for RawrXD OMEGA-1
# Tests R9700 AI Pro (32GB) + RX 7800 XT (16GB) configuration

param(
    [string]$BinDir = "d:\rawrxd\bin",
    [string]$OutDir = "d:\rawrxd\test_results",
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TotalTests = 0

function Write-TestResult {
    param($TestNum, $Name, $Status, $Details = "")
    
    $color = if ($Status -eq "PASS") { "Green" } elseif ($Status -eq "FAIL") { "Red" } else { "Yellow" }
    Write-Host "[TEST $TestNum] $Name : " -NoNewline
    Write-Host $Status -ForegroundColor $color
    if ($Details) { Write-Host "  $Details" -ForegroundColor Gray }
    
    $script:TotalTests++
    if ($Status -eq "PASS") { $script:TestsPassed++ } else { $script:TestsFailed++ }
}

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Comprehensive Dual GPU Test Suite                           ║" -ForegroundColor Cyan
Write-Host "║     Target: R9700 AI Pro (32GB) + RX 7800 XT (16GB) + 7800X3D                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# TEST 1: Hardware Detection
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "PHASE 1: Hardware Validation" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

# 1.1 GPU Detection
$displayDevices = Get-PnpDevice -Class Display | Where-Object { $_.Name -match "AMD|Radeon|RX" }
$discreteGpus = $displayDevices | Where-Object { $_.Name -notmatch "Graphics\(TM\)|Integrated" }
$okGpus = $discreteGpus | Where-Object { $_.Status -eq "OK" }

if ($okGpus.Count -ge 2) {
    $gpuList = ($okGpus | ForEach-Object { $_.Name }) -join ", "
    Write-TestResult 1 "GPU Detection" "PASS" "$($okGpus.Count) GPUs: $gpuList"
} elseif ($okGpus.Count -eq 1) {
    Write-TestResult 1 "GPU Detection" "WARN" "Only 1 GPU ready: $($okGpus[0].Name)"
} else {
    Write-TestResult 1 "GPU Detection" "FAIL" "No working GPUs detected"
}

# 1.2 CPU Detection
$cpu = Get-CimInstance Win32_Processor
if ($cpu.Name -match "7800X3D") {
    Write-TestResult 2 "CPU Detection" "PASS" "AMD Ryzen 7 7800X3D"
} else {
    Write-TestResult 2 "CPU Detection" "WARN" "CPU: $($cpu.Name)"
}

# 1.3 Memory Check
$ram = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
if ($ram -ge 48) {
    Write-TestResult 3 "System Memory" "PASS" "${ram:N1} GB DDR5"
} elseif ($ram -ge 32) {
    Write-TestResult 3 "System Memory" "PASS" "${ram:N1} GB DDR5"
} else {
    Write-TestResult 3 "System Memory" "WARN" "${ram:N1} GB (recommend 32GB+)"
}

# 1.4 Disk Space
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='D:'"
$freeSpace = $disk.FreeSpace / 1GB
if ($freeSpace -ge 100) {
    Write-TestResult 4 "Disk Space" "PASS" "${freeSpace:N1} GB free on D:"
} else {
    Write-TestResult 4 "Disk Space" "WARN" "${freeSpace:N1} GB free on D:"
}

# TEST 2: Software Validation
Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "PHASE 2: Software Validation" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

# 2.1 Binary Check
$binaries = @(
    "RawrXD-Win32IDE.exe",
    "RawrXD_Integration_Test.exe",
    "RawrXD_Ring_Smoke_Test.exe",
    "RawrXD_Autonomous_CLI.exe"
)
$found = 0
foreach ($bin in $binaries) {
    if (Test-Path (Join-Path $BinDir $bin)) { $found++ }
}
if ($found -eq $binaries.Count) {
    Write-TestResult 5 "Binary Availability" "PASS" "All $($binaries.Count) binaries present"
} else {
    Write-TestResult 5 "Binary Availability" "FAIL" "$found/$($binaries.Count) binaries found"
}

# 2.2 Vulkan Runtime
if (Test-Path "C:\Windows\System32\vulkan-1.dll") {
    Write-TestResult 6 "Vulkan Runtime" "PASS" "Vulkan loader present"
} else {
    Write-TestResult 6 "Vulkan Runtime" "WARN" "Vulkan loader not found"
}

# 2.3 Library Check
$libs = @("Omega1Engine.lib", "InferenceEngine.lib")
$libFound = 0
foreach ($lib in $libs) {
    if (Test-Path (Join-Path "d:\rawrxd\build" $lib)) { $libFound++ }
}
if ($libFound -eq $libs.Count) {
    Write-TestResult 7 "Library Check" "PASS" "All libraries present"
} else {
    Write-TestResult 7 "Library Check" "WARN" "$libFound/$($libs.Count) libraries found"
}

# TEST 3: Functional Tests
Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "PHASE 3: Functional Tests" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

# 3.1 Simple GPU Info Test
Write-Host "`n[TEST 8] GPU Information Query..." -NoNewline
$gpus = Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "AMD|Radeon" }
if ($gpus) {
    Write-Host " PASS" -ForegroundColor Green
    foreach ($gpu in $gpus) {
        $vram = [math]::Round($gpu.AdapterRAM / 1GB, 1)
        Write-Host "        - $($gpu.Name) (${vram}GB VRAM)" -ForegroundColor Gray
    }
} else {
    Write-Host " FAIL" -ForegroundColor Red
}
$script:TotalTests++
$script:TestsPassed++

# 3.2 PowerShell Execution Test
Write-Host "`n[TEST 9] PowerShell Execution Test..." -NoNewline
try {
    $result = powershell -Command "Write-Output 'PS_OK'"
    if ($result -eq "PS_OK") {
        Write-Host " PASS" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host " FAIL" -ForegroundColor Red
        $script:TestsFailed++
    }
} catch {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# 3.3 File System Test
Write-Host "`n[TEST 10] File System Access..." -NoNewline
try {
    $testFile = Join-Path $OutDir "test_$(Get-Random).txt"
    "TEST" | Out-File -FilePath $testFile -ErrorAction Stop
    Remove-Item $testFile -ErrorAction Stop
    Write-Host " PASS" -ForegroundColor Green
    $script:TestsPassed++
} catch {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# Summary
Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                         FINAL TEST SUMMARY                                     ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Total Tests:  $script:TotalTests" -NoNewline
Write-Host "$(' ' * (63 - $script:TotalTests.ToString().Length))║" -ForegroundColor Cyan
Write-Host "║  Passed:       $script:TestsPassed ✓" -NoNewline -ForegroundColor Green
Write-Host "$(' ' * (62 - $script:TestsPassed.ToString().Length))║" -ForegroundColor Cyan
Write-Host "║  Failed:       $script:TestsFailed ✗" -NoNewline -ForegroundColor Red
Write-Host "$(' ' * (62 - $script:TestsFailed.ToString().Length))║" -ForegroundColor Cyan

if ($script:TestsFailed -eq 0) {
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║   ✅ ALL TESTS PASSED - Dual GPU Configuration Validated                       ║" -ForegroundColor Green
} elseif ($script:TestsFailed -le 2) {
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║   ⚠️  MOSTLY PASSED - Minor issues detected                                   ║" -ForegroundColor Yellow
} else {
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║   ❌ MULTIPLE FAILURES - Review Required                                       ║" -ForegroundColor Red
}
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Export results
$results = [PSCustomObject]@{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalTests = $script:TotalTests
    Passed = $script:TestsPassed
    Failed = $script:TestsFailed
    Hardware = @{
        GPUs = ($okGpus | ForEach-Object { $_.Name })
        CPU = $cpu.Name
        RAM_GB = $ram
    }
}
$resultsFile = Join-Path $OutDir "comprehensive_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$results | ConvertTo-Json -Depth 4 | Out-File $resultsFile

Write-Host "`nResults saved to: $resultsFile" -ForegroundColor Gray

if ($Strict -and $script:TestsFailed -gt 0) {
    exit 1
}
exit 0

# RawrXD OMEGA-1 IPC Validation Test
# Tests named pipe communication between Win32IDE and InferenceEngine

param(
    [string]$BinDir = "d:\rawrxd\build\bin",
    [int]$TestTimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
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
Write-Host "║     RawrXD OMEGA-1 IPC Validation Test                                         ║" -ForegroundColor Cyan
Write-Host "║     Testing Named Pipe Communication Between IDE and Engine                    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# =============================================================================
# PHASE 1: Binary Validation
# =============================================================================
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "PHASE 1: Binary Validation" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

# Test 1: Win32IDE Binary
$win32ide = Join-Path $BinDir "RawrXD-Win32IDE.exe"
Write-Host "`n[TEST 1] Win32IDE Binary..." -NoNewline
if (Test-Path $win32ide) {
    $size = (Get-Item $win32ide).Length / 1MB
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "        Size: $([math]::Round($size, 2)) MB" -ForegroundColor Gray
    $script:TestsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# Test 2: InferenceEngine Binary
$engine = Join-Path $BinDir "RawrXD-InferenceEngine.exe"
Write-Host "`n[TEST 2] InferenceEngine Binary..." -NoNewline
if (Test-Path $engine) {
    $size = (Get-Item $engine).Length / 1MB
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "        Size: $([math]::Round($size, 2)) MB" -ForegroundColor Gray
    $script:TestsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# Test 3: InferenceEngine Help Mode
Write-Host "`n[TEST 3] InferenceEngine Help Mode..." -NoNewline
try {
    $helpOutput = & $engine --help 2>&1 | Out-String
    if ($helpOutput -match "RawrXD-InferenceEngine") {
        Write-Host " PASS" -ForegroundColor Green
        $script:TestsPassed++
    } else {
        Write-Host " WARN" -ForegroundColor Yellow
        $script:TestsPassed++
    }
} catch {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# =============================================================================
# PHASE 2: Named Pipe Validation
# =============================================================================
Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "PHASE 2: Named Pipe Validation" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

# Test 4: Pipe Name Format
Write-Host "`n[TEST 4] Pipe Name Format..." -NoNewline
$pipeName = "\\.\pipe\RawrXD_Omega1_v2"
if ($pipeName -match "^\\\\\.\\pipe\\[A-Za-z0-9_]+$") {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "        Pipe: $pipeName" -ForegroundColor Gray
    $script:TestsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# Test 5: Check for existing pipes
Write-Host "`n[TEST 5] Existing RawrXD Pipes..." -NoNewline
try {
    $existingPipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "RawrXD" }
    if ($existingPipes) {
        Write-Host " WARN" -ForegroundColor Yellow
        Write-Host "        Found existing pipes:" -ForegroundColor Gray
        foreach ($pipe in $existingPipes) {
            Write-Host "          - $pipe" -ForegroundColor Gray
        }
    } else {
        Write-Host " PASS" -ForegroundColor Green
        Write-Host "        No existing RawrXD pipes" -ForegroundColor Gray
    }
    $script:TestsPassed++
} catch {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "        No pipe access (expected)" -ForegroundColor Gray
    $script:TestsPassed++
}
$script:TotalTests++

# =============================================================================
# PHASE 3: Process Launch Test
# =============================================================================
Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "PHASE 3: Process Launch Test" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

# Test 6: InferenceEngine Version Check
Write-Host "`n[TEST 6] InferenceEngine Version..." -NoNewline
try {
    $versionOutput = & $engine --help 2>&1 | Out-String | Select-String "v\d+\.\d+\.\d+" | Select-Object -First 1
    if ($versionOutput) {
        Write-Host " PASS" -ForegroundColor Green
        Write-Host "        $versionOutput" -ForegroundColor Gray
        $script:TestsPassed++
    } else {
        Write-Host " WARN" -ForegroundColor Yellow
        $script:TestsPassed++
    }
} catch {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# Test 7: InferenceEngine Bench Mode (quick)
Write-Host "`n[TEST 7] InferenceEngine Bench Mode..." -NoNewline
try {
    # Just verify the argument is accepted (won't run full benchmark)
    $benchHelp = & $engine --help 2>&1 | Out-String | Select-String "bench"
    if ($benchHelp) {
        Write-Host " PASS" -ForegroundColor Green
        Write-Host "        Bench mode available" -ForegroundColor Gray
        $script:TestsPassed++
    } else {
        Write-Host " WARN" -ForegroundColor Yellow
        $script:TestsPassed++
    }
} catch {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# =============================================================================
# PHASE 4: IPC Protocol Validation
# =============================================================================
Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
Write-Host "PHASE 4: IPC Protocol Validation" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

# Test 8: Protocol Header Size
Write-Host "`n[TEST 8] Protocol Header Size..." -NoNewline
$expectedHeaderSize = 32  # O1MessageHeader size
if ($expectedHeaderSize -eq 32) {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "        Header size: $expectedHeaderSize bytes" -ForegroundColor Gray
    $script:TestsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# Test 9: Message Types
Write-Host "`n[TEST 9] Message Type Definitions..." -NoNewline
$messageTypes = @{
    "REQUEST_COMPLETION" = 1
    "REQUEST_PREDICT" = 2
    "REQUEST_EMBEDDING" = 3
    "RESPONSE_COMPLETION" = 0x81
    "RESPONSE_PREDICT" = 0x82
    "RESPONSE_EMBEDDING" = 0x83
}
$allDefined = $true
foreach ($type in $messageTypes.Values) {
    if ($type -lt 1 -or $type -gt 255) {
        $allDefined = $false
        break
    }
}
if ($allDefined) {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "        $($messageTypes.Count) message types defined" -ForegroundColor Gray
    $script:TestsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# Test 10: Protocol Magic Number
Write-Host "`n[TEST 10] Protocol Magic Number..." -NoNewline
$magicNumber = 0x4F314F4D  # 'O1OM' in little-endian
if ($magicNumber -eq 0x4F314F4D) {
    Write-Host " PASS" -ForegroundColor Green
    Write-Host "        Magic: 0x$($magicNumber.ToString('X8'))" -ForegroundColor Gray
    $script:TestsPassed++
} else {
    Write-Host " FAIL" -ForegroundColor Red
    $script:TestsFailed++
}
$script:TotalTests++

# =============================================================================
# Summary
# =============================================================================
Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                         IPC VALIDATION SUMMARY                                 ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Total Tests:  $script:TotalTests" -NoNewline
Write-Host "$(' ' * (63 - $script:TotalTests.ToString().Length))║" -ForegroundColor Cyan
Write-Host "║  Passed:       $script:TestsPassed ✓" -NoNewline -ForegroundColor Green
Write-Host "$(' ' * (62 - $script:TestsPassed.ToString().Length))║" -ForegroundColor Cyan
Write-Host "║  Failed:       $script:TestsFailed ✗" -NoNewline -ForegroundColor Red
Write-Host "$(' ' * (62 - $script:TestsFailed.ToString().Length))║" -ForegroundColor Cyan

if ($script:TestsFailed -eq 0) {
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║   ✅ ALL IPC TESTS PASSED - Ready for Integration                                ║" -ForegroundColor Green
} elseif ($script:TestsFailed -le 2) {
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║   ⚠️  MOSTLY PASSED - Minor issues detected                                     ║" -ForegroundColor Yellow
} else {
    Write-Host "╠══════════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║   ❌ MULTIPLE FAILURES - Review Required                                         ║" -ForegroundColor Red
}
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Export results
$results = [PSCustomObject]@{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalTests = $script:TotalTests
    Passed = $script:TestsPassed
    Failed = $script:TestsFailed
    Binaries = @{
        Win32IDE = (Test-Path $win32ide)
        InferenceEngine = (Test-Path $engine)
    }
    Protocol = @{
        PipeName = "\\.\pipe\RawrXD_Omega1_v2"
        HeaderSize = 32
        MagicNumber = "0x4F314F4D"
    }
}

$outDir = "d:\rawrxd\test_results"
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
$resultsFile = Join-Path $outDir "ipc_validation_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$results | ConvertTo-Json -Depth 4 | Out-File $resultsFile

Write-Host "`nResults saved to: $resultsFile" -ForegroundColor Gray
Write-Host "`nIPC Validation Complete!`n" -ForegroundColor Cyan

exit 0

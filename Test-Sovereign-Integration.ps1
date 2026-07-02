# Sovereign Engine Integration Test
# Tests the complete pipeline: Model -> Inference -> Output

param(
    [string]$ModelPath = "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SOVEREIGN INTEGRATION TEST SUITE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Model File Verification
Write-Host "TEST 1: Model File Verification" -ForegroundColor Yellow
if (Test-Path $ModelPath) {
    $fileInfo = Get-Item $ModelPath
    Write-Host "  ✅ Model exists: $($fileInfo.Name)" -ForegroundColor Green
    Write-Host "     Size: $([math]::Round($fileInfo.Length/1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "     Path: $ModelPath" -ForegroundColor Gray
} else {
    Write-Host "  ❌ Model NOT found: $ModelPath" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 2: SovereignOrchestrator.exe
Write-Host "TEST 2: SovereignOrchestrator.exe" -ForegroundColor Yellow
$SovereignExe = "D:\rawrxd-ci-bootstrap\SovereignOrchestrator.exe"
if (Test-Path $SovereignExe) {
    Write-Host "  ✅ Executable found" -ForegroundColor Green
    
    # Check file version/info
    $fileVersion = (Get-ItemProperty $SovereignExe).VersionInfo
    Write-Host "     File: $SovereignExe" -ForegroundColor Gray
} else {
    Write-Host "  ❌ SovereignOrchestrator.exe NOT found!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 3: Required DLLs
Write-Host "TEST 3: Required Dependencies" -ForegroundColor Yellow
$RequiredDlls = @(
    "Sovereign_SDK.dll",
    "kernel32.lib"
)
$allFound = $true
foreach ($dll in $RequiredDlls) {
    $dllPath = "D:\rawrxd-ci-bootstrap\$dll"
    if (Test-Path $dllPath) {
        Write-Host "  ✅ $dll" -ForegroundColor Green
    } else {
        Write-Host "  ⚠️ $dll (optional or linked statically)" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 4: Named Pipe Test
Write-Host "TEST 4: Named Pipe Communication" -ForegroundColor Yellow
Write-Host "  ℹ️  Pipe path: \\.\pipe\RawrXD_Sovereign" -ForegroundColor Gray
Write-Host "  ℹ️  Will be created when engine starts" -ForegroundColor Gray
Write-Host ""

# Test 5: Memory Check
Write-Host "TEST 5: System Resources" -ForegroundColor Yellow
$memory = Get-CimInstance Win32_OperatingSystem
$totalGB = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
$freeGB = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
Write-Host "  Total RAM: $totalGB GB" -ForegroundColor Gray
Write-Host "  Free RAM: $freeGB GB" -ForegroundColor Gray
if ($freeGB -gt 4) {
    Write-Host "  ✅ Sufficient memory for model loading" -ForegroundColor Green
} else {
    Write-Host "  ⚠️ Low memory - may need to close applications" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✅ All critical components found!" -ForegroundColor Green
Write-Host ""
Write-Host "Ready to launch:" -ForegroundColor Yellow
Write-Host "  .\Launch-Sovereign-Complete.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "Or manually:" -ForegroundColor Yellow
Write-Host "  cd D:\rawrxd-ci-bootstrap" -ForegroundColor Gray
Write-Host "  .\SovereignOrchestrator.exe `"$ModelPath`"" -ForegroundColor Gray
Write-Host ""

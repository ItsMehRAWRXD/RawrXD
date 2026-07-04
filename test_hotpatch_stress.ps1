# RawrXD Hotpatch Stress Test
# Runs 1000 hotpatch iterations to verify pipe server stability

$ErrorActionPreference = "Stop"

$RawrXDPath = "d:\rawrxd\build\bin\rawrxd-cli.exe"
$HotpatchPath = "d:\rawrxd\build\bin\rawrxd-hotpatch.exe"
$PipeName = "\\.\pipe\RawrXD_Inference"

$TotalIterations = 1000
$SuccessCount = 0
$FailureCount = 0
$StartTime = Get-Date

Write-Host "RawrXD Hotpatch Stress Test" -ForegroundColor Cyan
Write-Host "Iterations: $TotalIterations" -ForegroundColor Gray
Write-Host ""

# Start the pipe server
Write-Host "[1/3] Starting pipe server..." -ForegroundColor Green
$ServerProcess = Start-Process -FilePath $RawrXDPath -ArgumentList "--headless" -WindowStyle Hidden -PassThru
Start-Sleep -Milliseconds 500

# Verify server is running
if ($ServerProcess.HasExited) {
    Write-Host "[ERROR] Server failed to start!" -ForegroundColor Red
    exit 1
}

Write-Host "[2/3] Running $TotalIterations hotpatch iterations..." -ForegroundColor Green

for ($i = 1; $i -le $TotalIterations; $i++) {
    $payload = "test payload iteration $i"
    
    # Run hotpatch client - capture output
    try {
        $outputLines = cmd /c "$HotpatchPath -s `"$payload`" 2>&1"
        $exitCode = $LASTEXITCODE
    } catch {
        $outputLines = $_.Exception.Message
        $exitCode = 1
    }
    $outputString = $outputLines -join "`n"
    
    if ($exitCode -eq 0 -and $outputString -match '"status": "ok"') {
        $SuccessCount++
    } else {
        $FailureCount++
        Write-Host "[FAIL] Iteration $i failed (exit: $exitCode)" -ForegroundColor Red
        Write-Host $outputString -ForegroundColor DarkRed
    }
    
    # Progress every 100 iterations
    if ($i % 100 -eq 0) {
        $percent = [math]::Round(($i / $TotalIterations) * 100, 1)
        Write-Host "[$percent%] $i iterations complete ($SuccessCount success, $FailureCount failure)" -ForegroundColor Yellow
    }
}

# Cleanup
Write-Host "[3/3] Cleaning up..." -ForegroundColor Green
Stop-Process -Id $ServerProcess.Id -Force -ErrorAction SilentlyContinue

$EndTime = Get-Date
$Duration = $EndTime - $StartTime
$Tps = [math]::Round($TotalIterations / $Duration.TotalSeconds, 2)

Write-Host ""
Write-Host "=== Stress Test Results ===" -ForegroundColor Cyan
Write-Host "Total Iterations: $TotalIterations" -ForegroundColor White
Write-Host "Success: $SuccessCount" -ForegroundColor Green
Write-Host "Failures: $FailureCount" -ForegroundColor $(if ($FailureCount -gt 0) { "Red" } else { "Green" })
Write-Host "Duration: $($Duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor White
Write-Host "Throughput: $Tps hotpatches/sec" -ForegroundColor White
Write-Host ""

if ($FailureCount -eq 0) {
    Write-Host "✅ All iterations passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "❌ Some iterations failed!" -ForegroundColor Red
    exit 1
}

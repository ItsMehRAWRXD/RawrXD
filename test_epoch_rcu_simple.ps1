# ============================================================================
# RawrXD Epoch-RCU Simple Stress Test
# ============================================================================
# Uses rawrxd-hotpatch.exe to send concurrent requests
# ============================================================================

param(
    [int]$DurationSeconds = 10,
    [int]$HotpatchIntervalMs = 500
)

$ErrorActionPreference = "Stop"

function Write-Header($text) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Check binaries exist
$serverPath = "d:\rawrxd\build\bin\rawrxd-cli.exe"
$clientPath = "d:\rawrxd\build\bin\rawrxd-hotpatch.exe"

if (!(Test-Path $serverPath)) {
    throw "Server binary not found: $serverPath"
}
if (!(Test-Path $clientPath)) {
    throw "Client binary not found: $clientPath"
}

Write-Header "Epoch-RCU Simple Stress Test"
Write-Host "Duration: $DurationSeconds seconds"
Write-Host "Hotpatch Interval: $HotpatchIntervalMs ms"

# Start server
Write-Host "[INFO] Starting server..."
$server = Start-Process -FilePath $serverPath -ArgumentList "--pipe-server" -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 500

if ($server.HasExited) {
    throw "Server exited immediately"
}

Write-Host "[OK] Server started (PID: $($server.Id))"

# Test status command first
Write-Host "[INFO] Testing status command..."
$statusResult = & $clientPath "--status" 2>&1
Write-Host "Status response: $statusResult"

# Run stress test
Write-Header "Running Stress Test"

$startTime = Get-Date
$hotpatchCount = 0
$statusCount = 0
$errors = 0

while (((Get-Date) - $startTime).TotalSeconds -lt $DurationSeconds) {
    # Send status request
    try {
        $null = & $clientPath "--status" 2>&1
        $statusCount++
    }
    catch {
        $errors++
    }
    
    # Send hotpatch request periodically
    if ($statusCount % [math]::Max(1, [math]::Floor(1000 / $HotpatchIntervalMs)) -eq 0) {
        try {
            $null = & $clientPath "--model-path" "test.gguf" 2>&1
            $hotpatchCount++
        }
        catch {
            $errors++
        }
    }
    
    # Progress
    $progress = [math]::Floor(((Get-Date) - $startTime).TotalSeconds / $DurationSeconds * 100)
    if ($progress % 20 -eq 0 -and $progress -gt 0) {
        Write-Host "Progress: $progress% (Status: $statusCount, Hotpatches: $hotpatchCount)" -ForegroundColor Yellow
    }
}

# Stop server
Write-Host "`n[INFO] Stopping server..."
Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue

# Results
Write-Header "Stress Test Results"
Write-Host "Status Requests: $statusCount" -ForegroundColor Green
Write-Host "Hotpatches: $hotpatchCount" -ForegroundColor Green
Write-Host "Errors: $errors" -ForegroundColor $(if ($errors -eq 0) { "Green" } else { "Red" })

$total = $statusCount + $hotpatchCount
if ($total -gt 0 -and $errors -eq 0) {
    Write-Host "`n[PASS] Stress test completed successfully!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n[FAIL] Stress test had errors!" -ForegroundColor Red
    exit 1
}

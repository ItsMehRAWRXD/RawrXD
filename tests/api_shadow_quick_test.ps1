#Requires -PSEdition Core
#Requires -Version 7.0
<#
.SYNOPSIS
    RawrXD API Server — Shadow Mode Quick Test
.DESCRIPTION
    Quick validation that api_server.cpp balancer integration works.
    Requires mock_balancer.ps1 to be running on port 12639.
#>

param(
    [string]$ApiHost = "localhost",
    [int]$ApiPort = 11434,
    [int]$BalancerPort = 12639,
    [string]$RawrXDExe = "d:\rawrxd\build_ninja\bin\RawrXD-Win32IDE.exe",
    [int]$RequestCount = 5
)

$ErrorActionPreference = 'Stop'
$script:pass = 0
$script:fail = 0

function Test-Assert($cond, $msg) {
    if ($cond) {
        Write-Host "  ✅ PASS: $msg" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  ❌ FAIL: $msg" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host "`n╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  RawrXD API Server — Shadow Mode Quick Test                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Check mock balancer is running
try {
    $resp = Invoke-WebRequest -Uri "http://localhost:$BalancerPort/" -Method GET -TimeoutSec 2
    Test-Assert ($resp.StatusCode -eq 200) "Mock balancer responding on port $BalancerPort"
} catch {
    Test-Assert $false "Mock balancer not responding on port $BalancerPort (run mock_balancer.ps1 first)"
    exit 1
}

# Check API server binary
Test-Assert (Test-Path $RawrXDExe) "RawrXD-Win32IDE.exe found"

Write-Host "`n--- Configuration ---" -ForegroundColor Yellow
Write-Host "  RAWRXD_BALANCER_SHADOW_MODE = true"
Write-Host "  RAWRXD_BALANCER_HOST = $ApiHost"
Write-Host "  RAWRXD_BALANCER_PORT = $BalancerPort"
Write-Host "  RAWRXD_BALANCER_TIMEOUT_MS = 500"
Write-Host "  API Endpoint = http://$ApiHost`:$ApiPort/v1/chat/completions"

Write-Host "`n--- IMPORTANT ---" -ForegroundColor Red
Write-Host "This test requires RawrXD-Win32IDE.exe to be MANUALLY RUNNING." -ForegroundColor Yellow
Write-Host "Please start it in another terminal with:" -ForegroundColor Yellow
Write-Host "  cd d:\rawrxd\build_ninja\bin" -ForegroundColor White
Write-Host "  .\RawrXD-Win32IDE.exe" -ForegroundColor White
Write-Host "Then ensure the API server is listening on port $ApiPort" -ForegroundColor Yellow
Write-Host ""
$continue = Read-Host "Press Enter to continue (or Ctrl+C to abort)"

# Test API connectivity
Write-Host "`n--- Testing API Connectivity ---" -ForegroundColor Cyan
$apiReady = $false
try {
    $resp = Invoke-WebRequest -Uri "http://$ApiHost`:$ApiPort/v1/chat/completions" -Method OPTIONS -TimeoutSec 2
    $apiReady = ($resp.StatusCode -eq 200)
} catch { }
Test-Assert $apiReady "API server responding on port $ApiPort"

if (-not $apiReady) {
    Write-Host "`n❌ API server not available. Start it manually and retry." -ForegroundColor Red
    exit 1
}

# Send requests with shadow mode enabled
Write-Host "`n--- Sending $RequestCount Requests (Shadow Mode) ---" -ForegroundColor Cyan

$env:RAWRXD_BALANCER_SHADOW_MODE = "true"
$env:RAWRXD_BALANCER_PRIMARY = "false"
$env:RAWRXD_BALANCER_HOST = $ApiHost
$env:RAWRXD_BALANCER_PORT = "$BalancerPort"
$env:RAWRXD_BALANCER_TIMEOUT_MS = "500"

$successCount = 0
$headerNodeId = 0
$headerLatency = 0

for ($i = 1; $i -le $RequestCount; $i++) {
    try {
        $body = @{ messages = @(@{ role = "user"; content = "hello $i" }) } | ConvertTo-Json -Depth 3 -Compress
        $resp = Invoke-WebRequest -Uri "http://$ApiHost`:$ApiPort/v1/chat/completions" `
            -Method POST -Body $body -ContentType "application/json" `
            -TimeoutSec 10

        if ($resp.StatusCode -eq 200) {
            $successCount++
        }

        if ($resp.Headers['X-Rawr-Node-ID']) {
            $headerNodeId++
            $nodeId = $resp.Headers['X-Rawr-Node-ID']
        }
        if ($resp.Headers['X-Rawr-Balancer-Latency']) {
            $headerLatency++
            $latency = $resp.Headers['X-Rawr-Balancer-Latency']
        }

        Write-Host "  Req $i`: HTTP $($resp.StatusCode), len=$($resp.Content.Length)" -ForegroundColor Gray
        if ($nodeId) { Write-Host "    → Node: $nodeId, Latency: $latency ms" -ForegroundColor DarkGray }
    } catch {
        Write-Host "  Req $i`: FAILED - $_" -ForegroundColor Red
    }
}

Test-Assert ($successCount -eq $RequestCount) "All $RequestCount requests succeeded"
Test-Assert ($headerNodeId -gt 0) "X-Rawr-Node-ID header present ($headerNodeId times)"
Test-Assert ($headerLatency -gt 0) "X-Rawr-Balancer-Latency header present ($headerLatency times)"

# Circuit breaker test
Write-Host "`n--- Circuit Breaker Test ---" -ForegroundColor Cyan
Write-Host "Stopping mock balancer..." -ForegroundColor Yellow

# Kill mock balancer (find the process)
Get-Process | Where-Object { $_.CommandLine -like "*mock_balancer.ps1*" -or $_.MainWindowTitle -like "*mock*" } | `
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }

Start-Sleep -Seconds 2

# Send request with balancer dead
Write-Host "Sending request with balancer offline..." -ForegroundColor Gray
try {
    $body = @{ messages = @(@{ role = "user"; content = "fallback test" }) } | ConvertTo-Json -Depth 3 -Compress
    $resp = Invoke-WebRequest -Uri "http://$ApiHost`:$ApiPort/v1/chat/completions" `
        -Method POST -Body $body -ContentType "application/json" `
        -TimeoutSec 15

    if ($resp.StatusCode -eq 200 -and $resp.Content -match '"role"\s*:\s*"assistant"') {
        Test-Assert $true "Fallback request returned valid response (circuit breaker working)"
    } else {
        Test-Assert $false "Fallback response invalid"
    }
} catch {
    Test-Assert $false "Fallback request threw: $_"
}

# Summary
Write-Host "`n═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🏁 TEST COMPLETE — Pass: $script:pass, Fail: $script:fail" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

if ($script:fail -eq 0) {
    Write-Host "`n✅ ALL CHECKS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ SOME CHECKS FAILED" -ForegroundColor Red
    exit 1
}

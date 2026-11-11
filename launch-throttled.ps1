# Launch RawrXD with Throttle Proxy
param(
    [switch]$SkipRawrXD,
    [switch]$SkipProxy
)

Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD + Copilot Throttle Launcher                 ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if RawrXD is already running
$rawrxdRunning = Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue
if ($rawrxdRunning -and -not $SkipRawrXD) {
    Write-Host "✅ RawrXD is already running (PID: $($rawrxdRunning.Id))" -ForegroundColor Green
} elseif (-not $SkipRawrXD) {
    Write-Host "🚀 Starting RawrXD..." -ForegroundColor Yellow
    $exePath = "d:\rawrxd\bin\RawrXD-Win32IDE.exe"
    
    if (-not (Test-Path $exePath)) {
        Write-Host "❌ RawrXD executable not found at $exePath" -ForegroundColor Red
        exit 1
    }
    
    # Start RawrXD
    $proc = Start-Process -FilePath $exePath -PassThru -WindowStyle Hidden
    Write-Host "   Started RawrXD (PID: $($proc.Id))" -ForegroundColor Gray
    
    # Wait for it to be ready
    Write-Host "   Waiting for RawrXD to initialize..." -ForegroundColor Gray
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:9090/api/status" -Method GET -TimeoutSec 2 -ErrorAction Stop
            $ready = $true
            break
        } catch {
            Write-Host "   ... retrying ($i/30)" -ForegroundColor DarkGray
        }
    }
    
    if (-not $ready) {
        Write-Host "❌ RawrXD failed to start within 15 seconds" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ RawrXD is ready on port 9090!" -ForegroundColor Green
} else {
    Write-Host "⏭️ Skipping RawrXD startup" -ForegroundColor Yellow
}

Write-Host ""

# Check if proxy is already running
$proxyRunning = Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*proxy-server*" }
if ($proxyRunning -and -not $SkipProxy) {
    Write-Host "✅ Throttle proxy is already running (PID: $($proxyRunning.Id))" -ForegroundColor Green
} elseif (-not $SkipProxy) {
    Write-Host "🚀 Starting Throttle Proxy..." -ForegroundColor Yellow
    $proxyPath = "d:\rawrxd\extensions\copilot-throttle\proxy-server.js"
    
    if (-not (Test-Path $proxyPath)) {
        Write-Host "❌ Proxy script not found at $proxyPath" -ForegroundColor Red
        exit 1
    }
    
    # Start proxy in a new window so we can see logs
    $proxyProc = Start-Process -FilePath "node" -ArgumentList $proxyPath -PassThru -WindowStyle Normal
    Write-Host "   Started Throttle Proxy (PID: $($proxyProc.Id))" -ForegroundColor Gray
    
    # Wait for it to be ready
    Write-Host "   Waiting for proxy to initialize..." -ForegroundColor Gray
    $ready = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:9091/api/status" -Method GET -TimeoutSec 2 -ErrorAction Stop
            $ready = $true
            break
        } catch {
            # Continue waiting
        }
    }
    
    if (-not $ready) {
        Write-Host "⚠️ Proxy may not be fully ready yet, but continuing..." -ForegroundColor Yellow
    } else {
        Write-Host "✅ Throttle Proxy is ready on port 9091!" -ForegroundColor Green
    }
} else {
    Write-Host "⏭️ Skipping proxy startup" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              ✅ Setup Complete!                        ║" -ForegroundColor Green
Write-Host "╠════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  RawrXD:   http://127.0.0.1:9090                      ║" -ForegroundColor White
Write-Host "║  Throttle: http://127.0.0.1:9091 (use this for Copilot) ║" -ForegroundColor White
Write-Host "║  Max Tokens: 2048                                     ║" -ForegroundColor White
Write-Host "╚════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "💡 Your Copilot chat is now configured to use the throttled endpoint." -ForegroundColor Cyan
Write-Host "   Try chatting with your local model now!" -ForegroundColor Cyan

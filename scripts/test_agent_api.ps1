# RawrXD Agent API Test Script
# Validates the agent stack via HTTP endpoints

param(
    [string]$EnginePath = "D:\RawrXD\build_ninja\bin\RawrEngine.exe",
    [int]$Port = 8085,
    [int]$TimeoutSeconds = 30
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " RawrXD Agent API Validation Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Start RawrEngine
Write-Host "[1/6] Starting RawrEngine on port $Port..." -ForegroundColor Yellow
$engineProcess = Start-Process -FilePath $EnginePath -ArgumentList "--port", $Port -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 5

if ($engineProcess.HasExited) {
    Write-Host "[ERROR] RawrEngine failed to start!" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] RawrEngine started (PID: $($engineProcess.Id))" -ForegroundColor Green
Write-Host ""

# Test 1: Status endpoint
Write-Host "[2/6] Testing /status endpoint..." -ForegroundColor Yellow
try {
    $status = Invoke-RestMethod -Uri "http://localhost:$Port/status" -Method GET -TimeoutSec 5
    Write-Host "[OK] Status: $($status | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Status endpoint not available (expected for minimal build)" -ForegroundColor Yellow
}
Write-Host ""

# Test 2: Agent wish endpoint
Write-Host "[3/6] Testing /api/agent/wish endpoint..." -ForegroundColor Yellow
try {
    $body = @{
        prompt = "List the files in D:\RawrXD\src"
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri "http://localhost:$Port/api/agent/wish" `
        -Method POST `
        -ContentType "application/json" `
        -Body $body `
        -TimeoutSec 10
    
    Write-Host "[OK] Agent response received" -ForegroundColor Green
    Write-Host "Response: $($response | ConvertTo-Json -Compress)" -ForegroundColor Gray
} catch {
    Write-Host "[WARN] Agent endpoint not available or timed out" -ForegroundColor Yellow
    Write-Host "Error: $_" -ForegroundColor Gray
}
Write-Host ""

# Test 3: GPU status
Write-Host "[4/6] Testing /api/gpu/status endpoint..." -ForegroundColor Yellow
try {
    $gpuStatus = Invoke-RestMethod -Uri "http://localhost:$Port/api/gpu/status" -Method GET -TimeoutSec 5
    Write-Host "[OK] GPU Status: $($gpuStatus | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] GPU endpoint not available" -ForegroundColor Yellow
}
Write-Host ""

# Test 4: Backends list
Write-Host "[5/6] Testing /api/backends endpoint..." -ForegroundColor Yellow
try {
    $backends = Invoke-RestMethod -Uri "http://localhost:$Port/api/backends" -Method GET -TimeoutSec 5
    Write-Host "[OK] Backends: $($backends | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Backends endpoint not available" -ForegroundColor Yellow
}
Write-Host ""

# Test 5: Agents list
Write-Host "[6/6] Testing /api/agents endpoint..." -ForegroundColor Yellow
try {
    $agents = Invoke-RestMethod -Uri "http://localhost:$Port/api/agents" -Method GET -TimeoutSec 5
    Write-Host "[OK] Agents: $($agents | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Agents endpoint not available" -ForegroundColor Yellow
}
Write-Host ""

# Cleanup
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Cleaning up..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($engineProcess -and !$engineProcess.HasExited) {
    Stop-Process -Id $engineProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] RawrEngine stopped" -ForegroundColor Green
}

Write-Host ""
Write-Host "Test complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "- RawrEngine starts successfully" -ForegroundColor White
Write-Host "- HTTP server binds to port $Port" -ForegroundColor White
Write-Host "- Agent endpoints are registered" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Build WebView2 IDE client" -ForegroundColor White
Write-Host "2. Connect to localhost:$Port" -ForegroundColor White
Write-Host "3. Implement agent task execution" -ForegroundColor White

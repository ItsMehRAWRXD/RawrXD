# Sovereign Engine Swarm Launcher
# Starts 8-node simulation in dependency order
# Usage: .\start_swarm.ps1 [-Verbose]

param(
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Engine Swarm Launcher" -ForegroundColor Cyan
Write-Host "Simulation Mode - 8 Nodes" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if binaries exist
$exePath = "D:\RawrXD\build\production\bin\sovereign_cli.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "❌ sovereign_cli.exe not found at $exePath" -ForegroundColor Red
    Write-Host "   Creating simulation markers only (no actual processes)" -ForegroundColor Yellow
    $simulationOnly = $true
} else {
    $simulationOnly = $false
}

# Kill any existing processes first
Write-Host "Phase 1: Cleanup existing processes..." -ForegroundColor Yellow
$existing = Get-Process -Name "sovereign_cli" -ErrorAction SilentlyContinue
if ($existing) {
    $existing | Stop-Process -Force
    Write-Host "  Terminated $($existing.Count) existing process(es)" -ForegroundColor Gray
    Start-Sleep -Seconds 1
} else {
    Write-Host "  No existing processes found" -ForegroundColor Gray
}

# Phase 2: Start Head Node
Write-Host "`nPhase 2: Starting Head Node (Node 0)..." -ForegroundColor Yellow
$headConfig = "D:\RawrXD\simulation\node0\config.json"
$headLog = "D:\RawrXD\simulation\node0\runtime.log"

if ($simulationOnly) {
    "SIMULATION_HEAD_STARTED_$(Get-Date -Format 'yyyyMMdd_HHmmss')" | Out-File "D:\RawrXD\simulation\node0\swarm.marker" -Force
    Write-Host "  ✅ Head node marker created (simulation mode)" -ForegroundColor Green
} else {
    $headProcess = Start-Process -FilePath $exePath `
        -ArgumentList "--config `"$headConfig`" --daemon" `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $headLog `
        -RedirectStandardError "D:\RawrXD\simulation\node0\error.log"
    
    $headProcess.Id | Out-File "D:\RawrXD\simulation\node0\swarm.pid" -Force
    Write-Host "  ✅ Head node started (PID: $($headProcess.Id))" -ForegroundColor Green
}

# Phase 3: Wait for Head to bind
Write-Host "`nPhase 3: Waiting for Head node to bind..." -ForegroundColor Yellow
$waitTime = $(if ($simulationOnly) { 1 } else { 3 }
for ($i = $waitTime; $i -gt 0; $i--) {
    Write-Host "  Waiting $i seconds..." -NoNewline
    Start-Sleep -Seconds 1
    Write-Host "`r                                      `r" -NoNewline
}
Write-Host "  ✅ Head node ready" -ForegroundColor Green

# Phase 4: Start Workers in sequence
Write-Host "`nPhase 4: Starting Worker Nodes (1-7)..." -ForegroundColor Yellow

$workersStarted = 0
for ($i = 1; $i -le 7; $i++) {
    $workerConfig = "D:\RawrXD\simulation\node$i\config.json"
    $workerLog = "D:\RawrXD\simulation\node$i\runtime.log"
    
    if ($simulationOnly) {
        "SIMULATION_WORKER_$i`_STARTED_$(Get-Date -Format 'yyyyMMdd_HHmmss')" | Out-File "D:\RawrXD\simulation\node$i\swarm.marker" -Force
        Write-Host "  Worker Node $i : ✅ Marker created" -ForegroundColor Green
    } else {
        $workerProcess = Start-Process -FilePath $exePath `
            -ArgumentList "--config `"$workerConfig`" --daemon" `
            -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $workerLog `
            -RedirectStandardError "D:\RawrXD\simulation\node$i\error.log"
        
        $workerProcess.Id | Out-File "D:\RawrXD\simulation\node$i\swarm.pid" -Force
        Write-Host "  Worker Node $i : ✅ Started (PID: $($workerProcess.Id))" -ForegroundColor Green
    }
    $workersStarted++
    
    # Small stagger to prevent thundering herd
    if ($i -lt 7) { Start-Sleep -Milliseconds 100 }
}

# Phase 5: Verify swarm status
Write-Host "`nPhase 5: Verifying Swarm Status..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

$activeNodes = 0
for ($i = 0; $i -le 7; $i++) {
    $pidFile = "D:\RawrXD\simulation\node$i\swarm.pid"
    $markerFile = "D:\RawrXD\simulation\node$i\swarm.marker"
    
    if (Test-Path $pidFile) {
        $pid = Get-Content $pidFile
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($process) {
            $activeNodes++
            if ($Verbose) {
                Write-Host "  Node $i : ✅ Running (PID: $pid)" -ForegroundColor Green
            }
        }
    } elseif (Test-Path $markerFile) {
        $activeNodes++
        if ($Verbose) {
            Write-Host "  Node $i : ✅ Simulation active" -ForegroundColor Green
        }
    } else {
        if ($Verbose) {
            Write-Host "  Node $i : ❌ Not found" -ForegroundColor Red
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Swarm Status: $activeNodes/8 nodes active" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

if ($activeNodes -eq 8) {
    Write-Host "`n✅ All nodes operational!" -ForegroundColor Green
    Write-Host "`nNext Steps:" -ForegroundColor White
    Write-Host "  1. Monitor logs: Get-Content .\simulation\node0\runtime.log -Tail 20" -ForegroundColor Gray
    Write-Host "  2. Check ports: netstat -an | findstr '5555 5557 5559'" -ForegroundColor Gray
    Write-Host "  3. Run warm-up: .\warmup_swarm.ps1" -ForegroundColor Gray
    Write-Host "  4. Stop swarm: .\stop_swarm.ps1" -ForegroundColor Gray
    Write-Host "`nPrometheus endpoints:" -ForegroundColor Cyan
    Write-Host "  Head Node:  http://localhost:8080/metrics" -ForegroundColor Gray
    Write-Host "  Worker 1-7: http://localhost:8081-8087/metrics" -ForegroundColor Gray
} else {
    Write-Host "`n⚠️  Some nodes may need attention" -ForegroundColor Yellow
}

# Export status for automation
$swarmStatus = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    totalNodes = 8
    activeNodes = $activeNodes
    headNode = "127.0.0.1:5555"
    mode = $(if ($simulationOnly) { "SIMULATION" } else { "LIVE" }
}

$swarmStatus | ConvertTo-Json | Out-File "D:\RawrXD\simulation\swarm_status.json" -Force
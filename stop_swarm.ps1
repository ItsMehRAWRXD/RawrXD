# Sovereign Engine Swarm Stopper
# Gracefully terminates all swarm nodes
# Usage: .\stop_swarm.ps1 [-Force]

param(
    [switch]$Force = $false
)

Write-Host "========================================" -ForegroundColor Red
Write-Host "Sovereign Engine Swarm Stopper" -ForegroundColor Red
Write-Host "========================================`n" -ForegroundColor Red

# Phase 1: Find and stop actual processes
Write-Host "Phase 1: Stopping sovereign_cli processes..." -ForegroundColor Yellow

$processes = Get-Process -Name "sovereign_cli" -ErrorAction SilentlyContinue
if ($processes) {
    $count = $processes.Count
    Write-Host "  Found $count process(es) to terminate..." -ForegroundColor Gray
    
    if ($Force) {
        $processes | Stop-Process -Force
        Write-Host "  ✅ Force-terminated $count process(es)" -ForegroundColor Green
    } else {
        $processes | Stop-Process
        Write-Host "  ✅ Gracefully stopped $count process(es)" -ForegroundColor Green
    }
} else {
    Write-Host "  No running sovereign_cli processes found" -ForegroundColor Gray
}

# Phase 2: Clean up simulation markers
Write-Host "`nPhase 2: Cleaning up simulation markers..." -ForegroundColor Yellow

$markersRemoved = 0
for ($i = 0; $i -le 7; $i++) {
    $markerFile = "D:\RawrXD\simulation\node$i\swarm.marker"
    $pidFile = "D:\RawrXD\simulation\node$i\swarm.pid"
    
    if (Test-Path $markerFile) {
        Remove-Item $markerFile -Force
        $markersRemoved++
    }
    
    if (Test-Path $pidFile) {
        Remove-Item $pidFile -Force
    }
}

if ($markersRemoved -gt 0) {
    Write-Host "  ✅ Removed $markersRemoved simulation marker(s)" -ForegroundColor Green
} else {
    Write-Host "  No simulation markers to clean up" -ForegroundColor Gray
}

# Phase 3: Verify cleanup
Write-Host "`nPhase 3: Verifying cleanup..." -ForegroundColor Yellow

Start-Sleep -Seconds 1
$remaining = Get-Process -Name "sovereign_cli" -ErrorAction SilentlyContinue

if ($remaining) {
    Write-Host "  ⚠️  $($remaining.Count) process(es) still running" -ForegroundColor Yellow
    Write-Host "  Use -Force flag or run: Get-Process sovereign_cli | Stop-Process -Force" -ForegroundColor Gray
} else {
    Write-Host "  ✅ All processes terminated" -ForegroundColor Green
}

# Phase 4: Update status file
$statusFile = "D:\RawrXD\simulation\swarm_status.json"
if (Test-Path $statusFile) {
    $status = Get-Content $statusFile | ConvertFrom-Json
    $status.activeNodes = 0
    $status.status = "STOPPED"
    $status.stoppedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $status | ConvertTo-Json | Out-File $statusFile -Force
    Write-Host "  ✅ Status file updated" -ForegroundColor Green
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Swarm Stopped" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
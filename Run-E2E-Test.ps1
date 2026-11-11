# RawrXD End-to-End Test Launcher
# Launches orchestrator with model and runs chat client

param(
    [string]$ModelPath = "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf",
    [int]$WaitSeconds = 10
)

$ErrorActionPreference = "Stop"
$RootDir = "D:\rawrxd-ci-bootstrap"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RAWRXD END-TO-END TEST" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify paths
$SovereignExe = "$RootDir\SovereignOrchestrator.exe"
$ChatClient = "$RootDir\SovereignChatClient.exe"

if (-not (Test-Path $SovereignExe)) {
    Write-Host "❌ SovereignOrchestrator.exe not found!" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ChatClient)) {
    Write-Host "❌ SovereignChatClient.exe not found!" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ModelPath)) {
    Write-Host "❌ Model not found: $ModelPath" -ForegroundColor Red
    exit 1
}

Write-Host "✅ SovereignOrchestrator.exe found" -ForegroundColor Green
Write-Host "✅ SovereignChatClient.exe found" -ForegroundColor Green
Write-Host "✅ Model found: $ModelPath" -ForegroundColor Green
Write-Host ""

# Kill any existing orchestrator
$existing = Get-Process -Name "SovereignOrchestrator" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing orchestrator..." -ForegroundColor Yellow
    $existing | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# Launch orchestrator
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  STEP 1: Launching Orchestrator" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$orchJob = Start-Job -ScriptBlock {
    param($exe, $model)
    & $exe $model 2>&1
} -ArgumentList $SovereignExe, $ModelPath

Write-Host "🚀 Orchestrator started (Job ID: $($orchJob.Id))" -ForegroundColor Green
Write-Host ""

# Wait for initialization
Write-Host "⏳ Waiting $WaitSeconds seconds for initialization..." -ForegroundColor Yellow
for ($i = $WaitSeconds; $i -gt 0; $i--) {
    Write-Host "  $i..." -NoNewline -ForegroundColor Gray
    Start-Sleep -Seconds 1
}
Write-Host ""
Write-Host ""

# Check if orchestrator is running
$orchProcess = Get-Process -Name "SovereignOrchestrator" -ErrorAction SilentlyContinue
if (-not $orchProcess) {
    Write-Host "❌ Orchestrator failed to start!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Job output:" -ForegroundColor Yellow
    Receive-Job -Job $orchJob
    Remove-Job -Job $orchJob
    exit 1
}

Write-Host "✅ Orchestrator running (PID: $($orchProcess.Id))" -ForegroundColor Green
Write-Host ""

# Run chat client
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  STEP 2: Running Chat Client" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $RootDir
& $ChatClient

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  STEP 3: Cleanup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Stop orchestrator
Write-Host "Stopping orchestrator..." -ForegroundColor Yellow
$orchProcess | Stop-Process -Force -ErrorAction SilentlyContinue
Stop-Job -Job $orchJob -ErrorAction SilentlyContinue
Remove-Job -Job $orchJob -ErrorAction SilentlyContinue

Write-Host "✅ Test complete!" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ORCHESTRATOR OUTPUT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Receive-Job -Job $orchJob -Keep | ForEach-Object { Write-Host $_ }

Remove-Job -Job $orchJob -ErrorAction SilentlyContinue

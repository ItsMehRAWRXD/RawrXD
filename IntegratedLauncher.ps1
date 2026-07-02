# RawrXD Integrated Launcher
# Launches orchestrator and client with proper permissions

param(
    [string]$ModelPath = "F:\OllamaModels\Codestral-22B-v0.1-Q4_K_M.gguf",
    [string]$Prompt = "Hello, how are you?",
    [int]$MaxTokens = 50
)

$ErrorActionPreference = "Stop"
$RootDir = "D:\rawrxd-ci-bootstrap"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RAWRXD INTEGRATED LAUNCHER" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verify files exist
$Orchestrator = "$RootDir\SovereignOrchestrator.exe"
$ChatClient = "$RootDir\SovereignChatClient.exe"

if (-not (Test-Path $Orchestrator)) {
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

Write-Host "✅ All files found" -ForegroundColor Green
Write-Host ""

# Kill any existing orchestrator
$existing = Get-Process -Name "SovereignOrchestrator" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping existing orchestrator..." -ForegroundColor Yellow
    $existing | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# Launch orchestrator in the same PowerShell session
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting Orchestrator" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$env:RAWRXD_MODEL_PATH = $ModelPath

# Start orchestrator as a job in this session
$orchJob = Start-Job -ScriptBlock {
    param($exe, $model)
    Set-Location "D:\rawrxd-ci-bootstrap"
    & $exe $model 2>&1
} -ArgumentList $Orchestrator, $ModelPath

Write-Host "🚀 Orchestrator started (Job ID: $($orchJob.Id))" -ForegroundColor Green
Write-Host "⏳ Waiting for initialization..." -ForegroundColor Yellow

# Wait for shared memory to be created
$maxWait = 30
$waited = 0
$ready = $false

while ($waited -lt $maxWait -and -not $ready) {
    Start-Sleep -Seconds 1
    $waited++
    
    # Check if orchestrator output shows it's listening
    $output = Receive-Job -Job $orchJob -Keep 2>&1
    if ($output -match "Listening on beacon") {
        $ready = $true
        Write-Host "✅ Orchestrator ready!" -ForegroundColor Green
    }
    
    Write-Host "." -NoNewline -ForegroundColor Gray
}

Write-Host ""
Write-Host ""

if (-not $ready) {
    Write-Host "⚠️  Timeout waiting for orchestrator" -ForegroundColor Yellow
    Write-Host "Job output:" -ForegroundColor Gray
    Receive-Job -Job $orchJob
    Remove-Job -Job $orchJob -Force
    exit 1
}

# Run chat client
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Running Chat Client" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prompt: $Prompt" -ForegroundColor White
Write-Host ""

Set-Location $RootDir
& $ChatClient

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Cleanup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Stop orchestrator
Stop-Job -Job $orchJob -ErrorAction SilentlyContinue
Remove-Job -Job $orchJob -Force -ErrorAction SilentlyContinue

# Also kill any remaining process
Get-Process -Name "SovereignOrchestrator" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "✅ Complete!" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Orchestrator Output" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Receive-Job -Job $orchJob -Keep -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

Remove-Job -Job $orchJob -Force -ErrorAction SilentlyContinue

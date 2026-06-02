# diagnose_inference.ps1
# Diagnostic script to isolate inference crash in RawrXD-Win32IDE
# Usage: .\diagnose_inference.ps1 [-TimeoutSeconds 30]

param([int]$TimeoutSeconds = 30)

$ErrorActionPreference = "Continue"
$exe = "D:\rawrxd\build_win32ide\bin\RawrXD-Win32IDE.exe"
$api = "http://127.0.0.1:11435"

Write-Host "=== RawrXD Inference Diagnostics ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# Test 1: Model file existence
Write-Host "`n[TEST 1] Checking model files..." -ForegroundColor Yellow
$modelPaths = @(
    "D:\rawrxd\models\headless-default.gguf",
    "D:\rawrxd\models\headless-default.bin",
    "D:\rawrxd\build_win32ide\bin\headless-default.gguf",
    "F:\OllamaModels\headless-default.gguf",
    "D:\rawrxd\models\model.gguf"
)
$foundModel = $false
foreach ($path in $modelPaths) {
    if (Test-Path $path) {
        $size = (Get-Item $path).Length / 1MB
        Write-Host "  FOUND: $path ($([math]::Round($size,2)) MB)" -ForegroundColor Green
        $foundModel = $true
    } else {
        Write-Host "  MISSING: $path" -ForegroundColor DarkGray
    }
}
if (-not $foundModel) {
    Write-Host "  WARNING: No model file found - inference may crash or return empty" -ForegroundColor Red
}

# Test 2: Check for any GGUF files
Write-Host "`n[TEST 2] Available GGUF models..." -ForegroundColor Yellow
$ggufFiles = Get-ChildItem -Path "D:\rawrxd\models" -Filter "*.gguf" -ErrorAction SilentlyContinue | 
              Select-Object -First 5 Name, @{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}}
if ($ggufFiles) {
    $ggufFiles | Format-Table -AutoSize
} else {
    Write-Host "  No GGUF files found in D:\rawrxd\models" -ForegroundColor DarkGray
}

# Test 3: Launch headless
Write-Host "`n[TEST 3] Launching headless..." -ForegroundColor Yellow
$proc = Start-Process -FilePath $exe -ArgumentList "--headless" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5

# Test 4: API health
Write-Host "`n[TEST 4] API health check..." -ForegroundColor Yellow
try {
    $tags = Invoke-RestMethod -Uri "$api/api/tags" -Method GET -TimeoutSec 5
    Write-Host "  /api/tags: OK - $($tags.models.Count) models" -ForegroundColor Green
    foreach ($model in $tags.models) {
        Write-Host "    - $($model.name) (loaded: $($model.loaded))" -ForegroundColor Gray
    }
} catch {
    Write-Host "  /api/tags: FAIL - $_" -ForegroundColor Red
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

# Test 5: Version info
Write-Host "`n[TEST 5] Version check..." -ForegroundColor Yellow
try {
    $version = Invoke-RestMethod -Uri "$api/api/version" -Method GET -TimeoutSec 5
    Write-Host "  /api/version: OK" -ForegroundColor Green
    Write-Host "    version: $($version.version)" -ForegroundColor Gray
    Write-Host "    phase: $($version.phase)" -ForegroundColor Gray
    Write-Host "    mode: $($version.mode)" -ForegroundColor Gray
} catch {
    Write-Host "  /api/version: FAIL - $_" -ForegroundColor Red
}

# Test 6: Inference with minimal payload
Write-Host "`n[TEST 6] Inference test (minimal)..." -ForegroundColor Yellow
$body = @{
    model = "headless-default"
    prompt = "hi"
    stream = $false
    options = @{
        num_predict = 1
        temperature = 0.1
    }
} | ConvertTo-Json -Depth 3

Write-Host "  Request: $body" -ForegroundColor DarkGray

try {
    $resp = Invoke-RestMethod -Uri "$api/api/generate" -Method POST -Body $body -ContentType "application/json" -TimeoutSec $TimeoutSeconds
    Write-Host "  INFERENCE: OK" -ForegroundColor Green
    Write-Host "    response: $($resp.response)" -ForegroundColor Gray
    Write-Host "    done: $($resp.done)" -ForegroundColor Gray
    if ($resp.context) {
        Write-Host "    context tokens: $($resp.context.Count)" -ForegroundColor Gray
    }
} catch {
    Write-Host "  INFERENCE: FAIL - $_" -ForegroundColor Red
    Write-Host "  Exception type: $($_.Exception.GetType().Name)" -ForegroundColor DarkRed
    Write-Host "  Exception message: $($_.Exception.Message)" -ForegroundColor DarkRed
    
    # Check if process crashed
    Start-Sleep -Milliseconds 500
    $stillRunning = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if (-not $stillRunning) {
        Write-Host "  PROCESS CRASHED during inference" -ForegroundColor Red
        
        # Check event log
        $crashEvents = Get-EventLog -LogName Application -Newest 3 -EntryType Error -ErrorAction SilentlyContinue | 
                       Where-Object { $_.Message -like "*RawrXD*" -or $_.Message -like "*Win32IDE*" }
        if ($crashEvents) {
            Write-Host "`n  CRASH DETAILS:" -ForegroundColor Red
            foreach ($evt in $crashEvents) {
                Write-Host "    Time: $($evt.TimeGenerated)" -ForegroundColor DarkRed
                Write-Host "    Module: $($evt.Message -split '`n' | Select-String 'Faulting module' | Select-Object -First 1)" -ForegroundColor DarkRed
            }
        }
    }
}

# Test 7: Prometheus metrics
Write-Host "`n[TEST 7] Prometheus metrics..." -ForegroundColor Yellow
try {
    $metrics = Invoke-WebRequest -Uri "http://127.0.0.1:9090/metrics" -TimeoutSec 5 -UseBasicParsing
    Write-Host "  /metrics: OK ($($metrics.Content.Length) bytes)" -ForegroundColor Green
} catch {
    Write-Host "  /metrics: FAIL - $_" -ForegroundColor Red
}

# Cleanup
Write-Host "`n[Cleanup] Stopping process..." -ForegroundColor Yellow
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

Write-Host "`n=== Diagnostic Complete ===" -ForegroundColor Cyan
Write-Host "Process ID: $($proc.Id)" -ForegroundColor Gray
Write-Host "Log file: D:\rawrxd\__smoke_logs\smoke_*.log" -ForegroundColor Gray
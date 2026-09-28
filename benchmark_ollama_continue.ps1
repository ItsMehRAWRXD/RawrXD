# Ollama TPS Benchmark - Continue from where we left off
# Uses Ollama REST API for accurate token counting and timing

$resultsFile = "F:\OllamaModels\ollama_tps_benchmark.csv"
$prompt = "Write a complete C++ implementation of a lock-free bounded queue. Include memory ordering and correctness notes."

# All models (29 total) - in priority order, with failed ones retried first
$models = @(
    # Retry failed models first
    "starcoder2:15b",
    "deepseek-r1:32b",
    "ornith-1.5:35b",
    # Continue with remaining
    "bigdaddyglocal:latest",
    "bigdaddygnative:latest",
    "deepseek-r1:70b",
    "gpt-oss:20b",
    "gpt-oss:latest",
    "qwen3-next:80b",
    "laguna-s-2.1:Q4_K_M",
    "bluehawana/deepseek-v4-flash:iq2_m",
    "pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest",
    "qwen35-40b-heretic-q8:latest",
    "nemotron-3-nano:4b",
    "nemotron-3.5-lightning:30b",
    "kiminoto/T0.0.1:latest",
    "bigdaddyg-productivity-local:latest",
    "bigdaddyg-productivity-native:latest",
    "llama3.2:latest",
    "gpt-oss:120b"
)

# Load existing results to skip already-done models
$existing = @()
if (Test-Path $resultsFile) {
    $existing = Import-Csv -Path $resultsFile | Where-Object { $_.status -eq "OK" } | ForEach-Object { $_.model }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  OLLAMA TPS BENCHMARK - CONTINUATION" -ForegroundColor Cyan
Write-Host "  Already done: $($existing.Count)" -ForegroundColor Green
Write-Host "  Remaining: $($models.Count)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

$total = $models.Count
$current = 0

foreach ($model in $models) {
    $current++
    
    # Skip if already successfully benchmarked
    if ($existing -contains $model) {
        Write-Host "[$current/$total] SKIPPING (already done): $model" -ForegroundColor DarkGray
        continue
    }
    
    Write-Host ""
    Write-Host "[$current/$total] Testing: $model" -ForegroundColor Yellow
    
    try {
        $body = @{
            model = $model
            prompt = $prompt
            stream = $false
            options = @{
                temperature = 0.7
                num_predict = 200
            }
        } | ConvertTo-Json -Depth 3
        
        $start = Get-Date
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/generate" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 600
        $end = Get-Date
        
        $duration = ($end - $start).TotalSeconds
        $evalCount = $response.eval_count
        $promptEvalCount = $response.prompt_eval_count
        $evalDuration = $response.eval_duration
        $totalDuration = $response.total_duration
        
        # Calculate TPS from Ollama's precise timing
        $tps = if ($evalDuration -gt 0) { [math]::Round($evalCount / ($evalDuration / 1e9), 2) } else { 0 }
        
        Write-Host "    Tokens: $evalCount | Time: $([math]::Round($duration, 2))s | TPS: $tps" -ForegroundColor Green
        
        $csvLine = "$model,$evalCount,$promptEvalCount,$([math]::Round($duration, 2)),$tps,$evalDuration,$totalDuration,OK,$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $csvLine | Out-File -FilePath $resultsFile -Append -Encoding utf8
        
    } catch {
        $errorMsg = $_.Exception.Message -replace ',', ';'
        Write-Host "    FAILED: $errorMsg" -ForegroundColor Red
        
        $csvLine = "$model,0,0,0,0,0,0,ERROR: $errorMsg,$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $csvLine | Out-File -FilePath $resultsFile -Append -Encoding utf8
    }
    
    # Brief pause between models
    Start-Sleep -Seconds 3
}

# Print final summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BENCHMARK COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$results = Import-Csv -Path $resultsFile
$successful = $results | Where-Object { $_.status -eq "OK" }

if ($successful) {
    Write-Host ""
    Write-Host "Successful Results (sorted by TPS):" -ForegroundColor Green
    $successful | Sort-Object { [double]$_.tps } -Descending | Format-Table model, tps, tokens_generated, duration_sec -AutoSize
    
    $fastest = $successful | Sort-Object { [double]$_.tps } -Descending | Select-Object -First 1
    Write-Host ""
    Write-Host "Fastest Model: $($fastest.model) at $($fastest.tps) TPS" -ForegroundColor Magenta
} else {
    Write-Host "No successful results." -ForegroundColor Red
}

Write-Host ""
Write-Host "Results saved to: $resultsFile" -ForegroundColor Cyan

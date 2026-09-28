# Ollama TPS Benchmark - Complete
# Uses Ollama REST API for accurate token counting and timing
# Results saved incrementally to prevent data loss

$resultsFile = "F:\OllamaModels\ollama_tps_benchmark.csv"
$prompt = "Write a complete C++ implementation of a lock-free bounded queue. Include memory ordering and correctness notes."

# All local models (29 total)
$models = @(
    "qwen2.5-coder:1.5b-base",
    "llama3.2:3b",
    "gemma3:4b",
    "qwen3:8b",
    "llama3.1:8b",
    "granite3.3:8b",
    "deepseek-coder-v2:16b",
    "qwen3.8:27b",
    "starcoder2:15b",
    "deepseek-r1:32b",
    "gemma3:latest",
    "ornith-1.5:35b",
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

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  OLLAMA TPS BENCHMARK" -ForegroundColor Cyan
Write-Host "  Models: $($models.Count)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Create CSV with headers if it doesn't exist
if (-not (Test-Path $resultsFile)) {
    "model,tokens_generated,prompt_tokens,duration_sec,tps,eval_duration_ns,total_duration_ns,status,timestamp" | Out-File -FilePath $resultsFile -Encoding utf8
}

$total = $models.Count
$current = 0

foreach ($model in $models) {
    $current++
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
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/generate" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 300
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
    Start-Sleep -Seconds 2
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
    Write-Host "Successful Results:" -ForegroundColor Green
    $successful | Sort-Object { [double]$_.tps } -Descending | Format-Table -AutoSize
    
    $fastest = $successful | Sort-Object { [double]$_.tps } -Descending | Select-Object -First 1
    Write-Host "Fastest Model: $($fastest.model) at $($fastest.tps) TPS" -ForegroundColor Magenta
} else {
    Write-Host "No successful results." -ForegroundColor Red
}

Write-Host ""
Write-Host "Results saved to: $resultsFile" -ForegroundColor Cyan

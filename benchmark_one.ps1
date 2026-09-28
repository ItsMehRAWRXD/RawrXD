# Ollama TPS Benchmark - One model at a time to avoid terminal timeout
# Run this repeatedly until all models are done

$resultsFile = "F:\OllamaModels\ollama_tps_benchmark.csv"
$prompt = "Write a complete C++ implementation of a lock-free bounded queue. Include memory ordering and correctness notes."

$allModels = @(
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

# Load existing results (skip both OK and ERROR entries)
$existing = @()
if (Test-Path $resultsFile) {
    $existing = Import-Csv -Path $resultsFile | Where-Object { $_.status -eq "OK" -or $_.status -like "ERROR:*" } | ForEach-Object { $_.model }
}

# Find next model to benchmark
$nextModel = $null
foreach ($model in $allModels) {
    if ($existing -notcontains $model) {
        $nextModel = $model
        break
    }
}

if (-not $nextModel) {
    Write-Host "All models benchmarked!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Final Results:" -ForegroundColor Cyan
    $results = Import-Csv -Path $resultsFile | Where-Object { $_.status -eq "OK" }
    $results | Sort-Object { [double]$_.tps } -Descending | Format-Table model, tps, tokens_generated, duration_sec -AutoSize
    exit 0
}

Write-Host "Next model to benchmark: $nextModel" -ForegroundColor Yellow
Write-Host "Already done: $($existing.Count)/$($allModels.Count)" -ForegroundColor Green

# Benchmark just this one model
try {
    $body = @{
        model = $nextModel
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
    
    $tps = if ($evalDuration -gt 0) { [math]::Round($evalCount / ($evalDuration / 1e9), 2) } else { 0 }
    
    Write-Host "SUCCESS: Tokens=$evalCount Time=$([math]::Round($duration, 2))s TPS=$tps" -ForegroundColor Green
    
    $csvLine = "$nextModel,$evalCount,$promptEvalCount,$([math]::Round($duration, 2)),$tps,$evalDuration,$totalDuration,OK,$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $csvLine | Out-File -FilePath $resultsFile -Append -Encoding utf8
    
} catch {
    $errorMsg = $_.Exception.Message -replace ',', ';'
    Write-Host "FAILED: $errorMsg" -ForegroundColor Red
    
    $csvLine = "$nextModel,0,0,0,0,0,0,ERROR: $errorMsg,$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $csvLine | Out-File -FilePath $resultsFile -Append -Encoding utf8
}

Write-Host ""
Write-Host "Run this script again to continue with the next model." -ForegroundColor Cyan

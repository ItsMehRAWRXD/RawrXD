# Ollama TPS Benchmark Script
# Processes models in batches of 5
# Measures decode TPS for each model

$models = @(
    "qwen2.5-coder:1.5b-base",
    "bluehawana/deepseek-v4-flash:iq2_m",
    "nemotron-3-nano:4b",
    "pdurugyan/qwen3.5-9b-deepseek-v4-flash-Q4_K_M-v_2:latest",
    "deepseek-r1:32b",
    "nemotron-3.5-lightning:30b",
    "gpt-oss:120b",
    "gpt-oss:latest",
    "deepseek-coder-v2:16b",
    "starcoder2:15b",
    "ornith-1.5:35b",
    "gemma3:latest",
    "bigdaddyglocal:latest",
    "deepseek-r1:70b",
    "laguna-s-2.1:Q4_K_M",
    "qwen3-next:80b",
    "llama3.1:8b",
    "qwen3:8b",
    "gemma3:4b",
    "llama3.2:3b",
    "granite3.3:8b",
    "qwen3.8:27b",
    "qwen35-40b-heretic-q8:latest",
    "llama3.2:latest"
)

$prompt = "Explain quantum computing in one paragraph."
$ollamaPath = "C:\Users\Garrett\AppData\Local\Programs\Ollama\ollama.exe"
$results = @()

Write-Host "================================" 
Write-Host "OLLAMA TPS BENCHMARK"
Write-Host "Models: $($models.Count)"
Write-Host "================================"

$batchNum = 1
$modelIndex = 0

while ($modelIndex -lt $models.Count) {
    Write-Host ""
    Write-Host "BATCH $batchNum ============================"
    $batchCount = 0
    
    while ($batchCount -lt 5 -and $modelIndex -lt $models.Count) {
        $model = $models[$modelIndex]
        Write-Host ""
        Write-Host "Testing: $model"
        
        $start = Get-Date
        try {
            # Generate with verbose timing
            $output = & $ollamaPath run $model $prompt 2>&1
            $end = Get-Date
            $duration = ($end - $start).TotalSeconds
            
            # Estimate tokens (rough heuristic: ~4 chars per token)
            $tokenCount = [math]::Ceiling($output.Length / 4)
            $tps = if ($duration -gt 0) { [math]::Round($tokenCount / $duration, 2) } else { 0 }
            
            $result = [PSCustomObject]@{
                Model = $model
                Batch = $batchNum
                Tokens = $tokenCount
                Duration = [math]::Round($duration, 2)
                TPS = $tps
                Status = "OK"
                Output = $output.Substring(0, [Math]::Min(100, $output.Length))
            }
        }
        catch {
            $result = [PSCustomObject]@{
                Model = $model
                Batch = $batchNum
                Tokens = 0
                Duration = 0
                TPS = 0
                Status = "ERROR: $($_.Exception.Message)"
                Output = ""
            }
        }
        
        $results += $result
        Write-Host "  TPS: $($result.TPS) | Tokens: $($result.Tokens) | Time: $($result.Duration)s"
        
        $modelIndex++
        $batchCount++
    }
    
    $batchNum++
    
    # Show batch summary
    Write-Host ""
    Write-Host "BATCH $batchNum Summary:"
    $batchResults = $results | Where-Object { $_.Batch -eq ($batchNum - 1) }
    $batchResults | Format-Table Model, TPS, Tokens, Duration, Status -AutoSize
}

# Final results
Write-Host ""
Write-Host "================================"
Write-Host "FINAL RESULTS"
Write-Host "================================"
$results | Format-Table Model, TPS, Tokens, Duration, Status -AutoSize

# Save to file
$results | Export-Csv -Path "F:\OllamaModels\ollama_tps_benchmark.csv" -NoTypeInformation
Write-Host ""
Write-Host "Results saved to: F:\OllamaModels\ollama_tps_benchmark.csv"

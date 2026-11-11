# RawrXD 32K Medusa TPS Benchmark Harness
# Measures token generation speed with different optimizations

param(
    [string]$ServerUrl = "http://127.0.0.1:8080",
    [int]$WarmupTokens = 50,
    [int]$BenchmarkTokens = 256,
    [int]$Runs = 3
)

function Measure-TPS {
    param($Prompt, $NPredict)
    
    $body = @{
        prompt = $Prompt
        n_predict = $NPredict
        temperature = 0.7
        stream = $false
    } | ConvertTo-Json -Compress
    
    $start = Get-Date
    $response = Invoke-RestMethod -Uri "$ServerUrl/completion" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 120
    $end = Get-Date
    
    $duration = ($end - $start).TotalSeconds
    $tps = $response.tokens_predicted / $duration
    
    return [PSCustomObject]@{
        PromptTokens = $response.tokens_evaluated
        GeneratedTokens = $response.tokens_predicted
        Duration = $duration
        TPS = [math]::Round($tps, 2)
        PromptTPS = [math]::Round($response.tokens_evaluated / ($response.timings.prompt_ms / 1000), 2)
        DecodeTPS = [math]::Round($response.tokens_predicted / ($response.timings.predicted_ms / 1000), 2)
    }
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "RawrXD 32K Medusa TPS Benchmark" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Server: $ServerUrl"
Write-Host "Warmup: $WarmupTokens tokens"
Write-Host "Benchmark: $BenchmarkTokens tokens"
Write-Host "Runs: $Runs"
Write-Host ""

# Warmup
Write-Host "[WARMUP] Running warmup to stabilize GPU..." -ForegroundColor Yellow
$warmup = Measure-TPS -Prompt "Hello world" -NPredict $WarmupTokens
Write-Host "  Warmup TPS: $($warmup.TPS)"
Write-Host ""

# Benchmark runs
Write-Host "[BENCHMARK] Running $Runs benchmark iterations..." -ForegroundColor Green
$results = @()

for ($i = 1; $i -le $Runs; $i++) {
    Write-Host "  Run $i/$Runs..." -NoNewline
    $result = Measure-TPS -Prompt "Explain quantum computing:" -NPredict $BenchmarkTokens
    $results += $result
    Write-Host " TPS: $($result.TPS) (prompt: $($result.PromptTPS), decode: $($result.DecodeTPS))"
}

# Summary
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$avgTPS = ($results | Measure-Object -Property TPS -Average).Average
$minTPS = ($results | Measure-Object -Property TPS -Minimum).Minimum
$maxTPS = ($results | Measure-Object -Property TPS -Maximum).Maximum
$avgDecodeTPS = ($results | Measure-Object -Property DecodeTPS -Average).Average

Write-Host "Average TPS:        $([math]::Round($avgTPS, 2))"
Write-Host "Min/Max TPS:        $([math]::Round($minTPS, 2)) / $([math]::Round($maxTPS, 2))"
Write-Host "Average Decode TPS: $([math]::Round($avgDecodeTPS, 2))"
Write-Host ""

# Target comparison
$targetTPS = 100
$progress = [math]::Round(($avgTPS / $targetTPS) * 100, 1)
Write-Host "Progress to 100 TPS target: $progress%"
Write-Host ""

# Export results
$results | Export-Csv -Path "d:enchmark_results.csv" -NoTypeInformation
Write-Host "Results saved to: d:enchmark_results.csv"

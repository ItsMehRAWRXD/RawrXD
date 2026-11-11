# Context Length Scaling Benchmark
# Tests TPS at different context lengths to find degradation

param(
    [string]$ServerUrl = "http://127.0.0.1:8080",
    [int[]]$ContextLengths = @(512, 1024, 2048, 4096, 8192, 16384, 32768),
    [int]$GenerateTokens = 100
)

function Generate-Prompt {
    param($TargetTokens)
    # Approximate: 1 token ≈ 4 characters
    $charsNeeded = $TargetTokens * 4
    $lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. "
    $repeatCount = [math]::Ceiling($charsNeeded / $lorem.Length)
    return ($lorem * $repeatCount).Substring(0, [math]::Min($charsNeeded, $repeatCount * $lorem.Length))
}

function Measure-ContextPerformance {
    param($ContextLength, $GenerateTokens)
    
    $prompt = Generate-Prompt -TargetTokens $ContextLength
    
    $body = @{
        prompt = $prompt
        n_predict = $GenerateTokens
        temperature = 0.7
        stream = $false
    } | ConvertTo-Json -Compress
    
    $start = Get-Date
    try {
        $response = Invoke-RestMethod -Uri "$ServerUrl/completion" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 300
        $end = Get-Date
        
        $duration = ($end - $start).TotalSeconds
        $promptTPS = $response.tokens_evaluated / ($response.timings.prompt_ms / 1000)
        $decodeTPS = $response.tokens_predicted / ($response.timings.predicted_ms / 1000)
        
        return [PSCustomObject]@{
            ContextLength = $ContextLength
            PromptTokens = $response.tokens_evaluated
            GeneratedTokens = $response.tokens_predicted
            TotalDuration = $duration
            PromptTPS = [math]::Round($promptTPS, 2)
            DecodeTPS = [math]::Round($decodeTPS, 2)
            Success = $true
        }
    } catch {
        return [PSCustomObject]@{
            ContextLength = $ContextLength
            PromptTokens = 0
            GeneratedTokens = 0
            TotalDuration = 0
            PromptTPS = 0
            DecodeTPS = 0
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Context Length Scaling Benchmark" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "Testing TPS degradation at increasing context lengths"
Write-Host "Generate tokens: $GenerateTokens per test"
Write-Host ""

$results = @()

foreach ($ctxLen in $ContextLengths) {
    Write-Host "Testing context length: $ctxLen tokens..." -NoNewline -ForegroundColor Yellow
    $result = Measure-ContextPerformance -ContextLength $ctxLen -GenerateTokens $GenerateTokens
    $results += $result
    
    if ($result.Success) {
        Write-Host " Prompt: $($result.PromptTPS) TPS, Decode: $($result.DecodeTPS) TPS" -ForegroundColor Green
    } else {
        Write-Host " FAILED - $($result.Error)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "SCALING SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Context Length | Prompt TPS | Decode TPS | Status"
Write-Host "-------------|------------|------------|--------"
foreach ($r in $results) {
    $status = if ($r.Success) { "OK" } else { "FAIL" }
    Write-Host "{0,12} | {1,10:F2} | {2,10:F2} | {3}" -f $r.ContextLength, $r.PromptTPS, $r.DecodeTPS, $status
}

# Find degradation point
$baseline = ($results | Where-Object { $_.Success -and $_.ContextLength -eq 512 }).DecodeTPS
if ($baseline) {
    Write-Host ""
    Write-Host "Degradation from 512-token baseline ($([math]::Round($baseline,2)) TPS):"
    foreach ($r in $results | Where-Object { $_.Success -and $_.ContextLength -gt 512 }) {
        $degradation = [math]::Round((1 - ($r.DecodeTPS / $baseline)) * 100, 1)
        Write-Host "  $($r.ContextLength) tokens: $degradation% slower"
    }
}

# Save results
$results | Export-Csv -Path "d:\context_scaling_results.csv" -NoTypeInformation
Write-Host ""
Write-Host "Results saved to: d:\context_scaling_results.csv"

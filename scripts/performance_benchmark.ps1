# RawrXD OMEGA-1 Performance Benchmark
# Measures TPS (tokens per second) for prompt processing and generation

param(
    [string]$BinDir = "d:\rawrxd\build\bin",
    [string]$ModelPath = "",
    [int]$WarmupTokens = 128,
    [int]$BenchmarkTokens = 512,
    [int]$Iterations = 3
)

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date

function Write-Header {
    param($Text)
    Write-Host "`n═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Write-Status {
    param($Text, $Status)
    $color = switch ($Status) {
        "OK" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "White" }
    }
    Write-Host "  [$Status] $Text" -ForegroundColor $color
}

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD OMEGA-1 Performance Benchmark                                       ║" -ForegroundColor Cyan
Write-Host "║     Measuring TPS: Prompt Processing & Token Generation                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# =============================================================================
# Phase 1: Environment Check
# =============================================================================
Write-Header "Phase 1: Environment Check"

$engine = Join-Path $BinDir "RawrXD-InferenceEngine.exe"
if (!(Test-Path $engine)) {
    Write-Status "InferenceEngine not found: $engine" "FAIL"
    exit 1
}
Write-Status "InferenceEngine found" "OK"

# Check for model
if ([string]::IsNullOrEmpty($ModelPath)) {
    # Look for common model locations
    $possibleModels = @(
        "d:\models\*.gguf",
        "d:\rawrxd\models\*.gguf",
        "$env:USERPROFILE\models\*.gguf"
    )
    
    foreach ($pattern in $possibleModels) {
        $found = Get-ChildItem $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            $ModelPath = $found.FullName
            Write-Status "Found model: $ModelPath" "OK"
            break
        }
    }
    
    if ([string]::IsNullOrEmpty($ModelPath)) {
        Write-Status "No model specified or found" "WARN"
        Write-Host "`n  Usage: .\performance_benchmark.ps1 -ModelPath <path\to\model.gguf>" -ForegroundColor Yellow
        exit 0
    }
} else {
    if (!(Test-Path $ModelPath)) {
        Write-Status "Model not found: $ModelPath" "FAIL"
        exit 1
    }
    Write-Status "Model: $ModelPath" "OK"
}

# =============================================================================
# Phase 2: GPU Warmup
# =============================================================================
Write-Header "Phase 2: GPU Warmup"

Write-Status "Warming up GPUs with $WarmupTokens tokens..." "OK"
Write-Host "  This ensures GPUs are at operating temperature..." -ForegroundColor Gray

$warmupPrompt = "The quick brown fox jumps over the lazy dog. " * 10
$warmupArgs = @(
    "--model", $ModelPath,
    "--prompt", $warmupPrompt,
    "--max-tokens", $WarmupTokens,
    "--temperature", "0.7"
)

try {
    $warmupOutput = & $engine @warmupArgs 2>&1 | Out-String
    Write-Status "GPU warmup complete" "OK"
} catch {
    Write-Status "GPU warmup failed: $_" "WARN"
}

# =============================================================================
# Phase 3: Prompt Processing Benchmark
# =============================================================================
Write-Header "Phase 3: Prompt Processing Benchmark"

Write-Status "Testing prompt processing speed..." "OK"

$promptSizes = @(128, 256, 512, 1024)
$promptResults = @()

foreach ($size in $promptSizes) {
    Write-Host "`n  Testing with $size token prompt..." -ForegroundColor Gray
    
    # Generate test prompt
    $testPrompt = "The quick brown fox jumps over the lazy dog. " * [math]::Ceiling($size / 10)
    
    $times = @()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        $args = @(
            "--model", $ModelPath,
            "--prompt", $testPrompt,
            "--max-tokens", 1,
            "--temperature", "0.7"
        )
        
        try {
            $output = & $engine @args 2>&1 | Out-String
            $sw.Stop()
            $times += $sw.ElapsedMilliseconds
        } catch {
            Write-Status "Iteration $i failed" "WARN"
        }
    }
    
    if ($times.Count -gt 0) {
        $avgTime = ($times | Measure-Object -Average).Average
        $tps = $size / ($avgTime / 1000)
        
        $promptResults += [PSCustomObject]@{
            Tokens = $size
            AvgTimeMs = [math]::Round($avgTime, 2)
            TPS = [math]::Round($tps, 2)
        }
        
        Write-Host "    Avg time: $([math]::Round($avgTime, 2)) ms" -ForegroundColor Gray
        Write-Host "    TPS: $([math]::Round($tps, 2))" -ForegroundColor Gray
    }
}

# =============================================================================
# Phase 4: Token Generation Benchmark
# =============================================================================
Write-Header "Phase 4: Token Generation Benchmark"

Write-Status "Testing token generation speed..." "OK"

$genPrompt = "Once upon a time"
$genResults = @()

$tokenCounts = @(128, 256, 512)

foreach ($count in $tokenCounts) {
    Write-Host "`n  Testing $count token generation..." -ForegroundColor Gray
    
    $times = @()
    for ($i = 0; $i -lt $Iterations; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        $args = @(
            "--model", $ModelPath,
            "--prompt", $genPrompt,
            "--max-tokens", $count,
            "--temperature", "0.7"
        )
        
        try {
            $output = & $engine @args 2>&1 | Out-String
            $sw.Stop()
            $times += $sw.ElapsedMilliseconds
        } catch {
            Write-Status "Iteration $i failed" "WARN"
        }
    }
    
    if ($times.Count -gt 0) {
        $avgTime = ($times | Measure-Object -Average).Average
        $tps = $count / ($avgTime / 1000)
        
        $genResults += [PSCustomObject]@{
            Tokens = $count
            AvgTimeMs = [math]::Round($avgTime, 2)
            TPS = [math]::Round($tps, 2)
        }
        
        Write-Host "    Avg time: $([math]::Round($avgTime, 2)) ms" -ForegroundColor Gray
        Write-Host "    TPS: $([math]::Round($tps, 2))" -ForegroundColor Gray
    }
}

# =============================================================================
# Phase 5: Results Summary
# =============================================================================
Write-Header "Phase 5: Results Summary"

Write-Host "`n  Prompt Processing Results:" -ForegroundColor Cyan
if ($promptResults.Count -gt 0) {
    $promptResults | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Gray
    
    $avgPromptTps = ($promptResults | Measure-Object -Property TPS -Average).Average
    Write-Status "Average Prompt TPS: $([math]::Round($avgPromptTps, 2))" "OK"
} else {
    Write-Status "No prompt processing results" "WARN"
}

Write-Host "`n  Token Generation Results:" -ForegroundColor Cyan
if ($genResults.Count -gt 0) {
    $genResults | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Gray
    
    $avgGenTps = ($genResults | Measure-Object -Property TPS -Average).Average
    Write-Status "Average Generation TPS: $([math]::Round($avgGenTps, 2))" "OK"
} else {
    Write-Status "No generation results" "WARN"
}

# =============================================================================
# Phase 6: Target Comparison
# =============================================================================
Write-Header "Phase 6: Target Comparison"

$targetPromptTps = 557
$targetGenTps = 344

if ($avgPromptTps) {
    $promptDiff = (($avgPromptTps - $targetPromptTps) / $targetPromptTps) * 100
    Write-Host "`n  Prompt Processing:" -ForegroundColor Gray
    Write-Host "    Target: $targetPromptTps t/s" -ForegroundColor Gray
    Write-Host "    Actual: $([math]::Round($avgPromptTps, 2)) t/s" -ForegroundColor Gray
    Write-Host "    Diff: $([math]::Round($promptDiff, 1))%" -ForegroundColor $(if ($promptDiff -ge 0) { "Green" } else { "Yellow" })
}

if ($avgGenTps) {
    $genDiff = (($avgGenTps - $targetGenTps) / $targetGenTps) * 100
    Write-Host "`n  Token Generation:" -ForegroundColor Gray
    Write-Host "    Target: $targetGenTps t/s" -ForegroundColor Gray
    Write-Host "    Actual: $([math]::Round($avgGenTps, 2)) t/s" -ForegroundColor Gray
    Write-Host "    Diff: $([math]::Round($genDiff, 1))%" -ForegroundColor $(if ($genDiff -ge 0) { "Green" } else { "Yellow" })
}

# =============================================================================
# Export Results
# =============================================================================
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

$results = [PSCustomObject]@{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Duration = $Duration.ToString()
    Model = $ModelPath
    Hardware = @{
        GPUs = (Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "AMD|Radeon" -and $_.Status -eq "OK" } | ForEach-Object { $_.Name })
    }
    PromptProcessing = $promptResults
    TokenGeneration = $genResults
    Targets = @{
        PromptTPS = $targetPromptTps
        GenerationTPS = $targetGenTps
    }
}

$outDir = "d:\rawrxd\test_results"
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
$resultsFile = Join-Path $outDir "performance_benchmark_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$results | ConvertTo-Json -Depth 4 | Out-File $resultsFile

Write-Status "Results saved to: $resultsFile" "OK"

# =============================================================================
# Summary
# =============================================================================
Write-Header "Benchmark Complete"

Write-Status "Duration: $($Duration.ToString('hh\:mm\:ss'))" "OK"

Write-Host "`n╔══════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     ✅ Performance Benchmark Complete                                            ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

exit 0

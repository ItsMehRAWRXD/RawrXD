# Sovereign vs Ollama Benchmark Comparison Script
# Copyright (c) 2026 RawrXD Team

param(
    [string]$Model = "phi-3-mini-Q4",
    [string]$OllamaModel = "phi3:mini",
    [int]$Runs = 50,
    [int]$Warmup = 10,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     Sovereign vs Ollama Benchmark Comparison Suite             ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Configuration
$BenchmarkExe = ".\sovereign_vs_ollama_benchmark.exe"
$OutputDir = "reports"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Check if benchmark executable exists
if (-not (Test-Path $BenchmarkExe)) {
    Write-Error "Benchmark executable not found: $BenchmarkExe"
    Write-Host "Please build the benchmark suite first:" -ForegroundColor Yellow
    Write-Host "  mkdir build" -ForegroundColor Yellow
    Write-Host "  cd build" -ForegroundColor Yellow
    Write-Host "  cmake .." -ForegroundColor Yellow
    Write-Host "  cmake --build . --config Release" -ForegroundColor Yellow
    exit 1
}

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Configuration:" -ForegroundColor Green
Write-Host "  Model: $Model"
Write-Host "  Ollama Model: $OllamaModel"
Write-Host "  Runs: $Runs"
Write-Host "  Warmup: $Warmup"
Write-Host "  Output: $OutputDir"
Write-Host ""

# Function to run benchmark
function Run-Benchmark {
    param(
        [string]$Backend,
        [string]$ModelName
    )
    
    Write-Host "Running benchmarks for $Backend..." -ForegroundColor Yellow
    
    $args = @(
        "--backend", $Backend,
        "--model", $ModelName,
        "--runs", $Runs,
        "--warmup", $Warmup,
        "--output", $OutputDir
    )
    
    if ($Verbose) {
        $args += "--verbose"
    }
    
    & $BenchmarkExe @args
    
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Benchmark for $Backend failed with exit code $LASTEXITCODE"
        return $false
    }
    
    return $true
}

# Run Sovereign benchmarks
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Phase 1: Sovereign Benchmarks" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$sovereignSuccess = Run-Benchmark -Backend "sovereign" -ModelName $Model

if (-not $sovereignSuccess) {
    Write-Warning "Sovereign benchmarks failed. Continuing with Ollama..."
}

Write-Host ""

# Run Ollama benchmarks
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Phase 2: Ollama Benchmarks" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Ollama is running
try {
    $ollamaResponse = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method GET -TimeoutSec 5
    Write-Host "Ollama is running" -ForegroundColor Green
} catch {
    Write-Error "Ollama does not appear to be running on localhost:11434"
    Write-Host "Please start Ollama first:" -ForegroundColor Yellow
    Write-Host "  ollama serve" -ForegroundColor Yellow
    exit 1
}

$ollamaSuccess = Run-Benchmark -Backend "ollama" -ModelName $OllamaModel

if (-not $ollamaSuccess) {
    Write-Warning "Ollama benchmarks failed."
}

Write-Host ""

# Generate comparison report
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Phase 3: Generating Comparison Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$sovereignJson = "$OutputDir\benchmark_sovereign_$Model.json"
$ollamaJson = "$OutputDir\benchmark_ollama_$OllamaModel.json"
$comparisonMd = "$OutputDir\comparison_report_$Timestamp.md"

# Create comparison markdown
$comparisonReport = @"
# Sovereign vs Ollama Benchmark Comparison Report

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Model:** $Model vs $OllamaModel  
**Runs:** $Runs per benchmark  
**Warmup:** $Warmup iterations

---

## Executive Summary

This report compares RawrXD's Sovereign Runtime against Ollama/llama.cpp across multiple dimensions:
- Raw inference performance
- Agent lifecycle management
- Swarm coordination (16 agents)
- Execution graph efficiency
- Decision-making quality
- Self-correction capabilities
- Response quality
- Context handling
- Autonomous runtime
- Resource utilization

---

## Results

| Benchmark | Sovereign | Ollama | Delta |
|-----------|-----------|--------|-------|
| Inference TPS | TBD | TBD | TBD |
| Agent Spawn | TBD | TBD | TBD |
| Swarm16 | TBD | TBD | TBD |
| SEG Execution | TBD | N/A | N/A |
| Decision Making | TBD | TBD | TBD |
| Self-Correction | TBD | TBD | TBD |
| Response Quality | TBD | TBD | TBD |
| Context Handling | TBD | TBD | TBD |
| Autonomous Runtime | TBD | TBD | TBD |
| Resource Usage | TBD | TBD | TBD |

---

## Sovereign Intelligence Score (SIS)

| Component | Weight | Sovereign | Ollama | Delta |
|-----------|--------|-----------|--------|-------|
| Inference | 15% | TBD | TBD | TBD |
| Agent Speed | 15% | TBD | TBD | TBD |
| Planning | 15% | TBD | TBD | TBD |
| SEG Efficiency | 15% | TBD | N/A | N/A |
| Swarm | 15% | TBD | TBD | TBD |
| Decision | 10% | TBD | TBD | TBD |
| Recovery | 10% | TBD | TBD | TBD |
| Response Quality | 5% | TBD | TBD | TBD |

**Overall SIS:**
- Sovereign: TBD
- Ollama: TBD
- Advantage: TBD%

---

## Detailed Results

### Raw JSON Reports

- [Sovereign Report]($sovereignJson)
- [Ollama Report]($ollamaJson)

---

## Methodology

### Hardware Lock
Both systems ran on:
- Same machine
- Same model ($Model)
- Same quantization
- Same context length
- Same prompt sets
- Same GPU/CPU backend

### Swarm Configuration
- **Size:** 16 agents (Phi workers)
- **Distribution:** Round-robin across available compute

### Metrics Collected

1. **Latency:** Time to complete operation (ms)
2. **Throughput:** Operations per second
3. **Success Rate:** Percentage of successful completions
4. **Quality Score:** 0-100 based on structure, correctness, depth
5. **Resource Usage:** CPU%, Memory, VRAM, GPU%

---

## Conclusion

*Results pending completion of both benchmark runs...*

---

## Next Steps

1. Review individual benchmark JSON files for detailed metrics
2. Analyze performance deltas
3. Identify optimization opportunities
4. Re-run with different models/configurations

---

*Generated by Sovereign vs Ollama Benchmark Suite v1.0*
"@

$comparisonReport | Out-File -FilePath $comparisonMd -Encoding UTF8

Write-Host "Comparison report saved to: $comparisonMd" -ForegroundColor Green
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Green
Write-Host "Benchmark Comparison Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Results:" -ForegroundColor Cyan
Write-Host "  Sovereign JSON: $sovereignJson"
Write-Host "  Ollama JSON: $ollamaJson"
Write-Host "  Comparison MD: $comparisonMd"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review the comparison report"
Write-Host "  2. Analyze individual JSON files"
Write-Host "  3. Run with different models: .\run_comparison.ps1 -Model 'llama-3.1-8B'"
Write-Host ""

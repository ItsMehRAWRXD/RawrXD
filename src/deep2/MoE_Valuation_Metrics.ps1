# ============================================================================
# MoE_Valuation_Metrics.ps1 - Modernized valuation harness for the new MoE
# runtime. Replaces the deleted Deep2_Valuation_Metrics.ps1.
#
# Builds and runs the VAL-038 acceptance test against the clean, unencumbered
# MoE runtime, producing the definitive benchmark report.
#
# Usage:
#   .\MoE_Valuation_Metrics.ps1 [-ModelPath path] [-Tokens N] [-Threads N]
#
# Copyright (c) 2026 RawrXD Sovereign Runtime
# ============================================================================

param(
    [string]$ModelPath = "d:\models\deepseek_moe_q4_k.gguf",
    [int]$Tokens = 32,
    [int]$Threads = 16,
    [string]$ClPath = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe",
    [string]$IncludeDir = "d:\RawrXD\src\deep2"
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  MoE Valuation Metrics - VAL-038" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Model:    $ModelPath"
Write-Host "  Tokens:   $Tokens"
Write-Host "  Threads:  $Threads"
Write-Host ""

# --- Verify compiler ---
if (-not (Test-Path $ClPath)) {
    Write-Host "[!] cl.exe not found at: $ClPath" -ForegroundColor Red
    Write-Host "    Set -ClPath to your MSVC cl.exe location." -ForegroundColor Yellow
    exit 1
}

# --- Source files ---
$Sources = @(
    "val038_deepseek_moe_e2e.cpp",
    "DeepSeekMoELoader.cpp",
    "MoEArchitectureParser.cpp",
    "MoERouter.cpp",
    "MoEWeightProxy.cpp",
    "MoEWeightsLoader.cpp",
    "Deep2Engine.cpp",
    "GGUFLoader.cpp",
    "ThreadPool.cpp",
    "QuantKernelRegistry.cpp"
)

$SourceDir = "d:\RawrXD\src\deep2"
$OutputExe = "moe_val_bench.exe"

# --- Verify all sources exist ---
Write-Host "[*] Verifying source files..." -ForegroundColor Cyan
$missing = @()
foreach ($src in $Sources) {
    $fullPath = Join-Path $SourceDir $src
    if (-not (Test-Path $fullPath)) {
        $missing += $src
    }
}

if ($missing.Count -gt 0) {
    Write-Host "[!] Missing source files:" -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "    $m" -ForegroundColor Red
    }
    exit 1
}

Write-Host "[*] All $($Sources.Count) source files present." -ForegroundColor Green

# --- Build ---
Write-Host ""
Write-Host "[*] Building MoE Valuation Binary..." -ForegroundColor Cyan

$sourceArgs = $Sources | ForEach-Object { Join-Path $SourceDir $_ }
$buildArgs = @(
    "/O2", "/arch:AVX512", "/std:c++17", "/EHsc",
    "/I$IncludeDir",
    "/Fe:$OutputExe"
) + $sourceArgs

Write-Host "    cl.exe $($buildArgs -join ' ')" -ForegroundColor DarkGray

& $ClPath @buildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Build failed (exit code $LASTEXITCODE)." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[*] Build succeeded: $OutputExe" -ForegroundColor Green

# --- Run ---
Write-Host ""
Write-Host "[*] Executing Valuation Benchmark..." -ForegroundColor Cyan

$runArgs = @("--tokens", $Tokens, "--threads", $Threads)
if (Test-Path $ModelPath) {
    $runArgs += @("--model", $ModelPath)
}

& ".\$OutputExe" @runArgs

$exitCode = $LASTEXITCODE

Write-Host ""
if ($exitCode -eq 0) {
    Write-Host "[*] VAL-038: PASS" -ForegroundColor Green
} else {
    Write-Host "[!] VAL-038: FAIL (exit code $exitCode)" -ForegroundColor Red
}

exit $exitCode
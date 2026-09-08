$ErrorActionPreference = "Stop"

$Repo = "G:\~dev\rawrxd"
$Build = Join-Path $Repo "build-ninja"
$K2 = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M"

if (!(Test-Path $Repo)) { throw "Missing repo: $Repo" }
if (!(Test-Path $K2)) { throw "Missing K2 root: $K2" }

$env:DEEP2_K2_SHARD_DIR = $K2

Write-Host "C1-C9 source drop installed."
Write-Host "Do not auto-mark gates PASS."
Write-Host "Run each existing/new cert target after wiring its live adapter."
Write-Host ""
Write-Host "Order:"
Write-Host "  C1 K2_LOGITS_GPU_RANGE_ATTRIBUTION_001"
Write-Host "  C2 K2_LOGITS_RANGE_SWEEP_001"
Write-Host "  C3 K2_LOGITS_RANGE_FREEZE_001"
Write-Host "  C4 VWA_ASYNC_FILE_RANGE_001"
Write-Host "  C5 VWA_GPU_TRANSFER_001"
Write-Host "  C6 VWA_K2_EXPERT_SELECTIVE_001"
Write-Host "  C7 VWA_K2_PREFETCH_OVERLAP_001"
Write-Host "  C8 VWA_BOUNDED_K2_001"
Write-Host "  C9 VWA_K2_FULL_E2E_001"

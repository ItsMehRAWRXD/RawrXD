# P1PRA reconclusion E2E — preserves E2E.log / RUN.log / WITNESS.log (no delete at start).
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$env:RAWRXD_EVIDENCE_ROOT = 'f:\~dev\rawrxd\evidence'
$env:RAWRXD_E2E_SHUTDOWN = '1'
$env:OLLAMA_MODELS = 'G:\OllamaModels'
$env:RAWRXD_MODELS_PATH = 'G:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf'
$env:VK_ICD_FILENAMES = 'C:\__no_vulkan_icd__.json'
$env:VK_DRIVER_FILES = 'C:\__no_vulkan_icd__.json'
$env:DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1 = '1'
$env:RAWRXD_SKIP_STREAMER_POSTLOAD = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:RAWRXD_BRIDGE_CPU_ONLY = '1'
$env:RAWRXD_SKIP_DEFERRED_MODEL_LOAD = '1'
$env:RAWRXD_INFERENCE_CTX = '512'
# UTC MASM path faults at cf_shadow_rsp_pre (utc_stage=47) on this host; bypass for E2E witness.
$env:RAWRXD_SKIP_UTC_MASM = '1'

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$archive = Join-Path $root "RECONCLUSION_RUN_$stamp"
New-Item -ItemType Directory -Force -Path $archive | Out-Null

foreach ($name in @('E2E.log', 'RUN.log', 'WITNESS.log')) {
  $src = Join-Path $root $name
  if (Test-Path $src) {
    Copy-Item $src (Join-Path $archive "pre_$name") -Force
  }
}

$runner = Join-Path $root 'run_e2e_product_authority.ps1'
$content = Get-Content $runner -Raw
$content = $content -replace "Remove-Item `$e2e -ErrorAction SilentlyContinue\r?\n", ''
$content = $content -replace "Remove-Item `$run -ErrorAction SilentlyContinue\r?\n", ''
$content = $content -replace "Remove-Item Env:RAWRXD_SKIP_UTC_MASM -ErrorAction SilentlyContinue\r?\n", ''
$patched = Join-Path $env:TEMP "p1pra_reconclusion_e2e_$stamp.ps1"
Set-Content -Path $patched -Value $content -Encoding UTF8

Write-Host "archive_pre=$archive"
Write-Host "patched_runner=$patched"
& $patched
$code = if ($null -ne $LASTEXITCODE) { $LASTEXITCODE } else { 1 }

foreach ($name in @('E2E.log', 'RUN.log', 'WITNESS.log')) {
  $src = Join-Path $root $name
  if (Test-Path $src) {
    Copy-Item $src (Join-Path $archive "post_$name") -Force
  }
}
Set-Content -Path (Join-Path $archive 'exit.code') -Value $code -NoNewline

$hooks = @()
$w = Join-Path $root 'WITNESS.log'
$witnessBaseline = 0
$preWitness = Join-Path $archive "pre_WITNESS.log"
if (Test-Path $preWitness) {
  $witnessBaseline = @(Get-Content -LiteralPath $preWitness -ErrorAction SilentlyContinue).Count
}
if (Test-Path $w) {
  $allW = @(Get-Content -LiteralPath $w -ErrorAction SilentlyContinue)
  if ($witnessBaseline -lt $allW.Count) {
    $freshW = $allW[$witnessBaseline..($allW.Count - 1)]
    $hooks = $freshW | Where-Object { $_ -match 'P1PRA_HOOK=' } | Select-Object -Last 20
  }
}
$summary = @(
  "exit=$code",
  "archive=$archive",
  "hook_lines=$($hooks.Count)"
)
if ($hooks) { $summary += @($hooks) }
Set-Content -Path (Join-Path $archive 'RECONCLUSION_RUN_SUMMARY.txt') -Value $summary
Write-Host "post_archive=$archive exit=$code"
exit $code

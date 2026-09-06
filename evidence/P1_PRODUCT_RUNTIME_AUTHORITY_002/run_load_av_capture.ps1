# P1PRA Load AV isolation — debug session 1ed348
# Run after rebuilding build_p1pra_win32ide with instrumentation.

$ErrorActionPreference = 'Stop'
$env:RAWRXD_EVIDENCE_ROOT = 'f:\~dev\rawrxd\evidence'
$env:RAWRXD_E2E_SHUTDOWN = '1'
$env:RAWRXD_MODELS_PATH = 'G:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf'
$env:OLLAMA_MODELS = 'G:\OllamaModels'
$env:VK_ICD_FILENAMES = 'C:\__no_vulkan_icd__.json'
$env:VK_DRIVER_FILES = 'C:\__no_vulkan_icd__.json'
$env:DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1 = '1'
$env:RAWRXD_SKIP_STREAMER_POSTLOAD = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:RAWRXD_BRIDGE_CPU_ONLY = '1'
$env:RAWRXD_SKIP_DEFERRED_MODEL_LOAD = '1'
$env:RAWRXD_INFERENCE_CTX = '512'
$env:RAWRXD_E2E_EXE = 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe'
$evidenceDbg = Join-Path $env:RAWRXD_EVIDENCE_ROOT 'P1_PRODUCT_RUNTIME_AUTHORITY_002\debug-1ed348.log'
$dbg = 'f:\~dev\debug-1ed348.log'
$env:RAWRXD_DEBUG_LOG = $evidenceDbg
# Post-fix verification: skip MASM UTC kernel (fatal AV at cf_shadow_rsp_pre)
$env:RAWRXD_SKIP_UTC_MASM = '1'

foreach ($p in @($dbg, $evidenceDbg)) {
    if (Test-Path $p) { Remove-Item $p -Force }
}

Write-Host "=== P1PRA load AV capture (session 1ed348) ==="
Write-Host "NDJSON logs: $dbg ; $evidenceDbg"
& "$PSScriptRoot\run_e2e_product_authority.ps1"
$exit = $LASTEXITCODE
Write-Host "harness_exit=$exit"
if (Test-Path $dbg) {
  Write-Host '--- debug-1ed348.log (workspace) ---'
  Get-Content $dbg
} elseif (Test-Path $evidenceDbg) {
  Write-Host '--- debug-1ed348.log (evidence) ---'
  Get-Content $evidenceDbg
} else {
  Write-Host 'debug log missing (process may have died before instrumentation)'
}
exit $exit

# Wrapper: run physical E2E and tee full trace to %TEMP%\P1PRA_E2E_TRACE.txt
$ErrorActionPreference = 'Stop'
$env:RAWRXD_EVIDENCE_ROOT = 'f:\~dev\rawrxd\evidence'
$env:RAWRXD_P1PRA_TRACE = '1'
$env:RAWRXD_MODEL = 'G:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf'
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
$trace = Join-Path $env:TEMP 'P1PRA_E2E_TRACE.txt'
$script = Join-Path $PSScriptRoot 'run_e2e_product_authority.ps1'
Remove-Item $trace -Force -ErrorAction SilentlyContinue
& $script *>&1 | Tee-Object -FilePath $trace
$code = $LASTEXITCODE
Add-Content -Path $trace -Value "EXIT=$code"
exit $code

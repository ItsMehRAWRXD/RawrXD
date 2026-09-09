# ONE_BY_ONE_IGNORE_LADDER_001 diagnostic harness skeleton.
# Purpose: ownership only. PROMOTE=0 for every run.

$ErrorActionPreference = 'Stop'
$exe = 'G:\~dev\rawrxd\build-fd\bin\deep2_streamer_parity.exe'
$model = 'g:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$prompt = 'Say hello in one short sentence.'
$outDir = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\ONE_BY_ONE_IGNORE_LADDER_001'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

function Run-Iso($name, $vars) {
    Get-ChildItem Env:RAWRXD_IGNORE_* -EA SilentlyContinue | Remove-Item -EA SilentlyContinue
    Get-ChildItem Env:RAWRXD_DIAG_* -EA SilentlyContinue | Remove-Item -EA SilentlyContinue
    foreach ($k in $vars.Keys) { Set-Item -Path "Env:$k" -Value $vars[$k] }
    Set-Item Env:RAWRXD_ISOLATION_RUN $name
    Set-Item Env:RAWRXD_PROMOTE 0
    & $exe --model $model --prompt $prompt --max-tokens 20 `
      1> (Join-Path $outDir "$name.out") `
      2> (Join-Path $outDir "$name.err")
    Select-String -LiteralPath (Join-Path $outDir "$name.out"),(Join-Path $outDir "$name.err") `
      -Pattern 'ISOLATION_RUN|IGNORED_OWNER|TOKENS_COMMITTED|TOKENS_DECODED|DECODE_OWNER|FORWARD_MS|LOGITS_MS|SAMPLE_MS|DETOK_MS|CALLBACK_MS|RECEIPT_MS|STREAMER_TPS|PROMOTE|DISPOSITION' |
      ForEach-Object { $_.Line }
}

Run-Iso 'A0_BASELINE' @{}
Run-Iso 'A1_IGNORE_BATCH007' @{ 'RAWRXD_IGNORE_BATCH007_EMIT'='1' }
Run-Iso 'A2_IGNORE_PRODUCT_SEAL' @{ 'RAWRXD_IGNORE_PRODUCT_PATH_SEAL'='1' }
Run-Iso 'A6_LOGITS_DIAG' @{ 'RAWRXD_DIAG_LOGITS_ATTRIB'='1' }
Run-Iso 'A8_FORWARD_DIAG' @{ 'RAWRXD_DIAG_FORWARD_ATTRIB'='1' }
Run-Iso 'A10_FFN_DIAG' @{ 'RAWRXD_DIAG_FFN_ATTRIB'='1' }

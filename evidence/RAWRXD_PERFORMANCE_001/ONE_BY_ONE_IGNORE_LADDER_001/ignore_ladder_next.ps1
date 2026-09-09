# ONE_BY_ONE_IGNORE_LADDER_001 — DEEP2_ISOLATION_RUN=A0..A12
# Ownership only. PROMOTE=0. One ignore per run.
$ErrorActionPreference = 'Stop'
$exe = 'G:\~dev\rawrxd\build-fd\bin\deep2_streamer_parity.exe'
$model = 'G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$prompt = 'Say hello in one short sentence.'
$outDir = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\ONE_BY_ONE_IGNORE_LADDER_001'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$env:DEEP2_EV512 = '0'
$env:RAWRXD_FFN_TRACE = '0'
$env:TOKEN_PACING = 'OFF'
$env:DECODE_SLEEP = '0'
$env:RAWRXD_PROMOTE = '0'
$env:DEEP2_ISOLATION_BASELINE_TPS = '5.523'
Remove-Item Env:RAWRXD_ISOLATION_RUN -EA SilentlyContinue

function Run-Iso([string]$run) {
    $env:DEEP2_ISOLATION_RUN = $run
    Write-Host "=== $run ==="
    & $exe --model $model --prompt $prompt --max-tokens 20 `
        1> (Join-Path $outDir "$run.out") `
        2> (Join-Path $outDir "$run.err")
    Select-String -LiteralPath (Join-Path $outDir "$run.out"),(Join-Path $outDir "$run.err") `
        -Pattern 'ISOLATION_RUN=|IGNORED_OWNER=|TOKENS_COMMITTED=|DECODE_OWNER=|FORWARD_MS=|LOGITS_MS=|STREAMER_TPS=|DISPOSITION=|MODEL_PROVENANCE_MATCH=' |
        ForEach-Object { $_.Line.Trim() }
}

foreach ($r in @('A0','A1','A2','A3','A4','A5','A6','A7','A8','A9','A10')) { Run-Iso $r }

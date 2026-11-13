$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch11_gpu_residual'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$want = 'E6A387C3272E4B0A3E1EC44FE96DB7B2DEDE5E4CB4B3E0E6108620F6DA7452B7'
$sha = (Get-FileHash $SMOKE -Algorithm SHA256).Hash
$sha | Set-Content -Encoding ascii (Join-Path $out 'EXE_SHA256.txt')
@"
LIVE_EXE_PATH=$SMOKE
EXE_SHA256=$sha
WANT=$want
MATCH=$($sha -eq $want)
ASOF=$((Get-Date).ToString('o'))
CROSS_SHA_CREDIT=0
"@ | Set-Content -Encoding ascii (Join-Path $out 'EXE_CONFIRM.txt')
Write-Host "EXE_CONFIRM MATCH=$($sha -eq $want) SHA=$sha"
if ($sha -ne $want) { throw 'EXE_SHA mismatch; refuse credit' }

Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_Q6K_FORCE_F32_GPU -ErrorAction SilentlyContinue
Remove-Item Env:DEEP2_KV_F32 -ErrorAction SilentlyContinue
$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'

Push-Location $EV
Write-Host "START GPU remasure $(Get-Date -Format o)"
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'gpu_t16.stdout.txt')
$ec = $LASTEXITCODE
Pop-Location
Write-Host "GPU_EXIT=$ec DONE $(Get-Date -Format o)"

$lines = Get-Content (Join-Path $out 'gpu_t16.stdout.txt')
$toks = @()
$seen16 = 0
foreach ($ln in $lines) {
  if ($ln -match 'LAYER_COUNT=28 TOKENS=16') {
    $seen16++
    if ($seen16 -eq 1) { $toks = @() }
  }
  if ($seen16 -ge 1 -and $ln -match '\[DBG\] sampled token=(\d+)') {
    $toks += [int]$Matches[1]
  }
  if ($toks.Count -ge 16 -and $ln -match 'DECODE: 16 tok') { break }
}
$gpu16 = ($toks | Select-Object -First 16) -join ','
Write-Host "GPU_16=$gpu16"
"GPU_16=$gpu16" | Set-Content -Encoding ascii (Join-Path $out 'GPU_16.txt')
Select-String -Path (Join-Path $out 'gpu_t16.stdout.txt') -Pattern 'DEEP2_REAL_GPU_FORWARD=|GPU_FORWARD_LAYERS_PER_TOKEN=|batchedMatMulCount|ROPE_PAIRING=|RAWR_REAP_CPU_ONLY|PREFILL_BATCHED=' |
  Select-Object -Last 40 |
  ForEach-Object { $_.Line }

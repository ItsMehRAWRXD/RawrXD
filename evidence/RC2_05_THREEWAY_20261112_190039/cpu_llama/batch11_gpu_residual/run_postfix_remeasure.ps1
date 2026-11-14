$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch11_gpu_residual'
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$old = 'E6A387C3272E4B0A3E1EC44FE96DB7B2DEDE5E4CB4B3E0E6108620F6DA7452B7'
$sha = (Get-FileHash $SMOKE -Algorithm SHA256).Hash
$sha | Set-Content -Encoding ascii (Join-Path $out 'EXE_SHA256_POSTFIX.txt')
@"
LIVE_EXE_PATH=$SMOKE
EXE_SHA256=$sha
PRIOR_E6A387C3=$old
CROSS_SHA_CREDIT=0
NEW_SHA=$([bool]($sha -ne $old))
ASOF=$((Get-Date).ToString('o'))
"@ | Set-Content -Encoding ascii (Join-Path $out 'EXE_CONFIRM_POSTFIX.txt')
Write-Host "POSTFIX_SHA=$sha NEW=$($sha -ne $old)"
if ($sha -eq $old) { throw 'EXE SHA unchanged after rebuild; refuse credit' }

$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
Remove-Item Env:DEEP2_BATCHED_PREFILL -ErrorAction SilentlyContinue
Remove-Item Env:DEEP2_KV_F32 -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_Q6K_FORCE_F32_GPU -ErrorAction SilentlyContinue

function Parse-SecondGen16([string]$path) {
  $lines = Get-Content $path
  $toks = @(); $seen16 = 0
  foreach ($ln in $lines) {
    if ($ln -match 'LAYER_COUNT=28 TOKENS=16') { $seen16++; if ($seen16 -eq 1) { $toks = @() } }
    if ($seen16 -ge 1 -and $ln -match '\[DBG\] sampled token=(\d+)') { $toks += [int]$Matches[1] }
    if ($toks.Count -ge 16 -and $ln -match 'DECODE: 16 tok') { break }
  }
  return ($toks | Select-Object -First 16) -join ','
}

Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Push-Location $EV
Write-Host "START GPU postfix $(Get-Date -Format o)"
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'gpu_t16_postfix.stdout.txt')
Write-Host "GPU_DONE exit=$LASTEXITCODE"
Pop-Location
$gpu16 = Parse-SecondGen16 (Join-Path $out 'gpu_t16_postfix.stdout.txt')
Write-Host "GPU_16=$gpu16"
"GPU_16=$gpu16" | Set-Content -Encoding ascii (Join-Path $out 'GPU_16_POSTFIX.txt')

$env:RAWR_REAP_CPU_ONLY = '1'
Push-Location $EV
Write-Host "START CPU postfix $(Get-Date -Format o)"
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'cpu_t16_postfix.stdout.txt')
Write-Host "CPU_DONE exit=$LASTEXITCODE"
Pop-Location
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
$cpu16 = Parse-SecondGen16 (Join-Path $out 'cpu_t16_postfix.stdout.txt')
Write-Host "CPU_16=$cpu16"
"CPU_16=$cpu16" | Set-Content -Encoding ascii (Join-Path $out 'CPU_16_POSTFIX.txt')

$ref = '576,23192,16895,63762,374,279,2790,1372,315,821,27035,429,646,387,15233,553'
Write-Host "CPU_EQ_FAOFF=$($cpu16 -eq $ref)"
Write-Host "--- GPU markers ---"
Select-String -Path (Join-Path $out 'gpu_t16_postfix.stdout.txt') -Pattern 'PREFILL_BATCHED|batchedMatMulCount|DEEP2_REAL_GPU_FORWARD=|GPU_HOST_KV' |
  Select-Object -Last 16 | ForEach-Object { $_.Line.Trim() }
Write-Host "--- CPU markers ---"
Select-String -Path (Join-Path $out 'cpu_t16_postfix.stdout.txt') -Pattern 'PREFILL_BATCHED|batchedMatMulCount|RAWR_REAP_CPU_ONLY|DEEP2_REAL_GPU_FORWARD=' |
  Select-Object -Last 16 | ForEach-Object { $_.Line.Trim() }

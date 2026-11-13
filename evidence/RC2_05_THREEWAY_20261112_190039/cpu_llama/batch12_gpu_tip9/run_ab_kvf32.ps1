$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch12_gpu_tip9'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$want = '0AC0481DD26979FF3155D1F427C32BA94E932B9A7395D9EC8CB668C5B84371F4'
$sha = (Get-FileHash $SMOKE -Algorithm SHA256).Hash
"EXE_SHA256=$sha`nMATCH=$($sha -eq $want)" | Set-Content (Join-Path $out 'EXE_CONFIRM.txt')
Write-Host "EXE MATCH=$($sha -eq $want) $sha"
if ($sha -ne $want) { throw 'EXE SHA mismatch' }

$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
Remove-Item Env:DEEP2_BATCHED_PREFILL -ErrorAction SilentlyContinue

function Parse16([string]$path) {
  $lines = Get-Content $path
  $toks = @(); $seen16 = 0
  foreach ($ln in $lines) {
    if ($ln -match 'LAYER_COUNT=28 TOKENS=16') { $seen16++; if ($seen16 -eq 1) { $toks = @() } }
    if ($seen16 -ge 1 -and $ln -match '\[DBG\] sampled token=(\d+)') { $toks += [int]$Matches[1] }
    if ($toks.Count -ge 16 -and $ln -match 'DECODE: 16 tok') { break }
  }
  return ($toks | Select-Object -First 16) -join ','
}

# CPU F16 (default authority)
$env:RAWR_REAP_CPU_ONLY = '1'
Remove-Item Env:DEEP2_KV_F32 -ErrorAction SilentlyContinue
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'cpu_f16.stdout.txt')
Pop-Location
$cpuF16 = Parse16 (Join-Path $out 'cpu_f16.stdout.txt')
Write-Host "CPU_F16=$cpuF16"

# CPU F32 KV (no roundtrip) — expect GPU basin if F16 is FIRST_OP
$env:DEEP2_KV_F32 = '1'
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'cpu_f32kv.stdout.txt')
Pop-Location
$cpuF32 = Parse16 (Join-Path $out 'cpu_f32kv.stdout.txt')
Write-Host "CPU_F32KV=$cpuF32"
Remove-Item Env:DEEP2_KV_F32 -ErrorAction SilentlyContinue
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue

# GPU default (device KV F32 copy)
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'gpu_default.stdout.txt')
Pop-Location
$gpu = Parse16 (Join-Path $out 'gpu_default.stdout.txt')
Write-Host "GPU=$gpu"

$ref = '576,23192,16895,63762,374,279,2790,1372,315,821,27035,429,646,387,15233,553'
@"
CPU_F16=$cpuF16
CPU_F32KV=$cpuF32
GPU=$gpu
CPU_F16_EQ_FAOFF=$($cpuF16 -eq $ref)
CPU_F32KV_EQ_GPU=$($cpuF32 -eq $gpu)
CPU_F32KV_TIP9=$(($cpuF32 -split ',')[9])
GPU_TIP9=$(($gpu -split ',')[9])
CPU_F16_TIP9=$(($cpuF16 -split ',')[9])
"@ | Set-Content (Join-Path $out 'AB_KVF32.txt')
Get-Content (Join-Path $out 'AB_KVF32.txt')

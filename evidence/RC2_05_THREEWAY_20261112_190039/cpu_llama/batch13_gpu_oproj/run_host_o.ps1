$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch13_gpu_oproj'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$prior = 'D24DFC60A52DC1E70714E6A4FF0893089F7EAE0761F0A0D0668B54613F90B530'
$sha = (Get-FileHash $SMOKE -Algorithm SHA256).Hash
@"
EXE_SHA256=$sha
PRIOR_D24DFC60=$prior
NEW_SHA=$([bool]($sha -ne $prior))
CROSS_SHA_CREDIT=0
ASOF=$((Get-Date).ToString('o'))
"@ | Set-Content (Join-Path $out 'EXE_CONFIRM.txt')
$sha | Set-Content (Join-Path $out 'EXE_SHA256.txt')
Write-Host "EXE_SHA=$sha NEW=$($sha -ne $prior)"

$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
Remove-Item Env:DEEP2_BATCHED_PREFILL,Env:DEEP2_KV_F32,Env:DEEP2_GPU_DEVICE_ATTN,Env:DEEP2_GPU_DEVICE_O,Env:DEEP2_01B_DUMP -ErrorAction SilentlyContinue

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

Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'gpu.stdout.txt')
Pop-Location
$gpu = Parse16 (Join-Path $out 'gpu.stdout.txt')
Write-Host "GPU_16=$gpu"

$env:RAWR_REAP_CPU_ONLY = '1'
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'cpu.stdout.txt')
Pop-Location
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
$cpu = Parse16 (Join-Path $out 'cpu.stdout.txt')
Write-Host "CPU_16=$cpu"

$ref = '576,23192,16895,63762,374,279,2790,1372,315,821,27035,429,646,387,15233,553'
$gc = $gpu.Split(','); $cc = $cpu.Split(','); $fc = $ref.Split(',')
$misG = -1; for ($i = 0; $i -lt [Math]::Min(16,$gc.Count); $i++) { if ($gc[$i] -ne $cc[$i]) { $misG = $i; break } }
if ($gc.Count -lt 16 -and $misG -lt 0) { $misG = $gc.Count }
$misC = -1; for ($i = 0; $i -lt 16; $i++) { if ($cc[$i] -ne $fc[$i]) { $misC = $i; break } }
@"
GPU_16=$gpu
CPU_16=$cpu
LLAMA_FAOFF_16=$ref
EXACT16_CPU=$($misC -lt 0)
THREE_WAY=$(($misC -lt 0) -and ($misG -lt 0) -and ($gc.Count -ge 16))
FIRST_MIS_GPU_CPU=@$misG
"@ | Set-Content (Join-Path $out 'RESULT.txt')
Get-Content (Join-Path $out 'RESULT.txt')
Select-String -Path (Join-Path $out 'gpu.stdout.txt') -Pattern 'GPU_HOST_ATTN|HOST_O|DEEP2_REAL_GPU_FORWARD=|PREFILL_BATCHED|B3_FAIL|FORWARD_FAULT|sampled token=' |
  Select-Object -First 40 | ForEach-Object { $_.Line.Trim() }

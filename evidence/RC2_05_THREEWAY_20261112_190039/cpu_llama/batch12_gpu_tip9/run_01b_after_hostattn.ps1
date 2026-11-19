$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch12_gpu_tip9'
$cpuDir = Join-Path $out '01b_cpu_post'
$gpuDir = Join-Path $out '01b_gpu_hostattn'
New-Item -ItemType Directory -Force -Path $cpuDir,$gpuDir | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
$env:DEEP2_01B_DUMP = '1'
$env:DEEP2_01B_POS_LIST = '17'
Remove-Item Env:DEEP2_GPU_DEVICE_ATTN,Env:DEEP2_BATCHED_PREFILL,Env:DEEP2_KV_F32 -ErrorAction SilentlyContinue

function Parse16([string]$path) {
  $lines = Get-Content $path; $toks=@(); $seen16=0
  foreach ($ln in $lines) {
    if ($ln -match 'LAYER_COUNT=28 TOKENS=16') { $seen16++; if ($seen16 -eq 1) { $toks=@() } }
    if ($seen16 -ge 1 -and $ln -match '\[DBG\] sampled token=(\d+)') { $toks += [int]$Matches[1] }
    if ($toks.Count -ge 16 -and $ln -match 'DECODE: 16 tok') { break }
  }
  return ($toks | Select-Object -First 16) -join ','
}

$env:RAWR_REAP_CPU_ONLY='1'; $env:DEEP2_01B_SIDE='cpu'; $env:DEEP2_01B_DIR=$cpuDir
Push-Location $EV; & $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out '01b_cpu_post.stdout.txt'); Pop-Location
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Write-Host "CPU=$(Parse16 (Join-Path $out '01b_cpu_post.stdout.txt'))"

$env:DEEP2_01B_SIDE='gpu'; $env:DEEP2_01B_DIR=$gpuDir
Push-Location $EV; & $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out '01b_gpu_hostattn.stdout.txt'); Pop-Location
Write-Host "GPU=$(Parse16 (Join-Path $out '01b_gpu_hostattn.stdout.txt'))"
Remove-Item Env:DEEP2_01B_DUMP,Env:DEEP2_01B_SIDE,Env:DEEP2_01B_DIR,Env:DEEP2_01B_POS_LIST -ErrorAction SilentlyContinue

$stages=@('Q_POSTROPE','K_POSTROPE','KV_WRITE_K','KV_WRITE_V','ATTN_OUT','O_PROJ','AFTER_ATTN_RESIDUAL')
$cmp=Join-Path $out '01b_cmp_hostattn.txt'
Remove-Item $cmp -ErrorAction SilentlyContinue
Add-Content $cmp '=== POS 17 hostattn vs cpu ==='
foreach ($st in $stages) {
  $a=Join-Path $cpuDir ("cpu_L0_P17_{0}.f32" -f $st)
  $b=Join-Path $gpuDir ("gpu_L0_P17_{0}.f32" -f $st)
  if (!(Test-Path $a) -or !(Test-Path $b)) { Add-Content $cmp "MISSING $st a=$(Test-Path $a) b=$(Test-Path $b)"; continue }
  $ba=[IO.File]::ReadAllBytes($a); $bb=[IO.File]::ReadAllBytes($b)
  $n=[int]($ba.Length/4); $maxAbs=0.0; $sumSq=0.0; $first=-1
  for ($i=0;$i -lt $n;$i++) {
    $fa=[BitConverter]::ToSingle($ba,$i*4); $fb=[BitConverter]::ToSingle($bb,$i*4)
    $d=[Math]::Abs([double]$fa-$fb); $sumSq+=$d*$d
    if ($d -gt $maxAbs) { $maxAbs=$d }
    if ($first -lt 0 -and $d -gt 1e-5) { $first=$i }
  }
  Add-Content $cmp ("{0}: maxAbs={1:E6} rms={2:E6} first={3}" -f $st,$maxAbs,[Math]::Sqrt($sumSq/[Math]::Max(1,$n)),$first)
}
Get-Content $cmp
Select-String -Path (Join-Path $out '01b_gpu_hostattn.stdout.txt') -Pattern 'GPU_HOST_ATTN|LOGIT_DIAG\] step=18|sampled token=16895|sampled token=821' | Select-Object -First 20 | ForEach-Object { $_.Line.Trim() }

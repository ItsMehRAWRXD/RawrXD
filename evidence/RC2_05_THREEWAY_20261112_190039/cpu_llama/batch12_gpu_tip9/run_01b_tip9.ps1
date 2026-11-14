$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch12_gpu_tip9'
$cpuDir = Join-Path $out '01b_cpu'
$gpuDir = Join-Path $out '01b_gpu'
New-Item -ItemType Directory -Force -Path $cpuDir,$gpuDir | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
$env:DEEP2_01B_DUMP = '1'
$env:DEEP2_01B_POS_LIST = '9,17'
Remove-Item Env:DEEP2_KV_F32 -ErrorAction SilentlyContinue
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

$env:RAWR_REAP_CPU_ONLY = '1'
$env:DEEP2_01B_SIDE = 'cpu'
$env:DEEP2_01B_DIR = $cpuDir
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out '01b_cpu.stdout.txt')
Pop-Location
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Write-Host "CPU_16=$(Parse16 (Join-Path $out '01b_cpu.stdout.txt'))"

$env:DEEP2_01B_SIDE = 'gpu'
$env:DEEP2_01B_DIR = $gpuDir
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out '01b_gpu.stdout.txt')
Pop-Location
Write-Host "GPU_16=$(Parse16 (Join-Path $out '01b_gpu.stdout.txt'))"

Remove-Item Env:DEEP2_01B_DUMP,Env:DEEP2_01B_SIDE,Env:DEEP2_01B_DIR,Env:DEEP2_01B_POS_LIST -ErrorAction SilentlyContinue

# Compare dumps
$stages = @('Q_POSTBIAS','K_POSTBIAS','V_POSTBIAS','Q_POSTROPE','K_POSTROPE','KV_WRITE_K','KV_WRITE_V','ATTN_OUT','O_PROJ','AFTER_ATTN_RESIDUAL')
$cmp = Join-Path $out '01b_cmp.txt'
Remove-Item $cmp -ErrorAction SilentlyContinue
foreach ($pos in @(9,17)) {
  Add-Content $cmp "=== POS $pos ==="
  foreach ($st in $stages) {
    $a = Join-Path $cpuDir ("cpu_L0_P{0}_{1}.f32" -f $pos, $st)
    $b = Join-Path $gpuDir ("gpu_L0_P{0}_{1}.f32" -f $pos, $st)
    if (!(Test-Path $a) -or !(Test-Path $b)) {
      Add-Content $cmp "MISSING $st cpu=$(Test-Path $a) gpu=$(Test-Path $b)"
      continue
    }
    $ba = [System.IO.File]::ReadAllBytes($a)
    $bb = [System.IO.File]::ReadAllBytes($b)
    if ($ba.Length -ne $bb.Length) { Add-Content $cmp "$st SIZE_MISMATCH $($ba.Length) vs $($bb.Length)"; continue }
    $n = [int]($ba.Length / 4)
    $maxAbs = 0.0; $sumSq = 0.0; $first = -1
    for ($i = 0; $i -lt $n; $i++) {
      $fa = [BitConverter]::ToSingle($ba, $i * 4)
      $fb = [BitConverter]::ToSingle($bb, $i * 4)
      $d = [Math]::Abs([double]$fa - $fb)
      $sumSq += $d * $d
      if ($d -gt $maxAbs) { $maxAbs = $d }
      if ($first -lt 0 -and $d -gt 1e-5) { $first = $i }
    }
    $rms = [Math]::Sqrt($sumSq / [Math]::Max(1, $n))
    Add-Content $cmp ("{0}: maxAbs={1:E6} rms={2:E6} firstIdx={3} n={4}" -f $st, $maxAbs, $rms, $first, $n)
  }
}
Get-Content $cmp
Write-Host "--- 01B markers ---"
Select-String -Path (Join-Path $out '01b_cpu.stdout.txt'),(Join-Path $out '01b_gpu.stdout.txt') -Pattern '01B_|LAYER0_POST_ROPE|GPU_ROPE_NEOX|KV_F16' |
  Select-Object -First 40 | ForEach-Object { "$($_.Filename):$($_.Line.Trim())" }

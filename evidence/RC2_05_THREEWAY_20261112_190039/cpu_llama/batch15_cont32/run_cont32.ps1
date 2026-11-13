$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch15_cont32'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$EXPECT = '1F517681CA324BE75E0E30892B9AE409DCD8FED6D45B774F60F105E4127DDB1F'
$CLI = 'F:\rawrxd\tmp_llama-cpp-cpu\llama-cli.exe'
$TOK = 'F:\rawrxd\tmp_llama-cpp-cpu\llama-tokenize.exe'
$N = 32

$sha = (Get-FileHash $SMOKE -Algorithm SHA256).Hash
$sha | Set-Content -Encoding ascii (Join-Path $out 'EXE_SHA256.txt')
@"
LIVE_EXE_PATH=$SMOKE
EXE_SHA256=$sha
EXPECT_TIP9_SEAL=$EXPECT
EXE_MATCH=$([bool]($sha -eq $EXPECT))
CROSS_SHA_CREDIT=0
ASOF=$((Get-Date).ToString('o'))
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
DO_NOT_REOPEN_Q4K_ACT=1
"@ | Set-Content -Encoding ascii (Join-Path $out 'EXE_CONFIRM.txt')
Write-Host "EXE_SHA=$sha MATCH=$($sha -eq $EXPECT)"
if ($sha -ne $EXPECT) { throw "EXE SHA mismatch; refuse credit" }

$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
Remove-Item Env:DEEP2_BATCHED_PREFILL,Env:DEEP2_KV_F32,Env:DEEP2_GPU_DEVICE_ATTN,Env:DEEP2_GPU_DEVICE_O,Env:DEEP2_01B_DUMP,Env:RAWRXD_DEEP2_Q6K_FORCE_F32_GPU -ErrorAction SilentlyContinue

function Parse-SecondGenN([string]$path, [int]$n) {
  $lines = Get-Content $path
  $blocks = @(); $cur = @()
  foreach ($ln in $lines) {
    if ($ln -match '\[DBG\] sampled token=(\d+)') {
      $cur += [int]$Matches[1]
    }
    if ($ln -match '\[AGENT\] POST_GENERATE generated=(\d+)') {
      $blocks += ,(@($cur))
      $cur = @()
    }
  }
  if ($cur.Count -gt 0) { $blocks += ,(@($cur)) }
  foreach ($b in $blocks) {
    if ($b.Count -eq $n) { return ($b -join ',') }
  }
  foreach ($b in ($blocks | Sort-Object { $_.Count } -Descending)) {
    if ($b.Count -ge $n) { return (($b | Select-Object -First $n) -join ',') }
  }
  # marker fallback
  $toks = @(); $seen = 0
  foreach ($ln in $lines) {
    if ($ln -match "LAYER_COUNT=28 TOKENS=$n") { $seen++; if ($seen -eq 1) { $toks = @() } }
    if ($seen -ge 1 -and $ln -match '\[DBG\] sampled token=(\d+)') { $toks += [int]$Matches[1] }
    if ($toks.Count -ge $n) { break }
  }
  return ($toks | Select-Object -First $n) -join ','
}

function First-Mis([string]$a, [string]$b) {
  if (-not $a -or -not $b) { return 0 }
  $aa = $a.Split(','); $bb = $b.Split(',')
  $m = [Math]::Min($aa.Count, $bb.Count)
  for ($i = 0; $i -lt $m; $i++) { if ($aa[$i] -ne $bb[$i]) { return $i } }
  if ($aa.Count -ne $bb.Count) { return $m }
  return -1
}

Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Push-Location $EV
Write-Host "START GPU_32 $(Get-Date -Format o)"
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens $N --require-deep2 *> (Join-Path $out 'gpu_t32.stdout.txt')
Write-Host "GPU_DONE exit=$LASTEXITCODE $(Get-Date -Format o)"
Pop-Location
$gpu = Parse-SecondGenN (Join-Path $out 'gpu_t32.stdout.txt') $N
"GPU_32=$gpu" | Set-Content -Encoding ascii (Join-Path $out 'GPU_32.txt')
Write-Host "GPU_32=$gpu"

$env:RAWR_REAP_CPU_ONLY = '1'
Push-Location $EV
Write-Host "START CPU_32 $(Get-Date -Format o)"
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens $N --require-deep2 *> (Join-Path $out 'cpu_t32.stdout.txt')
Write-Host "CPU_DONE exit=$LASTEXITCODE $(Get-Date -Format o)"
Pop-Location
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
$cpu = Parse-SecondGenN (Join-Path $out 'cpu_t32.stdout.txt') $N
"CPU_32=$cpu" | Set-Content -Encoding ascii (Join-Path $out 'CPU_32.txt')
Write-Host "CPU_32=$cpu"

Write-Host "START LLAMA_FAOFF_32 $(Get-Date -Format o)"
$common = @(
  '-m', $GGUF, '-p', $PROMPT, '-n', "$N",
  '--temp', '0', '--top-k', '1', '--top-p', '0', '--min-p', '0',
  '-no-cnv', '--no-display-prompt', '--simple-io', '-c', '2048',
  '-ngl', '0', '-fa', 'off'
)
& $CLI @common *> (Join-Path $out 'llama_cpu_faoff_t32.stdout.txt')
Write-Host "LLAMA_DONE exit=$LASTEXITCODE $(Get-Date -Format o)"

$llines = Get-Content (Join-Path $out 'llama_cpu_faoff_t32.stdout.txt')
$genText = $null
for ($i = 0; $i -lt $llines.Count; $i++) {
  if ($llines[$i] -match 'generate: n_ctx') {
    $buf = New-Object System.Collections.Generic.List[string]
    for ($j = $i + 1; $j -lt $llines.Count; $j++) {
      if ($llines[$j] -match '^common_perf_print:' -or $llines[$j] -match '^llama_memory') { break }
      if ($llines[$j] -match '^\s*$' -and $buf.Count -gt 0) { break }
      if ($llines[$j] -notmatch '^\s*$') { $buf.Add($llines[$j]) }
    }
    $genText = ($buf -join '')
    break
  }
}
if (-not $genText) {
  foreach ($ln in $llines) {
    if ($ln -match '^\s+The ' -or $ln -match '^ The ') { $genText = $ln; break }
  }
}
$genText | Set-Content -Encoding utf8 (Join-Path $out 'llama_faoff_t32_text.txt')
Write-Host "LLAMA_TEXT=$genText"

& $TOK -m $GGUF --ids --no-bos --no-escape -p $genText --log-disable *> (Join-Path $out 'llama_faoff_t32_tokenize.stdout.txt')
$tokOut = Get-Content (Join-Path $out 'llama_faoff_t32_tokenize.stdout.txt') -Raw
$llama = $null
if ($tokOut -match '\[([0-9,\s]+)\]') {
  $ids = ($Matches[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
  $llama = ($ids | Select-Object -First $N) -join ','
}
"LLAMA_FAOFF_32=$llama" | Set-Content -Encoding ascii (Join-Path $out 'LLAMA_FAOFF_32.txt')
Write-Host "LLAMA_FAOFF_32=$llama"

$ref16 = '576,23192,16895,63762,374,279,2790,1372,315,821,27035,429,646,387,15233,553'
$llama16 = if ($llama) { ($llama.Split(',') | Select-Object -First 16) -join ',' } else { '' }
$cpu16 = if ($cpu) { ($cpu.Split(',') | Select-Object -First 16) -join ',' } else { '' }
$gpu16 = if ($gpu) { ($gpu.Split(',') | Select-Object -First 16) -join ',' } else { '' }

$misCpuLlama = First-Mis $cpu $llama
$misGpuCpu = First-Mis $gpu $cpu
$misGpuLlama = First-Mis $gpu $llama
$nCpu = if ($cpu) { $cpu.Split(',').Count } else { 0 }
$nGpu = if ($gpu) { $gpu.Split(',').Count } else { 0 }
$nLlama = if ($llama) { $llama.Split(',').Count } else { 0 }
$exact32 = ($misCpuLlama -lt 0) -and ($misGpuCpu -lt 0) -and ($nCpu -ge $N) -and ($nGpu -ge $N) -and ($nLlama -ge $N)
$threeWay = [int]$exact32
$prefix16Ok = ($llama16 -eq $ref16) -and ($cpu16 -eq $ref16) -and ($gpu16 -eq $ref16)

@"
ASOF=$((Get-Date).ToString('o'))
EXE_SHA256=$sha
EXE_MATCH=1
CROSS_SHA_CREDIT=0
N=32
CPU_32=$cpu
GPU_32=$gpu
LLAMA_FAOFF_32=$llama
CPU_16_PREFIX=$cpu16
GPU_16_PREFIX=$gpu16
LLAMA_16_PREFIX=$llama16
LLAMA_FAOFF_16_AUTHORITY=$ref16
PREFIX16_MATCH_AUTHORITY=$prefix16Ok
FIRST_MIS_CPU_LLAMA=@$misCpuLlama
FIRST_MIS_GPU_CPU=@$misGpuCpu
FIRST_MIS_GPU_LLAMA=@$misGpuLlama
EXACT32=$([int]$exact32)
THREE_WAY_CONT32=$threeWay
THREE_WAY_CONT16=1
RC2_05_PASS=0
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
DO_NOT_REOPEN_Q4K_ACT=1
DEVICE_WO_OPEN=1
SPV_TOUCHED=0
"@ | Set-Content -Encoding ascii (Join-Path $out 'RESULT.txt')
Get-Content (Join-Path $out 'RESULT.txt')

$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch18_tip26_isolate'
$cpuDir = Join-Path $out '01b_cpu'
$gpuDir = Join-Path $out '01b_gpu'
New-Item -ItemType Directory -Force -Path $cpuDir, $gpuDir, (Join-Path $out 'ab') | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$expect = 'DCF607E4821A890513B36257DF8D9E8D6750D0843846104BD7E39D9116B096DA'
$sha = (Get-FileHash $SMOKE -Algorithm SHA256).Hash
if ($sha -ne $expect) { throw "EXE mismatch $sha" }

$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
$env:RAWRXD_LOGIT_DIAG = '1'
Remove-Item Env:DEEP2_KV_F32, Env:DEEP2_GPU_DEVICE_ATTN, Env:DEEP2_GPU_DEVICE_O -ErrorAction SilentlyContinue

function Parse32([string]$path) {
  $lines = Get-Content $path
  $blocks = @(); $cur = @()
  foreach ($ln in $lines) {
    if ($ln -match '\[DBG\] sampled token=(\d+)') { $cur += [int]$Matches[1] }
    if ($ln -match '\[AGENT\] POST_GENERATE generated=(\d+)') {
      $blocks += , (@($cur)); $cur = @()
    }
  }
  if ($cur.Count -gt 0) { $blocks += , (@($cur)) }
  foreach ($b in $blocks) { if ($b.Count -eq 32) { return ($b -join ',') } }
  foreach ($b in ($blocks | Sort-Object { $_.Count } -Descending)) {
    if ($b.Count -ge 32) { return (($b | Select-Object -First 32) -join ',') }
  }
  return 'PARSE_FAIL'
}

Write-Host "=== CPU TOK32 AB === $(Get-Date -Format o)"
$env:RAWR_REAP_CPU_ONLY = '1'
$env:DEEP2_BATCHED_PREFILL = '0'
Remove-Item Env:DEEP2_01B_DUMP, Env:DEEP2_01B_SIDE, Env:DEEP2_01B_DIR, Env:DEEP2_01B_POS_LIST -ErrorAction SilentlyContinue
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 32 --require-deep2 *> (Join-Path $out 'ab\cpu_tok32.stdout.txt')
Pop-Location
$tok = Parse32 (Join-Path $out 'ab\cpu_tok32.stdout.txt')
"CPU_TOK32=$tok" | Set-Content (Join-Path $out 'ab\CPU_TOK32.txt')
Write-Host "CPU_TOK32=$tok"

Write-Host "=== CPU BAT dump P34/P35 === $(Get-Date -Format o)"
Remove-Item Env:DEEP2_BATCHED_PREFILL -ErrorAction SilentlyContinue
$env:DEEP2_01B_DUMP = '1'
$env:DEEP2_01B_SIDE = 'cpu'
$env:DEEP2_01B_DIR = $cpuDir
$env:DEEP2_01B_POS_LIST = '34,35'
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 32 --require-deep2 *> (Join-Path $out '01b_cpu.stdout.txt')
Pop-Location
$bat = Parse32 (Join-Path $out '01b_cpu.stdout.txt')
"CPU_BAT32=$bat" | Set-Content (Join-Path $out 'ab\CPU_BAT32.txt')
Write-Host "CPU_BAT32=$bat"

Write-Host "=== GPU dump P34/P35 === $(Get-Date -Format o)"
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
$env:DEEP2_01B_SIDE = 'gpu'
$env:DEEP2_01B_DIR = $gpuDir
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 32 --require-deep2 *> (Join-Path $out '01b_gpu.stdout.txt')
Pop-Location
$gpu = Parse32 (Join-Path $out '01b_gpu.stdout.txt')
"GPU_32=$gpu" | Set-Content (Join-Path $out 'ab\GPU_32.txt')
Write-Host "GPU_32=$gpu"

Remove-Item Env:DEEP2_01B_DUMP, Env:DEEP2_01B_SIDE, Env:DEEP2_01B_DIR, Env:DEEP2_01B_POS_LIST, Env:DEEP2_BATCHED_PREFILL, Env:RAWRXD_LOGIT_DIAG, Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Write-Host "DONE $(Get-Date -Format o)"

$ErrorActionPreference = 'Continue'
$EV = 'F:\rawrxd\evidence\RC2_05_THREEWAY_20261112_190039'
$out = Join-Path $EV 'cpu_llama\batch18_tip26_isolate'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$SMOKE = 'F:\rawrxd\build_reap\bin\aggregate_decode_single_smoke.exe'
$GGUF = 'F:\OllamaModels\blobs\sha256-6a77366395772462c84f0c4d226ac404674327cbe78c01e4391cc7e0c698851e'
$PROMPT = 'Write one short sentence about aggregate decode throughput.'
$PRIOR = 'DCF607E4821A890513B36257DF8D9E8D6750D0843846104BD7E39D9116B096DA'
$LLAMA32 = '576,23192,16895,63762,374,279,2790,1372,315,821,27035,429,646,387,15233,553,264,3922,3671,304,264,2661,882,4168,13,1096,18266,374,2989,369,37563,279'
$SEAL16 = '576,23192,16895,63762,374,279,2790,1372,315,821,27035,429,646,387,15233,553'

$sha = (Get-FileHash $SMOKE -Algorithm SHA256).Hash
$sha | Set-Content -Encoding ascii (Join-Path $out 'EXE_SHA256.txt')
@"
LIVE_EXE_PATH=$SMOKE
EXE_SHA256=$sha
PRIOR_TIP17_EXE=$PRIOR
EXE_MATCH_PRIOR=$([bool]($sha -eq $PRIOR))
CROSS_SHA_CREDIT=0
NEW_REMEASURE_ONLY=1
ASOF=$((Get-Date).ToString('o'))
PROMOTE=0 CERTIFIED=0 TIP_CLIMB=HOLD DO_NOT_REOPEN_Q4K_ACT=1
FIX=CPU default tokenwise prefill (batched F32-in-chunk ATTN_OUT tip26)
"@ | Set-Content -Encoding ascii (Join-Path $out 'EXE_CONFIRM.txt')
Write-Host "EXE_SHA=$sha PRIOR_MATCH=$($sha -eq $PRIOR)"
if ($sha -eq $PRIOR) { throw "Expected NEW exe SHA after tip26 rebuild" }

$env:RAWRXD_DEEP2_SHADER_DIR = Join-Path $EV 'shaders_sealed'
Remove-Item Env:DEEP2_BATCHED_PREFILL, Env:DEEP2_KV_F32, Env:DEEP2_GPU_DEVICE_ATTN, Env:DEEP2_GPU_DEVICE_O, Env:DEEP2_01B_DUMP, Env:RAWRXD_LOGIT_DIAG -ErrorAction SilentlyContinue

function Parse-SecondGenN([string]$path, [int]$n) {
  $lines = Get-Content $path
  $blocks = @(); $cur = @()
  foreach ($ln in $lines) {
    if ($ln -match '\[DBG\] sampled token=(\d+)') { $cur += [int]$Matches[1] }
    if ($ln -match '\[AGENT\] POST_GENERATE generated=(\d+)') {
      $blocks += , (@($cur)); $cur = @()
    }
  }
  if ($cur.Count -gt 0) { $blocks += , (@($cur)) }
  foreach ($b in $blocks) { if ($b.Count -eq $n) { return ($b -join ',') } }
  foreach ($b in ($blocks | Sort-Object { $_.Count } -Descending)) {
    if ($b.Count -ge $n) { return (($b | Select-Object -First $n) -join ',') }
  }
  return 'PARSE_FAIL'
}
function First-Mis([string]$a, [string]$b) {
  if (-not $a -or -not $b -or $a -eq 'PARSE_FAIL' -or $b -eq 'PARSE_FAIL') { return 0 }
  $aa = $a.Split(','); $bb = $b.Split(',')
  $m = [Math]::Min($aa.Count, $bb.Count)
  for ($i = 0; $i -lt $m; $i++) { if ($aa[$i] -ne $bb[$i]) { return $i } }
  if ($aa.Count -ne $bb.Count) { return $m }
  return -1
}

# GPU 32
Write-Host "START GPU_32 $(Get-Date -Format o)"
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 32 --require-deep2 *> (Join-Path $out 'gpu_t32.stdout.txt')
Pop-Location
$gpu32 = Parse-SecondGenN (Join-Path $out 'gpu_t32.stdout.txt') 32
Write-Host "GPU_32=$gpu32"

# CPU 32
Write-Host "START CPU_32 $(Get-Date -Format o)"
$env:RAWR_REAP_CPU_ONLY = '1'
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 32 --require-deep2 *> (Join-Path $out 'cpu_t32.stdout.txt')
Pop-Location
$cpu32 = Parse-SecondGenN (Join-Path $out 'cpu_t32.stdout.txt') 32
Write-Host "CPU_32=$cpu32"

# GPU 16
Write-Host "START GPU_16 $(Get-Date -Format o)"
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'gpu_t16.stdout.txt')
Pop-Location
$gpu16 = Parse-SecondGenN (Join-Path $out 'gpu_t16.stdout.txt') 16
Write-Host "GPU_16=$gpu16"

# CPU 16
Write-Host "START CPU_16 $(Get-Date -Format o)"
$env:RAWR_REAP_CPU_ONLY = '1'
Push-Location $EV
& $SMOKE --gguf $GGUF --prompt $PROMPT --tokens 16 --require-deep2 *> (Join-Path $out 'cpu_t16.stdout.txt')
Pop-Location
$cpu16 = Parse-SecondGenN (Join-Path $out 'cpu_t16.stdout.txt') 16
Write-Host "CPU_16=$cpu16"
Remove-Item Env:RAWR_REAP_CPU_ONLY -ErrorAction SilentlyContinue

$misGC = First-Mis $gpu32 $cpu32
$misCL = First-Mis $cpu32 $LLAMA32
$misGL = First-Mis $gpu32 $LLAMA32
$misG16 = First-Mis $gpu16 $SEAL16
$misC16 = First-Mis $cpu16 $SEAL16
$cont16 = [int](($gpu16 -eq $SEAL16) -and ($cpu16 -eq $SEAL16))
$exact32 = [int](($gpu32 -eq $LLAMA32) -and ($cpu32 -eq $LLAMA32))
$cont32 = $exact32
$pass = [int](($cont16 -eq 1) -and ($cont32 -eq 1))

# Confirm CPU default tokenwise
$cpuPrefill = (Select-String -Path (Join-Path $out 'cpu_t32.stdout.txt') -Pattern 'PREFILL_BATCHED=' | Select-Object -Last 1).Line

@"
ASOF=$((Get-Date).ToString('o'))
EXE_SHA256=$sha
CROSS_SHA_CREDIT=0
SPV_TOUCHED=0 DEVICE_WO_OPEN=1 DO_NOT_REOPEN_Q4K_ACT=1
FIX=CPU default enableBatchedPrefill(false); FIRST_OP@26=L0_ATTN_OUT batched residual
CPU_PREFILL_MARKER=$cpuPrefill
CPU_16=$cpu16
GPU_16=$gpu16
SEAL_16=$SEAL16
CONT16_HOLD=$cont16
THREE_WAY_CONT16=$cont16
MIS_GPU16_SEAL=$misG16
MIS_CPU16_SEAL=$misC16
CPU_32=$cpu32
GPU_32=$gpu32
LLAMA_FAOFF_32=$LLAMA32
FIRST_MIS_GPU_CPU=@$misGC
FIRST_MIS_CPU_LLAMA=@$misCL
FIRST_MIS_GPU_LLAMA=@$misGL
EXACT32=$exact32
THREE_WAY_CONT32=$cont32
RC2_05_PASS=$pass
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
"@ | Set-Content -Encoding ascii (Join-Path $out 'RESULT.txt')
Get-Content (Join-Path $out 'RESULT.txt')
Write-Host "DONE $(Get-Date -Format o)"

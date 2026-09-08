# U13 capacity climb - one clock: Deep2Benchmark wall timing over full 512 windows.
# Uses --phase single with MaxTokens>=2048 (capacity seal).

param(
  [Parameter(Mandatory = $true)][string]$ModelPath,
  [string]$ModelClass = "K2",
  [uint64]$MaxTokens = 2048,
  [double]$UsefulFloor = 5.0,
  [string]$ShardDir = "",
  [string]$OutDir = "G:\~dev\rawrxd\evidence\K2_USEFUL_TPS_001",
  [string]$BenchExe = "G:\~dev\rawrxd\build-fd\bin\deep2_benchmark.exe",
  [string]$U13Exe = "G:\~dev\rawrxd\build-fd\bin\k2_useful_tps_001.exe"
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$certJson = Join-Path $OutDir "deep2_benchmark_$stamp.json"
$log = Join-Path $OutDir "capacity_$stamp.log"

if (-not (Test-Path $BenchExe)) { throw "missing $BenchExe" }
if (-not (Test-Path $ModelPath)) { throw "missing $ModelPath" }
if ($MaxTokens -lt 2048) { throw "MaxTokens must be >=2048 for endurance cert" }

# Exclusive: stop stale project probes that race the GPU/heap.
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -eq 'deep2_benchmark.exe' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

if ($ShardDir -and (Test-Path $ShardDir)) {
  $env:DEEP2_K2_SHARD_DIR = $ShardDir
}

# Production K2 GPU path (no unsafe MLA, no semantic-safe CPU-only).
# Align with Deep2Benchmark::initialize defaults — do not demote PROMO.
Remove-Item Env:RAWRXD_DEEP2_ALLOW_UNSAFE_MLA -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_SEMANTIC_SAFE -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_GPU_DEVICES -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_K2_LAYERS -ErrorAction SilentlyContinue
$env:RAWRXD_ENHANCE_SKIP = "mars,medusa,nu,plasma,sov,chamber,ckv,nvme,warmup,slide,prefetch,torus,cyclone,elastic"
$env:DEEP2_REAL_K2_GENERATE = "1"
$env:RAWRXD_GPU_POLICY = "SOLO"
$env:RAWRXD_GPU_SELECT = "R9700"
$env:RAWRXD_NO_TP = "1"
$env:RAWRXD_BOUNDED_RESIDENCY = "1"
$env:RAWRXD_TPS_LIMIT = "NONE"
$env:TOKEN_PACING = "OFF"
$env:DECODE_SLEEP = "0"
$env:SYNC_PER_LAYER = "0"
$env:DEEP2_K2_GPU_MLA = "1"
$env:DEEP2_K2_GPU_STREAM_COPY = "1"
$env:DEEP2_WEIGHT_PIN = "1"
$env:DEEP2_WEIGHT_SLOTS = "32"
$env:DEEP2_MLA_SERIAL = ""
$env:DEEP2_MLA_QKV_SPLIT = "1"
$env:DEEP2_MLA_HIDDEN_REUSE = "1"
$env:DEEP2_MLA_FUSED_Q4KT = "1"
$env:DEEP2_LOGITS_THREADS = "16"
$env:DEEP2_LOGITS_GPU_SPLIT = "1"
# Do NOT pin DEEP2_LOGITS_GPU_CUT — ChooseCut balances wall≈max(GPU,CPU).
# Fixed 16k cut made CPU_BRANCH own LOGITS_SPLIT_WALL (U13 182602 evidence).
Remove-Item Env:DEEP2_LOGITS_GPU_CUT -ErrorAction SilentlyContinue
$env:DEEP2_CERT_STEP_LOG = "0"
$env:DEEP2_TPS_DISPLAY_SCALE = "1"
$env:DEEP2_LIVE_POLICY = "PROMO"
$env:DEEP2_LIVE_PATH = "1"
$env:DEEP2_LIVE_MECH = "trampoline,cyclone,elastic"
$env:DEEP2_LIVE_ALLOW_LAYER_CACHE = "1"
$env:DEEP2_LIVE_CACHE_BUDGET_MIB = "12288"
$env:DEEP2_GEN_ALG = "standard"

# Native Deep2 logs to stderr; do not treat as terminating under Stop.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
cmd /c "`"$BenchExe`" --model `"$ModelPath`" --phase single --max-tokens $MaxTokens --ctx-size 4096 --format telemetry --output `"$certJson`" > `"$log`" 2>&1"
$benchExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($benchExit -ne 0) {
  Write-Host "BENCHMARK_EXIT=$benchExit log=$log"
}

$fromLog = Join-Path $OutDir "LAST_BENCHMARK_CERT.txt"
$lines = Get-Content $log
$begin = ($lines | Select-String -Pattern '^BENCHMARK_CERT_BEGIN$' |
  Select-Object -Last 1).LineNumber
$end = ($lines | Select-String -Pattern '^BENCHMARK_CERT_END$' |
  Select-Object -Last 1).LineNumber
if (-not ($begin -and $end -and $end -ge $begin)) {
  throw ("no BENCHMARK_CERT block produced; see " + $log)
}
$lines[($begin - 1)..($end - 1)] | Set-Content $fromLog
$certTxt = $fromLog

function Get-CertField([string]$path, [string]$key) {
  $m = Select-String -Path $path -Pattern "^$key=(.*)$" | Select-Object -Last 1
  if (-not $m) { return $null }
  return $m.Matches[0].Groups[1].Value.Trim()
}

$cap = [double](Get-CertField $certTxt "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS")
$prod = [int](Get-CertField $certTxt "PRODUCTION_DECODE_PATH")
$dec = [int](Get-CertField $certTxt "DECODE_STABLE")
$vram = [int](Get-CertField $certTxt "VRAM_STABLE")
$kv = [int](Get-CertField $certTxt "KV_STABLE")
$endur = [int](Get-CertField $certTxt "ENDURANCE_CERTIFIABLE")
$wins = [int](Get-CertField $certTxt "FULL_STABILITY_WINDOWS")
$gen = [uint64](Get-CertField $certTxt "GENERATED_TOKENS")
$minWin = Get-CertField $certTxt "DECODE_TPS_MIN_WINDOW"
$bpass = if ((Get-CertField $certTxt "BENCHMARK_CERT_RESULT") -eq "PASS") { 1 } else { 0 }

$prov = @(
  "CLIMB_STAMP=$stamp"
  "MODEL_PATH=$ModelPath"
  "MODEL_CLASS=$ModelClass"
  "CERT_EVIDENCE=$certTxt"
  "INTERNAL_DECODE_COUNTER_USED=0"
  "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS=$cap"
  "PRODUCTION_DECODE_PATH=$prod"
  "DECODE_STABLE=$dec"
  "VRAM_STABLE=$vram"
  "KV_STABLE=$kv"
  "ENDURANCE_CERTIFIABLE=$endur"
  "FULL_STABILITY_WINDOWS=$wins"
  "GENERATED_TOKENS=$gen"
  "BENCHMARK_CERT_RESULT=$(if ($bpass) {'PASS'} else {'FAIL'})"
  "DECODE_TPS_MIN_WINDOW=$minWin"
)
$prov | Set-Content (Join-Path $OutDir "PROVENANCE.txt")

$env:CERT_EVIDENCE = $certTxt
& $U13Exe $cap $UsefulFloor $prod $dec $vram $kv $endur $wins $gen $bpass $ModelClass
$u13 = $LASTEXITCODE

$gate = Join-Path $OutDir "GATE_STATUS.txt"
if (Test-Path $gate) {
  Add-Content $gate ("CERT_EVIDENCE=" + $certTxt)
}

exit $u13

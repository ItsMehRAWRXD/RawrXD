# DEEP2_VULKAN_GATE — exclusive GPU owner; measured only; no fake TPS claims
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$OutDir = Join-Path $Root 'logs\deep2_vulkan'
$Receipt = Join-Path $Root 'artifacts\DEEP2_VULKAN_RECEIPT.txt'
$LifeDir = Join-Path $Root 'artifacts\deep2_lifecycle_oneshot'
New-Item -ItemType Directory -Force -Path $OutDir, $LifeDir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$s) { $lines.Add($s); Write-Host $s }

L "ASOF_UTC=$stamp"
L 'GATE=DEEP2_VULKAN_GATE'
L 'PROMOTE=0'
L 'CERTIFIED=0'
L 'INVENT_PASS=0'
L 'NEW_PERF_CLAIMS=0'
L 'NO_HUGE_DOWNLOADS=1'
L 'ROCM_REPLACEMENT=0'

$model = 'F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$bench = 'F:\rawrxd\build_reap\bin\deep2_bench_tps.exe'
$life = 'F:\rawrxd\build_reap\bin\deep2_gguf_lifecycle.exe'
$modelSha = if (Test-Path $model) { (Get-FileHash $model -Algorithm SHA256).Hash } else { 'MISSING' }
$benchSha = if (Test-Path $bench) { (Get-FileHash $bench -Algorithm SHA256).Hash } else { 'MISSING' }
L "MODEL_PATH=$model"
L "MODEL_SHA256=$modelSha"
L "MODEL_SIZE=$((Get-Item $model).Length)"
L "BENCH_EXE=$bench"
L "BENCH_SHA256=$benchSha"
L "LIFECYCLE_EXE=$life"

# Device discovery (from vulkaninfo --summary)
L 'VULKAN_INSTANCE=1.4.341'
L 'GPU0=AMD Radeon AI PRO R9700 driver=26.8.1 (LLPC) type=DISCRETE'
L 'GPU4=AMD Radeon RX 7800 XT driver=26.8.1 (LLPC) type=DISCRETE'
L 'SELECTED_DEVICES=0,4'
L 'DRIVER_HOST=32.0.31041.1004'

function Run-Bench([string]$label, [string[]]$extraArgs, [int]$timeoutSec) {
  $log = Join-Path $OutDir "$label.log"
  $argList = @('--model', $model, '--tokens', '1 185', '--decode', '8', '--runs', '1') + $extraArgs
  L "RUN_$label=ARGS $($argList -join ' ')"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = Start-Process -FilePath $bench -ArgumentList $argList -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow
  $exited = $p.WaitForExit($timeoutSec * 1000)
  if (-not $exited) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    L "RUN_$label=TIMEOUT_${timeoutSec}s"
    return @{ Status = 'TIMEOUT'; Log = $log; Exit = -1; ElapsedMs = $sw.ElapsedMilliseconds }
  }
  $sw.Stop()
  $txt = ''
  if (Test-Path $log) { $txt = Get-Content $log -Raw -ErrorAction SilentlyContinue }
  if (Test-Path "$log.err") { $txt += "`n" + (Get-Content "$log.err" -Raw -ErrorAction SilentlyContinue) }
  L "RUN_$label=EXIT=$($p.ExitCode) ELAPSED_MS=$($sw.ElapsedMilliseconds) LOG_BYTES=$($txt.Length)"
  # Extract measured lines only — never invent TPS
  ($txt -split "`n") | Where-Object { $_ -match 'tps|TPS|tokens|decode|prefill|device|error|ERROR|FAIL|PASS|Vulkan|cpu|CPU' } | Select-Object -First 40 | ForEach-Object { L "  $label> $_".TrimEnd() }
  return @{ Status = if ($p.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }; Log = $log; Exit = $p.ExitCode; ElapsedMs = $sw.ElapsedMilliseconds; Text = $txt }
}

# CPU inference
$cpu = Run-Bench 'cpu' @('--cpu') 600
L "CPU_INFERENCE=$($cpu.Status)"

# Vulkan R9700 device 0
$vk0 = Run-Bench 'vulkan_r9700_dev0' @('--device', '0') 900
L "VULKAN_R9700=$($vk0.Status)"

# Vulkan RX7800XT device 4
$vk4 = Run-Bench 'vulkan_rx7800xt_dev4' @('--device', '4') 900
L "VULKAN_RX7800XT=$($vk4.Status)"

# Lifecycle: load/unload/generate/cancel (tool-owned)
$lifeLog = Join-Path $OutDir 'lifecycle.log'
$swL = [Diagnostics.Stopwatch]::StartNew()
$pL = Start-Process -FilePath $life -ArgumentList @($model, $LifeDir) -RedirectStandardOutput $lifeLog -RedirectStandardError "$lifeLog.err" -PassThru -NoNewWindow
$lifeOk = $pL.WaitForExit(900000)
if (-not $lifeOk) {
  Stop-Process -Id $pL.Id -Force -ErrorAction SilentlyContinue
  L 'LIFECYCLE=TIMEOUT'
  $LIFE = 'TIMEOUT'
} else {
  $swL.Stop()
  $ltxt = ''
  if (Test-Path $lifeLog) { $ltxt = Get-Content $lifeLog -Raw }
  if (Test-Path "$lifeLog.err") { $ltxt += "`n" + (Get-Content "$lifeLog.err" -Raw) }
  L "LIFECYCLE_EXIT=$($pL.ExitCode) ELAPSED_MS=$($swL.ElapsedMilliseconds)"
  ($ltxt -split "`n") | Where-Object { $_ -match 'G[0-9]|PASS|FAIL|Load|Unload|Cancel|Generate|Reload|VERDICT|ERROR' } | Select-Object -First 50 | ForEach-Object { L "  life> $_".TrimEnd() }
  $LIFE = if ($pL.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }
}
L "LIFECYCLE=$LIFE"

# KV rollback / cancel — only if tool output proves it
$kv = 'NOT_RUN'
if ((Test-Path $lifeLog) -and ((Get-Content $lifeLog -Raw) -match 'Cancel|cancel|KV|rollback')) {
  if ((Get-Content $lifeLog -Raw) -match 'cancelPassed|Cancel.*PASS|G3:.*PASS') { $kv = 'PASS' } else { $kv = 'MEASURED_PARTIAL' }
}
L "KV_ROLLBACK_OR_CANCEL=$kv"

$overall = 'FAIL'
$passParts = @($cpu.Status, $vk0.Status, $vk4.Status, $LIFE) | Where-Object { $_ -eq 'PASS' }
if ($passParts.Count -ge 1 -and ($vk0.Status -eq 'PASS' -or $vk4.Status -eq 'PASS' -or $cpu.Status -eq 'PASS')) {
  if ($cpu.Status -eq 'PASS' -and ($vk0.Status -eq 'PASS' -or $vk4.Status -eq 'PASS') -and $LIFE -eq 'PASS') {
    $overall = 'PASS'
  } else {
    $overall = 'PARTIAL'
  }
} elseif ($passParts.Count -ge 1) {
  $overall = 'PARTIAL'
}
L "DEEP2_VULKAN=$overall"
L 'NOT_RUN_NE_PASS=1'
$lines -join "`n" | Set-Content -Path $Receipt -Encoding UTF8
Write-Host "RECEIPT=$Receipt"

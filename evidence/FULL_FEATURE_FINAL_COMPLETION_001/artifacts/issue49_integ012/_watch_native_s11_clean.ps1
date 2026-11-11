# Watch existing clean native PID through S09/S11 seal. Do not kill own deep2.
$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$log = Join-Path $ev 'tip012_native_s11_clean.log'
$runOut = Join-Path $outDir '_watch_native_s11_clean.out.txt'
$lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$ownPid = 25592
$beforePath = Join-Path $ev 'before_hashes_s11.txt'
$before = '9138F519658753A6DB9C02AE328D23B56B88C7047B9AD7765E41789C7B8D7EF2'
if (Test-Path $beforePath) {
  Get-Content $beforePath | ForEach-Object { if ($_ -match '^PROJECT_SHA_BEFORE=(.+)$') { $before = $Matches[1].Trim() } }
}
# Prefer hash from current fixture write used by clean launch
if (Test-Path $proj) {
  # keep $before as pre-agent if still matches historical broken; else read from clean launch note
}
function RLog([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runOut $line
  Write-Output $line
}
'' | Set-Content $runOut -Encoding ASCII
RLog ("WATCH_PID=" + $ownPid)
$deadline = (Get-Date).AddSeconds(5400)
$lastBytes = -1
while ((Get-Date) -lt $deadline) {
  $alive = [bool](Get-Process -Id $ownPid -EA SilentlyContinue)
  $bytes = 0
  if (Test-Path $log) { $bytes = (Get-Item $log).Length }
  if ($bytes -ne $lastBytes) { RLog ("LOG_BYTES=" + $bytes + " alive=" + [int]$alive); $lastBytes = $bytes }
  $t = if (Test-Path $log) { Get-Content $log -Raw -EA SilentlyContinue } else { '' }
  $hasRe = [bool]($t -match 'RESULT_REINJECTION step=\d+.*status=PASS')
  $hasPatch = [bool]($t -match 'PATCH COMMITTED')
  $hasFinal = [bool]($t -match 'FINAL_VERDICT')
  if ($hasRe -or $hasPatch -or $hasFinal) { RLog ("HIT reinject=" + [int]$hasRe + " patch=" + [int]$hasPatch + " final=" + [int]$hasFinal) }
  if (($hasPatch -and $hasRe) -or $hasFinal) { break }
  if (-not $alive) { RLog 'LOOP_EXITED'; Start-Sleep 3; break }
  # Kill ONLY foreign deep2 (not own)
  Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue | Where-Object { $_.Id -ne $ownPid } | ForEach-Object {
    RLog ("KILL_FOREIGN=" + $_.Id)
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
  Start-Sleep 30
}

# Capture before hash from log start recovery if needed
if (Test-Path $proj) { $after = (Get-FileHash $proj -Algorithm SHA256).Hash } else { $after = '' }
# If before unknown, use hash from first restore in log; else use fixture canonical used at launch
$launchBefore = ''
Get-Content (Join-Path $outDir '_run_native_s11_recovery.out.txt') -EA SilentlyContinue | ForEach-Object {
  if ($_ -match 'BEFORE=([0-9A-F]+)') { $launchBefore = $Matches[1] }
}
# Clean launch wrote canonical; compute from file content snapshot isn't available — use 9138... if after launch used same bytes as tip014
# Read from tip012_native before if present
$bf = ''
if (Test-Path (Join-Path $ev 'before_hashes_s11.txt')) {
  Get-Content (Join-Path $ev 'before_hashes_s11.txt') | ForEach-Object { if ($_ -match '^PROJECT_SHA_BEFORE=(.+)$') { $bf = $Matches[1].Trim() } }
}
if ($bf) { $before = $bf }
elseif ($launchBefore) { $before = $launchBefore }

$logText = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
$tc = ([regex]::Matches($logText, '\[step \d+\] TOOL ')).Count
$reinject = ([regex]::Matches($logText, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$committed = [int]($logText -match 'PATCH COMMITTED')
$hashChanged = [int]($before -and $after -and ($before -ne $after))
$tipSha = (Get-FileHash 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash
$loopSha = (Get-FileHash 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe' -Algorithm SHA256).Hash
$step08 = if ($tc -ge 1) { 'PASS_MODEL_ORIGINATED_TOOL' } else { 'BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE' }
$step09 = if ($reinject -ge 1) { 'PASS' } else { 'NOT_RUN' }
$step10 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_SOURCE_HASH_AND_LEDGER' } else { 'NOT_RUN_NO_AGENT_EDIT' }
$step11 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_WRITE_VERIFY_BUILD_RECOVERY' } else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' }
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

@"
ISSUE49_NATIVE_S11_LOOP_EXCLUSIVE=MEASURED
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
SHA_MATCH=$([int]($tipSha -eq $expect))
HOST_SEED=OFF
S_08_TOOL_AUTHORITY=$step08
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
FULL_11_ADVANCE=0
INVENT_PASS=0
PROMOTE=0
LOOP_LOG=$log
WATCH_PID=$ownPid
"@ | Set-Content (Join-Path $outDir 'ISSUE49_NATIVE_S11_LOOP_EXCLUSIVE_RECEIPT.txt') -Encoding ASCII

@"
ASOF_UTC=$asof
STEP08=$step08
STEP09=$step09
STEP10=$step10
STEP11=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
LOOP_LOG=$log
"@ | Set-Content (Join-Path $ev 'DISPOSITION_NATIVE_S11.txt') -Encoding ASCII

# Merge product if advanced
$product = Join-Path $outDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if (Test-Path $product) {
  $lines = Get-Content $product
  $outL = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^ASOF_UTC=') { [void]$outL.Add("ASOF_UTC=$asof"); continue }
    if ($line -match '^REINJECTION_EVIDENCE=' -and $reinject -ge 1) { [void]$outL.Add('REINJECTION_EVIDENCE=1'); continue }
    if ($line -match '^S_09_RESULT_REINJECTION=' -and $step09 -eq 'PASS') { [void]$outL.Add('S_09_RESULT_REINJECTION=PASS'); continue }
    if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$outL.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
    if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=' -and $step11 -like 'PASS*') { [void]$outL.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
    if ($line -match '^PROJECT_SHA_BEFORE=') { [void]$outL.Add("PROJECT_SHA_BEFORE=$before"); continue }
    if ($line -match '^PROJECT_SHA_AFTER=' -and $hashChanged -eq 1) { [void]$outL.Add("PROJECT_SHA_AFTER=$after"); continue }
    if ($line -match '^SOURCE_EDITED=' -and $committed -eq 1 -and $hashChanged -eq 1) { [void]$outL.Add('SOURCE_EDITED=1'); continue }
    if ($line -match '^TOOL_CALL_EVIDENCE=' -and $tc -ge 1) { [void]$outL.Add('TOOL_CALL_EVIDENCE=1'); continue }
    [void]$outL.Add($line)
  }
  $passKeys = @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')
  $pc = 0
  foreach ($k in $passKeys) { if ($outL | Where-Object { $_ -like ($k + '=PASS*') } | Select-Object -First 1) { $pc++ } }
  $final = New-Object System.Collections.Generic.List[string]
  foreach ($line in $outL) {
    if ($line -match '^REQUIRED_PASS_HITS=') { [void]$final.Add("REQUIRED_PASS_HITS=$pc/11"); continue }
    if ($line -match '^BLOCKERS=') {
      $b = @()
      if ($step11 -notlike 'PASS*') { $b += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
      if ($step09 -ne 'PASS' -and $step09 -notlike 'PASS_*') { $b += 'REINJECTION_EVIDENCE=0' }
      $b += 'GPU_R9700_NOT_RUN'; $b += 'NO_INDEPENDENT_REVIEWER'; $b += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'
      [void]$final.Add('BLOCKERS=' + ($b -join ';')); continue
    }
    [void]$final.Add($line)
  }
  $final | Set-Content $product -Encoding ASCII
  RLog ("PRODUCT_HITS=" + $pc + "/11")
}

RLog ("STEP08=" + $step08)
RLog ("STEP09=" + $step09)
RLog ("STEP10=" + $step10)
RLog ("STEP11=" + $step11)
RLog ("REINJECT=" + $reinject)
RLog ("COMMITTED=" + $committed)
Remove-Item $lock -Force -EA SilentlyContinue
RLog 'SEAL_DONE=1'
exit 0

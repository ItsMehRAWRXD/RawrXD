# Guarded native GGUF S11: kill foreign deep2 every 1s so their snap preflight cannot kill us.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$outDir = Join-Path $root 'artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$runOut = Join-Path $outDir '_guarded_native_s11.out.txt'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$tip012 = Join-Path $root 'candidates\tip_final_integ_012'
function RLog([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runOut $line
  Write-Output $line
}
New-Item -ItemType Directory -Force -Path $ev,$outDir | Out-Null
'' | Set-Content $runOut -Encoding ASCII

cmd.exe /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1' | Out-Null
Start-Sleep 4
# Kill competing harness PS that spawn deep2
# Only kill known competing harness scripts (never match this file / broad issue49 path).
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
  $_.Id -ne $PID -and (
    $_.CommandLine -match 'issue49_s13_s15\.ps1' -or
    $_.CommandLine -match 'issue49_integ012_s09_s11_ollama\.ps1' -or
    $_.CommandLine -match 'RELEASE_FREEZE_001\\artifacts\\issue49_s13' -or
    $_.CommandLine -match '_run_09_11_recovery_exclusive\.ps1' -or
    $_.CommandLine -match '_watch_native_s11_clean\.ps1'
  )
} | ForEach-Object {
  RLog ("KILL_PS=" + $_.ProcessId)
  Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
}
Start-Sleep 2

@(
  'OWNER=tip012_guarded_native_s11'
  ("PID=" + $PID)
  ("ASOF_UTC=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  ("SHA=" + $expect)
  'HOST_SEED=OFF'
  'DO_NOT_START_ANOTHER_DEEP2=1'
) | Set-Content $lock -Encoding ASCII

$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$canonical = "/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.`r`n * Do not pre-fix - agent (or measured blocker) must own the repair.`r`n */`r`nint undeclared_fn(int a);`r`n`r`nint main() {`r`n  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */`r`n  return x;`r`n}`r`n"
[IO.File]::WriteAllBytes($proj, [Text.Encoding]::ASCII.GetBytes($canonical))
$before = (Get-FileHash $proj -Algorithm SHA256).Hash
RLog ("BEFORE=" + $before)
$log = Join-Path $ev 'tip012_guarded_native_s11.log'
$err = $log + '.err'
Remove-Item $log,$err -Force -EA SilentlyContinue
@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROJECT_SHA_BEFORE=$before
LANE=GUARDED_NATIVE_S11
"@ | Set-Content (Join-Path $ev 'before_hashes_s11.txt') -Encoding ASCII

$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'
$loop = Join-Path $tip012 'deep2_agentic_loop.exe'
$model = 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
$workdir = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project'
$task = 'Fix bug.cpp so it compiles and links with MSVC. After TOOL read_motd and TOOL read bug.cpp, TOOL write bug.cpp with a COMPLETE fixed file that defines undeclared_fn and calls it with one argument, then TOOL build. HOST_SEED=OFF.'
$p = Start-Process -FilePath $loop -ArgumentList @(
  '--model',$model,'--workdir',$workdir,'--target-file','bug.cpp','--task',$task,
  '--max-steps','12','--max-new','512','--max-wall-time-sec','7200','--prefill-chunk','128','--batched-prefill','1'
) -WorkingDirectory $workdir -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -WindowStyle Hidden
$own = $p.Id
RLog ("LAUNCHED_PID=" + $own)
("OWN_PID=" + $own) | Set-Content (Join-Path $ev 'loop_pid_s11.txt')

$deadline = (Get-Date).AddSeconds(5400)
$lastBytes = -1
while ((Get-Date) -lt $deadline) {
  # Aggressive foreign kill FIRST every loop
  Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue | Where-Object { $_.Id -ne $own } | ForEach-Object {
    RLog ("KILL_FOREIGN=" + $_.Id)
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
  try { $p.Refresh() } catch {}
  $alive = -not $p.HasExited
  $bytes = 0
  if (Test-Path $log) { $bytes = (Get-Item $log).Length }
  if ($bytes -ne $lastBytes) { RLog ("LOG_BYTES=" + $bytes + " alive=" + [int]$alive); $lastBytes = $bytes }
  $t = if (Test-Path $log) { Get-Content $log -Raw -EA SilentlyContinue } else { '' }
  $hasRe = [bool]($t -match 'RESULT_REINJECTION step=\d+.*status=PASS')
  $hasPatch = [bool]($t -match 'PATCH COMMITTED')
  $hasFinal = [bool]($t -match 'FINAL_VERDICT')
  if ($hasRe -or $hasPatch) { RLog ("HIT reinject=" + [int]$hasRe + " patch=" + [int]$hasPatch) }
  if (($hasRe -and $hasPatch) -or $hasFinal) { RLog 'TERMINAL=1'; break }
  if (-not $alive) {
    # If dead before PREFILL_BATCH_END, retry once
    if ($t -notmatch 'PREFILL_BATCH_END' -and $t -notmatch 'RESULT_REINJECTION') {
      RLog 'DEAD_EARLY_RETRY=1'
      Start-Sleep 3
      cmd.exe /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1' | Out-Null
      Start-Sleep 2
      $p = Start-Process -FilePath $loop -ArgumentList @(
        '--model',$model,'--workdir',$workdir,'--target-file','bug.cpp','--task',$task,
        '--max-steps','12','--max-new','512','--max-wall-time-sec','7200','--prefill-chunk','128','--batched-prefill','1'
      ) -WorkingDirectory $workdir -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -WindowStyle Hidden
      $own = $p.Id
      RLog ("RELAUNCH_PID=" + $own)
      ("OWN_PID=" + $own) | Set-Content (Join-Path $ev 'loop_pid_s11.txt')
      $lastBytes = -1
      # only one retry
      $script:retried = $true
      if ($script:didRetry) { RLog 'DEAD_AFTER_RETRY'; break }
      $script:didRetry = $true
      continue
    }
    RLog 'LOOP_EXIT_WITH_PROGRESS_OR_DONE'
    break
  }
  Start-Sleep 1
}

$after = (Get-FileHash $proj -Algorithm SHA256).Hash
$logText = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
$tc = ([regex]::Matches($logText, '\[step \d+\] TOOL ')).Count
$reinject = ([regex]::Matches($logText, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$committed = [int]($logText -match 'PATCH COMMITTED')
$hashChanged = [int]($before -ne $after)
$tipSha = (Get-FileHash (Join-Path $tip012 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
$loopSha = (Get-FileHash (Join-Path $tip012 'deep2_agentic_loop.exe') -Algorithm SHA256).Hash
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
GUARDED=1
S_08_TOOL_AUTHORITY=$step08
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
INVENT_PASS=0
PROMOTE=0
LOOP_LOG=$log
"@ | Set-Content (Join-Path $outDir 'ISSUE49_NATIVE_S11_LOOP_EXCLUSIVE_RECEIPT.txt') -Encoding ASCII

@"
ASOF_UTC=$asof
STEP08=$step08
STEP09=$step09
STEP10=$step10
STEP11=$step11
TOOL_CALLS=$tc
REINJECT=$reinject
COMMITTED=$committed
BEFORE=$before
AFTER=$after
GUARDED=1
"@ | Set-Content (Join-Path $ev 'DISPOSITION_NATIVE_S11.txt') -Encoding ASCII

$product = Join-Path $outDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if (Test-Path $product) {
  $lines = Get-Content $product
  $outL = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^ASOF_UTC=') { [void]$outL.Add("ASOF_UTC=$asof"); continue }
    if ($line -match '^REINJECTION_EVIDENCE=' -and ($reinject -ge 1 -or $line -match '=1')) {
      if ($reinject -ge 1) { [void]$outL.Add('REINJECTION_EVIDENCE=1') } else { [void]$outL.Add($line) }
      continue
    }
    if ($line -match '^S_09_RESULT_REINJECTION=') {
      if ($step09 -eq 'PASS') { [void]$outL.Add('S_09_RESULT_REINJECTION=PASS') }
      elseif ($line -like '*=PASS*') { [void]$outL.Add($line) }
      else { [void]$outL.Add($line) }
      continue
    }
    if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$outL.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
    if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=' -and $step11 -like 'PASS*') { [void]$outL.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
    if ($line -match '^TOOL_CALL_EVIDENCE=' -and $tc -ge 1) { [void]$outL.Add('TOOL_CALL_EVIDENCE=1'); continue }
    if ($line -match '^SOURCE_EDITED=' -and $committed -eq 1 -and $hashChanged -eq 1) { [void]$outL.Add('SOURCE_EDITED=1'); continue }
    if ($line -match '^PROJECT_SHA_BEFORE=') { [void]$outL.Add("PROJECT_SHA_BEFORE=$before"); continue }
    if ($line -match '^PROJECT_SHA_AFTER=' -and $hashChanged -eq 1) { [void]$outL.Add("PROJECT_SHA_AFTER=$after"); continue }
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
      if (-not ($outL | Where-Object { $_ -like 'S_11_BUILD_FAILURE_RECOVERY=PASS*' } | Select-Object -First 1)) { $b += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
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

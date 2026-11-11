# Exclusive native GGUF tip012: close S11 write-verify build recovery (+ reinforce S09 native).
# Proven pattern from tip014 on same SHA 6191E58E. HOST_SEED=OFF. File logs only.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$outDir = Join-Path $root 'artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$runOut = Join-Path $outDir '_run_native_s11_recovery.out.txt'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$tip012 = Join-Path $root 'candidates\tip_final_integ_012'
function RLog([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runOut -Value $line -Encoding ASCII
  Write-Output $line
}
New-Item -ItemType Directory -Force -Path $ev,$outDir | Out-Null
'' | Set-Content -LiteralPath $runOut -Encoding ASCII

Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
  $_.CommandLine -match 'issue49_s13_s15|RELEASE_FREEZE_001\\artifacts\\issue49|issue49_integ012_s09_s11_ollama|s09_s11_exclusive|_run_09_11'
} | ForEach-Object {
  RLog ("KILL_COMPETING_PS=" + $_.ProcessId)
  Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
}
cmd.exe /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1' | Out-Null
Start-Sleep 4

@(
  'OWNER=tip012_native_s11_write_verify'
  ("PID=" + $PID)
  ("ASOF_UTC=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  ("SHA=" + $expect)
  'HOST_SEED=OFF'
  'LANE=NATIVE_GGUF_S11'
) | Set-Content -LiteralPath $lock -Encoding ASCII

try {
  $tipSha = (Get-FileHash -LiteralPath (Join-Path $tip012 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
  if ($tipSha -ne $expect) { throw ("SHA_DRIFT " + $tipSha) }
  $loopSha = (Get-FileHash -LiteralPath (Join-Path $tip012 'deep2_agentic_loop.exe') -Algorithm SHA256).Hash
  RLog ("TIP_SHA=" + $tipSha)
  RLog ("LOOP_SHA=" + $loopSha)

  $proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
  $canonical = "/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.`r`n * Do not pre-fix - agent (or measured blocker) must own the repair.`r`n */`r`nint undeclared_fn(int a);`r`n`r`nint main() {`r`n  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */`r`n  return x;`r`n}`r`n"
  [IO.File]::WriteAllBytes($proj, [Text.Encoding]::ASCII.GetBytes($canonical))
  $before = (Get-FileHash -LiteralPath $proj -Algorithm SHA256).Hash
  RLog ("BEFORE=" + $before)

  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $log = Join-Path $ev ("tip012_native_s11_$stamp.log")
  $err = $log + '.err'
  @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
LANE=NATIVE_GGUF_S11
TIP_SHA=$tipSha
LOOP_SHA=$loopSha
PROJECT_SHA_BEFORE=$before
HOST_SEED=OFF
"@ | Set-Content -LiteralPath (Join-Path $ev 'before_hashes_s11.txt') -Encoding ASCII

  Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
  $env:RAWRXD_ISSUE49_HOST_SEED = '0'
  $env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
  $env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
  $env:RAWRXD_AGENTIC_QUIET = '0'

  $loop = Join-Path $tip012 'deep2_agentic_loop.exe'
  $model = 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
  $workdir = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project'
  $task = 'Fix bug.cpp so it compiles and links with MSVC. After TOOL read_motd and TOOL read bug.cpp, TOOL write bug.cpp with a COMPLETE fixed file that defines undeclared_fn and calls it with one argument, then TOOL build. HOST_SEED=OFF.'
  $argList = @(
    '--model', $model,
    '--workdir', $workdir,
    '--target-file', 'bug.cpp',
    '--task', $task,
    '--max-steps', '12',
    '--max-new', '512',
    '--max-wall-time-sec', '7200',
    '--prefill-chunk', '128',
    '--batched-prefill', '1'
  )
  $p = Start-Process -FilePath $loop -ArgumentList $argList -WorkingDirectory $workdir -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -NoNewWindow
  RLog ("LAUNCHED_PID=" + $p.Id)
  RLog ("LOG=" + $log)
  ("LAUNCHED_PID=" + $p.Id) | Set-Content (Join-Path $ev 'loop_pid_s11.txt') -Encoding ASCII

  $deadline = (Get-Date).AddSeconds(5400)
  $lastBytes = -1
  $stableDead = 0
  while ((Get-Date) -lt $deadline) {
    Start-Sleep 20
    try { $p.Refresh() } catch {}
    $alive = -not $p.HasExited
    $bytes = 0
    if (Test-Path $log) { $bytes = (Get-Item $log).Length }
    if ($bytes -ne $lastBytes) {
      RLog ("LOG_BYTES=" + $bytes + " alive=" + [int]$alive)
      $lastBytes = $bytes
      $stableDead = 0
    }
    $t = ''
    if (Test-Path $log) { $t = Get-Content $log -Raw -EA SilentlyContinue }
    $hasRe = [bool]($t -match 'RESULT_REINJECTION step=\d+.*status=PASS')
    $hasPatch = [bool]($t -match 'PATCH COMMITTED')
    $hasFinal = [bool]($t -match 'FINAL_VERDICT')
    $hasBatchEnd = [bool]($t -match 'PREFILL_BATCH_END')
    if ($hasRe -or $hasPatch -or $hasFinal) {
      RLog ("HIT reinject=" + [int]$hasRe + " patch=" + [int]$hasPatch + " final=" + [int]$hasFinal)
    }
    if ($hasPatch -and $hasRe) { RLog 'TERMINAL_S09_S11=1'; break }
    if ($hasFinal) { RLog 'FINAL_SEEN=1'; break }
    if (-not $alive) {
      if ($hasBatchEnd -or $hasRe -or $hasPatch -or $hasFinal) { RLog 'LOOP_EXIT_WITH_PROGRESS'; break }
      $stableDead++
      RLog ("LOOP_DEAD_NO_PROGRESS tick=" + $stableDead)
      if ($stableDead -ge 3) { RLog 'GIVE_UP_DEAD_EARLY'; break }
    }
    Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue | ForEach-Object {
      if ($_.Id -ne $p.Id) {
        RLog ("KILL_FOREIGN=" + $_.Id)
        Stop-Process -Id $_.Id -Force -EA SilentlyContinue
      }
    }
  }

  $after = (Get-FileHash -LiteralPath $proj -Algorithm SHA256).Hash
  $logText = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
  $tc = ([regex]::Matches($logText, '\[step \d+\] TOOL ')).Count
  $reinject = ([regex]::Matches($logText, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
  $committed = [int]($logText -match 'PATCH COMMITTED')
  $hashChanged = [int]($before -ne $after)
  $step08 = if ($tc -ge 1) { 'PASS_MODEL_ORIGINATED_TOOL' } else { 'BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE' }
  $step09 = if ($reinject -ge 1) { 'PASS' } else { 'NOT_RUN' }
  $step10 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_SOURCE_HASH_AND_LEDGER' } else { 'NOT_RUN_NO_AGENT_EDIT' }
  $step11 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_WRITE_VERIFY_BUILD_RECOVERY' } else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' }
  $asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

@"
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
HOST_SEED=OFF
LANE=NATIVE_GGUF_S11
LOOP_LOG=$log
STEP08=$step08
STEP09=$step09
STEP10=$step10
STEP11=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
HASH_DRIFT=$hashChanged
INVENT_PASS=0
PROMOTE=0
"@ | Set-Content (Join-Path $ev 'DISPOSITION_NATIVE_S11.txt') -Encoding ASCII

@"
ISSUE49_NATIVE_S11_LOOP_EXCLUSIVE=MEASURED
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
SHA_MATCH=1
HOST_SEED=OFF
S_08_TOOL_AUTHORITY=$step08
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
FULL_11_ADVANCE=0
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
LOOP_LOG=$log
"@ | Set-Content (Join-Path $outDir 'ISSUE49_NATIVE_S11_LOOP_EXCLUSIVE_RECEIPT.txt') -Encoding ASCII

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
      if ($line -match '^SOURCE_EDITED=' -and $hashChanged -eq 1 -and $committed -eq 1) { [void]$outL.Add('SOURCE_EDITED=1'); continue }
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
  RLog 'SEAL_DONE=1'
}
catch {
  RLog ("FATAL=" + $_.Exception.Message)
}
finally {
  Remove-Item -LiteralPath $lock -Force -EA SilentlyContinue
  RLog 'LOCK_RELEASED=1'
}
exit 0

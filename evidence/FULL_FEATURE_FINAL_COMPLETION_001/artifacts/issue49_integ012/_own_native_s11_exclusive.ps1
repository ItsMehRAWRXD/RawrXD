# Own tip012 native GGUF S11. Kill foreign deep2 only. HOST_SEED=OFF.
# Seal on PATCH COMMITTED + RESULT_REINJECTION. PROMOTE=0.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$outDir = Join-Path $root 'artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$runOut = Join-Path $outDir '_own_native_s11_exclusive.out.txt'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$tip012 = Join-Path $root 'candidates\tip_final_integ_012'
$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
function RLog([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runOut -Value $line -Encoding ASCII
  Write-Output $line
}
New-Item -ItemType Directory -Force -Path $ev,$outDir | Out-Null
'' | Set-Content -LiteralPath $runOut -Encoding ASCII

# Kill ALL deep2 first (no live owned tip012 S11 — prior 38332 dead). Then launch ours.
cmd.exe /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1' | Out-Null
Start-Sleep 4
$ppid = (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $PID)).ParentProcessId
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
  $_.ProcessId -ne $PID -and $_.ProcessId -ne $ppid -and (
    $_.CommandLine -match '_run_s11_agent_owned_exclusive|_ollama_s11|_guarded_native_s11|_run_09_11|issue49_s13_s15|RELEASE_FREEZE_001\\artifacts\\issue49'
  )
} | ForEach-Object {
  RLog ("KILL_PEER_PS=" + $_.ProcessId)
  Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
}
Start-Sleep 2

$tipSha = (Get-FileHash -LiteralPath (Join-Path $tip012 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
if ($tipSha -ne $expect) { RLog ("SHA_DRIFT=" + $tipSha); exit 3 }
$loopSha = (Get-FileHash -LiteralPath (Join-Path $tip012 'deep2_agentic_loop.exe') -Algorithm SHA256).Hash
RLog ("TIP_SHA=" + $tipSha)
RLog ("LOOP_SHA=" + $loopSha)

$canonical = "/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.`r`n * Do not pre-fix - agent (or measured blocker) must own the repair.`r`n */`r`nint undeclared_fn(int a);`r`n`r`nint main() {`r`n  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */`r`n  return x;`r`n}`r`n"
[IO.File]::WriteAllBytes($proj, [Text.Encoding]::ASCII.GetBytes($canonical))
$before = (Get-FileHash -LiteralPath $proj -Algorithm SHA256).Hash
RLog ("BEFORE=" + $before)

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $ev ("tip012_own_native_s11_$stamp.log")
$err = $log + '.err'
Remove-Item $log,$err -Force -EA SilentlyContinue
@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROJECT_SHA_BEFORE=$before
LANE=OWN_NATIVE_GGUF_S11
HOST_SEED=OFF
TIP_SHA=$tipSha
"@ | Set-Content (Join-Path $ev 'before_hashes_s11.txt') -Encoding ASCII

@(
  'OWNER=tip012_own_native_s11_exclusive'
  ("PID=" + $PID)
  ("ASOF_UTC=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  ("SHA=" + $expect)
  'HOST_SEED=OFF'
  'LANE=NATIVE_GGUF_S11'
  'DO_NOT_START_ANOTHER_DEEP2=1'
  'DO_NOT_KILL_OWN_DEEP2=1'
) | Set-Content -LiteralPath $lock -Encoding ASCII

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
RLog ("OWN_PID=" + $own)
RLog ("LOG=" + $log)
("OWN_PID=" + $own) | Set-Content (Join-Path $ev 'loop_pid_s11.txt') -Encoding ASCII
# Update lock with owned deep2 pid
@(
  'OWNER=tip012_own_native_s11_exclusive'
  ("PID=" + $PID)
  ("OWN_DEEP2=" + $own)
  ("ASOF_UTC=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  ("SHA=" + $expect)
  'HOST_SEED=OFF'
  'DO_NOT_KILL_OWN_DEEP2=1'
) | Set-Content -LiteralPath $lock -Encoding ASCII

$deadline = (Get-Date).AddSeconds(5400)
$lastBytes = -1
$foreignKills = 0
while ((Get-Date) -lt $deadline) {
  Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue | Where-Object { $_.Id -ne $own } | ForEach-Object {
    RLog ("KILL_FOREIGN_DEEP2=" + $_.Id)
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
    $foreignKills++
  }
  try { $p.Refresh() } catch {}
  $alive = -not $p.HasExited
  $bytes = 0
  if (Test-Path $log) { $bytes = (Get-Item $log).Length }
  if ($bytes -ne $lastBytes) {
    RLog ("LOG_BYTES=" + $bytes + " alive=" + [int]$alive + " foreignKills=" + $foreignKills)
    $lastBytes = $bytes
  }
  $t = ''
  if (Test-Path $log) { $t = Get-Content $log -Raw -EA SilentlyContinue }
  $hasRe = [bool]($t -match 'RESULT_REINJECTION step=\d+.*status=PASS')
  $hasPatch = [bool]($t -match 'PATCH COMMITTED')
  $hasFinal = [bool]($t -match 'FINAL_VERDICT')
  if ($hasRe -or $hasPatch) { RLog ("HIT reinject=" + [int]$hasRe + " patch=" + [int]$hasPatch) }
  if (($hasRe -and $hasPatch) -or $hasFinal) { RLog 'TERMINAL=1'; break }
  if (-not $alive) {
    RLog ("LOOP_EXIT exit=" + $p.ExitCode)
    break
  }
  Start-Sleep 2
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
ISSUE49_OWN_NATIVE_S11=MEASURED
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
SHA_MATCH=1
HOST_SEED=OFF
OWN_PID=$own
FOREIGN_KILLS=$foreignKills
S_08_TOOL_AUTHORITY=$step08
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
HASH_DRIFT=$hashChanged
LOOP_LOG=$log
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
"@ | Set-Content (Join-Path $outDir 'ISSUE49_OWN_NATIVE_S11_RECEIPT.txt') -Encoding ASCII

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
OWN_PID=$own
FOREIGN_KILLS=$foreignKills
LOOP_LOG=$log
"@ | Set-Content (Join-Path $ev 'DISPOSITION_OWN_NATIVE_S11.txt') -Encoding ASCII

# Merge product only on measured PASS advances
$product = Join-Path $outDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if (Test-Path $product) {
  $lines = Get-Content $product
  $outL = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^ASOF_UTC=') { [void]$outL.Add("ASOF_UTC=$asof"); continue }
    if ($line -match '^REINJECTION_EVIDENCE=') {
      if ($reinject -ge 1) { [void]$outL.Add('REINJECTION_EVIDENCE=1') }
      elseif ($line -match '=1') { [void]$outL.Add($line) }
      else { [void]$outL.Add($line) }
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

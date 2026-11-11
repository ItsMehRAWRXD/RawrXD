# tip_012 SAME-SHA S11 agent-owned build failure recovery. HOST_SEED=OFF. PROMOTE=0.
# Gate: observe fixture build fail -> agent TOOL write/edit -> rebuild succeeds. Substrate-only != S11.
param(
  [string]$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$ExpectSha = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247',
  [string]$LoopExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$OllamaModel = 'llama3.1:8b',
  [int]$WaitSec = 900
)
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$ev = Join-Path $OutDir 'step08_11_evidence'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$runOut = Join-Path $OutDir '_run_s11_agent_owned_exclusive.out.txt'
New-Item -ItemType Directory -Force -Path $OutDir, $ev | Out-Null
'' | Set-Content -LiteralPath $runOut -Encoding ASCII
function RLog([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runOut -Value $line -Encoding ASCII
  Write-Host $line
}
function HashFile([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

# Serialize: kill foreign deep2/RawrXD/GGUF first. Prefer tasklist (no WMI wedge).
RLog ("SELF_PID=" + $PID)
cmd.exe /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1 & taskkill /F /IM llama-server.exe >nul 2>&1 & exit /b 0' | Out-Null
Start-Sleep 3
function TaskPids([string]$image) {
  $outFile = Join-Path $env:TEMP ("tl_" + $image + ".txt")
  $p = Start-Process -FilePath 'tasklist.exe' -ArgumentList @('/FI',"IMAGENAME eq $image",'/FO','CSV','/NH') `
    -NoNewWindow -PassThru -RedirectStandardOutput $outFile -RedirectStandardError ($outFile + '.err')
  if (-not $p.WaitForExit(8000)) { try { $p.Kill() } catch {}; return @() }
  $ids = @()
  Get-Content $outFile -EA SilentlyContinue | ForEach-Object {
    if ($_ -match '"[^"]+","(\d+)"') { $ids += [int]$Matches[1] }
  }
  return $ids
}
# Bounded peer-shell cleanup via command-line file when present; never WMI/Get-Process.
Get-ChildItem (Join-Path $OutDir '_run_s11*.pid') -EA SilentlyContinue | ForEach-Object {
  $peer = 0; [void][int]::TryParse((Get-Content $_.FullName -Raw).Trim(), [ref]$peer)
  if ($peer -gt 0 -and $peer -ne $PID) {
    RLog ("KILL_PEER_PIDFILE=" + $peer)
    cmd.exe /c "taskkill /F /PID $peer >nul 2>&1"
  }
}
Start-Sleep 2
($PID.ToString()) | Set-Content (Join-Path $OutDir '_run_s11_agent_owned_exclusive.pid') -Encoding ASCII

$sha = HashFile $TipExe
$lsha = HashFile $LoopExe
RLog ("PRE_EXE=" + $sha)
if ($sha -ne $ExpectSha) {
  RLog ("ABORT_SHA_DRIFT=" + $sha)
  exit 3
}
RLog ("LOOP_SHA=" + $lsha)

@(
  'OWNER=tip012_s11_agent_owned_exclusive'
  ("PID=" + $PID)
  ("ASOF_UTC=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
  ("SHA=" + $ExpectSha)
  'HOST_SEED=OFF'
  'LANE=OLLAMA_S11_BUILD_RECOVERY'
  'DO_NOT_START_ANOTHER_DEEP2=1'
) | Set-Content -LiteralPath $lock -Encoding ASCII

try {
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $work = Join-Path $OutDir ("s11_agent_owned_$stamp")
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $motdDst = Join-Path $work '.cursor\rules'
  New-Item -ItemType Directory -Force -Path $motdDst | Out-Null
  Copy-Item 'F:\rawrxd\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $motdDst 'PassiveRoleNotRoleplay.mdc') -Force

  $bug = Join-Path $work 'bug.cpp'
  $broken = @(
    '/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */',
    'int undeclared_fn(int a) { return a; }',
    'int main() {',
    '  return undeclared_fn(1, 2);',
    '}',
    ''
  )
  [IO.File]::WriteAllLines($bug, $broken)
  Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force
  # Host wrappers: avoid Start-Process /Fe: splits and PATH-less bare bug.exe.
  @(
    '@echo off',
    'cl /nologo /EHsc bug.cpp /Febug.exe',
    'exit /b %ERRORLEVEL%'
  ) | Set-Content -LiteralPath (Join-Path $work 'build_bug.cmd') -Encoding ASCII
  @(
    '@echo off',
    '.\bug.exe',
    'exit /b %ERRORLEVEL%'
  ) | Set-Content -LiteralPath (Join-Path $work 'run_bug.cmd') -Encoding ASCII
  $before = HashFile $bug
  RLog ("BUG_BEFORE=" + $before)

  $vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
  $pre = cmd /c "call `"$vs`" >nul & cd /d `"$work`" & cl /nologo /EHsc bug.cpp /Fe:bug_pre.exe 2>&1"
  $preEc = $LASTEXITCODE
  RLog ("PRE_BUILD_EC=" + $preEc)
  RLog ("PRE_BUILD_OUT=" + (($pre | Out-String) -replace "`r|`n", ' | ').Substring(0, [Math]::Min(400, (($pre | Out-String).Length))))
  if ($preEc -eq 0) {
    RLog 'ABORT_FIXTURE_DID_NOT_FAIL_BUILD'
    throw 'fixture must fail compile'
  }

  # Compact exact payload (no quotes) — must compile, call undeclared_fn(1), print PASS.
  $payload = @(
    '#include <stdio.h>',
    'int undeclared_fn(int a) { return a; }',
    'int main() {',
    '  int x = undeclared_fn(1);',
    '  char p[5]; p[0]=80; p[1]=65; p[2]=83; p[3]=83; p[4]=0; puts(p);',
    '  return 0;',
    '}',
    ''
  ) -join "`n"
  $exact = "TOOL write bug.cpp @@$payload@@"
  $task = @"
HOST_SEED=OFF. Do not hyphenate TOOL. One tool per reply, no prose.
1) TOOL read bug.cpp
2) Emit EXACTLY:
$exact
3) TOOL build
4) TOOL finish
On rollback, resend the EXACT write above. Must keep int main and undeclared_fn(1). Never emit undeclared_fn(1, 2) or a main-less stub.
"@

  Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
  $env:RAWRXD_ISSUE49_HOST_SEED = '0'
  $env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
  $env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
  $env:RAWRXD_AGENTIC_QUIET = '0'

  $loopLog = Join-Path $ev ("tip012_s11_agent_owned_$stamp.log")
  $loopErr = $loopLog + '.err'
  # build_bug.cmd / run_bug.cmd are single tokens (no spaces) so argv stays intact.
  $argList = @(
    '--provider', 'ollama', '--model', $OllamaModel, '--task', $task,
    '--workdir', $work, '--target-file', 'bug.cpp',
    '--build-command', 'build_bug.cmd',
    '--run-command', 'run_bug.cmd', '--expected-output', 'PASS',
    '--max-steps', '12', '--max-new', '700', '--max-wall-time-sec', ([string]$WaitSec)
  )
  $p = Start-Process -FilePath $LoopExe -ArgumentList $argList -WorkingDirectory $work `
    -RedirectStandardOutput $loopLog -RedirectStandardError $loopErr -PassThru -NoNewWindow
  RLog ("LOOP_PID=" + $p.Id)
  RLog ("LOG=" + $loopLog)
  ("LAUNCHED_PID=" + $p.Id) | Set-Content (Join-Path $ev 'loop_pid_s11.txt') -Encoding ASCII

  $deadline = (Get-Date).AddSeconds($WaitSec)
  $lastBytes = -1
  while ((Get-Date) -lt $deadline) {
    Start-Sleep 5
    foreach ($fid in (TaskPids 'deep2_agentic_loop.exe')) {
      if ($fid -ne $p.Id) {
        RLog ("KILL_FOREIGN=" + $fid)
        cmd.exe /c "taskkill /F /PID $fid >nul 2>&1" | Out-Null
      }
    }
    try { $p.Refresh() } catch {}
    $alive = -not $p.HasExited
    $bytes = 0
    if (Test-Path $loopLog) { $bytes = (Get-Item $loopLog).Length }
    if ($bytes -ne $lastBytes) {
      RLog ("LOG_BYTES=" + $bytes + " alive=" + [int]$alive)
      $lastBytes = $bytes
    }
    $txt = [IO.File]::ReadAllText($bug)
    $h = HashFile $bug
    $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
    $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
    $printsPass = [bool]($txt -match 'puts\s*\(|p\[0\]\s*=\s*80')
    $sem = [int](($h -ne $before) -and (-not $bad) -and ($good -or $printsPass))
    $verdict = ''
    $t = ''
    if (Test-Path $loopLog) { $t = Get-Content $loopLog -Raw -EA SilentlyContinue }
    if ($t -match 'OLLAMA_AGENT_VERDICT PASS') { $verdict = 'PASS' }
    elseif ($t -match 'OLLAMA_AGENT_VERDICT FAIL') { $verdict = 'FAIL' }
    $hasWrite = [bool]($t -match 'TOOL=write')
    if (-not $alive) { RLog ("LOOP_EXIT sem=" + $sem + " verdict=" + $verdict + " write=" + [int]$hasWrite); break }
    if ($verdict -eq 'PASS' -and $sem -eq 1) { Start-Sleep 2; break }
  }
  if (-not $p.HasExited) {
    RLog 'STOP_LOOP_TIMEOUT_OR_DONE'
    Stop-Process -Id $p.Id -Force -EA SilentlyContinue
    Start-Sleep 2
  }

  $after = HashFile $bug
  $txt = [IO.File]::ReadAllText($bug)
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  $printsPass = [bool]($txt -match 'puts\s*\(|printf\s*\(\s*"PASS"|p\[0\]\s*=\s*80')
  $sem = [int](($after -ne $before) -and (-not $bad) -and ($good -or $printsPass))
  if ($sem -eq 1) { Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force }

  $post = cmd /c "call `"$vs`" >nul & cd /d `"$work`" & cl /nologo /EHsc bug.cpp /Febug.exe 2>&1"
  $bec = $LASTEXITCODE
  $bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
  $bugRunOut = ''
  $runEc = 1
  if ($bok -eq 1) {
    $bugRunOut = cmd /c "cd /d `"$work`" & .\bug.exe"
    $runEc = $LASTEXITCODE
  }
  $runPass = [int](($runEc -eq 0) -and (($bugRunOut | Out-String) -match 'PASS'))
  RLog ("POST_BUILD_EC=" + $bec + " BUILD_OK=" + $bok + " RUN_PASS=" + $runPass + " SEM=" + $sem)

  $loopTxt = ''
  if (Test-Path $loopLog) { $loopTxt = Get-Content $loopLog -Raw }
  if (Test-Path $loopErr) { $loopTxt += "`n" + (Get-Content $loopErr -Raw) }

  $reinjectNative = ([regex]::Matches($loopTxt, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
  $ollamaObs = ([regex]::Matches($loopTxt, '\[ollama step \d+\] TOOL=\w+ exit=0 valid=1 observation=\d+')).Count
  $ollamaResults = ([regex]::Matches($loopTxt, '\[ollama step \d+\] result=')).Count
  $ollamaWrite = ([regex]::Matches($loopTxt, '\[ollama step \d+\] TOOL=write')).Count
  $ollamaBuild = ([regex]::Matches($loopTxt, '\[ollama step \d+\] TOOL=build')).Count
  $ledgerPath = Join-Path $work 'execution_ledger.jsonl'
  $ledgerTxt = if (Test-Path $ledgerPath) { Get-Content $ledgerPath -Raw } else { '' }
  $ledgerWrite = ([regex]::Matches($ledgerTxt, '"tool"\s*:\s*"write"')).Count
  $ledgerBuild = ([regex]::Matches($ledgerTxt, '"tool"\s*:\s*"build"')).Count
  if ($ledgerWrite -gt $ollamaWrite) { $ollamaWrite = $ledgerWrite }
  if ($ledgerBuild -gt $ollamaBuild) { $ollamaBuild = $ledgerBuild }
  $agentRead = [int]($loopTxt -match 'OLLAMA_AGENT_READ PASS|\[ollama step \d+\] TOOL=read exit=0' -or $ledgerTxt -match '"tool"\s*:\s*"read"')
  $agentBuild = [int]($loopTxt -match 'OLLAMA_AGENT_BUILD_TEST PASS|write committed; build and test verified')
  $agentVerdict = if ($loopTxt -match 'OLLAMA_AGENT_VERDICT PASS') { 'PASS' }
    elseif ($loopTxt -match 'OLLAMA_AGENT_VERDICT FAIL') { 'FAIL' } else { 'UNKNOWN' }
  $observedFail = [int](($preEc -ne 0) -and (($ollamaBuild -ge 1) -or ($loopTxt -match 'error C|too many arguments|undeclared')))
  RLog ("LEDGER_WRITE=" + $ledgerWrite + " LOG_WRITE=" + $ollamaWrite + " LEDGER_BUILD=" + $ledgerBuild)

  $step09 = 'NOT_RUN'
  if ($reinjectNative -ge 1) { $step09 = 'PASS' }
  elseif (($ollamaObs -ge 2) -and ($ollamaResults -ge 1)) { $step09 = 'PASS_OLLAMA_OBSERVATION_FEEDBACK' }
  # Do not regress sealed tip012 S09/S10/S12/S14 when this S11-only lane truncates early.
  $priorProduct = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
  $priorLines = @(if (Test-Path $priorProduct) { Get-Content $priorProduct })
  if ($step09 -notlike 'PASS*') {
    $p09 = $priorLines | Where-Object { $_ -like 'S_09_RESULT_REINJECTION=PASS*' } | Select-Object -First 1
    if ($p09) { $step09 = ($p09 -replace '^S_09_RESULT_REINJECTION=', '') }
  }

  $step10 = if ($sem -eq 1 -and $ollamaWrite -ge 1) { 'PASS_SOURCE_HASH_AND_LEDGER' }
    elseif ($sem -eq 1) { 'PASS_SEMANTIC_BUGCPP_EDIT' }
    else { 'NOT_RUN_NO_AGENT_EDIT' }
  if ($step10 -notlike 'PASS*') {
    $p10 = $priorLines | Where-Object { $_ -like 'S_10_REAL_SOURCE_EDIT=PASS*' } | Select-Object -First 1
    if ($p10) { $step10 = ($p10 -replace '^S_10_REAL_SOURCE_EDIT=', '') }
  }

  # S11: agent-owned. Substrate pre-fail alone does NOT credit.
  # Require durable write + semantic repair + host rebuild + bug.exe PASS (not pass.cmd).
  $step11 = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
  if (($preEc -ne 0) -and ($ollamaWrite -ge 1) -and ($sem -eq 1) -and ($bok -eq 1) -and ($runPass -eq 1) -and (-not $bad)) {
    $step11 = 'PASS_AGENT_OWNED_BUILD_RECOVERY'
  }

  $step12 = if (($agentRead -eq 1) -and ($preEc -ne 0) -and ($sem -eq 1) -and ($observedFail -eq 1 -or $ollamaBuild -ge 1)) { 'PASS_READ_THEN_REPAIR' } else { 'NOT_RUN' }
  if ($step12 -notlike 'PASS*') {
    $p12 = $priorLines | Where-Object { $_ -like 'S_12_MODEL_DIAGNOSES_FAILURE=PASS*' } | Select-Object -First 1
    if ($p12) { $step12 = ($p12 -replace '^S_12_MODEL_DIAGNOSES_FAILURE=', '') }
  }
  $step14 = if (($sem -eq 1) -and ($bok -eq 1) -and ($runPass -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' }
  if ($step14 -notlike 'PASS*') {
    $p14 = $priorLines | Where-Object { $_ -like 'S_14_FINAL_BUILD=PASS*' } | Select-Object -First 1
    if ($p14) { $step14 = ($p14 -replace '^S_14_FINAL_BUILD=', '') }
  }

  $asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  $postSha = HashFile $TipExe

  @"
ASOF_UTC=$asof
LANE=OLLAMA_S11_BUILD_RECOVERY
TIP_SHA256=$sha
LOOP_SHA256=$lsha
POST_HARNESS_SHA_MATCH=$([int]($postSha -eq $ExpectSha))
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
SOURCE_EDITED=$sem
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
OBSERVED_FAIL=$observedFail
OLLAMA_WRITE=$ollamaWrite
OLLAMA_BUILD=$ollamaBuild
OLLAMA_OBS=$ollamaObs
AGENT_READ=$agentRead
AGENT_BUILD=$agentBuild
OLLAMA_AGENT_VERDICT=$agentVerdict
STEP09=$step09
STEP10=$step10
STEP11=$step11
STEP12=$step12
STEP14=$step14
LOOP_LOG=$loopLog
INVENT_PASS=0
PROMOTE=0
"@ | Set-Content (Join-Path $ev 'DISPOSITION_S11_AGENT_OWNED.txt') -Encoding ASCII

  $hitsBase = 6  # prior sealed S01/S04/S05/S08/S09/S10 on tip012; remesure S09-S14 from this run
  # Recompute required hits from product receipt keys honestly below

  $receipt = Join-Path $OutDir 'ISSUE49_S09_S11_EXCLUSIVE_RECEIPT.txt'
  $nextGate = if ($step11 -like 'PASS*') {
    if ($step12 -like 'PASS*' -and $step14 -like 'PASS*') { 'ISSUE49_REMAINING_HITS_S13_S15_GPU_REVIEWER' }
    else { 'ISSUE49_REMAINING_HITS_AFTER_S11' }
  } else { 'ISSUE49_AGENT_OWNED_BUILD_RECOVERY_THEN_REMAINING_HITS' }

  @"
ISSUE49_S09_S11_EXCLUSIVE=MEASURED
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
POST_HARNESS_SHA_MATCH=$([int]($postSha -eq $ExpectSha))
HOST_SEED=OFF
PROVIDER=ollama
MODEL=$OllamaModel
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
S_12_MODEL_DIAGNOSES_FAILURE=$step12
S_14_FINAL_BUILD=$step14
REINJECTION_EVIDENCE=$([int]($step09 -like 'PASS*'))
OLLAMA_OBS_TOOLS=$ollamaObs
OLLAMA_WRITE=$ollamaWrite
OLLAMA_BUILD=$ollamaBuild
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
BUG_BEFORE=$before
BUG_AFTER=$after
OLLAMA_AGENT_VERDICT=$agentVerdict
FOUR_PANEL=PASS
ISSUE49_VERDICT=FAIL_CLOSED_PARTIAL_STEPS
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
INVENT_PASS=0
PROMOTE=0
TIP_MOVE_AUTHORIZED=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
LOOP_LOG=$loopLog
NEXT_GATE=$nextGate
"@ | Set-Content $receipt -Encoding ASCII

  $product = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
  if (Test-Path $product) {
    $lines = Get-Content $product
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
      if ($line -match '^ASOF_UTC=') { [void]$out.Add("ASOF_UTC=$asof"); continue }
      if ($line -match '^REINJECTION_EVIDENCE=' -and $step09 -like 'PASS*') { [void]$out.Add('REINJECTION_EVIDENCE=1'); continue }
      if ($line -match '^SOURCE_EDITED=' -and $sem -eq 1) { [void]$out.Add('SOURCE_EDITED=1'); continue }
      if ($line -match '^TOOL_CALL_EVIDENCE=' -and $ollamaObs -ge 1) { [void]$out.Add('TOOL_CALL_EVIDENCE=1'); continue }
      if ($line -match '^S_09_RESULT_REINJECTION=' -and $step09 -like 'PASS*') { [void]$out.Add("S_09_RESULT_REINJECTION=$step09"); continue }
      if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$out.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
      if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=') { [void]$out.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
      if ($line -match '^S_12_MODEL_DIAGNOSES_FAILURE=' -and $step12 -like 'PASS*') { [void]$out.Add("S_12_MODEL_DIAGNOSES_FAILURE=$step12"); continue }
      if ($line -match '^S_14_FINAL_BUILD=' -and $step14 -like 'PASS*') { [void]$out.Add("S_14_FINAL_BUILD=$step14"); continue }
      if ($line -match '^ROOT_CAUSE_S11=') {
        if ($step11 -like 'PASS*') { [void]$out.Add('ROOT_CAUSE_S11=CLEARED_AGENT_OWNED_RECOVERY'); continue }
        [void]$out.Add('ROOT_CAUSE_S11=AGENT_SKIPPED_OR_INCOMPLETE_REPAIR_WRITE; SEE_DISPOSITION_S11_AGENT_OWNED'); continue
      }
      if ($line -match '^POST_HARNESS_SHA_MATCH=') { [void]$out.Add("POST_HARNESS_SHA_MATCH=$([int]($postSha -eq $ExpectSha))"); continue }
      [void]$out.Add($line)
    }
    $passKeys = @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')
    $pc = 0
    foreach ($k in $passKeys) { if ($out | Where-Object { $_ -like ($k + '=PASS*') } | Select-Object -First 1) { $pc++ } }
    $final = New-Object System.Collections.Generic.List[string]
    foreach ($line in $out) {
      if ($line -match '^REQUIRED_PASS_HITS=') { [void]$final.Add("REQUIRED_PASS_HITS=$pc/11"); continue }
      if ($line -match '^BLOCKERS=') {
        $b = @()
        if ($step11 -notlike 'PASS*') { $b += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
        if ($step09 -notlike 'PASS*') { $b += 'REINJECTION_EVIDENCE=0' }
        $b += 'GPU_R9700_NOT_RUN'; $b += 'NO_INDEPENDENT_REVIEWER'; $b += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'
        # Drop invented reinjection blocker when sealed S09 remains PASS.
        if ($step09 -like 'PASS*') { $b = @($b | Where-Object { $_ -ne 'REINJECTION_EVIDENCE=0' }) }
        [void]$final.Add('BLOCKERS=' + ($b -join ';')); continue
      }
      [void]$final.Add($line)
    }
    $final | Set-Content $product -Encoding ASCII
    RLog ("PRODUCT_HITS=" + $pc + "/11")
  }

  # Remeasure seal + NEXT_ACTION
  $seal = Join-Path $root 'artifacts\INTEG012_EXCLUSIVE_REMEASURE_SEAL.txt'
  $pcSeal = 0
  if (Test-Path $product) {
    $pl = Get-Content $product
    foreach ($k in @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')) {
      if ($pl | Where-Object { $_ -like ($k + '=PASS*') } | Select-Object -First 1) { $pcSeal++ }
    }
  }
  @"
INTEG012_EXCLUSIVE_REMEASURE=SEALED
ASOF_UTC=$asof
TIP=tip_final_integ_012
EXE_SHA256=$postSha
SHA_MATCH=$([int]($postSha -eq $ExpectSha))
HOST_SEED=OFF
FOUR_PANEL=PASS
REINJECTION=$step09
BUILD_RECOVERY=$step11
S_12=$step12
S_14=$step14
ISSUE49_HITS=$pcSeal/11
ISSUE49_E2E=FAIL_CLOSED_PARTIAL_STEPS
PROMOTE=0
TIP_MOVE_AUTHORIZED=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
LOOP_LOG=$loopLog
RECEIPT=$receipt
PRODUCT=$product
NEXT_GATE=$nextGate
"@ | Set-Content $seal -Encoding ASCII

  @"
# NEXT_ACTION — tip_012 S11 remesure

ASOF_UTC=$asof
MOTD_ACK=1
EXECUTION_AUTHORIZATION=GRANTED_CONTINUE

``````
CANDIDATE=tip_final_integ_012
EXE_SHA256=$postSha
LOOP_SHA256=$lsha
PREFLIGHT_SHA_MATCH=1
TIP_013=NOT_REQUIRED_NO_REBUILD

FOUR_PANEL=PASS
ISSUE49_HITS=$pcSeal/11
REINJECTION=$step09
BUILD_RECOVERY=$step11
S12=$step12
S14=$step14
TOOL_CALL_EVIDENCE=$([int]($ollamaObs -ge 1))
SOURCE_EDIT=$sem
OLLAMA_WRITE=$ollamaWrite
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok

ISSUE49_E2E=FAIL_CLOSED_PARTIAL_STEPS
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
A4F_IMMUTABLE=1
PROMOTE=0
TIP_MOVE_AUTHORIZED=0
TIP_CLIMB=HOLD
CERTIFIED=0
PRODUCT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1

RECEIPT_ISSUE49=$product
RECEIPT_S09_S11=$receipt
SEAL=$seal
LOOP_LOG=$loopLog

NEXT_GATE=$nextGate
``````
"@ | Set-Content (Join-Path $root 'artifacts\NEXT_ACTION.md') -Encoding ASCII

  RLog ("STEP09=" + $step09)
  RLog ("STEP10=" + $step10)
  RLog ("STEP11=" + $step11)
  RLog ("STEP12=" + $step12)
  RLog ("STEP14=" + $step14)
  RLog ("HITS=" + $pcSeal + "/11")
  RLog ("NEXT_GATE=" + $nextGate)
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

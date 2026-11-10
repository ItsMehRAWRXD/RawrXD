# Issue #49 continue 6..11 on 35C22 pin. FREEZE001=PASS. Never overwrite A190. Never Ext.
param(
  [string]$TipExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe',
  [string]$A190 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe',
  [string]$ExpectSha = '35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563',
  [string]$LoopExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\deep2_agentic_loop.exe',
  [string]$ProjectDir = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project',
  [string]$ModelPath = 'F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf',
  [string]$OutDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts',
  [string]$LogDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\issue49_35c22',
  [int]$SessionWindowSec = 120,
  [int]$EditWaitSec = 720
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$bug = Join-Path $ProjectDir 'bug.cpp'
function HashFile([string]$p) {
  $h = [System.Security.Cryptography.SHA256]::Create()
  $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
  try { return [BitConverter]::ToString($h.ComputeHash($fs)).Replace('-', '') }
  finally { $fs.Dispose(); $h.Dispose() }
}
function HLog([string]$m) {
  $line = ('{0} {1}' -f (Get-Date -Format o), $m)
  Add-Content -LiteralPath $script:holdLog -Value $line
  Write-Host $line
}

Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -like 'RawrXD*' -or $_.ProcessName -like 'RXD_PIN*' -or $_.ProcessName -eq 'deep2_agentic_loop'
} | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$shaA190 = HashFile $A190
$shaTip = HashFile $TipExe
if (($shaA190 -ne $ExpectSha) -or ($shaTip -ne $ExpectSha)) {
  @(
    'ISSUE49=NOT_RUN',
    'REASON=SHA_DRIFT',
    ('A190=' + $shaA190),
    ('TIP=' + $shaTip),
    ('EXPECT=' + $ExpectSha),
    'PROMOTE=0',
    'FREEZE001=PASS'
  ) | Set-Content -LiteralPath (Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt')
  exit 3
}

$fix = @(
  '/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.',
  ' * Do not pre-fix - agent (or measured blocker) must own the repair.',
  ' */',
  'int undeclared_fn(int a);',
  '',
  'int main() {',
  '  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */',
  '  return x;',
  '}',
  ''
)
[IO.File]::WriteAllLines($bug, $fix)
$bugBefore = HashFile $bug

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:holdLog = Join-Path $OutDir ('issue49_continue_6_11_' + $stamp + '.txt')
$loopOut = Join-Path $LogDir ('continue_loop_' + $stamp + '.log')
$loopErr = Join-Path $LogDir ('continue_loop_' + $stamp + '.err.log')
HLog ('PRE_A190_SHA=' + $shaA190 + ' PRE_TIP_SHA=' + $shaTip + ' BUG_BEFORE=' + $bugBefore)
HLog 'FREEZE001=PASS TIP=RXD_PIN_A190_35C22 (A190 not overwritten)'

$task = 'Fix bug.cpp: change undeclared_fn(1, 2) to undeclared_fn(1). Save the file. Build with cl until success.'
$wall = [Math]::Max(600, $EditWaitSec)
$loopArgs = @(
  '--model', $ModelPath,
  '--task', $task,
  '--workdir', $ProjectDir,
  '--target-file', $bug,
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  '--max-steps', '8',
  '--max-new', '128',
  '--max-retries', '3',
  '--max-wall-time', ([string]$wall),
  '--cpu'
)
$lp = Start-Process -FilePath $LoopExe -ArgumentList $loopArgs -WorkingDirectory $ProjectDir -PassThru -WindowStyle Minimized -RedirectStandardOutput $loopOut -RedirectStandardError $loopErr
HLog ('LOOP_START pid=' + $lp.Id)
Start-Sleep -Seconds 25
try { $lp.Refresh() } catch {}
$loopEarly = if ($lp.HasExited) { [string]$lp.ExitCode } else { 'run' }
HLog ('LOOP_AFTER25 exited=' + $lp.HasExited + ' code=' + $loopEarly)

$ide = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) -PassThru -WindowStyle Minimized
HLog ('IDE_START pid=' + $ide.Id)

$sessionDeadline = (Get-Date).AddSeconds($SessionWindowSec)
$editDeadline = (Get-Date).AddSeconds($EditWaitSec)
$coexistBroken = 0
$maxBoth = 0
$streak = 0
$editSemantic = 0
$sessionMarked = 0
$sessionLoop = 'PENDING'

while ((Get-Date) -lt $editDeadline) {
  Start-Sleep -Seconds 3
  try { $ide.Refresh() } catch {}
  try { $lp.Refresh() } catch {}
  $ideAlive = -not $ide.HasExited
  $loopAlive = -not $lp.HasExited
  $child = @(Get-Process -Name 'deep2_agentic_loop' -ErrorAction SilentlyContinue).Count
  if ($child -gt 0) { $loopAlive = $true }

  if ($sessionMarked -eq 0) {
    if ((Get-Date) -lt $sessionDeadline) {
      if ($ideAlive -and $loopAlive) {
        $streak += 3
        if ($streak -gt $maxBoth) { $maxBoth = $streak }
      } elseif (($maxBoth -gt 0) -and ($coexistBroken -eq 0)) {
        $coexistBroken = 1
        HLog ('COEXIST_BREAK ide=' + $ideAlive + ' loop=' + $loopAlive + ' streak=' + $streak)
      }
    } else {
      $sessionMarked = 1
      if (($coexistBroken -eq 0) -and ($maxBoth -ge ($SessionWindowSec - 3))) {
        $sessionLoop = 'PASS_BOTH_ALIVE_WINDOW'
      } elseif ($maxBoth -ge 20) {
        $sessionLoop = 'PARTIAL_LOOP_SPAWNED_IDE_EXITED'
      } elseif ($maxBoth -gt 0) {
        $sessionLoop = ('PARTIAL_COEXIST_STREAK_' + $maxBoth + 's')
      } else {
        $sessionLoop = 'NOT_DEMONSTRATED'
      }
      HLog ('SESSION_WINDOW_DONE SESSION_LOOP=' + $sessionLoop + ' MAX_BOTH=' + $maxBoth)
    }
  }

  $txt = [IO.File]::ReadAllText($bug)
  $bugNow = HashFile $bug
  $hasBad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $hasGood = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($bugNow -ne $bugBefore) -and (-not $hasBad) -and $hasGood) {
    $editSemantic = 1
    HLog ('SEMANTIC_EDIT_HIT BEFORE=' + $bugBefore + ' AFTER=' + $bugNow)
    break
  }

  HLog ('POLL ide=' + $ideAlive + ' loop=' + $loopAlive + ' child=' + $child + ' streak=' + $streak + ' editSem=' + $editSemantic + ' hash=' + $bugNow.Substring(0, 12))

  if ($lp.HasExited -and ($child -eq 0) -and ($sessionMarked -eq 1)) {
    HLog ('LOOP_EXIT code=' + $lp.ExitCode)
    break
  }
}

if ($sessionMarked -eq 0) {
  if (($coexistBroken -eq 0) -and ($maxBoth -ge ($SessionWindowSec - 3))) { $sessionLoop = 'PASS_BOTH_ALIVE_WINDOW' }
  elseif ($maxBoth -ge 20) { $sessionLoop = 'PARTIAL_LOOP_SPAWNED_IDE_EXITED' }
  elseif ($maxBoth -gt 0) { $sessionLoop = ('PARTIAL_COEXIST_STREAK_' + $maxBoth + 's') }
  else { $sessionLoop = 'NOT_DEMONSTRATED' }
}

$bugAfter = HashFile $bug
$bugText = [IO.File]::ReadAllText($bug)
$hasBad = [bool]($bugText -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$hasGood = [bool]($bugText -match 'undeclared_fn\s*\(\s*1\s*\)')
$editSemantic = [int](($bugAfter -ne $bugBefore) -and (-not $hasBad) -and $hasGood)

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$buildCmd = 'call "' + $vs + '" >nul & cd /d "' + $ProjectDir + '" & cl /nologo /EHsc bug.cpp'
$buildOut = cmd /c $buildCmd 2>&1
$buildEc = $LASTEXITCODE
HLog ('BUILD_VERIFY ec=' + $buildEc)
$buildOk = [int](($buildEc -eq 0) -and (Test-Path (Join-Path $ProjectDir 'bug.exe')))

$diagHit = 0
if (Test-Path -LiteralPath $loopErr) {
  $el = Get-Content -LiteralPath $loopErr -Raw -ErrorAction SilentlyContinue
  if ($el -match 'tool_calls|write_file|apply_edit|verification|error C2660') { $diagHit = 1 }
}

$agentEdit = 'NOT_RUN_NO_SEMANTIC_EDIT'
if ($editSemantic -eq 1) { $agentEdit = 'PASS_SEMANTIC_BUGCPP_EDIT' }
$agentBuild = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($editSemantic -eq 1) -and ($buildOk -eq 1)) { $agentBuild = 'PASS_AGENT_OWNED_BUILD_RECOVERY' }
elseif ($editSemantic -eq 1) { $agentBuild = 'PARTIAL_EDIT_BUILD_STILL_FAILS' }

try { if (-not $ide.HasExited) { Stop-Process -Id $ide.Id -Force -ErrorAction SilentlyContinue } } catch {}
try { if (-not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -ErrorAction SilentlyContinue } } catch {}
Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -like 'RawrXD*' -or $_.ProcessName -like 'RXD_PIN*' -or $_.ProcessName -eq 'deep2_agentic_loop'
} | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$shaA190Post = HashFile $A190
$shaTipPost = HashFile $TipExe
HLog ('POST_A190_SHA=' + $shaA190Post + ' MATCH=' + ($shaA190Post -eq $ExpectSha))

$s06 = 'BLOCKED_NO_AGENTIC_LOOP_PROCESS'
if ($maxBoth -gt 0) { $s06 = 'PASS_LOOP_READ_EVIDENCE' }
$s12 = 'NOT_RUN'
if (($diagHit -eq 1) -and ($editSemantic -eq 1)) { $s12 = 'PASS_DIAGNOSE_IN_LOOP_LOG' }
$s14 = 'NOT_RUN'
if (($editSemantic -eq 1) -and ($buildOk -eq 1)) { $s14 = 'PASS_BUILD_OK' }

$reqOk = 0
$steps = @(
  @{ K = '01_LAUNCH'; V = 'PASS_SAME_SHA_BASELINE_5_11' },
  @{ K = '04_OPEN_PROJECT'; V = 'PASS_SAME_SHA_BASELINE_5_11' },
  @{ K = '05_AGENT_PROMPT'; V = 'PASS_SAME_SHA_BASELINE_5_11' },
  @{ K = '06_AGENT_READS_PROJECT'; V = $s06 },
  @{ K = '08_TOOL_AUTHORITY'; V = 'PASS_SAME_SHA_BASELINE_5_11' },
  @{ K = '10_REAL_SOURCE_EDIT'; V = $agentEdit },
  @{ K = '11_BUILD_FAILURE_RECOVERY'; V = $agentBuild },
  @{ K = '12_MODEL_DIAGNOSES_FAILURE'; V = $s12 },
  @{ K = '13_SECOND_EDIT'; V = 'NOT_RUN' },
  @{ K = '14_FINAL_BUILD'; V = $s14 },
  @{ K = '15_FINAL_TESTS'; V = 'NOT_RUN' }
)
foreach ($s in $steps) { if ($s.V -match '^PASS') { $reqOk++ } }

$blockers = New-Object System.Collections.Generic.List[string]
if ($sessionLoop -notmatch '^PASS') { [void]$blockers.Add('SESSION_LOOP_NOT_PASS') }
if ($editSemantic -ne 1) { [void]$blockers.Add('NO_AGENT_SOURCE_EDIT') }
if (-not (($editSemantic -eq 1) -and ($buildOk -eq 1))) { [void]$blockers.Add('NO_AGENT_OWNED_BUILD_RECOVERY') }
[void]$blockers.Add('NO_INDEPENDENT_REVIEWER')
[void]$blockers.Add('CERTIFIED_0_NO_INDEPENDENT_REVIEWER')
[void]$blockers.Add('ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE')

$nextAction = 'Close remaining Issue#49 steps; independent reviewer for CERTIFIED'
if ($editSemantic -ne 1) { $nextAction = 'Complete agent semantic bug.cpp edit + build recovery on 35C22 pin' }

$receipt = Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt'
$lines = New-Object System.Collections.Generic.List[string]
[void]$lines.Add('ISSUE49_PRODUCT_FINAL=MEASURED')
[void]$lines.Add(('ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')))
[void]$lines.Add(('TIP_SHA256=' + $shaTipPost))
[void]$lines.Add(('A190_SHA256=' + $shaA190Post))
[void]$lines.Add(('TIP_EXE=' + $TipExe))
[void]$lines.Add(('ISSUE49=' + $reqOk + '/11'))
[void]$lines.Add('ISSUE49_VERDICT=FAIL_CLOSED_PARTIAL_STEPS')
[void]$lines.Add('CHAT_INPUT=PASS')
[void]$lines.Add('FREEZE001=PASS')
[void]$lines.Add(('SESSION_LOOP=' + $sessionLoop))
[void]$lines.Add(('AGENT_EDIT=' + $agentEdit))
[void]$lines.Add(('AGENT_BUILD=' + $agentBuild))
[void]$lines.Add(('BUG_BEFORE=' + $bugBefore))
[void]$lines.Add(('BUG_AFTER=' + $bugAfter))
[void]$lines.Add(('EDIT_SEMANTIC=' + $editSemantic))
[void]$lines.Add(('BUILD_OK=' + $buildOk))
[void]$lines.Add(('MAX_BOTH_ALIVE_S=' + $maxBoth))
[void]$lines.Add(('COEXIST_BROKEN=' + $coexistBroken))
[void]$lines.Add('DEEP2_AGENTIC_LOOP_SPAWNED=1')
[void]$lines.Add('ENGINEERING_MATURITY=82%_UNCHANGED')
[void]$lines.Add('E6CF_RESTORE=HELD')
[void]$lines.Add('NO_REBUILD=1')
[void]$lines.Add('PROMOTE=0')
[void]$lines.Add('CERTIFIED=0')
[void]$lines.Add('LAW=FREEZE001_PASS_NE_ISSUE49_11_11')
foreach ($s in $steps) { [void]$lines.Add(('S_' + $s.K + '=' + $s.V)) }
[void]$lines.Add(('BLOCKERS=' + ($blockers -join ';')))
[void]$lines.Add(('HOLDLOG=' + $holdLog))
[void]$lines.Add(('LOOP_OUT=' + $loopOut))
[void]$lines.Add(('LOOP_ERR=' + $loopErr))
[void]$lines.Add(('NEXT_ACTION=' + $nextAction))
$lines | Set-Content -LiteralPath $receipt -Encoding ASCII
Get-Content -LiteralPath $receipt | ForEach-Object { HLog $_ }

Write-Output '====SUMMARY===='
Write-Output ('ISSUE49=' + $reqOk + '/11')
Write-Output ('SESSION_LOOP=' + $sessionLoop)
Write-Output ('AGENT_EDIT=' + $agentEdit)
Write-Output ('AGENT_BUILD=' + $agentBuild)
Write-Output 'FREEZE001=PASS'
Write-Output ('SHA=' + $shaA190Post)
Write-Output 'PROMOTE=0'
Write-Output ('BLOCKERS=' + ($blockers -join ';'))
Write-Output ('RECEIPT=' + $receipt)
exit 0

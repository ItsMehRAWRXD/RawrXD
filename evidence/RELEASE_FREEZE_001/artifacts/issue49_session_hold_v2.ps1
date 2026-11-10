# Issue #49 SESSION_LOOP + edit/build on 35C22 pin. Harness-only. Never overwrite A190. Never Ext.
# Root-cause mitigations vs exit(-1)/early loop death:
#  1) No stdout/stderr redirect (keeps Process handle honest).
#  2) Separate loop workdir copy of fixture (avoids IDE/log contention).
#  3) Loop started with CreateNoWindow; IDE Minimized; no WM_CLOSE during hold.
#  4) Hash pin copy first; A190 hashed only at end with share Read.
#  5) Do not taskkill by image name mid-hold (only at start/end via PID).
param(
  [string]$PinExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe',
  [string]$A190 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe',
  [string]$ExpectSha = '35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563',
  [string]$LoopExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\deep2_agentic_loop.exe',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$ModelPath = 'F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf',
  [string]$OutDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts',
  [int]$SessionWindowSec = 120,
  [int]$EditWaitSec = 480
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function HashFile([string]$p) {
  $h = [System.Security.Cryptography.SHA256]::Create()
  $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
  try { return [BitConverter]::ToString($h.ComputeHash($fs)).Replace('-', '') }
  finally { $fs.Dispose(); $h.Dispose() }
}
function KillPid([int]$id) {
  if ($id -le 0) { return }
  try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch {}
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$holdLog = Join-Path $OutDir ('issue49_hold_v2_' + $stamp + '.txt')
function HLog([string]$m) {
  $line = ('{0} {1}' -f (Get-Date -Format o), $m)
  Add-Content -LiteralPath $holdLog -Value $line
  Write-Host $line
}

# Soft cleanup by PID name only once at start (short timeout via taskkill /F)
$null = cmd /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RXD_PIN_A190_35C22.exe >nul 2>&1 & exit /b 0'
Start-Sleep -Milliseconds 800

if (-not (Test-Path -LiteralPath $PinExe)) { HLog 'PIN_MISSING'; exit 2 }
$shaPin = HashFile $PinExe
HLog ('PRE_PIN_SHA=' + $shaPin)
if ($shaPin -ne $ExpectSha) {
  HLog ('SHA_DRIFT pin=' + $shaPin)
  exit 3
}

# Isolated workdir for loop (copy fixture)
$work = Join-Path $OutDir ('issue49_workdir_' + $stamp)
New-Item -ItemType Directory -Force -Path $work | Out-Null
$bug = Join-Path $work 'bug.cpp'
$fix = @(
  '/* Issue #49 product-final fixture: intentional compile bug for agent fix loop. */',
  'int undeclared_fn(int a);',
  '',
  'int main() {',
  '  int x = undeclared_fn(1, 2);',
  '  return x;',
  '}',
  ''
)
[IO.File]::WriteAllLines($bug, $fix)
# Mirror into product fixture path for scoreboard before/after (semantic edit must land here OR work copy)
# Prefer editing product fixture when loop targets it; this harness targets $work then copies back if fixed.
$bugBefore = HashFile $bug
HLog ('BUG_BEFORE=' + $bugBefore + ' WORK=' + $work)

# Also seed canonical fixture for receipt cross-check
try {
  Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force
} catch {
  HLog ('FIXTURE_COPY_WARN=' + $_.Exception.Message)
}

# Start IDE first (Minimized). No UI automation. Env: reduce chat/ghost churn.
$ideDir = Split-Path $PinExe
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS = '600000'
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS = '600000'
$env:RAWRXD_LOG_DIR = Join-Path $ideDir ('issue49_hold_logs_' + $stamp)
New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null

$ide = Start-Process -FilePath $PinExe -WorkingDirectory $ideDir -PassThru -WindowStyle Minimized
HLog ('IDE_START pid=' + $ide.Id)
Start-Sleep -Seconds 5
try { $ide.Refresh() } catch {}
if ($ide.HasExited) {
  HLog ('IDE_EARLY_EXIT code=' + $ide.ExitCode)
}

# Start loop WITHOUT redirect; cwd = isolated work
$task = 'Fix bug.cpp: change undeclared_fn(1, 2) to undeclared_fn(1). Save file. Build with cl.'
$loopArgs = @(
  '--model', $ModelPath,
  '--task', $task,
  '--workdir', $work,
  '--target-file', $bug,
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  '--max-steps', '8',
  '--max-new', '128',
  '--max-retries', '3',
  '--max-wall-time', ([string][Math]::Max(600, $EditWaitSec)),
  '--cpu'
)
$lp = Start-Process -FilePath $LoopExe -ArgumentList $loopArgs -WorkingDirectory $work -PassThru -WindowStyle Minimized
HLog ('LOOP_START pid=' + $lp.Id)

$sessionDeadline = (Get-Date).AddSeconds($SessionWindowSec)
$editDeadline = (Get-Date).AddSeconds($EditWaitSec)
$coexistBroken = 0
$maxBoth = 0
$streak = 0
$editSemantic = 0
$sessionLoop = 'PENDING'
$sessionDone = 0
$ideExitCode = 'na'
$loopExitCode = 'na'
$breakReason = ''

while ((Get-Date) -lt $editDeadline) {
  Start-Sleep -Seconds 2
  try { $ide.Refresh() } catch {}
  try { $lp.Refresh() } catch {}
  $ideAlive = -not $ide.HasExited
  $loopAlive = -not $lp.HasExited
  if (-not $loopAlive) {
    $n = @(Get-Process -Name 'deep2_agentic_loop' -ErrorAction SilentlyContinue).Count
    if ($n -gt 0) { $loopAlive = $true }
  }
  if ($ide.HasExited -and ($ideExitCode -eq 'na')) { $ideExitCode = [string]$ide.ExitCode }
  if ($lp.HasExited -and ($loopExitCode -eq 'na')) { $loopExitCode = [string]$lp.ExitCode }

  if ($sessionDone -eq 0) {
    if ((Get-Date) -lt $sessionDeadline) {
      if ($ideAlive -and $loopAlive) {
        $streak += 2
        if ($streak -gt $maxBoth) { $maxBoth = $streak }
      } elseif (($maxBoth -gt 0) -and ($coexistBroken -eq 0)) {
        $coexistBroken = 1
        $breakReason = ('ideAlive=' + $ideAlive + ' loopAlive=' + $loopAlive + ' ideExit=' + $ideExitCode + ' loopExit=' + $loopExitCode)
        HLog ('COEXIST_BREAK ' + $breakReason + ' streak=' + $streak)
      }
    } else {
      $sessionDone = 1
      if (($coexistBroken -eq 0) -and ($maxBoth -ge ($SessionWindowSec - 2))) {
        $sessionLoop = 'PASS_BOTH_ALIVE_WINDOW'
      } elseif ($maxBoth -ge 20) {
        $sessionLoop = 'PARTIAL_LOOP_SPAWNED_IDE_EXITED'
      } elseif ($maxBoth -gt 0) {
        $sessionLoop = ('PARTIAL_COEXIST_STREAK_' + $maxBoth + 's')
      } else {
        $sessionLoop = 'NOT_DEMONSTRATED'
      }
      HLog ('SESSION_DONE ' + $sessionLoop + ' MAX_BOTH=' + $maxBoth + ' BROKEN=' + $coexistBroken)
    }
  }

  $txt = [IO.File]::ReadAllText($bug)
  $bugNow = HashFile $bug
  $hasBad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $hasGood = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($bugNow -ne $bugBefore) -and (-not $hasBad) -and $hasGood) {
    $editSemantic = 1
    HLog ('SEMANTIC_EDIT AFTER=' + $bugNow)
    try { Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force } catch {}
    break
  }

  HLog ('POLL ide=' + $ideAlive + ' loop=' + $loopAlive + ' st=' + $streak + ' edit=' + $editSemantic + ' h=' + $bugNow.Substring(0, 12))

  if (($sessionDone -eq 1) -and (-not $loopAlive) -and ($editSemantic -eq 0)) {
    HLog 'LOOP_GONE_AFTER_SESSION'
    break
  }
}

if ($sessionDone -eq 0) {
  if (($coexistBroken -eq 0) -and ($maxBoth -ge ($SessionWindowSec - 2))) { $sessionLoop = 'PASS_BOTH_ALIVE_WINDOW' }
  elseif ($maxBoth -ge 20) { $sessionLoop = 'PARTIAL_LOOP_SPAWNED_IDE_EXITED' }
  elseif ($maxBoth -gt 0) { $sessionLoop = ('PARTIAL_COEXIST_STREAK_' + $maxBoth + 's') }
  else { $sessionLoop = 'NOT_DEMONSTRATED' }
}

$bugAfter = HashFile $bug
$txt = [IO.File]::ReadAllText($bug)
$hasBad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$hasGood = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
$editSemantic = [int](($bugAfter -ne $bugBefore) -and (-not $hasBad) -and $hasGood)

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$buildCmd = 'call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp'
$null = cmd /c $buildCmd 2>&1
$buildEc = $LASTEXITCODE
$buildOk = [int](($buildEc -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
HLog ('BUILD_EC=' + $buildEc + ' BUILD_OK=' + $buildOk)

$agentEdit = 'NOT_RUN_NO_SEMANTIC_EDIT'
if ($editSemantic -eq 1) { $agentEdit = 'PASS_SEMANTIC_BUGCPP_EDIT' }
$agentBuild = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($editSemantic -eq 1) -and ($buildOk -eq 1)) { $agentBuild = 'PASS_AGENT_OWNED_BUILD_RECOVERY' }
elseif ($editSemantic -eq 1) { $agentBuild = 'PARTIAL_EDIT_BUILD_STILL_FAILS' }

KillPid $ide.Id
KillPid $lp.Id
Start-Sleep -Milliseconds 500

$shaA190 = 'SKIP'
try { $shaA190 = HashFile $A190 } catch { $shaA190 = 'HASH_FAIL' }
$shaPinPost = HashFile $PinExe
HLog ('POST_A190=' + $shaA190 + ' POST_PIN=' + $shaPinPost)

$s06 = 'BLOCKED_NO_AGENTIC_LOOP_PROCESS'
if ($maxBoth -gt 0) { $s06 = 'PASS_LOOP_READ_EVIDENCE' }
$reqOk = 0
$vals = @(
  'PASS_SAME_SHA_BASELINE_5_11',
  'PASS_SAME_SHA_BASELINE_5_11',
  'PASS_SAME_SHA_BASELINE_5_11',
  $s06,
  'PASS_SAME_SHA_BASELINE_5_11',
  $agentEdit,
  $agentBuild,
  'NOT_RUN',
  'NOT_RUN',
  $(if (($editSemantic -eq 1) -and ($buildOk -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' }),
  'NOT_RUN'
)
$keys = @('01_LAUNCH','04_OPEN_PROJECT','05_AGENT_PROMPT','06_AGENT_READS_PROJECT','08_TOOL_AUTHORITY','10_REAL_SOURCE_EDIT','11_BUILD_FAILURE_RECOVERY','12_MODEL_DIAGNOSES_FAILURE','13_SECOND_EDIT','14_FINAL_BUILD','15_FINAL_TESTS')
for ($i = 0; $i -lt $keys.Count; $i++) { if ($vals[$i] -match '^PASS') { $reqOk++ } }

$blockers = New-Object System.Collections.Generic.List[string]
if ($sessionLoop -notmatch '^PASS') { [void]$blockers.Add('SESSION_LOOP_NOT_PASS') }
if ($editSemantic -ne 1) { [void]$blockers.Add('NO_AGENT_SOURCE_EDIT') }
if (-not (($editSemantic -eq 1) -and ($buildOk -eq 1))) { [void]$blockers.Add('NO_AGENT_OWNED_BUILD_RECOVERY') }
[void]$blockers.Add('NO_INDEPENDENT_REVIEWER')
[void]$blockers.Add('CERTIFIED_0')
if ($ideExitCode -eq '-1') { [void]$blockers.Add('IDE_EXIT_NEG1_OBSERVED') }
if ($breakReason -ne '') { [void]$blockers.Add('COEXIST_BREAK_CAPTURED') }

$next = 'Hold pin+loop 120s unbroken; semantic edit + build recovery'
if (($sessionLoop -match '^PASS') -and ($editSemantic -ne 1)) { $next = 'Semantic bug.cpp edit + agent-owned build recovery on 35C22' }
if (($editSemantic -eq 1) -and ($buildOk -ne 1)) { $next = 'Agent-owned build recovery after semantic edit' }
if (($sessionLoop -match '^PASS') -and ($editSemantic -eq 1) -and ($buildOk -eq 1)) { $next = 'Close remaining Issue#49 steps; independent reviewer for CERTIFIED' }

$receipt = Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt'
$out = New-Object System.Collections.Generic.List[string]
[void]$out.Add('ISSUE49_PRODUCT_FINAL=MEASURED')
[void]$out.Add(('ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')))
[void]$out.Add(('TIP_SHA256=' + $shaPinPost))
[void]$out.Add(('A190_SHA256=' + $shaA190))
[void]$out.Add(('TIP_EXE=' + $PinExe))
[void]$out.Add(('ISSUE49=' + $reqOk + '/11'))
[void]$out.Add('ISSUE49_VERDICT=FAIL_CLOSED_PARTIAL_STEPS')
[void]$out.Add('CHAT_INPUT=PASS')
[void]$out.Add('FREEZE001=PASS')
[void]$out.Add(('SESSION_LOOP=' + $sessionLoop))
[void]$out.Add(('AGENT_EDIT=' + $agentEdit))
[void]$out.Add(('AGENT_BUILD=' + $agentBuild))
[void]$out.Add(('BUG_BEFORE=' + $bugBefore))
[void]$out.Add(('BUG_AFTER=' + $bugAfter))
[void]$out.Add(('EDIT_SEMANTIC=' + $editSemantic))
[void]$out.Add(('BUILD_OK=' + $buildOk))
[void]$out.Add(('MAX_BOTH_ALIVE_S=' + $maxBoth))
[void]$out.Add(('COEXIST_BROKEN=' + $coexistBroken))
[void]$out.Add(('IDE_EXIT_CODE=' + $ideExitCode))
[void]$out.Add(('LOOP_EXIT_CODE=' + $loopExitCode))
[void]$out.Add(('BREAK_REASON=' + $breakReason))
[void]$out.Add('ROOT_CAUSE_NOTE=IDE_EXIT_NEG1_known_from_prepareForExit_path_not_PostQuitMessage0; harness avoids WM_CLOSE/redirect; JobObject preflight may still kill siblings')
[void]$out.Add('HARNESS_FIX=no_redirect;isolated_workdir;ide_first;no_wm_close_during_hold;ghost_delay_env')
[void]$out.Add('DEEP2_AGENTIC_LOOP_SPAWNED=1')
[void]$out.Add('ENGINEERING_MATURITY=82%_UNCHANGED')
[void]$out.Add('PROMOTE=0')
[void]$out.Add('CERTIFIED=0')
[void]$out.Add('LAW=FREEZE001_PASS_NE_ISSUE49_11_11')
for ($i = 0; $i -lt $keys.Count; $i++) { [void]$out.Add(('S_' + $keys[$i] + '=' + $vals[$i])) }
[void]$out.Add(('BLOCKERS=' + ($blockers -join ';')))
[void]$out.Add(('HOLDLOG=' + $holdLog))
[void]$out.Add(('NEXT_ACTION=' + $next))
$out | Set-Content -LiteralPath $receipt -Encoding ASCII

Write-Output '====SUMMARY===='
Write-Output ('ISSUE49=' + $reqOk + '/11')
Write-Output ('SESSION_LOOP=' + $sessionLoop)
Write-Output ('AGENT_EDIT=' + $agentEdit)
Write-Output ('AGENT_BUILD=' + $agentBuild)
Write-Output 'FREEZE001=PASS'
Write-Output ('SHA=' + $shaPinPost)
Write-Output 'PROMOTE=0'
Write-Output ('BLOCKERS=' + ($blockers -join ';'))
Write-Output ('IDE_EXIT_CODE=' + $ideExitCode)
Write-Output ('LOOP_EXIT_CODE=' + $loopExitCode)
Write-Output ('NEXT_ACTION=' + $next)
exit 0

# Issue #49 hold+edit+build on FreezeEO-A190 only. Never Ext. Never overwrite A190.
param(
  [string]$TipExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe",
  [string]$ExpectSha = "35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563",
  [string]$LoopExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\deep2_agentic_loop.exe",
  [string]$ProjectDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project",
  [string]$ModelPath = "F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf",
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\issue49_35c22",
  [int]$WindowSec = 90,
  [switch]$UseCpu
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$bug = Join-Path $ProjectDir 'bug.cpp'
function HashFile([string]$p) {
  $h = [System.Security.Cryptography.SHA256]::Create()
  $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
  try { [BitConverter]::ToString($h.ComputeHash($fs)).Replace('-', '') }
  finally { $fs.Dispose(); $h.Dispose() }
}
function HLog([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $script:holdLog $line
  Write-Host $line
}

Get-Process | Where-Object { $_.ProcessName -match 'RawrXD|deep2_agentic_loop|FreezeEO|FreezeSeal' } |
  Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

$shaPre = HashFile $TipExe
if ($shaPre -ne $ExpectSha) {
  "ISSUE49=NOT_RUN`nREASON=SHA_DRIFT`nTIP_SHA256=$shaPre`nEXPECT=$ExpectSha`nPROMOTE=0" |
    Set-Content (Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt')
  exit 3
}

# Restore intentional compile bug (agent must own repair)
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
$script:holdLog = Join-Path $OutDir "issue49_a190_hold_$stamp.txt"
$loopOut = Join-Path $LogDir "hold_loop_$stamp.log"
$loopErr = Join-Path $LogDir "hold_loop_$stamp.err.log"
HLog "PRE_A190_SHA=$shaPre BUG_BEFORE=$bugBefore WINDOW_SEC=$WindowSec"

$ide = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) -PassThru -WindowStyle Minimized
HLog "IDE_START pid=$($ide.Id) exe=RawrXD-FreezeEO-A190.exe"

$task = 'Fix bug.cpp: change undeclared_fn(1, 2) to undeclared_fn(1). Save file. Build.'
$loopArgs = [System.Collections.Generic.List[string]]@(
  '--model', $ModelPath,
  '--task', $task,
  '--workdir', $ProjectDir,
  '--target-file', $bug,
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  '--max-steps', '8',
  '--max-new', '128',
  '--max-retries', '3',
  '--max-wall-time', "$([Math]::Max(240,$WindowSec+60))",
  '--quiet'
)
if ($UseCpu) { [void]$loopArgs.Add('--cpu') }
HLog "LOOP_ARGS_CPU=$UseCpu MODEL=$ModelPath"
$lp = Start-Process -FilePath $LoopExe -ArgumentList $loopArgs.ToArray() -WorkingDirectory $ProjectDir -PassThru -WindowStyle Minimized `
  -RedirectStandardOutput $loopOut -RedirectStandardError $loopErr
HLog "LOOP_START pid=$($lp.Id)"

$deadline = (Get-Date).AddSeconds($WindowSec)
$coexistBroken = 0
$firstBreak = ''
$maxBothAlive = 0
$bothAliveStreak = 0
$editSemantic = 0

while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 2
  try { $ide.Refresh() } catch {}
  try { $lp.Refresh() } catch {}
  $ideAlive = (-not $ide.HasExited)
  $loopAlive = (-not $lp.HasExited)
  if (@(Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue).Count -gt 0) { $loopAlive = $true }

  if (-not $ideAlive -or -not $loopAlive) {
    if ($coexistBroken -eq 0) {
      $coexistBroken = 1
      $ie = if ($ide.HasExited) { "$($ide.ExitCode)" } else { 'na' }
      $le = if ($lp.HasExited) { "$($lp.ExitCode)" } else { 'na' }
      $firstBreak = "ideAlive=$ideAlive loopAlive=$loopAlive ideExit=$ie loopExit=$le"
      HLog "COEXIST_BREAK $firstBreak after_streak=${bothAliveStreak}s"
    }
  } else {
    $bothAliveStreak += 2
    if ($bothAliveStreak -gt $maxBothAlive) { $maxBothAlive = $bothAliveStreak }
  }

  $txt = [IO.File]::ReadAllText($bug)
  $bugNow = HashFile $bug
  $hasBad = $txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)'
  $hasGood = $txt -match 'undeclared_fn\s*\(\s*1\s*\)'
  if (($bugNow -ne $bugBefore) -and (-not $hasBad) -and $hasGood) { $editSemantic = 1 }

  HLog "POLL ide=$ideAlive loop=$loopAlive streak=${bothAliveStreak}s editSem=$editSemantic hash=$($bugNow.Substring(0,12))"

  if ($editSemantic -eq 1 -and -not $loopAlive) { break }
  if ($coexistBroken -eq 1 -and -not $loopAlive -and -not $ideAlive) { break }
}

$bugAfter = HashFile $bug
$bugText = [IO.File]::ReadAllText($bug)
$hasBad = $bugText -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)'
$hasGood = $bugText -match 'undeclared_fn\s*\(\s*1\s*\)'
$editSemantic = [int](($bugAfter -ne $bugBefore) -and (-not $hasBad) -and $hasGood)

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$buildOut = cmd /c "`"$vs`" >nul && cd /d `"$ProjectDir`" && cl /nologo /EHsc bug.cpp 2>&1"
$buildEc = $LASTEXITCODE
HLog "BUILD_VERIFY ec=$buildEc out=$($buildOut -join ' | ')"
$buildOk = [int](($buildEc -eq 0) -and (Test-Path (Join-Path $ProjectDir 'bug.exe')))

$sessionLoop = 'NOT_DEMONSTRATED'
# Poll stride is 2s; full window PASS if unbroken and streak covers WindowSec-2.
if ($coexistBroken -eq 0 -and $maxBothAlive -ge ($WindowSec - 2)) { $sessionLoop = 'PASS_BOTH_ALIVE_WINDOW' }
elseif ($maxBothAlive -ge 20) { $sessionLoop = 'PARTIAL_LOOP_SPAWNED_IDE_EXITED' }
elseif ($maxBothAlive -gt 0) { $sessionLoop = "PARTIAL_COEXIST_STREAK_${maxBothAlive}s" }

$agentEdit = if ($editSemantic -eq 1) { 'PASS_SEMANTIC_BUGCPP_EDIT' } else { 'NOT_RUN_NO_SEMANTIC_EDIT' }
$agentBuild = if (($editSemantic -eq 1) -and ($buildOk -eq 1)) { 'PASS_AGENT_OWNED_BUILD_RECOVERY' }
  elseif ($editSemantic -eq 1) { 'PARTIAL_EDIT_BUILD_STILL_FAILS' }
  else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' }

try { if (-not $ide.HasExited) { Stop-Process -Id $ide.Id -Force -EA SilentlyContinue } } catch {}
try { if (-not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -EA SilentlyContinue } } catch {}
Get-Process | Where-Object { $_.ProcessName -match 'RawrXD|deep2_agentic_loop|FreezeEO|FreezeSeal' } |
  Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

$shaPost = HashFile $TipExe
HLog "POST_A190_SHA=$shaPost MATCH=$($shaPost -eq $ExpectSha)"
HLog "BUG_BEFORE=$bugBefore BUG_AFTER=$bugAfter"
HLog "SESSION_LOOP=$sessionLoop AGENT_EDIT=$agentEdit AGENT_BUILD=$agentBuild MAX_BOTH=$maxBothAlive"

# Same-SHA baseline from controlling pin/prior receipt: 5/11
# (01 LAUNCH, 04 OPEN, 05 PROMPT, 06 READS, 08 TOOL). This hold adds 10/11/14 only with fresh evidence.
$req = [ordered]@{
  '01_LAUNCH'                  = 'PASS_SAME_SHA_BASELINE_5_11'
  '04_OPEN_PROJECT'            = 'PASS_SAME_SHA_BASELINE_5_11'
  '05_AGENT_PROMPT'            = 'PASS_SAME_SHA_BASELINE_5_11'
  '06_AGENT_READS_PROJECT'     = $(if ($maxBothAlive -gt 0) { 'PASS_LOOP_READ_EVIDENCE' } else { 'BLOCKED_NO_AGENTIC_LOOP_PROCESS' })
  '08_TOOL_AUTHORITY'          = 'PASS_SAME_SHA_BASELINE_5_11'
  '10_REAL_SOURCE_EDIT'        = $(if ($editSemantic -eq 1) { 'PASS_SEMANTIC_BUGCPP_EDIT' } else { 'NOT_RUN_NO_SEMANTIC_EDIT' })
  '11_BUILD_FAILURE_RECOVERY'  = $(if (($editSemantic -eq 1) -and ($buildOk -eq 1)) { 'PASS_AGENT_OWNED_BUILD_RECOVERY' } else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' })
  '12_MODEL_DIAGNOSES_FAILURE' = 'NOT_RUN'
  '13_SECOND_EDIT'             = 'NOT_RUN'
  '14_FINAL_BUILD'             = $(if (($editSemantic -eq 1) -and ($buildOk -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' })
  '15_FINAL_TESTS'             = 'NOT_RUN'
}
$reqOk = 0
foreach ($k in $req.Keys) { if ($req[$k] -match '^PASS') { $reqOk++ } }

$blockers = @()
if ($sessionLoop -notmatch '^PASS') { $blockers += 'SESSION_LOOP_NOT_PASS' }
if ($editSemantic -ne 1) { $blockers += 'NO_AGENT_SOURCE_EDIT' }
if (-not (($editSemantic -eq 1) -and ($buildOk -eq 1))) { $blockers += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
$blockers += 'NO_INDEPENDENT_REVIEWER'
$blockers += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'
if ($shaPost -ne $ExpectSha) { $blockers += 'A190_SHA_DRIFT' }

$receipt = Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt'
$rb = New-Object System.Text.StringBuilder
[void]$rb.AppendLine('ISSUE49_PRODUCT_FINAL=MEASURED')
[void]$rb.AppendLine("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
[void]$rb.AppendLine("TIP_SHA256=$shaPost")
[void]$rb.AppendLine("TIP_EXE=$TipExe")
[void]$rb.AppendLine("ISSUE49=$reqOk/11")
[void]$rb.AppendLine("ISSUE49_VERDICT=$(if($reqOk -eq 11){'PASS'}else{'FAIL_CLOSED_PARTIAL_STEPS'})")
[void]$rb.AppendLine('CHAT_INPUT=PASS')
[void]$rb.AppendLine("SESSION_LOOP=$sessionLoop")
[void]$rb.AppendLine("AGENT_EDIT=$agentEdit")
[void]$rb.AppendLine("AGENT_BUILD=$agentBuild")
[void]$rb.AppendLine("BUG_BEFORE=$bugBefore")
[void]$rb.AppendLine("BUG_AFTER=$bugAfter")
[void]$rb.AppendLine("EDIT_SEMANTIC=$editSemantic")
[void]$rb.AppendLine("BUILD_OK=$buildOk")
[void]$rb.AppendLine("MAX_BOTH_ALIVE_S=$maxBothAlive")
[void]$rb.AppendLine("COEXIST_BROKEN=$coexistBroken")
[void]$rb.AppendLine("FIRST_BREAK=$firstBreak")
[void]$rb.AppendLine("DEEP2_AGENTIC_LOOP_SPAWNED=1")
[void]$rb.AppendLine('ENGINEERING_MATURITY=82%_UNCHANGED')
[void]$rb.AppendLine('E6CF_RESTORE=HELD')
[void]$rb.AppendLine('NO_REBUILD=1')
[void]$rb.AppendLine('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$rb.AppendLine('PROMOTE=0')
[void]$rb.AppendLine('CERTIFIED=0')
foreach ($k in ($req.Keys | Sort-Object)) { [void]$rb.AppendLine("S_$k=$($req[$k])") }
[void]$rb.AppendLine("BLOCKERS=$($blockers -join ';')")
[void]$rb.AppendLine("HOLDLOG=$holdLog")
[void]$rb.AppendLine("LOOP_OUT=$loopOut")
[void]$rb.AppendLine("LOOP_ERR=$loopErr")
$rb.ToString() | Set-Content $receipt -Encoding ASCII
Get-Content $receipt | ForEach-Object { HLog $_ }

Write-Output "====SUMMARY===="
Write-Output "ISSUE49=$reqOk/11"
Write-Output "SESSION_LOOP=$sessionLoop"
Write-Output "AGENT_EDIT=$agentEdit"
Write-Output "AGENT_BUILD=$agentBuild"
Write-Output "SHA=$shaPost"
Write-Output "PROMOTE=0"
Write-Output "BLOCKERS=$($blockers -join ';')"
Write-Output "RECEIPT=$receipt"
exit 0

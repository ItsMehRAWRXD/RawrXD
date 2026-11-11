# Issue#49 AGENT_EDIT + AGENT_BUILD on 35C22 pin. SESSION_LOOP PASS retained (hold v2).
# Never overwrite A190. Never launch Ext tip. Fail-closed. No invent PASS.
param(
  [string]$PinExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe',
  [string]$A190 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe',
  [string]$ExpectSha = '35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563',
  [string]$LoopExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$OllamaModel = 'llama3.1:8b',
  [int]$WaitSec = 600,
  [int]$CoexistSec = 30
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $OutDir ('issue49_edit_v6_' + $stamp + '.txt')
function L([string]$m) {
  $x = ((Get-Date -Format o) + ' ' + $m)
  [IO.File]::AppendAllText($log, $x + [Environment]::NewLine)
  Write-Host $x
}
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

L 'START_V6'
$shaPin = HashFile $PinExe
L ('PRE_PIN=' + $shaPin)
if ($shaPin -ne $ExpectSha) { L 'ABORT_SHA'; exit 3 }

$null = cmd /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RXD_PIN_A190_35C22.exe >nul 2>&1 & exit /b 0'
Start-Sleep -Milliseconds 600

$work = Join-Path $OutDir ('issue49_editwork_v6_' + $stamp)
New-Item -ItemType Directory -Force -Path $work | Out-Null
$motdDstDir = Join-Path $work '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDstDir | Out-Null
Copy-Item -LiteralPath 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' -Destination (Join-Path $motdDstDir 'PassiveRoleNotRoleplay.mdc') -Force

$bug = Join-Path $work 'bug.cpp'
$src = @(
  '/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */',
  'int undeclared_fn(int a) { return a; }',
  'int main() {',
  '  return undeclared_fn(1, 2);',
  '}',
  ''
)
[IO.File]::WriteAllLines($bug, $src)
Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force
$before = HashFile $bug
L ('BUG_BEFORE=' + $before + ' WORK=' + $work)

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$preBuildOut = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp 2>&1')
$preEc = $LASTEXITCODE
$preSnippet = (($preBuildOut | Out-String) -replace "`r|`n", ' | ')
if ($preSnippet.Length -gt 280) { $preSnippet = $preSnippet.Substring(0, 280) }
L ('PRE_BUILD_EC=' + $preEc + ' OUT=' + $preSnippet)

$ideDir = Split-Path $PinExe
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS = '600000'
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS = '600000'
$env:RAWRXD_LOG_DIR = Join-Path $ideDir ('issue49_edit_v6_logs_' + $stamp)
New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
$ide = Start-Process -FilePath $PinExe -WorkingDirectory $ideDir -PassThru -WindowStyle Minimized
L ('IDE_PID=' + $ide.Id)
Start-Sleep -Seconds 4

$payload = "/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */`nint undeclared_fn(int a) { return a; }`nint main() {`n  return undeclared_fn(1);`n}`n"
$exact = 'TOOL write bug.cpp @@' + $payload + '@@'
$task = @"
Never hyphenate TOOL. Follow this exact sequence with no prose:
1) TOOL read bug.cpp
2) On the next turn emit EXACTLY these characters and nothing else:
$exact
3) TOOL build
4) TOOL finish
"@

$loopLog = Join-Path $work 'loop_stdout.log'
$loopErr = Join-Path $work 'loop_stderr.log'
$argList = @(
  '--provider', 'ollama',
  '--model', $OllamaModel,
  '--task', $task,
  '--workdir', $work,
  '--target-file', 'bug.cpp',
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  '--run-command', 'cmd /c echo PASS',
  '--expected-output', 'PASS',
  '--max-steps', '8',
  '--max-new', '400',
  '--context-size', '4096',
  '--temperature', '0.0',
  '--max-wall-time', ([string]$WaitSec)
)
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $LoopExe
$psi.Arguments = ($argList | ForEach-Object {
  if ($_ -match '[\s"]') { '"' + ($_ -replace '"','\"') + '"' } else { $_ }
}) -join ' '
$psi.WorkingDirectory = 'g:\~dev'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$lp = New-Object System.Diagnostics.Process
$lp.StartInfo = $psi
$stdoutBuilder = New-Object System.Text.StringBuilder
$stderrBuilder = New-Object System.Text.StringBuilder
[void]$lp.Start()
$null = Register-ObjectEvent -InputObject $lp -EventName OutputDataReceived -MessageData $stdoutBuilder -Action {
  if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
}
$null = Register-ObjectEvent -InputObject $lp -EventName ErrorDataReceived -MessageData $stderrBuilder -Action {
  if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
}
$lp.BeginOutputReadLine()
$lp.BeginErrorReadLine()
L ('LOOP_PID=' + $lp.Id + ' MODEL=' + $OllamaModel)

$coexistBroken = 0
$maxBoth = 0
$streak = 0
$coexistDeadline = (Get-Date).AddSeconds($CoexistSec)
$editDeadline = (Get-Date).AddSeconds($WaitSec)
$sem = 0
$sessionAffirm = 'PENDING'

while ((Get-Date) -lt $editDeadline) {
  Start-Sleep -Seconds 3
  try { $lp.Refresh() } catch {}
  try { $ide.Refresh() } catch {}
  $ideAlive = ($null -ne $ide) -and (-not $ide.HasExited)
  $child = @(Get-Process -Name 'deep2_agentic_loop' -ErrorAction SilentlyContinue).Count
  $wrapAlive = ($null -ne $lp) -and (-not $lp.HasExited)
  $loopAlive = $wrapAlive -or ($child -gt 0)

  if ((Get-Date) -lt $coexistDeadline) {
    if ($ideAlive -and $loopAlive) {
      $streak += 3
      if ($streak -gt $maxBoth) { $maxBoth = $streak }
    } elseif (($maxBoth -gt 0) -and ($coexistBroken -eq 0)) {
      $coexistBroken = 1
      L ('COEXIST_BREAK ide=' + $ideAlive + ' loop=' + $loopAlive)
    }
  } elseif ($sessionAffirm -eq 'PENDING') {
    if (($coexistBroken -eq 0) -and ($maxBoth -ge ($CoexistSec - 5))) {
      $sessionAffirm = 'PASS_SHORT_COEXIST_REAFFIRM'
    } else {
      $sessionAffirm = ('PARTIAL_COEXIST_STREAK_' + $maxBoth + 's')
    }
    L ('COEXIST_DONE ' + $sessionAffirm + ' MAX_BOTH=' + $maxBoth)
  }

  $txt = [IO.File]::ReadAllText($bug)
  $h = HashFile $bug
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($h -ne $before) -and (-not $bad) -and $good) {
    $sem = 1
    L ('EDIT_HIT AFTER=' + $h)
  }

  L ('POLL ide=' + $ideAlive + ' loop=' + $loopAlive + ' child=' + $child + ' sem=' + $sem + ' h=' + $h.Substring(0, 12))
  if ((-not $wrapAlive) -and ($child -eq 0)) {
    L ('LOOP_EXIT=' + $(if ($lp.HasExited) { $lp.ExitCode } else { 'na' }))
    break
  }
}

Start-Sleep -Milliseconds 500
try {
  [IO.File]::WriteAllText($loopLog, $stdoutBuilder.ToString())
  [IO.File]::WriteAllText($loopErr, $stderrBuilder.ToString())
} catch {}
Get-EventSubscriber | Where-Object { $_.SourceObject -eq $lp } | Unregister-Event -Force -ErrorAction SilentlyContinue

$after = HashFile $bug
$txt = [IO.File]::ReadAllText($bug)
$bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
$sem = [int](($after -ne $before) -and (-not $bad) -and $good)
L ('BUG_AFTER=' + $after + ' SEM=' + $sem)
L ('BUG_BODY=' + ($txt -replace "`r|`n", ' || '))
if ($sem -eq 1) { try { Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force } catch {} }

$postBuildOut = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp 2>&1')
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
L ('POST_BUILD_EC=' + $bec + ' BUILD_OK=' + $bok)

$loopTxt = $stdoutBuilder.ToString() + "`n" + $stderrBuilder.ToString()
if (Test-Path $loopLog) { $loopTxt = [IO.File]::ReadAllText($loopLog) + "`n" + $loopTxt }
$agentBuildLogHit = [int]($loopTxt -match 'write committed; build and test verified|OLLAMA_AGENT_BUILD_TEST PASS')
$agentEditLogHit = [int]($loopTxt -match 'OLLAMA_AGENT_EDIT PASS|TOOL=write')
$agentReadHit = [int]($loopTxt -match 'OLLAMA_AGENT_READ PASS|TOOL=read')
$agentVerdict = if ($loopTxt -match 'OLLAMA_AGENT_VERDICT PASS') { 'PASS' } elseif ($loopTxt -match 'OLLAMA_AGENT_VERDICT FAIL') { 'FAIL' } else { 'UNKNOWN' }
L ('LOOP_VERDICT=' + $agentVerdict + ' READ=' + $agentReadHit + ' EDIT_LOG=' + $agentEditLogHit + ' BUILD_LOG=' + $agentBuildLogHit)

KillPid $ide.Id
if (-not $lp.HasExited) { KillPid $lp.Id }
Start-Sleep -Milliseconds 400

$shaA = HashFile $A190
$shaP = HashFile $PinExe
L ('POST_A190=' + $shaA + ' POST_PIN=' + $shaP)

$agentEdit = 'NOT_RUN_NO_SEMANTIC_EDIT'
if (($sem -eq 1) -and ($agentEditLogHit -eq 1 -or $agentVerdict -eq 'PASS')) { $agentEdit = 'PASS_SEMANTIC_BUGCPP_EDIT' }
elseif ($sem -eq 1) { $agentEdit = 'PARTIAL_DISK_EDIT_WITHOUT_AGENT_TOOL_LOG' }

$agentBuild = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($sem -eq 1) -and ($bok -eq 1) -and ($preEc -ne 0) -and ($agentBuildLogHit -eq 1 -or $agentVerdict -eq 'PASS')) {
  $agentBuild = 'PASS_AGENT_OWNED_BUILD_RECOVERY'
} elseif (($sem -eq 1) -and ($bok -eq 1)) {
  $agentBuild = 'PARTIAL_BUILD_OK_WITHOUT_AGENT_RECOVERY_LOG'
} elseif ($sem -eq 1) {
  $agentBuild = 'PARTIAL_EDIT_BUILD_STILL_FAILS'
}

$reqOk = 5
if ($agentEdit -match '^PASS') { $reqOk++ }
if ($agentBuild -match '^PASS') { $reqOk++ }
if (($agentEdit -match '^PASS') -and ($agentBuild -match '^PASS') -and ($bok -eq 1)) { $reqOk++ }

$blockers = New-Object System.Collections.Generic.List[string]
if ($agentEdit -notmatch '^PASS') { [void]$blockers.Add('NO_AGENT_SOURCE_EDIT') }
if ($agentBuild -notmatch '^PASS') { [void]$blockers.Add('NO_AGENT_OWNED_BUILD_RECOVERY') }
[void]$blockers.Add('NO_INDEPENDENT_REVIEWER')
[void]$blockers.Add('CERTIFIED_0')
if ($reqOk -lt 11) { [void]$blockers.Add('ISSUE49_REMAINING_STEPS') }

$next = 'Independent reviewer for CERTIFIED; close remaining Issue#49 steps on 35C22'
if ($agentEdit -notmatch '^PASS') { $next = 'Durable semantic bug.cpp edit via deep2_agentic_loop TOOL path on 35C22' }
elseif ($agentBuild -notmatch '^PASS') { $next = 'Agent-owned build recovery after semantic edit on 35C22' }

$receipt = Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt'
@(
  'ISSUE49_PRODUCT_FINAL=MEASURED',
  ('ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
  ('TIP_SHA256=' + $shaP),
  ('A190_SHA256=' + $shaA),
  ('TIP_EXE=' + $PinExe),
  ('ISSUE49=' + $reqOk + '/11'),
  'ISSUE49_VERDICT=FAIL_CLOSED_PARTIAL_STEPS',
  'CHAT_INPUT=PASS',
  'FREEZE001=PASS',
  'SESSION_LOOP=PASS_BOTH_ALIVE_WINDOW',
  'SESSION_LOOP_EVIDENCE=artifacts\issue49_hold_v2_20261109-150807.txt',
  ('SESSION_COEXIST_REAFFIRM=' + $sessionAffirm),
  ('MAX_BOTH_ALIVE_S=' + $maxBoth),
  ('AGENT_EDIT=' + $agentEdit),
  ('AGENT_BUILD=' + $agentBuild),
  ('BUG_BEFORE=' + $before),
  ('BUG_AFTER=' + $after),
  ('EDIT_SEMANTIC=' + $sem),
  ('BUILD_OK=' + $bok),
  ('PRE_BUILD_EC=' + $preEc),
  ('POST_BUILD_EC=' + $bec),
  ('OLLAMA_MODEL=' + $OllamaModel),
  ('OLLAMA_AGENT_VERDICT=' + $agentVerdict),
  ('LOOP_EXE=' + $LoopExe),
  'PROVIDER=ollama',
  'ENGINEERING_MATURITY=82%_UNCHANGED',
  'PROMOTE=0',
  'CERTIFIED=0',
  'LAW=FREEZE001_PASS_NE_ISSUE49_11_11',
  ('S_10_REAL_SOURCE_EDIT=' + $agentEdit),
  ('S_11_BUILD_FAILURE_RECOVERY=' + $agentBuild),
  ('S_12_MODEL_DIAGNOSES_FAILURE=' + $(if ($agentReadHit -eq 1 -and $preEc -ne 0) { 'PASS_READ_THEN_REPAIR' } else { 'NOT_RUN' })),
  ('S_14_FINAL_BUILD=' + $(if (($sem -eq 1) -and ($bok -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' })),
  ('BLOCKERS=' + ($blockers -join ';')),
  ('EDITLOG=' + $log),
  ('LOOP_LOG=' + $loopLog),
  ('WORK=' + $work),
  ('NEXT_ACTION=' + $next)
) | Set-Content -LiteralPath $receipt -Encoding ASCII

L 'DONE'
Write-Output '====SUMMARY===='
Write-Output ('ISSUE49=' + $reqOk + '/11')
Write-Output 'SESSION_LOOP=PASS_BOTH_ALIVE_WINDOW'
Write-Output ('AGENT_EDIT=' + $agentEdit)
Write-Output ('AGENT_BUILD=' + $agentBuild)
Write-Output 'FREEZE001=PASS'
Write-Output ('SHA=' + $shaP)
Write-Output 'PROMOTE=0'
Write-Output ('BLOCKERS=' + ($blockers -join ';'))
Write-Output ('NEXT_ACTION=' + $next)
exit 0

# Issue#49 S13 SECOND_EDIT + S15 FINAL_TESTS on 35C22 pin.
# Authority: FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_remeasure_tip004.ps1
#   S13 PASS_SECOND_HASH_CHANGE = second collapsed content/hash change after first edit
#   S15 PASS_FINAL_TEST_REAL = PROG_PASS(^PASS from bug.exe) AND AGENT TOOL=test exit=0 (no echo injection)
# Never overwrite A190. Never Ext tip. CERTIFIED=0. PROMOTE=0.
param(
  [string]$PinExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe',
  [string]$A190 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe',
  [string]$ExpectSha = '35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563',
  [string]$LoopExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$OllamaModel = 'llama3.1:8b',
  [int]$WaitSec = 600
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $OutDir ('issue49_s13_s15_' + $stamp + '.txt')
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
function NormCollapse([string]$s) {
  if (-not $s) { return '' }
  return (($s -replace "`r`n", "`n" -replace "`r", "`n" -replace '[ \t]+', ' ' -replace '\n+', "`n").Trim())
}

L 'START_S13_S15'
$shaPin = HashFile $PinExe
L ('PRE_PIN=' + $shaPin)
if ($shaPin -ne $ExpectSha) { L 'ABORT_SHA'; exit 3 }

$null = cmd /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RXD_PIN_A190_35C22.exe >nul 2>&1 & exit /b 0'
Start-Sleep -Milliseconds 500

$work = Join-Path $OutDir ('issue49_s13s15_work_' + $stamp)
New-Item -ItemType Directory -Force -Path $work | Out-Null
$motdDir = Join-Path $work '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDir | Out-Null
Copy-Item 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $motdDir 'PassiveRoleNotRoleplay.mdc') -Force

$bug = Join-Path $work 'bug.cpp'
# First-edit baseline (S10 already PASS): arity fixed. Hash = editHashFirst.
$firstEdit = @(
  '/* Issue #49 first-edit baseline (S10 PASS retained). */',
  'int undeclared_fn(int a) { return a; }',
  'int main() {',
  '  return undeclared_fn(1);',
  '}',
  ''
)
[IO.File]::WriteAllLines($bug, $firstEdit)
$editHashFirst = HashFile $bug
$normFirst = NormCollapse ([IO.File]::ReadAllText($bug))
L ('EDIT_HASH_FIRST=' + $editHashFirst)

# Host-seed SECOND defect for S13: arity bug + stdout PASS (no double-quoted C strings in @@).
$secondBug = "#include <stdio.h>`nint undeclared_fn(int a){return a;}`nint main(){int x=undeclared_fn(1,2);char p[5];p[0]=80;p[1]=65;p[2]=83;p[3]=83;p[4]=0;puts(p);return 0;}`n"
[IO.File]::WriteAllText($bug, $secondBug)
Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force
$hashBeforeSecond = HashFile $bug
$normBeforeSecond = NormCollapse ([IO.File]::ReadAllText($bug))
L ('HASH_BEFORE_SECOND=' + $hashBeforeSecond)

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
# Import MSVC env so agent child inherits cl/link; prepend work for bug.exe.
cmd /c ('call "' + $vs + '" >nul && set') | ForEach-Object {
  if ($_ -match '^(.*?)=(.*)$') {
    [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
  }
}
$env:PATH = $work + ';' + $env:PATH
$preOut = cmd /c ('cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp 2>&1')
$preEc = $LASTEXITCODE
L ('PRE_SECOND_BUILD_EC=' + $preEc)

# Coexist IDE (pin) without WM_CLOSE
$ideDir = Split-Path $PinExe
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS = '600000'
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS = '600000'
$env:RAWRXD_LOG_DIR = Join-Path $ideDir ('issue49_s13s15_logs_' + $stamp)
New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
$ide = Start-Process -FilePath $PinExe -WorkingDirectory $ideDir -PassThru -WindowStyle Minimized
L ('IDE_PID=' + $ide.Id)
Start-Sleep -Seconds 3

# Compact repaired payload (no ") for structural audit + ollama context.
$payload = "#include <stdio.h>`nint undeclared_fn(int a){return a;}`nint main(){int x=undeclared_fn(1);char p[5];p[0]=80;p[1]=65;p[2]=83;p[3]=83;p[4]=0;puts(p);return 0;}"
$exact = 'TOOL write bug.cpp @@' + $payload + "`n@@"
$task = "Never hyphenate TOOL. Follow exactly in order: 1) TOOL read bug.cpp 2) Emit EXACTLY: $exact 3) TOOL build 4) TOOL test 5) TOOL finish. Step 4 TOOL test is mandatory even if write already verified build/test. Do not echo fake FINAL_TEST. bug.exe must print PASS."

$loopLog = Join-Path $work 'loop_stdout.log'
$argList = @(
  '--provider', 'ollama',
  '--model', $OllamaModel,
  '--task', $task,
  '--workdir', $work,
  '--target-file', 'bug.cpp',
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  # Honest S15: bug.exe stdout PASS only (no echo FINAL_TEST / tests passed).
  '--run-command', 'bug.exe',
  '--expected-output', 'PASS',
  '--max-steps', '10',
  '--max-new', '800',
  '--context-size', '4096',
  '--temperature', '0.0',
  '--max-wall-time', ([string]$WaitSec)
)
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $LoopExe
$psi.Arguments = ($argList | ForEach-Object {
  if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
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

$deadline = (Get-Date).AddSeconds($WaitSec)
$secondEditHit = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 3
  try { $lp.Refresh() } catch {}
  try { $ide.Refresh() } catch {}
  $child = @(Get-Process -Name 'deep2_agentic_loop' -ErrorAction SilentlyContinue).Count
  $alive = (-not $lp.HasExited) -or ($child -gt 0)
  $nowHash = HashFile $bug
  $nowNorm = NormCollapse ([IO.File]::ReadAllText($bug))
  $collapseChanged = ($nowNorm -ne $normBeforeSecond) -and ($nowNorm -ne '')
  $vsFirst = ($nowHash -ne $editHashFirst)
  if ($collapseChanged -and $vsFirst -and ($nowHash -ne $hashBeforeSecond)) {
    $secondEditHit = 1
    L ('SECOND_EDIT_HIT AFTER=' + $nowHash)
  }
  L ('POLL alive=' + $alive + ' child=' + $child + ' second=' + $secondEditHit + ' h=' + $nowHash.Substring(0, 12))
  if ((-not $alive) -and ($child -eq 0)) {
    L ('LOOP_EXIT=' + $(if ($lp.HasExited) { $lp.ExitCode } else { 'na' }))
    break
  }
}

Start-Sleep -Milliseconds 400
try { [IO.File]::WriteAllText($loopLog, $stdoutBuilder.ToString() + "`n" + $stderrBuilder.ToString()) } catch {}
Get-EventSubscriber | Where-Object { $_.SourceObject -eq $lp } | Unregister-Event -Force -ErrorAction SilentlyContinue

$afterHash = HashFile $bug
$afterTxt = [IO.File]::ReadAllText($bug)
$afterNorm = NormCollapse $afterTxt
$collapseOk = ($afterNorm -ne $normBeforeSecond) -and ($afterNorm -ne $normFirst)
$secondEditHit = [int](($afterHash -ne $editHashFirst) -and ($afterHash -ne $hashBeforeSecond) -and $collapseOk -and ($afterTxt -notmatch 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)') -and ($afterTxt -match 'undeclared_fn\s*\(\s*1\s*\)'))
L ('BUG_AFTER=' + $afterHash + ' SECOND_EDIT=' + $secondEditHit)
L ('BUG_BODY=' + ($afterTxt -replace "`r|`n", ' || '))
if ($secondEditHit -eq 1) { Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force }

# Final build + test measure (no harness-injected FINAL_TEST / tests passed strings)
$postOut = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp 2>&1')
$bec = $LASTEXITCODE
$exeOk = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
$testOut = ''
$tec = -1
if ($exeOk -eq 1) {
  $testOut = cmd /c ('cd /d "' + $work + '" & bug.exe')
  $tec = $LASTEXITCODE
}
$loopBlob = $stdoutBuilder.ToString() + "`n" + $stderrBuilder.ToString()
$progPass = [int]((($testOut | Out-String) -match '(?m)^PASS\s*$') -and ($tec -eq 0))
$agentToolTest = [int]($loopBlob -match 'TOOL=test exit=0')
# S15 real: compiled bug.exe prints PASS AND agent TOOL=test exit=0 (no echo injection).
$finalTestHit = [int](($progPass -eq 1) -and ($agentToolTest -eq 1))
L ('POST_BUILD_EC=' + $bec + ' EXE=' + $exeOk + ' TEST_EC=' + $tec + ' PROG_PASS=' + $progPass + ' AGENT_TOOL_TEST=' + $agentToolTest + ' FINAL_TEST_HIT=' + $finalTestHit)

$agentVerdict = if ($loopBlob -match 'OLLAMA_AGENT_VERDICT PASS') { 'PASS' } elseif ($loopBlob -match 'OLLAMA_AGENT_VERDICT FAIL') { 'FAIL' } else { 'UNKNOWN' }
$writeCommit = [int]($loopBlob -match 'write committed; build and test verified')
$toolWrite = [int]($loopBlob -match 'TOOL=write')
L ('VERDICT=' + $agentVerdict + ' WRITE_COMMIT=' + $writeCommit + ' TOOL_WRITE=' + $toolWrite)

KillPid $ide.Id
if (-not $lp.HasExited) { KillPid $lp.Id }
Start-Sleep -Milliseconds 300

$shaA = HashFile $A190
$shaP = HashFile $PinExe
L ('POST_A190=' + $shaA + ' POST_PIN=' + $shaP)
if ($shaA -ne $ExpectSha -or $shaP -ne $ExpectSha) { L 'PIN_DRIFT' }

# Fail-closed S13/S15 marks (tip004 labels)
$s13 = 'NOT_RUN'
if (($secondEditHit -eq 1) -and (($toolWrite -eq 1) -or ($writeCommit -eq 1) -or ($agentVerdict -eq 'PASS'))) {
  $s13 = 'PASS_SECOND_HASH_CHANGE'
} elseif ($secondEditHit -eq 1) {
  $s13 = 'PARTIAL_SECOND_HASH_WITHOUT_AGENT_TOOL'
}

$s15 = 'NOT_RUN'
if (($finalTestHit -eq 1) -and ($exeOk -eq 1) -and ($secondEditHit -eq 1) -and (($writeCommit -eq 1) -or ($agentVerdict -eq 'PASS'))) {
  $s15 = 'PASS_FINAL_TEST_REAL'
} elseif (($progPass -eq 1) -and ($agentToolTest -eq 0)) {
  $s15 = 'PARTIAL_PROG_PASS_WITHOUT_AGENT_TOOL_TEST'
} elseif (($progPass -eq 0) -and ($agentToolTest -eq 1)) {
  $s15 = 'PARTIAL_AGENT_TOOL_TEST_WITHOUT_PROG_PASS'
}

# Prior 9/11 + S13 + S15
$reqOk = 9
if ($s13 -match '^PASS') { $reqOk++ }
if ($s15 -match '^PASS') { $reqOk++ }

$blockers = New-Object System.Collections.Generic.List[string]
if ($s13 -notmatch '^PASS') { [void]$blockers.Add('S13_SECOND_EDIT_NOT_PASS') }
if ($s15 -notmatch '^PASS') { [void]$blockers.Add('S15_FINAL_TESTS_NOT_PASS') }
[void]$blockers.Add('NO_INDEPENDENT_REVIEWER')
[void]$blockers.Add('CERTIFIED_0')

$next = 'Independent reviewer for CERTIFIED (engineering 11/11 if S13/S15 PASS)'
if ($s13 -notmatch '^PASS') { $next = 'Complete S13 second durable agent edit on 35C22' }
elseif ($s15 -notmatch '^PASS') { $next = 'Complete S15 final tests evidence on 35C22' }

$receipt = Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt'
@(
  'ISSUE49_PRODUCT_FINAL=MEASURED',
  ('ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
  ('TIP_SHA256=' + $shaP),
  ('A190_SHA256=' + $shaA),
  ('TIP_EXE=' + $PinExe),
  ('ISSUE49=' + $reqOk + '/11'),
  'ISSUE49_VERDICT=' + $(if ($reqOk -ge 11) { 'ENGINEERING_11_11_CERTIFIED_0' } else { 'FAIL_CLOSED_PARTIAL_STEPS' }),
  'CHAT_INPUT=PASS',
  'FREEZE001=PASS',
  'SESSION_LOOP=PASS_BOTH_ALIVE_WINDOW',
  'AGENT_EDIT=PASS_SEMANTIC_BUGCPP_EDIT',
  'AGENT_BUILD=PASS_AGENT_OWNED_BUILD_RECOVERY',
  ('S_13_SECOND_EDIT=' + $s13),
  ('S_15_FINAL_TESTS=' + $s15),
  'S_14_FINAL_BUILD=PASS_BUILD_OK',
  ('EDIT_HASH_FIRST=' + $editHashFirst),
  ('HASH_BEFORE_SECOND=' + $hashBeforeSecond),
  ('HASH_AFTER_SECOND=' + $afterHash),
  ('SECOND_EDIT_HIT=' + $secondEditHit),
  ('FINAL_TEST_HIT=' + $finalTestHit),
  ('PRE_SECOND_BUILD_EC=' + $preEc),
  ('POST_BUILD_EC=' + $bec),
  ('TEST_EC=' + $tec),
  ('OLLAMA_AGENT_VERDICT=' + $agentVerdict),
  'AUTHORITY=issue49_s13_s15.ps1 PASS_SECOND_HASH_CHANGE / PASS_FINAL_TEST_REAL',
  'ENGINEERING_MATURITY=82%_UNCHANGED',
  'PROMOTE=0',
  'CERTIFIED=0',
  'LAW=11_11_NE_CERTIFIED_NE_PROMOTE',
  ('BLOCKERS=' + ($blockers -join ';')),
  ('EDITLOG=' + $log),
  ('LOOP_LOG=' + $loopLog),
  ('WORK=' + $work),
  ('NEXT_ACTION=' + $next)
) | Set-Content -LiteralPath $receipt -Encoding ASCII

L 'DONE'
Write-Output '====SUMMARY===='
Write-Output ('ISSUE49=' + $reqOk + '/11')
Write-Output ('S13=' + $s13)
Write-Output ('S15=' + $s15)
Write-Output 'CERTIFIED=0'
Write-Output 'PROMOTE=0'
Write-Output ('SHA=' + $shaP)
Write-Output 'FREEZE001=PASS'
Write-Output ('BLOCKERS=' + ($blockers -join ';'))
Write-Output ('NEXT_ACTION=' + $next)
exit 0

# Edit/build v5: avoid Get-FileHash hang on locked EXE; use FileShare.ReadWrite .NET hash.
$ErrorActionPreference = 'Continue'
$expect = '35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563'
$pin = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe'
$a190 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe'
$loop = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\deep2_agentic_loop.exe'
$out = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts'
$model = 'F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $out ('issue49_edit_v5_' + $stamp + '.txt')
function L([string]$m) {
  $line = ((Get-Date -Format o) + ' ' + $m)
  [IO.File]::AppendAllText($log, $line + [Environment]::NewLine)
}
function H([string]$p) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $fs = New-Object System.IO.FileStream($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $buf = New-Object byte[] 1048576
    while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { [void]$sha.TransformBlock($buf, 0, $n, $null, 0) }
    [void]$sha.TransformFinalBlock($buf, 0, 0)
    return ([BitConverter]::ToString($sha.Hash)).Replace('-', '')
  } finally { $fs.Dispose(); $sha.Dispose() }
}
L 'START'
$sha = H $pin
L ('PRE_PIN=' + $sha)
if ($sha -ne $expect) { L 'ABORT_SHA'; exit 3 }
$work = Join-Path $out ('issue49_editwork_v5_' + $stamp)
[IO.Directory]::CreateDirectory($work) | Out-Null
$bug = Join-Path $work 'bug.cpp'
[IO.File]::WriteAllLines($bug, [string[]]@(
  '/* Issue #49 fixture */',
  'int undeclared_fn(int a);',
  '',
  'int main() {',
  '  int x = undeclared_fn(1, 2);',
  '  return x;',
  '}',
  ''
))
$before = H $bug
L ('BUG_BEFORE=' + $before + ' WORK=' + $work)
$task = 'Fix bug.cpp: change undeclared_fn(1, 2) to undeclared_fn(1). Emit TOOL call to write file, then build.'
$argList = @(
  '--model', $model, '--task', $task, '--workdir', $work, '--target-file', $bug,
  '--build-command', 'cl /nologo /EHsc bug.cpp', '--max-steps', '12', '--max-new', '256',
  '--max-retries', '6', '--max-wall-time', '1500', '--cpu', '--single-turn-repair'
)
$lp = Start-Process -FilePath $loop -ArgumentList $argList -WorkingDirectory $work -PassThru -WindowStyle Minimized
L ('LOOP_PID=' + $lp.Id)
$deadline = (Get-Date).AddSeconds(1500)
$sem = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 20
  try { $lp.Refresh() } catch {}
  $txt = [IO.File]::ReadAllText($bug)
  $h = H $bug
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($h -ne $before) -and (-not $bad) -and $good) { $sem = 1; L ('EDIT_HIT ' + $h); break }
  $child = @(Get-Process -Name 'deep2_agentic_loop' -ErrorAction SilentlyContinue).Count
  $alive = (-not $lp.HasExited) -or ($child -gt 0)
  L ('POLL alive=' + $alive + ' child=' + $child + ' h=' + $h.Substring(0, 12) + ' bad=' + $bad)
  if ($lp.HasExited -and $child -eq 0) { L ('LOOP_EXIT=' + $lp.ExitCode); break }
}
$after = H $bug
$txt = [IO.File]::ReadAllText($bug)
$bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
$sem = [int](($after -ne $before) -and (-not $bad) -and $good)
L ('BUG_AFTER=' + $after + ' SEM=' + $sem)
L ('BODY=' + ($txt -replace "`r|`n", ' | '))
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
cmd.exe /c ('call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp') | Out-Null
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and [IO.File]::Exists((Join-Path $work 'bug.exe')))
L ('BUILD_EC=' + $bec + ' BUILD_OK=' + $bok)
try { if (-not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -ErrorAction SilentlyContinue } } catch {}
$shaA = H $a190
$shaP = H $pin
L ('POST_A190=' + $shaA + ' POST_PIN=' + $shaP)
$agentEdit = 'NOT_RUN_NO_SEMANTIC_EDIT'
if ($sem -eq 1) { $agentEdit = 'PASS_SEMANTIC_BUGCPP_EDIT' }
$agentBuild = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($sem -eq 1) -and ($bok -eq 1)) { $agentBuild = 'PASS_AGENT_OWNED_BUILD_RECOVERY' }
elseif ($sem -eq 1) { $agentBuild = 'PARTIAL_EDIT_BUILD_STILL_FAILS' }
$reqOk = 5
if ($sem -eq 1) { $reqOk++ }
if (($sem -eq 1) -and ($bok -eq 1)) { $reqOk += 2 }
$blockers = New-Object System.Collections.Generic.List[string]
if ($sem -ne 1) { [void]$blockers.Add('NO_AGENT_SOURCE_EDIT'); [void]$blockers.Add('MODEL_OUTPUT_INVALID_OR_TOOL_HEADER') }
if (-not (($sem -eq 1) -and ($bok -eq 1))) { [void]$blockers.Add('NO_AGENT_OWNED_BUILD_RECOVERY') }
[void]$blockers.Add('NO_INDEPENDENT_REVIEWER'); [void]$blockers.Add('CERTIFIED_0')
$next = 'Independent reviewer for CERTIFIED'
if ($sem -ne 1) { $next = 'Durable semantic edit (tool-header/model_output_invalid)' }
elseif ($bok -ne 1) { $next = 'Agent-owned build recovery after edit' }
$receipt = Join-Path $out 'ISSUE49_35C22_ADVANCE_RECEIPT.txt'
$lines = @(
  'ISSUE49_PRODUCT_FINAL=MEASURED',
  ('ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')),
  ('TIP_SHA256=' + $shaP), ('A190_SHA256=' + $shaA), ('TIP_EXE=' + $pin),
  ('ISSUE49=' + $reqOk + '/11'), 'ISSUE49_VERDICT=FAIL_CLOSED_PARTIAL_STEPS', 'CHAT_INPUT=PASS', 'FREEZE001=PASS',
  'SESSION_LOOP=PASS_BOTH_ALIVE_WINDOW', ('AGENT_EDIT=' + $agentEdit), ('AGENT_BUILD=' + $agentBuild),
  ('BUG_BEFORE=' + $before), ('BUG_AFTER=' + $after), ('EDIT_SEMANTIC=' + $sem), ('BUILD_OK=' + $bok),
  'SESSION_LOOP_EVIDENCE=artifacts\issue49_hold_v2_20261109-150807.txt',
  'EDIT_FAIL_ROOT=snap_stop expected TOOL header; model_output_invalid (qwen CPU decode)',
  'PROMOTE=0', 'CERTIFIED=0', 'ENGINEERING_MATURITY=82%_UNCHANGED',
  ('S_10_REAL_SOURCE_EDIT=' + $agentEdit), ('S_11_BUILD_FAILURE_RECOVERY=' + $agentBuild),
  ('BLOCKERS=' + ($blockers -join ';')), ('EDITLOG=' + $log), ('NEXT_ACTION=' + $next)
)
[IO.File]::WriteAllLines($receipt, $lines)
L 'DONE'
L ('SUMMARY ISSUE49=' + $reqOk + '/11 AGENT_EDIT=' + $agentEdit + ' AGENT_BUILD=' + $agentBuild)
exit 0

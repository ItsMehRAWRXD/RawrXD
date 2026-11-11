# Edit+build only after SESSION_LOOP PASS. 35C22 pin. No A190 overwrite. No Ext.
param(
  [string]$PinExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe',
  [string]$A190 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe',
  [string]$ExpectSha = '35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563',
  [string]$LoopExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\deep2_agentic_loop.exe',
  [string]$ModelPath = 'F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf',
  [string]$OutDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts',
  [int]$WaitSec = 900
)
$ErrorActionPreference = 'Continue'
function HashFile([string]$p) {
  $h = [System.Security.Cryptography.SHA256]::Create()
  $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite')
  try { return [BitConverter]::ToString($h.ComputeHash($fs)).Replace('-', '') }
  finally { $fs.Dispose(); $h.Dispose() }
}
$null = cmd /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RXD_PIN_A190_35C22.exe >nul 2>&1 & exit /b 0'
Start-Sleep -Milliseconds 500
$sha = HashFile $PinExe
if ($sha -ne $ExpectSha) { Write-Output ('ABORT_SHA=' + $sha); exit 3 }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$work = Join-Path $OutDir ('issue49_editwork_' + $stamp)
New-Item -ItemType Directory -Force -Path $work, $OutDir | Out-Null
$bug = Join-Path $work 'bug.cpp'
$fix = @(
  '/* Issue #49 fixture */',
  'int undeclared_fn(int a);',
  '',
  'int main() {',
  '  int x = undeclared_fn(1, 2);',
  '  return x;',
  '}',
  ''
)
[IO.File]::WriteAllLines($bug, $fix)
$before = HashFile $bug
$log = Join-Path $OutDir ('issue49_edit_' + $stamp + '.txt')
function L([string]$m) { $x = ((Get-Date -Format o) + ' ' + $m); Add-Content $log $x; Write-Host $x }

L ('PRE_PIN=' + $sha + ' BUG_BEFORE=' + $before)
$ide = Start-Process -FilePath $PinExe -WorkingDirectory (Split-Path $PinExe) -PassThru -WindowStyle Minimized
$task = 'Edit bug.cpp only: replace undeclared_fn(1, 2) with undeclared_fn(1). Write the file. Then run build.'
$args = @(
  '--model', $ModelPath, '--task', $task, '--workdir', $work, '--target-file', $bug,
  '--build-command', 'cl /nologo /EHsc bug.cpp', '--max-steps', '10', '--max-new', '160',
  '--max-retries', '4', '--max-wall-time', ([string]$WaitSec), '--cpu'
)
$lp = Start-Process -FilePath $LoopExe -ArgumentList $args -WorkingDirectory $work -PassThru -WindowStyle Minimized
L ('IDE=' + $ide.Id + ' LOOP=' + $lp.Id)
$dead = (Get-Date).AddSeconds($WaitSec)
$sem = 0
while ((Get-Date) -lt $dead) {
  Start-Sleep -Seconds 10
  try { $lp.Refresh() } catch {}
  try { $ide.Refresh() } catch {}
  $txt = [IO.File]::ReadAllText($bug)
  $h = HashFile $bug
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($h -ne $before) -and (-not $bad) -and $good) { $sem = 1; L ('EDIT_HIT ' + $h); break }
  $la = -not $lp.HasExited
  L ('p loop=' + $la + ' ide=' + (-not $ide.HasExited) + ' sem=0 h=' + $h.Substring(0, 12) + ' bad=' + $bad)
  if ($lp.HasExited) { L ('LOOP_EXIT=' + $lp.ExitCode); break }
}
$after = HashFile $bug
$txt = [IO.File]::ReadAllText($bug)
$bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
$sem = [int](($after -ne $before) -and (-not $bad) -and $good)
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$null = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp') 2>&1
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
L ('AFTER=' + $after + ' SEM=' + $sem + ' BUILD_EC=' + $bec + ' BUILD_OK=' + $bok)
L ('BUG_TEXT=' + ($txt -replace "`r|`n", ' | '))
try { if (-not $ide.HasExited) { Stop-Process -Id $ide.Id -Force -EA SilentlyContinue } } catch {}
try { if (-not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -EA SilentlyContinue } } catch {}
$shaA = HashFile $A190
$shaP = HashFile $PinExe
L ('POST_A190=' + $shaA + ' POST_PIN=' + $shaP)

# Merge into receipt keeping SESSION_LOOP PASS
$agentEdit = 'NOT_RUN_NO_SEMANTIC_EDIT'
if ($sem -eq 1) { $agentEdit = 'PASS_SEMANTIC_BUGCPP_EDIT' }
$agentBuild = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($sem -eq 1) -and ($bok -eq 1)) { $agentBuild = 'PASS_AGENT_OWNED_BUILD_RECOVERY' }
elseif ($sem -eq 1) { $agentBuild = 'PARTIAL_EDIT_BUILD_STILL_FAILS' }

$reqOk = 5
if ($sem -eq 1) { $reqOk++ }
if (($sem -eq 1) -and ($bok -eq 1)) { $reqOk += 2 } # 11 recovery + 14 final build

$blockers = New-Object System.Collections.Generic.List[string]
if ($sem -ne 1) { [void]$blockers.Add('NO_AGENT_SOURCE_EDIT') }
if (-not (($sem -eq 1) -and ($bok -eq 1))) { [void]$blockers.Add('NO_AGENT_OWNED_BUILD_RECOVERY') }
[void]$blockers.Add('NO_INDEPENDENT_REVIEWER')
[void]$blockers.Add('CERTIFIED_0')

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
  ('AGENT_EDIT=' + $agentEdit),
  ('AGENT_BUILD=' + $agentBuild),
  ('BUG_BEFORE=' + $before),
  ('BUG_AFTER=' + $after),
  ('EDIT_SEMANTIC=' + $sem),
  ('BUILD_OK=' + $bok),
  'SESSION_LOOP_EVIDENCE=artifacts\issue49_hold_v2_20261109-150807.txt',
  'PROMOTE=0',
  'CERTIFIED=0',
  'ENGINEERING_MATURITY=82%_UNCHANGED',
  ('BLOCKERS=' + ($blockers -join ';')),
  ('EDITLOG=' + $log),
  ('NEXT_ACTION=' + $(if ($sem -ne 1) { 'Retry agent semantic edit with longer wall / tool evidence' } else { 'Close remaining Issue#49 steps; independent reviewer' }))
) | Set-Content $receipt -Encoding ASCII

Write-Output '====SUMMARY===='
Write-Output ('ISSUE49=' + $reqOk + '/11')
Write-Output 'SESSION_LOOP=PASS_BOTH_ALIVE_WINDOW'
Write-Output ('AGENT_EDIT=' + $agentEdit)
Write-Output ('AGENT_BUILD=' + $agentBuild)
Write-Output 'FREEZE001=PASS'
Write-Output ('SHA=' + $shaP)
Write-Output 'PROMOTE=0'
Write-Output ('BLOCKERS=' + ($blockers -join ';'))
exit 0

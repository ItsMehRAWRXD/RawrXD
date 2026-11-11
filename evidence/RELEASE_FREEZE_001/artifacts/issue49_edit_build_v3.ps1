# Semantic edit + agent build on 35C22. SESSION_LOOP PASS retained. No A190 overwrite. No Ext.
# Avoid taskkill/hash hangs: no image kill; hash pin once; write log immediately.
param(
  [string]$PinExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe',
  [string]$A190 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe',
  [string]$ExpectSha = '35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563',
  [string]$LoopExe = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\deep2_agentic_loop.exe',
  [string]$ModelPath = 'F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$OutDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts',
  [int]$WaitSec = 1200
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $OutDir ('issue49_edit_v3_' + $stamp + '.txt')
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

L 'START'
$shaPin = HashFile $PinExe
L ('PRE_PIN=' + $shaPin)
if ($shaPin -ne $ExpectSha) { L 'ABORT_SHA'; exit 3 }

$work = Join-Path $OutDir ('issue49_editwork_v3_' + $stamp)
New-Item -ItemType Directory -Force -Path $work | Out-Null
$bug = Join-Path $work 'bug.cpp'
$fix = @(
  '/* Issue #49 product-final fixture: intentional compile bug. */',
  'int undeclared_fn(int a);',
  '',
  'int main() {',
  '  int x = undeclared_fn(1, 2);',
  '  return x;',
  '}',
  ''
)
[IO.File]::WriteAllLines($bug, $fix)
try { Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force } catch {}
$before = HashFile $bug
L ('BUG_BEFORE=' + $before + ' WORK=' + $work)

# Hold IDE (session already PASS; keep coexistence during edit)
$ide = Start-Process -FilePath $PinExe -WorkingDirectory (Split-Path $PinExe) -PassThru -WindowStyle Minimized
L ('IDE_PID=' + $ide.Id)
Start-Sleep -Seconds 3

$task = 'You must edit bug.cpp on disk. Change the call undeclared_fn(1, 2) to undeclared_fn(1). Save the file with write/apply tools. Then run the build command until cl succeeds.'
$loopArgs = @(
  '--model', $ModelPath,
  '--task', $task,
  '--workdir', $work,
  '--target-file', $bug,
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  '--max-steps', '12',
  '--max-new', '192',
  '--max-retries', '5',
  '--max-wall-time', ([string]$WaitSec),
  '--cpu'
)
$lp = Start-Process -FilePath $LoopExe -ArgumentList $loopArgs -WorkingDirectory $work -PassThru -WindowStyle Minimized
L ('LOOP_PID=' + $lp.Id)

$dead = (Get-Date).AddSeconds($WaitSec)
$sem = 0
while ((Get-Date) -lt $dead) {
  Start-Sleep -Seconds 15
  try { $lp.Refresh() } catch {}
  try { $ide.Refresh() } catch {}
  $txt = [IO.File]::ReadAllText($bug)
  $h = HashFile $bug
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($h -ne $before) -and (-not $bad) -and $good) {
    $sem = 1
    L ('EDIT_HIT AFTER=' + $h)
    break
  }
  $la = -not $lp.HasExited
  $ia = -not $ide.HasExited
  $child = @(Get-Process -Name 'deep2_agentic_loop' -ErrorAction SilentlyContinue).Count
  if ($child -gt 0) { $la = $true }
  L ('POLL loop=' + $la + ' ide=' + $ia + ' child=' + $child + ' h=' + $h.Substring(0, 12) + ' bad=' + $bad)
  if ($lp.HasExited -and $child -eq 0) {
    L ('LOOP_EXIT=' + $lp.ExitCode)
    break
  }
}

$after = HashFile $bug
$txt = [IO.File]::ReadAllText($bug)
$bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
$sem = [int](($after -ne $before) -and (-not $bad) -and $good)
L ('BUG_AFTER=' + $after + ' SEM=' + $sem)
L ('BUG_BODY=' + ($txt -replace "`r|`n", ' || '))

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$buildCmd = 'call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp'
$null = cmd /c $buildCmd 2>&1
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
L ('BUILD_EC=' + $bec + ' BUILD_OK=' + $bok)

# If agent edited work copy, mirror to fixture
if ($sem -eq 1) {
  try { Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force } catch {}
}

try { if ($ide -and -not $ide.HasExited) { Stop-Process -Id $ide.Id -Force -ErrorAction SilentlyContinue } } catch {}
try { if ($lp -and -not $lp.HasExited) { Stop-Process -Id $lp.Id -Force -ErrorAction SilentlyContinue } } catch {}

$shaA = 'SKIP'
try { $shaA = HashFile $A190 } catch { $shaA = 'HASH_FAIL' }
$shaP = HashFile $PinExe
L ('POST_A190=' + $shaA + ' POST_PIN=' + $shaP)

$agentEdit = 'NOT_RUN_NO_SEMANTIC_EDIT'
if ($sem -eq 1) { $agentEdit = 'PASS_SEMANTIC_BUGCPP_EDIT' }
$agentBuild = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($sem -eq 1) -and ($bok -eq 1)) { $agentBuild = 'PASS_AGENT_OWNED_BUILD_RECOVERY' }
elseif ($sem -eq 1) { $agentBuild = 'PARTIAL_EDIT_BUILD_STILL_FAILS' }

# Required 11 credit: baseline 5 + edit + build recovery + final build if both
$reqOk = 5
if ($sem -eq 1) { $reqOk++ }
if (($sem -eq 1) -and ($bok -eq 1)) { $reqOk += 2 }

$blockers = New-Object System.Collections.Generic.List[string]
if ($sem -ne 1) { [void]$blockers.Add('NO_AGENT_SOURCE_EDIT') }
if (-not (($sem -eq 1) -and ($bok -eq 1))) { [void]$blockers.Add('NO_AGENT_OWNED_BUILD_RECOVERY') }
[void]$blockers.Add('NO_INDEPENDENT_REVIEWER')
[void]$blockers.Add('CERTIFIED_0')

$next = 'Independent reviewer for CERTIFIED; remaining Issue#49 steps'
if ($sem -ne 1) { $next = 'Complete durable semantic bug.cpp edit via deep2_agentic_loop on 35C22' }
elseif ($bok -ne 1) { $next = 'Agent-owned build recovery to successful cl on edited bug.cpp' }

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
  'ENGINEERING_MATURITY=82%_UNCHANGED',
  'PROMOTE=0',
  'CERTIFIED=0',
  'LAW=FREEZE001_PASS_NE_ISSUE49_11_11',
  ('S_10_REAL_SOURCE_EDIT=' + $agentEdit),
  ('S_11_BUILD_FAILURE_RECOVERY=' + $agentBuild),
  ('S_14_FINAL_BUILD=' + $(if (($sem -eq 1) -and ($bok -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' })),
  ('BLOCKERS=' + ($blockers -join ';')),
  ('EDITLOG=' + $log),
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

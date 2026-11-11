# INTEG_009 full requeue on tip_final_integ_009 / 0946 only. Stop at first FAIL.
# PROMOTE=0 TIP_MOVE_AUTHORIZED=0 A4F_IMMUTABLE=1 NO_CROSS_SHA_PASS_INHERITANCE.
# tip_008 E6CF historical — NO inherit Ext/Chat/FourPanel/Issue49 PASS to 0946.
$ErrorActionPreference = 'Continue'
$__i49lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
if (Test-Path -LiteralPath $__i49lock) {
  Write-Host 'SKIP: ISSUE49_EXCLUSIVE.lock present — not killing Native-Ext / not launching'
  exit 0
}
$tipDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_009'
$exe = Join-Path $tipDir 'RawrXD-Win32IDE-Native-Ext.exe'
$expect = '0946C7AA0397C1F400FB7A960D8DBC4AC98A601C128351054EE9857FA5D11BF9'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$art = Join-Path $root 'artifacts'
$oneshot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$summary = Join-Path $art 'integ009_requeue_summary.txt'
New-Item -ItemType Directory -Force -Path $art | Out-Null
'' | Set-Content $summary

function HashOk([string]$why) {
  $h = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
  $line = "REHASH_$why=$h"
  Write-Host $line; Add-Content $summary $line
  if ($h -ne $expect) {
    Write-Host 'DISK_DRIFT=1 ABORT'
    Add-Content $summary 'DISK_DRIFT=1 ABORT'
    return $false
  }
  return $true
}

function WriteReceipt([string]$name, [string]$body) {
  $path = Join-Path $root $name
  Set-Content -LiteralPath $path -Value $body -Encoding UTF8
  Write-Host "RECEIPT=$path"
  Add-Content $summary "RECEIPT=$path"
  return $path
}

$startLine = "REQUEUE_START=$(Get-Date -Format o)"
Write-Host $startLine; Add-Content $summary $startLine
if (-not (HashOk 'START')) { exit 3 }

# --- 1 EXT ---
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$extLog = Join-Path $art ("ext_smoke_integ009_requeue_{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $oneshot 'harness\ext_smoke_oneshot.ps1') -TipExe $exe *>&1 | Tee-Object -FilePath $extLog
$extExit = $LASTEXITCODE
$extText = if (Test-Path $extLog) { Get-Content $extLog -Raw } else { '' }
$forceKill = '0'
if ($extText -match 'FORCE_KILL=1') { $forceKill = '1' }
$extPass = ($extText -match 'FORCE_KILL=0' -and $extText -match 'EXT_LOAD=PASS' -and $extText -match 'INIT_OK=1' -and $extText -match 'CMD_OK=1')
if ($forceKill -eq '1') { $extPass = $false }
$sha = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
$extDisp = if ($extPass) { 'PASS' } else { 'FAIL' }
Add-Content $summary "EXT=$extDisp"
WriteReceipt 'INTEG009_EXT_REVERIFY_RECEIPT.md' @"
# INTEG009_EXT_REVERIFY_RECEIPT — Gate 1 Extensions on INTEG_009

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MOTD_ACK=1

``````
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_009
EXE_SHA256=$sha
EXE_AT_RUN=$exe
SHA_MATCH_AT_START=$([int]($sha -eq $expect))
DISK_DRIFT=$([int]($sha -ne $expect))
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_E6CF=1
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
FROZEN_TIP_009=1

HARNESS=$oneshot\harness\ext_smoke_oneshot.ps1
RUNLOG=$extLog
HARNESS_EXIT=$extExit
FORCE_KILL=$forceKill

EXT=$extDisp

PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
``````
"@
if (-not $extPass) { Write-Host 'STOP_AT=EXT FAIL'; Add-Content $summary 'STOP_AT=EXT FAIL'; exit 1 }
if (-not (HashOk 'POST_EXT')) { exit 3 }

# --- 2 PROBLEMS UI ---
$probLogDir = Join-Path $tipDir 'problems_ui_logs'
New-Item -ItemType Directory -Force -Path $probLogDir | Out-Null
Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $oneshot 'harness\problems_gui_measure_007.ps1') `
  -TipExe $exe `
  -BrokenCpp (Join-Path $oneshot 'fixtures\broken_multi.cpp') `
  -OutDir $art `
  -LogDir $probLogDir `
  -WaitSec 60
$probExit = $LASTEXITCODE
$probReceiptPath = Join-Path $art 'IDE_PANELS_GUI_RECEIPT.txt'
$probRun = Get-ChildItem $art -Filter 'ide_panels_gui_run_*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$probPass = $false
$probItems = -1
if (Test-Path $probReceiptPath) {
  $pr = Get-Content $probReceiptPath -Raw
  if ($pr -match 'GUI_PROBLEMS_PANEL_E2E=PASS') { $probPass = $true }
  if ($pr -match 'PROBLEMS_ID1312_ITEMS=(\d+)') { $probItems = [int]$Matches[1] }
}
$sha = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
$probDisp = if ($probPass) { 'PASS' } else { 'FAIL' }
Add-Content $summary "PROBLEMS_UI=$probDisp items=$probItems"
WriteReceipt 'INTEG009_PROBLEMS_UI_REVERIFY_RECEIPT.md' @"
# INTEG009_PROBLEMS_UI_REVERIFY_RECEIPT — Problems UI on INTEG_009

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MOTD_ACK=1

``````
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_009
MEASURED_EXE_SHA256=$sha
EXE_AT_RUN=$exe
SHA_MATCH_AT_HARNESS_START=$([int]($sha -eq $expect))
DISK_DRIFT=$([int]($sha -ne $expect))
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_E6CF=1
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1

HARNESS=$oneshot\harness\problems_gui_measure_007.ps1
RUNLOG=$(if($probRun){$probRun.FullName}else{'MISSING'})
HARNESS_RECEIPT=$probReceiptPath
HARNESS_EXIT=$probExit
PROBLEMS_ID1312_ITEMS=$probItems
GUI_PROBLEMS_PANEL_E2E=$probDisp
PROBLEMS_UI=$probDisp
FORCE_KILL=0

PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
``````
"@
if (-not $probPass) { Write-Host 'STOP_AT=PROBLEMS_UI FAIL'; Add-Content $summary 'STOP_AT=PROBLEMS_UI FAIL'; exit 1 }
if (-not (HashOk 'POST_PROBLEMS')) { exit 3 }

# --- 3 CHAT busywait ---
$chatLogDir = Join-Path $tipDir 'chat_logs'
New-Item -ItemType Directory -Force -Path $chatLogDir | Out-Null
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'harness\chat_ctrl_enter_verify_busywait.ps1') `
  -TipExe $exe `
  -OutDir $art `
  -LogDir $chatLogDir `
  -WaitIdleBetweenSends
$chatExit = $LASTEXITCODE
$chatRec = Join-Path $art 'CHAT_CTRL_ENTER_RECEIPT.txt'
$chatPass = $false
$passCount = ''
if (Test-Path $chatRec) {
  $cr = Get-Content $chatRec -Raw
  if ($cr -match 'PASS_COUNT=(\d+/\d+)') { $passCount = $Matches[1] }
  if ($cr -match 'CHAT_CTRL_ENTER_SEND=FAIL') { $chatPass = $false }
  elseif ($cr -match 'CHAT_CTRL_ENTER_SEND=PASS' -and $passCount -eq '7/7') { $chatPass = $true }
  elseif ($passCount -eq '7/7') { $chatPass = $true }
}
$sha = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
$chatDisp = if ($chatPass) { 'PASS' } else { 'FAIL' }
$chatRun = Get-ChildItem $art -Filter 'chat_ctrl_enter_run_*.txt' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item $chatRec (Join-Path $art 'CHAT_CTRL_ENTER_RECEIPT_INTEG009.txt') -Force -EA SilentlyContinue
Add-Content $summary "CHAT=$chatDisp PASS_COUNT=$passCount EXIT=$chatExit"
WriteReceipt 'INTEG009_CHAT_REVERIFY_RECEIPT.md' @"
# INTEG009_CHAT_REVERIFY_RECEIPT — Chat Ctrl+Enter busywait on INTEG_009

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MOTD_ACK=1

``````
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_009
MEASURED_EXE_SHA256=$sha
EXE_AT_RUN=$exe
SHA_MATCH_AT_HARNESS_START=$([int]($sha -eq $expect))
DISK_DRIFT=$([int]($sha -ne $expect))
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_E6CF=1
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1

HARNESS=$root\harness\chat_ctrl_enter_verify_busywait.ps1
RUNLOG=$(if($chatRun){$chatRun.FullName}else{'MISSING'})
HARNESS_RECEIPT=$chatRec
PASS_COUNT=$passCount
CHAT=$chatDisp
HARNESS_EXIT=$chatExit
FORCE_KILL=0

PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
``````
"@
if (-not $chatPass) { Write-Host 'STOP_AT=CHAT FAIL'; Add-Content $summary 'STOP_AT=CHAT FAIL'; exit 1 }
if (-not (HashOk 'POST_CHAT')) { exit 3 }

# --- 4 TERM ---
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
Remove-Item (Join-Path $oneshot 'artifacts\term_smoke_receipt.txt') -Force -EA SilentlyContinue
$termStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$termRun = Join-Path $art "term_smoke_run_integ009_$termStamp.txt"
$p = Start-Process -FilePath $exe -ArgumentList '--term-smoke','--term-quit' -PassThru -WindowStyle Minimized
$waited = $p.WaitForExit(120000)
$force = 0
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue; $force = 1 }
"START_WAITED=$waited EXIT=$($p.ExitCode) FORCE_KILL=$force" | Set-Content $termRun
$oneshotTerm = Join-Path $oneshot 'artifacts\term_smoke_receipt.txt'
$termCopy = Join-Path $art 'term_smoke_receipt_INTEG009.txt'
$termPass = $false
if (Test-Path $oneshotTerm) {
  Copy-Item $oneshotTerm $termCopy -Force
  Add-Content $termRun (Get-Content $oneshotTerm)
  $tr = Get-Content $oneshotTerm -Raw
  if ($tr -match 'START=PASS' -and $tr -match 'CONPTY=PASS' -and $tr -match 'ALIVE_ECHO=PASS' -and $force -eq 0) { $termPass = $true }
}
$sha = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
$termDisp = if ($termPass) { 'PASS' } else { 'FAIL' }
Add-Content $summary "TERM=$termDisp FORCE_KILL=$force"
WriteReceipt 'INTEG009_TERM_REVERIFY_RECEIPT.md' @"
# INTEG009_TERM_REVERIFY_RECEIPT — Term smoke on INTEG_009

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MOTD_ACK=1

``````
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_009
GATE=G3_TERM_REVERIFY
MEASURED_EXE_SHA256=$sha
EXE_AT_RUN=$exe
SHA_MATCH_AT_START=$([int]($sha -eq $expect))
DISK_DRIFT=$([int]($sha -ne $expect))
FORCE_KILL=$force
ARGS=--term-smoke --term-quit
ONESHOT_RECEIPT=$oneshotTerm
COPIED_RECEIPT=$termCopy
RUNLOG=$termRun
TERM=$termDisp
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_E6CF=1
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
``````
"@
if (-not $termPass) { Write-Host 'STOP_AT=TERM FAIL'; Add-Content $summary 'STOP_AT=TERM FAIL'; exit 1 }
if (-not (HashOk 'POST_TERM')) { exit 3 }

# --- 5 OUTPUT ---
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $art 'run_integ009_output_reverify.ps1')
$outExit = $LASTEXITCODE
$outHarness = Join-Path $art 'INTEG009_OUTPUT_HWND_HARNESS_RECEIPT.txt'
$outPass = $false
if (Test-Path $outHarness) {
  $oh = Get-Content $outHarness -Raw
  if ($oh -match 'GUI_OUTPUT_PANEL_E2E=PASS' -or $oh -match 'OUTPUT_HWND=PASS') { $outPass = $true }
}
$sha = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
$outDisp = if ($outPass) { 'PASS' } else { 'FAIL' }
Add-Content $summary "OUTPUT=$outDisp EXIT=$outExit RECEIPT=$outHarness"
WriteReceipt 'INTEG009_OUTPUT_REVERIFY_RECEIPT.md' @"
# INTEG009_OUTPUT_REVERIFY_RECEIPT — Output HWND on INTEG_009

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MOTD_ACK=1

``````
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_009
GATE=G4_OUTPUT_REVERIFY
MEASURED_EXE_SHA256=$sha
EXE_AT_RUN=$exe
HARNESS_EXIT=$outExit
HARNESS_RECEIPT=$outHarness
OUTPUT=$outDisp
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_E6CF=1
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
``````
"@
if (-not $outPass) { Write-Host 'STOP_AT=OUTPUT FAIL'; Add-Content $summary 'STOP_AT=OUTPUT FAIL'; exit 1 }
if (-not (HashOk 'POST_OUTPUT')) { exit 3 }

# --- 6+7 DEBUG + FOUR PANEL ---
if (-not (HashOk 'PRE_DEBUG_FOUR')) { exit 3 }
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $art 'run_integ009_four_panel_reverify.ps1')
$dbgExit = $LASTEXITCODE
$dbgHarness = Join-Path $art 'INTEG009_DEBUG_UI_HARNESS_RECEIPT.txt'
$dbgPass = $false
$fourPass = $false
$probVis = -1
$panelCont = -1
if (Test-Path $dbgHarness) {
  $dh = Get-Content $dbgHarness -Raw
  if ($dh -match 'IDE_DEBUG_UI=PASS') { $dbgPass = $true }
  if ($dh -match 'FOUR_PANEL_INTEGRATION=PASS') { $fourPass = $true }
  if ($dh -match 'PROBLEMS_ID1312_VISIBLE=(\d+)') { $probVis = [int]$Matches[1] }
  if ($dh -match 'PANEL_CONTAINER_VISIBLE=(\d+)') { $panelCont = [int]$Matches[1] }
}
$sha = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash
$dbgDisp = if ($dbgPass) { 'PASS' } else { 'FAIL' }
Add-Content $summary "DEBUG_UI=$dbgDisp"
WriteReceipt 'INTEG009_DEBUG_UI_REVERIFY_RECEIPT.md' @"
# INTEG009_DEBUG_UI_REVERIFY_RECEIPT — Debug UI on INTEG_009

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MOTD_ACK=1

``````
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_009
MEASURED_EXE_SHA256=$sha
EXE_AT_RUN=$exe
HARNESS=$art\run_integ009_four_panel_reverify.ps1
HARNESS_RECEIPT=$dbgHarness
HARNESS_EXIT=$dbgExit
DEBUG_UI=$dbgDisp
PROBLEMS_ID1312_VISIBLE=$probVis
PANEL_CONTAINER_VISIBLE=$panelCont
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_E6CF=1
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
``````
"@
if (-not $dbgPass) { Write-Host 'STOP_AT=DEBUG_UI FAIL'; Add-Content $summary 'STOP_AT=DEBUG_UI FAIL'; exit 1 }
if (-not (HashOk 'POST_DEBUG')) { exit 3 }

$fourDisp = if ($fourPass -and $probVis -eq 1 -and $panelCont -eq 1) { 'PASS' } else { 'FAIL' }
$next = if ($fourDisp -eq 'PASS') { 'ISSUE49_TOOL_AUTHORITY_AND_SOURCE_EDIT_ON_0946' } else { 'G7_FOUR_PANEL' }
Add-Content $summary "FOUR_PANEL=$fourDisp"
Add-Content $summary "PROBLEMS_VIS=$probVis"
Add-Content $summary "PANEL_CONT_VIS=$panelCont"
WriteReceipt 'INTEG009_FOUR_PANEL_RECEIPT.md' @"
# INTEG009_FOUR_PANEL_RECEIPT — G7_FOUR_PANEL on INTEG_009

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MOTD_ACK=1
SEALED_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))

``````
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_009
GATE=G7_FOUR_PANEL
MEASURED_EXE_SHA256=$sha
EXE_AT_RUN=$exe
SHA_MATCH_AT_START=1
DISK_DRIFT=0
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_E6CF=1
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
FROZEN_TIP_009=1

HARNESS=$art\run_integ009_four_panel_reverify.ps1
HARNESS_RECEIPT=$dbgHarness
REQUEUE_SUMMARY=$summary
PROBLEMS_ID1312_VISIBLE=$probVis
PANEL_CONTAINER_VISIBLE=$panelCont
FOUR_PANEL=$fourDisp

PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_CLIMB=HOLD
TIP_MOVE_AUTHORIZED=0
NEXT_GATE=$next
``````
"@
if ($fourDisp -ne 'PASS') { Write-Host 'STOP_AT=FOUR_PANEL FAIL'; Add-Content $summary 'STOP_AT=FOUR_PANEL FAIL'; exit 1 }

$done = "REQUEUE_COMPLETE=$(Get-Date -Format o)"
Write-Host $done; Add-Content $summary $done
Write-Host 'REQUEUE_COMPLETE FOUR_PANEL=PASS'
exit 0

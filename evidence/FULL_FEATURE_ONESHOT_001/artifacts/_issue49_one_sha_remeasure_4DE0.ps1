#Requires -Version 5.1
# ISSUE49 ONE_SHA remasure maps 1-11 on tip SHA 4DE06F9F… (NO_CROSS_SHA_PASS).
# Cite P3 four-panel PASS on 4DE0 separately — do NOT substitute for maps 1-11.
# Laws: PROMOTE=0 PRODUCT_PASS=0 CERTIFIED=0 MATURITY=82 E6CF HELD; NOT_RUN!=PASS.
$ErrorActionPreference = 'Continue'
$ExpectSha = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$EvidenceRoot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$TipExe = Join-Path $EvidenceRoot 'package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$OutDir = Join-Path $EvidenceRoot 'artifacts'
$HarnessDir = Join-Path $EvidenceRoot 'harness'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "integ_one_sha_1_11_4DE0_$Stamp"
$Journal = Join-Path $OutDir 'ISSUE49_ONE_SHA_REMEASURE_4DE0_JOURNAL.txt'
$Receipt = Join-Path $OutDir 'ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT.txt'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
'' | Set-Content -Encoding ascii $Journal
function J([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Encoding ascii $Journal $line
  Write-Host $line
}
function Run-Step([string]$name, [string]$script, [string[]]$extraArgs) {
  J "BEGIN_$name SCRIPT=$script"
  $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script) + $extraArgs
  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -PassThru -WindowStyle Hidden
  while (-not $p.HasExited) {
    try { $p.Refresh() } catch {}
    Start-Sleep -Seconds 1
  }
  $ec = 1
  try { $ec = [int]$p.ExitCode } catch { $ec = 1 }
  J "END_$name EXIT=$ec"
  return $ec
}

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
J "RUN_ID=$RunId EXPECT=$ExpectSha MEASURED=$Sha TIP=$TipExe"
if ($Sha -ne $ExpectSha) {
  J "SHA_DRIFT FAIL SHA_SUPERSEDED"
  @"
ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT
TIP_SHA256=$Sha
EXPECTED=$ExpectSha
SHA_VERIFY=FAIL
SHA_SUPERSEDED=1
ONE_SHA_1_11=FAIL
MAPS=NOT_RUN
NOTE=Rebuild mid-flight or tip moved; remasure on new tip required
PROMOTE=0
"@ | Set-Content -Encoding ascii $Receipt
  exit 9
}
J "SHA_VERIFY=PASS"
J "P3_FOUR_PANEL_CITE=artifacts\ISSUE49_P3_FOUR_PANEL_4DE0_RECEIPT.txt (ORDERED_BLOCKER seal; NOT maps 1-11)"

$bpScript = Join-Path $HarnessDir 'run_build_pipeline_gate.ps1'
$ec2 = Run-Step 'MAP2_BUILD_PIPELINE' $bpScript @()
$bpLog = Get-ChildItem (Join-Path $EvidenceRoot 'logs\build_pipeline\build_pipeline_receipt_*.txt') -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
$map2 = 'FAIL'
$map2Detail = 'NOT_RUN'
if ($bpLog) {
  $bpTxt = Get-Content $bpLog.FullName -Raw
  if ($bpTxt -match 'BUILD_PIPELINE_OFFLINE=PASS' -or $bpTxt -match 'BUILD_PIPELINE_OVERALL=PASS' -or ($bpTxt -match 'BP_HELLO_OK' -and $bpTxt -match 'OFFLINE_CASE_PASS_COUNT=7/7')) { $map2 = 'PASS' }
  $map2Detail = $bpLog.FullName
  $m2r = Join-Path $OutDir 'ISSUE49_COMPILE_LINK_RUN_RECEIPT.txt'
  @"
ISSUE49_COMPILE_LINK_RUN_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MAP=2
TIP_SHA256=$Sha
TIP_EXE=$TipExe
HARNESS=harness\run_build_pipeline_gate.ps1
PIPELINE_RECEIPT=$($bpLog.FullName)
COMPILE_LINK_RUN=$map2
MAP2=$map2
NOTE=Native MSVC path remasure bound to tip SHA 4DE0 under remasure (IDE HWND map3 separate)
NO_CROSS_SHA_PASS=1
PROMOTE=0
"@ | Set-Content -Encoding ascii $m2r
  J "MAP2=$map2 RECEIPT=$m2r"
} else {
  J "MAP2=FAIL MISSING_PIPELINE_RECEIPT EXIT=$ec2"
}

$ec1 = Run-Step 'MAP1_OES' (Join-Path $OutDir '_issue49_oes_e2e_4DE0.ps1') @()
$m1r = Join-Path $OutDir 'ISSUE49_OES_RECEIPT.txt'
$map1 = 'FAIL'
if (Test-Path $m1r) {
  if ((Select-String -Path $m1r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m1r -Pattern 'MAP1=PASS' -Quiet)) { $map1 = 'PASS' }
}
J "MAP1=$map1 RECEIPT=$m1r EXIT=$ec1"

$hwndOut = Join-Path $EvidenceRoot "candidates\tip_integ_candidate_001\map3_hwnd_4DE0_$Stamp"
New-Item -ItemType Directory -Force -Path $hwndOut | Out-Null
$hwndArgs = @(
  '-TipExe', $TipExe,
  '-ExpectSha', $ExpectSha,
  '-BrokenCpp', (Join-Path $EvidenceRoot 'fixtures\broken_multi.cpp'),
  '-OutDir', $OutDir,
  '-LogDir', $hwndOut,
  '-WaitSec', '70'
)
$ec3 = Run-Step 'MAP3_HWND' (Join-Path $HarnessDir 'ea5d_output_problems_hwnd.ps1') $hwndArgs
$ea5d = Join-Path $OutDir 'EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt'
$map3 = 'FAIL'
$click = 'MISS'; $outHwnd='MISS'; $probHwnd='MISS'; $msvcHits='0'
if (Test-Path $ea5d) {
  Copy-Item -Force $ea5d (Join-Path $OutDir 'INTEG_CANDIDATE_001_HWND_RECEIPT.txt')
  $h = Get-Content $ea5d -Raw
  if ($h -match 'TIP_SHA=4DE0' -and $h -match 'OUTPUT_HWND=PASS' -and $h -match 'PROBLEMS_HWND=PASS' -and $h -match 'CLICK_TO_LINE=POSTED_NM_DBLCLK') { $map3 = 'PASS' }
  if ($h -match 'CLICK_TO_LINE=([^\r\n]+)') { $click = $Matches[1] }
  if ($h -match 'OUTPUT_HWND=([^\r\n]+)') { $outHwnd = $Matches[1] }
  if ($h -match 'PROBLEMS_HWND=([^\r\n]+)') { $probHwnd = $Matches[1] }
  if ($h -match 'BUILD_OUTPUT_MSVC_HITS=(\d+)') { $msvcHits = $Matches[1] }
}
$m3r = Join-Path $OutDir 'ISSUE49_OUTPUT_PROBLEMS_HWND_RECEIPT.txt'
@"
ISSUE49_OUTPUT_PROBLEMS_HWND_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MAP=3
TIP_SHA256=$Sha
TIP_EXE=$TipExe
HARNESS=harness\ea5d_output_problems_hwnd.ps1
SOURCE_RECEIPT=$ea5d
OUTPUT_HWND=$outHwnd
PROBLEMS_HWND=$probHwnd
CLICK_TO_LINE=$click
BUILD_OUTPUT_MSVC_HITS=$msvcHits
MAP3=$map3
NO_CROSS_SHA_PASS=1
PROMOTE=0
"@ | Set-Content -Encoding ascii $m3r
J "MAP3=$map3 RECEIPT=$m3r EXIT=$ec3"

$ec4 = Run-Step 'MAP4_CHAT' (Join-Path $OutDir '_chat_e2e_uncanceled_4DE0.ps1') @()
$chatR = Join-Path $OutDir 'INTEG_CANDIDATE_001_CHAT_E2E_UNCANCELED_RECEIPT.txt'
$map4 = 'FAIL'
if (Test-Path $chatR) {
  $c = Get-Content $chatR -Raw
  if ($c -match 'TIP_SHA256=4DE0' -and $c -match 'E2E_CHAT_RESPONSE_CORRELATED=PASS' -and $c -match 'E2E_UNCANCELED_CHAT=PASS') { $map4 = 'PASS' }
}
$m4r = Join-Path $OutDir 'ISSUE49_E2E_CHAT_RESPONSE_RECEIPT.txt'
@"
ISSUE49_E2E_CHAT_RESPONSE_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MAP=4
TIP_SHA256=$Sha
SOURCE_RECEIPT=$chatR
E2E_CHAT_RESPONSE_CORRELATED=$(if($map4 -eq 'PASS'){'PASS'}else{'FAIL'})
MAP4=$map4
HARNESS=artifacts\_chat_e2e_uncanceled_4DE0.ps1
NO_CROSS_SHA_PASS=1
PROMOTE=0
"@ | Set-Content -Encoding ascii $m4r
if (Test-Path $chatR) { Get-Content $chatR | Add-Content $m4r }
J "MAP4=$map4 RECEIPT=$m4r EXIT=$ec4"

$ec5 = Run-Step 'MAP5_SESSION_LOOP' (Join-Path $OutDir '_issue49_session_loop_e2e_4DE0.ps1') @()
$m5r = Join-Path $OutDir 'ISSUE49_SESSION_LOOP_RECEIPT.txt'
$map5 = 'FAIL'
if (Test-Path $m5r) {
  $s5 = Get-Content $m5r -Raw
  if ($s5 -match 'TIP_SHA256=4DE0' -and $s5 -match 'SESSION_LOOP=PASS') { $map5 = 'PASS' }
}
J "MAP5=$map5 RECEIPT=$m5r EXIT=$ec5"

$ec6 = Run-Step 'MAP6_CANCEL' (Join-Path $OutDir '_issue49_cancel_recovery_e2e_4DE0.ps1') @()
$m6r = Join-Path $OutDir 'ISSUE49_CANCEL_RECOVERY_RECEIPT.txt'
$map6 = 'FAIL'
if (Test-Path $m6r) {
  if ((Select-String -Path $m6r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m6r -Pattern 'MAP6=PASS' -Quiet)) { $map6 = 'PASS' }
}
J "MAP6=$map6 RECEIPT=$m6r EXIT=$ec6"

$ec7 = Run-Step 'MAP7_PERSIST' (Join-Path $OutDir '_issue49_session_persistence_e2e_4DE0.ps1') @()
$m7r = Join-Path $OutDir 'ISSUE49_SESSION_PERSISTENCE_RECEIPT.txt'
$map7 = 'FAIL'
if (Test-Path $m7r) {
  if ((Select-String -Path $m7r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m7r -Pattern 'MAP7=PASS' -Quiet)) { $map7 = 'PASS' }
}
J "MAP7=$map7 RECEIPT=$m7r EXIT=$ec7"

$ec8 = Run-Step 'MAP8_EXT' (Join-Path $OutDir '_issue49_extension_lifecycle_e2e_4DE0.ps1') @()
$m8r = Join-Path $OutDir 'ISSUE49_EXTENSION_LIFECYCLE_RECEIPT.txt'
$map8 = 'FAIL'
if (Test-Path $m8r) {
  if ((Select-String -Path $m8r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m8r -Pattern 'MAP8=PASS' -Quiet)) { $map8 = 'PASS' }
}
J "MAP8=$map8 RECEIPT=$m8r EXIT=$ec8"

$ec9 = Run-Step 'MAP9_CLEAN_EXIT' (Join-Path $OutDir '_issue49_clean_exit_e2e_4DE0.ps1') @()
$m9r = Join-Path $OutDir 'ISSUE49_CLEAN_EXIT_RECEIPT.txt'
$map9 = 'FAIL'
if (Test-Path $m9r) {
  if ((Select-String -Path $m9r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m9r -Pattern 'MAP9=PASS' -Quiet)) { $map9 = 'PASS' }
}
J "MAP9=$map9 RECEIPT=$m9r EXIT=$ec9"

$ec10 = Run-Step 'MAP10_REPEATED' (Join-Path $OutDir '_issue49_repeated_use_e2e_4DE0.ps1') @()
$m10r = Join-Path $OutDir 'ISSUE49_REPEATED_USE_RECEIPT.txt'
$map10 = 'FAIL'
if (Test-Path $m10r) {
  if ((Select-String -Path $m10r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m10r -Pattern 'MAP10=PASS' -Quiet)) { $map10 = 'PASS' }
}
J "MAP10=$map10 RECEIPT=$m10r EXIT=$ec10"

$ec11 = Run-Step 'MAP11_PKG' (Join-Path $OutDir '_issue49_package_clean_rollback_e2e_4DE0.ps1') @()
$m11r = Join-Path $OutDir 'ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt'
$map11 = 'FAIL'
if (Test-Path $m11r) {
  if ((Select-String -Path $m11r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m11r -Pattern 'MAP11=PASS' -Quiet)) { $map11 = 'PASS' }
}
J "MAP11=$map11 RECEIPT=$m11r EXIT=$ec11"

$maps = @($map1,$map2,$map3,$map4,$map5,$map6,$map7,$map8,$map9,$map10,$map11)
$passN = ($maps | Where-Object { $_ -eq 'PASS' }).Count
$failMaps = @()
for ($i=0; $i -lt 11; $i++) { if ($maps[$i] -ne 'PASS') { $failMaps += [string]($i+1) } }
$oneSha = if ($passN -eq 11) { 'PASS' } elseif ($passN -eq 0) { 'FAIL' } else { 'PARTIAL' }
$major = if ($oneSha -eq 'PASS') { 'DEMONSTRATED' } else { 'NOT_DEMONSTRATED' }
$debt = if ($oneSha -eq 'PASS') { 'CLOSED' } else { "OPEN fail_maps=$($failMaps -join ',')" }
$next = if ($oneSha -eq 'PASS') {
  'ONE_SHA 1-11 measured PASS on 4DE0; PROMOTE=0 PRODUCT_PASS=0 CERTIFIED=0 held; P3 four-panel separate seal'
} else {
  "ONE_SHA remasure maps $($failMaps -join ',') still FAIL/OPEN on 4DE0 (NO_CROSS_SHA_PASS; 5A34 historical only)"
}

$tipFinal = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$shaFinalOk = ($tipFinal -eq $ExpectSha)
if (-not $shaFinalOk) { J "SHA_SUPERSEDED mid-flight FINAL=$tipFinal"; $oneSha = 'FAIL'; $major = 'NOT_DEMONSTRATED'; $debt = 'OPEN SHA_SUPERSEDED'; $next = "SHA_SUPERSEDED tip now $tipFinal; remasure on new tip" }
J "ONE_SHA_1_11=$oneSha PASS_COUNT=$passN/11 MAJOR=$major TIP_FINAL=$tipFinal"

@"
ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
ACTIVE_TRACK=ISSUE_49
CANDIDATE=tip_integ_candidate_001
RUN_ID=$RunId
SUITE_STAMP=$Stamp
TIP_EXE=$TipExe
TIP_SHA256=$Sha
TIP_FINAL=$tipFinal
SHA_VERIFY=$(if($Sha -eq $ExpectSha -and $tipFinal -eq $ExpectSha){'PASS'}else{'FAIL'})
NO_CROSS_SHA_PASS=1
HISTORICAL_5A34_MAJOR=SEAL_ONLY_NO_INHERIT
P3_FOUR_PANEL=PASS
P3_RECEIPT=artifacts\ISSUE49_P3_FOUR_PANEL_4DE0_RECEIPT.txt
P3_NOTE=ORDERED_BLOCKER seal separate from maps 1-11; not substituted
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82
E6CF_RESTORE=HELD

## Maps 1-11 (remeasured on 4DE0)
MAP1_OPEN_EDIT_SAVE=$map1
MAP1_RECEIPT=$m1r
MAP2_COMPILE_LINK_RUN=$map2
MAP2_RECEIPT=$(Join-Path $OutDir 'ISSUE49_COMPILE_LINK_RUN_RECEIPT.txt')
MAP2_PIPELINE=$map2Detail
MAP3_OUTPUT_PROBLEMS_CLICK=$map3
MAP3_RECEIPT=$m3r
MAP4_CHAT_MODEL_RESPONSE=$map4
MAP4_RECEIPT=$m4r
MAP5_AGENT_TOOL_DURABLE_FS=$map5
MAP5_RECEIPT=$m5r
MAP6_CANCEL_RECOVERY=$map6
MAP6_RECEIPT=$m6r
MAP7_SESSION_PERSISTENCE=$map7
MAP7_RECEIPT=$m7r
MAP8_EXTENSION_LIFECYCLE=$map8
MAP8_RECEIPT=$m8r
MAP9_CLEAN_EXIT=$map9
MAP9_RECEIPT=$m9r
MAP10_REPEATED_USE=$map10
MAP10_RECEIPT=$m10r
MAP11_PACKAGE_CLEAN_ROLLBACK=$map11
MAP11_RECEIPT=$m11r

## Conjunction
ISSUE49_MAP_COUNT=$passN/11
ONE_SHA_1_11=$oneSha
ONE_SHA_PASS_COUNT=$passN/11
FAIL_MAPS=$($failMaps -join ',')
ISSUE49_ONE_SHA_DEBT=$debt
MAJOR_INTEGRATED_ACCEPTANCE=$major
NOTE=11/11 on 4DE0 only closes ONE_SHA debt; != PRODUCT_PASS != PROMOTE; 5A34 historical no inherit
NEXT_GAP=$next
JOURNAL=$Journal
PROMOTE=0
"@ | Set-Content -Encoding ascii $Receipt

Write-Host "==== ONE_SHA_REMEASURE_4DE0 ===="
Get-Content $Receipt
exit $(if ($oneSha -eq 'PASS') { 0 } else { 1 })

#Requires -Version 5.1
# ISSUE49 ONE_SHA remasure maps 1-8 on tip SHA 5A34B393… (NO_CROSS_SHA_PASS).
# Maps 9-11 already PASS on 5A34 — cite existing receipts; do not weaken.
# Laws: PROMOTE=0 PRODUCT_PASS=0 CERTIFIED=0 MATURITY=82 E6CF HELD; NOT_RUN!=PASS.
$ErrorActionPreference = 'Continue'
$ExpectSha = '5A34B393ECF7380576CE718C688DC4006C0E3B01090BB4DCD8B844FB594D1619'
$EvidenceRoot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$TipExe = Join-Path $EvidenceRoot 'package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$OutDir = Join-Path $EvidenceRoot 'artifacts'
$HarnessDir = Join-Path $EvidenceRoot 'harness'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "integ_one_sha_1_8_run_$Stamp"
$Journal = Join-Path $OutDir 'ISSUE49_ONE_SHA_REMEASURE_5A34_JOURNAL.txt'
$Receipt = Join-Path $OutDir 'ISSUE49_ONE_SHA_REMEASURE_5A34_RECEIPT.txt'
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
  # Avoid Start-Process -Wait -NoNewWindow hang after child exit.
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

$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
J "RUN_ID=$RunId EXPECT=$ExpectSha MEASURED=$Sha TIP=$TipExe"
if ($Sha -ne $ExpectSha) {
  J "SHA_DRIFT FAIL"
  @"
ISSUE49_ONE_SHA_REMEASURE_5A34_RECEIPT
TIP_SHA256=$Sha
EXPECTED=$ExpectSha
SHA_VERIFY=FAIL
ONE_SHA_1_8=FAIL
MAPS=NOT_RUN
PROMOTE=0
"@ | Set-Content -Encoding ascii $Receipt
  exit 9
}
J "SHA_VERIFY=PASS"

# Cite sealed maps 9-11 (do not re-run / weaken)
$map9r = Join-Path $OutDir 'ISSUE49_CLEAN_EXIT_RECEIPT.txt'
$map10r = Join-Path $OutDir 'ISSUE49_REPEATED_USE_RECEIPT.txt'
$map11r = Join-Path $OutDir 'ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt'
$map9 = if ((Test-Path $map9r) -and (Select-String -Path $map9r -Pattern 'TIP_SHA256=5A34' -Quiet) -and (Select-String -Path $map9r -Pattern 'MAP9=PASS' -Quiet)) { 'PASS' } else { 'SEAL_MISS' }
$map10 = if ((Test-Path $map10r) -and (Select-String -Path $map10r -Pattern 'TIP_SHA256=5A34' -Quiet) -and (Select-String -Path $map10r -Pattern 'MAP10=PASS' -Quiet)) { 'PASS' } else { 'SEAL_MISS' }
$map11 = if ((Test-Path $map11r) -and (Select-String -Path $map11r -Pattern 'TIP_SHA256=5A34' -Quiet) -and (Select-String -Path $map11r -Pattern 'MAP11=PASS' -Quiet)) { 'PASS' } else { 'SEAL_MISS' }
J "CITE_MAP9=$map9 RECEIPT=$map9r"
J "CITE_MAP10=$map10 RECEIPT=$map10r"
J "CITE_MAP11=$map11 RECEIPT=$map11r"

# --- Map 2 first (no IDE conflict): native MSVC compile/link/run ---
$bpScript = Join-Path $HarnessDir 'run_build_pipeline_gate.ps1'
$ec2 = Run-Step 'MAP2_BUILD_PIPELINE' $bpScript @()
$bpReceipt = Join-Path $OutDir 'BUILD_PIPELINE_RECEIPT.txt'
# Prefer latest logs receipt if present
$bpLog = Get-ChildItem (Join-Path $EvidenceRoot 'logs\build_pipeline\build_pipeline_receipt_*.txt') -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
$map2 = 'FAIL'
$map2Detail = 'NOT_RUN'
if ($bpLog) {
  $bpTxt = Get-Content $bpLog.FullName -Raw
  if ($bpTxt -match 'BUILD_PIPELINE_OFFLINE=PASS' -or $bpTxt -match 'BUILD_PIPELINE_OVERALL=PASS' -or ($bpTxt -match 'BP_HELLO_OK' -and $bpTxt -match 'OFFLINE_CASE_PASS_COUNT=7/7')) { $map2 = 'PASS' }
  $map2Detail = $bpLog.FullName
  # Bind tip SHA into a dedicated map2 receipt
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
NOTE=Native MSVC path remasure bound to tip SHA under remasure (IDE HWND map3 separate)
NO_CROSS_SHA_PASS=1
PROMOTE=0
"@ | Set-Content -Encoding ascii $m2r
  J "MAP2=$map2 RECEIPT=$m2r"
} else {
  J "MAP2=FAIL MISSING_PIPELINE_RECEIPT EXIT=$ec2"
}

# --- Map 1 OES ---
$ec1 = Run-Step 'MAP1_OES' (Join-Path $OutDir '_issue49_oes_e2e.ps1') @()
$m1r = Join-Path $OutDir 'ISSUE49_OES_RECEIPT.txt'
$map1 = 'FAIL'
if (Test-Path $m1r) {
  if (Select-String -Path $m1r -Pattern 'MAP1=PASS' -Quiet) { $map1 = 'PASS' }
}
J "MAP1=$map1 RECEIPT=$m1r EXIT=$ec1"

# --- Map 3 Output/Problems/click-to-line (also exercises IDE build HWND / MSVC diags) ---
$hwndOut = Join-Path $EvidenceRoot "candidates\tip_integ_candidate_001\map3_hwnd_$Stamp"
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
  if ($h -match 'TIP_SHA=5A34' -and $h -match 'OUTPUT_HWND=PASS' -and $h -match 'PROBLEMS_HWND=PASS' -and $h -match 'CLICK_TO_LINE=POSTED_NM_DBLCLK') { $map3 = 'PASS' }
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

# --- Map 4 Chat model response ---
$ec4 = Run-Step 'MAP4_CHAT' (Join-Path $OutDir '_chat_e2e_uncanceled_5A34.ps1') @()
$chatR = Join-Path $OutDir 'INTEG_CANDIDATE_001_CHAT_E2E_UNCANCELED_RECEIPT.txt'
$map4 = 'FAIL'
if (Test-Path $chatR) {
  $c = Get-Content $chatR -Raw
  if ($c -match 'TIP_SHA256=5A34' -and $c -match 'E2E_CHAT_RESPONSE_CORRELATED=PASS' -and $c -match 'E2E_UNCANCELED_CHAT=PASS') { $map4 = 'PASS' }
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
HARNESS=artifacts\_chat_e2e_uncanceled_5A34.ps1
NO_CROSS_SHA_PASS=1
PROMOTE=0
"@ | Set-Content -Encoding ascii $m4r
if (Test-Path $chatR) { Get-Content $chatR | Add-Content $m4r }
J "MAP4=$map4 RECEIPT=$m4r EXIT=$ec4"

# --- Map 5 Session loop / agent durable FS ---
$ec5 = Run-Step 'MAP5_SESSION_LOOP' (Join-Path $OutDir '_issue49_session_loop_e2e.ps1') @()
$m5r = Join-Path $OutDir 'ISSUE49_SESSION_LOOP_RECEIPT.txt'
$map5 = 'FAIL'
if (Test-Path $m5r) {
  $s5 = Get-Content $m5r -Raw
  if ($s5 -match 'TIP_SHA256=5A34' -and $s5 -match 'SESSION_LOOP=PASS') { $map5 = 'PASS' }
}
J "MAP5=$map5 RECEIPT=$m5r EXIT=$ec5"

# --- Map 6 Cancel/recovery ---
$ec6 = Run-Step 'MAP6_CANCEL' (Join-Path $OutDir '_issue49_cancel_recovery_e2e.ps1') @()
$m6r = Join-Path $OutDir 'ISSUE49_CANCEL_RECOVERY_RECEIPT.txt'
$map6 = 'FAIL'
if (Test-Path $m6r) {
  if ((Select-String -Path $m6r -Pattern 'TIP_SHA256=5A34' -Quiet) -and (Select-String -Path $m6r -Pattern 'MAP6=PASS' -Quiet)) { $map6 = 'PASS' }
}
J "MAP6=$map6 RECEIPT=$m6r EXIT=$ec6"

# --- Map 7 Session persistence ---
$ec7 = Run-Step 'MAP7_PERSIST' (Join-Path $OutDir '_issue49_session_persistence_e2e.ps1') @()
$m7r = Join-Path $OutDir 'ISSUE49_SESSION_PERSISTENCE_RECEIPT.txt'
$map7 = 'FAIL'
if (Test-Path $m7r) {
  if ((Select-String -Path $m7r -Pattern 'TIP_SHA256=5A34' -Quiet) -and (Select-String -Path $m7r -Pattern 'MAP7=PASS' -Quiet)) { $map7 = 'PASS' }
}
J "MAP7=$map7 RECEIPT=$m7r EXIT=$ec7"

# --- Map 8 Extension lifecycle ---
$ec8 = Run-Step 'MAP8_EXT' (Join-Path $OutDir '_issue49_extension_lifecycle_e2e.ps1') @()
$m8r = Join-Path $OutDir 'ISSUE49_EXTENSION_LIFECYCLE_RECEIPT.txt'
$map8 = 'FAIL'
if (Test-Path $m8r) {
  if ((Select-String -Path $m8r -Pattern 'TIP_SHA256=5A34' -Quiet) -and (Select-String -Path $m8r -Pattern 'MAP8=PASS' -Quiet)) { $map8 = 'PASS' }
}
J "MAP8=$map8 RECEIPT=$m8r EXIT=$ec8"

$pass18 = @($map1,$map2,$map3,$map4,$map5,$map6,$map7,$map8) | Where-Object { $_ -eq 'PASS' }
$failMaps = @()
if ($map1 -ne 'PASS') { $failMaps += '1' }
if ($map2 -ne 'PASS') { $failMaps += '2' }
if ($map3 -ne 'PASS') { $failMaps += '3' }
if ($map4 -ne 'PASS') { $failMaps += '4' }
if ($map5 -ne 'PASS') { $failMaps += '5' }
if ($map6 -ne 'PASS') { $failMaps += '6' }
if ($map7 -ne 'PASS') { $failMaps += '7' }
if ($map8 -ne 'PASS') { $failMaps += '8' }
$oneSha = if ($pass18.Count -eq 8) { 'PASS' } elseif ($pass18.Count -eq 0) { 'FAIL' } else { 'PARTIAL' }
$conj1111 = ($oneSha -eq 'PASS' -and $map9 -eq 'PASS' -and $map10 -eq 'PASS' -and $map11 -eq 'PASS')
$major = if ($conj1111) { 'DEMONSTRATED' } else { 'NOT_DEMONSTRATED' }
$debt = if ($oneSha -eq 'PASS') { 'CLOSED' } else { "OPEN fail_maps=$($failMaps -join ',')" }
$next = if ($oneSha -eq 'PASS') {
  if ($major -eq 'DEMONSTRATED') { 'ONE_SHA 1-11 conjunction measured on 5A34; PROMOTE still 0 / PRODUCT_PASS=0' }
  else { 'Cite/repair map9-11 seal miss before MAJOR_INTEGRATED_ACCEPTANCE' }
} else { "ONE_SHA remasure maps $($failMaps -join ',') still FAIL/OPEN on 5A34 (NO_CROSS_SHA_PASS)" }

$tipFinal = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
J "ONE_SHA_1_8=$oneSha PASS_COUNT=$($pass18.Count)/8 MAJOR=$major TIP_FINAL=$tipFinal"

@"
ISSUE49_ONE_SHA_REMEASURE_5A34_RECEIPT
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
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82
E6CF_RESTORE=HELD

## Maps 1-8 (remeasured on 5A34)
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

## Maps 9-11 (cited seals on 5A34 — not weakened)
MAP9_CLEAN_EXIT=$map9
MAP9_RECEIPT=$map9r
MAP10_REPEATED_USE=$map10
MAP10_RECEIPT=$map10r
MAP11_PACKAGE_CLEAN_ROLLBACK=$map11
MAP11_RECEIPT=$map11r

## Conjunction
ISSUE49_MAP_COUNT=11/11
ONE_SHA_1_8=$oneSha
ONE_SHA_PASS_COUNT=$($pass18.Count)/8
FAIL_MAPS=$($failMaps -join ',')
ONE_SHA_REMEASURE_DEBT_MAPS_1_8=$debt
MAJOR_INTEGRATED_ACCEPTANCE=$major
NOTE=11/11 map-count != PRODUCT_PASS != PROMOTE; MAJOR only if 1-11 all PASS measured on same SHA
NEXT_GAP=$next
JOURNAL=$Journal
PROMOTE=0
"@ | Set-Content -Encoding ascii $Receipt

Write-Host "==== ONE_SHA_REMEASURE ===="
Get-Content $Receipt
exit $(if ($oneSha -eq 'PASS') { 0 } else { 1 })

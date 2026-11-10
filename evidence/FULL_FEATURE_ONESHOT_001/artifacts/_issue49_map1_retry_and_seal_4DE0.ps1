#Requires -Version 5.1
# Retry map1 only on 4DE0; if PASS, rewrite ONE_SHA batch receipt to closed conjunction.
$ErrorActionPreference = 'Continue'
$ExpectSha = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$EvidenceRoot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$OutDir = Join-Path $EvidenceRoot 'artifacts'
$TipExe = Join-Path $EvidenceRoot 'package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$Journal = Join-Path $OutDir 'ISSUE49_ONE_SHA_REMEASURE_4DE0_JOURNAL.txt'
$Receipt = Join-Path $OutDir 'ISSUE49_ONE_SHA_REMEASURE_4DE0_RECEIPT.txt'
function J([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Encoding ascii $Journal $line
  Write-Host $line
}
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
J "MAP1_RETRY BEGIN EXPECT=$ExpectSha MEASURED=$Sha"
if ($Sha -ne $ExpectSha) { J "SHA_DRIFT"; exit 9 }

$script = Join-Path $OutDir '_issue49_oes_e2e_4DE0.ps1'
$p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$script) -PassThru -WindowStyle Hidden
while (-not $p.HasExited) { Start-Sleep 1; try { $p.Refresh() } catch {} }
$ec = [int]$p.ExitCode
$m1r = Join-Path $OutDir 'ISSUE49_OES_RECEIPT.txt'
$map1 = 'FAIL'
if (Test-Path $m1r) {
  if ((Select-String -Path $m1r -Pattern 'TIP_SHA256=4DE0' -Quiet) -and (Select-String -Path $m1r -Pattern 'MAP1=PASS' -Quiet)) { $map1 = 'PASS' }
}
J "MAP1_RETRY END EXIT=$ec MAP1=$map1"

# Re-score maps 2-11 from existing 4DE0 receipts (do not invent)
function MapPass([string]$path, [string]$shaPat, [string]$passPat) {
  if (-not (Test-Path $path)) { return 'FAIL' }
  if ((Select-String -Path $path -Pattern $shaPat -Quiet) -and (Select-String -Path $path -Pattern $passPat -Quiet)) { return 'PASS' }
  return 'FAIL'
}
$map2 = MapPass (Join-Path $OutDir 'ISSUE49_COMPILE_LINK_RUN_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP2=PASS'
$map3 = MapPass (Join-Path $OutDir 'ISSUE49_OUTPUT_PROBLEMS_HWND_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP3=PASS'
$map4 = MapPass (Join-Path $OutDir 'ISSUE49_E2E_CHAT_RESPONSE_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP4=PASS'
$map5 = MapPass (Join-Path $OutDir 'ISSUE49_SESSION_LOOP_RECEIPT.txt') 'TIP_SHA256=4DE0' 'SESSION_LOOP=PASS'
$map6 = MapPass (Join-Path $OutDir 'ISSUE49_CANCEL_RECOVERY_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP6=PASS'
$map7 = MapPass (Join-Path $OutDir 'ISSUE49_SESSION_PERSISTENCE_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP7=PASS'
$map8 = MapPass (Join-Path $OutDir 'ISSUE49_EXTENSION_LIFECYCLE_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP8=PASS'
$map9 = MapPass (Join-Path $OutDir 'ISSUE49_CLEAN_EXIT_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP9=PASS'
$map10 = MapPass (Join-Path $OutDir 'ISSUE49_REPEATED_USE_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP10=PASS'
$map11 = MapPass (Join-Path $OutDir 'ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt') 'TIP_SHA256=4DE0' 'MAP11=PASS'

$maps = @($map1,$map2,$map3,$map4,$map5,$map6,$map7,$map8,$map9,$map10,$map11)
$passN = ($maps | Where-Object { $_ -eq 'PASS' }).Count
$failMaps = @(); for ($i=0; $i -lt 11; $i++) { if ($maps[$i] -ne 'PASS') { $failMaps += [string]($i+1) } }
$oneSha = if ($passN -eq 11) { 'PASS' } elseif ($passN -eq 0) { 'FAIL' } else { 'PARTIAL' }
$major = if ($oneSha -eq 'PASS') { 'DEMONSTRATED' } else { 'NOT_DEMONSTRATED' }
$debt = if ($oneSha -eq 'PASS') { 'CLOSED' } else { "OPEN fail_maps=$($failMaps -join ',')" }
$next = if ($oneSha -eq 'PASS') {
  'ONE_SHA 1-11 measured PASS on 4DE0; PROMOTE=0 PRODUCT_PASS=0 CERTIFIED=0 held; P3 four-panel separate seal'
} else {
  "ONE_SHA remasure maps $($failMaps -join ',') still FAIL/OPEN on 4DE0 (NO_CROSS_SHA_PASS; 5A34 historical only)"
}
$tipFinal = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "integ_one_sha_1_11_4DE0_map1retry_$Stamp"
J "ONE_SHA_1_11=$oneSha PASS_COUNT=$passN/11 MAJOR=$major"

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
MAP1_RETRY=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82
E6CF_RESTORE=HELD

## Maps 1-11 (remeasured on 4DE0)
MAP1_OPEN_EDIT_SAVE=$map1
MAP1_RECEIPT=$(Join-Path $OutDir 'ISSUE49_OES_RECEIPT.txt')
MAP2_COMPILE_LINK_RUN=$map2
MAP2_RECEIPT=$(Join-Path $OutDir 'ISSUE49_COMPILE_LINK_RUN_RECEIPT.txt')
MAP3_OUTPUT_PROBLEMS_CLICK=$map3
MAP3_RECEIPT=$(Join-Path $OutDir 'ISSUE49_OUTPUT_PROBLEMS_HWND_RECEIPT.txt')
MAP4_CHAT_MODEL_RESPONSE=$map4
MAP4_RECEIPT=$(Join-Path $OutDir 'ISSUE49_E2E_CHAT_RESPONSE_RECEIPT.txt')
MAP5_AGENT_TOOL_DURABLE_FS=$map5
MAP5_RECEIPT=$(Join-Path $OutDir 'ISSUE49_SESSION_LOOP_RECEIPT.txt')
MAP6_CANCEL_RECOVERY=$map6
MAP6_RECEIPT=$(Join-Path $OutDir 'ISSUE49_CANCEL_RECOVERY_RECEIPT.txt')
MAP7_SESSION_PERSISTENCE=$map7
MAP7_RECEIPT=$(Join-Path $OutDir 'ISSUE49_SESSION_PERSISTENCE_RECEIPT.txt')
MAP8_EXTENSION_LIFECYCLE=$map8
MAP8_RECEIPT=$(Join-Path $OutDir 'ISSUE49_EXTENSION_LIFECYCLE_RECEIPT.txt')
MAP9_CLEAN_EXIT=$map9
MAP9_RECEIPT=$(Join-Path $OutDir 'ISSUE49_CLEAN_EXIT_RECEIPT.txt')
MAP10_REPEATED_USE=$map10
MAP10_RECEIPT=$(Join-Path $OutDir 'ISSUE49_REPEATED_USE_RECEIPT.txt')
MAP11_PACKAGE_CLEAN_ROLLBACK=$map11
MAP11_RECEIPT=$(Join-Path $OutDir 'ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt')

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
Get-Content $Receipt
exit $(if ($oneSha -eq 'PASS') { 0 } else { 1 })

#Requires -Version 5.1
# Issue #49 map #8 — extension load→activate→deactivate→shutdown (FORCE_KILL=0)
# on tip_integ_candidate_001 (4DE0). Prefer harness\ext_smoke_oneshot.ps1.
# Laws: PROMOTE=0 MATURITY=82 E6CF HELD; NOT_RUN!=PASS; NO_CROSS_SHA_PASS; H51≠MAP8.
$ErrorActionPreference = 'Continue'
$ExpectSha = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$EvidenceRoot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$TipExe = Join-Path $EvidenceRoot 'package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$ExtEvidence = 'F:\rawrxd\evidence\FULL_FEATURE_EXTENSIONHOST_001'
$OutDir = Join-Path $EvidenceRoot 'artifacts'
$Harness = Join-Path $EvidenceRoot 'harness\ext_smoke_oneshot.ps1'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "integ_map8_run_$Stamp"
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) {
  Write-Host "SHA_DRIFT=$Sha expected=$ExpectSha"
  exit 9
}

New-Item -ItemType Directory -Force -Path $OutDir,(Join-Path $ExtEvidence 'logs') | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1

& powershell -NoProfile -ExecutionPolicy Bypass -File $Harness `
  -TipExe $TipExe -EvidenceRoot $EvidenceRoot -ExtEvidence $ExtEvidence
$harnessExit = $LASTEXITCODE

$summary = Get-ChildItem (Join-Path $OutDir 'ext_smoke_summary_*.json') |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
$runlog = $null
$init=$load=$act=$cmd=$deact=$reload=$mal=$null
$tipShaFromSummary = $null
if ($summary) {
  $j = Get-Content $summary.FullName -Raw | ConvertFrom-Json
  $init = $j.init; $load = $j.load; $act = $j.activate; $cmd = $j.cmd
  $deact = $j.deactivate; $reload = $j.reload; $mal = $j.malformed_fault
  $runlog = $j.runlog; $tipShaFromSummary = $j.tip_sha
}

$forceKill = 1
$exitA = -1
$pidA = 0
$hwndA = '0x0'
$orphans = @(Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue).Count
if ($runlog -and (Test-Path $runlog)) {
  foreach ($line in Get-Content $runlog) {
    if ($line -match 'SMOKE_A_PID=(\d+)') { $pidA = [int]$Matches[1] }
    if ($line -match 'SMOKE_A_EXIT=(-?\d+)\s+FORCE_KILL=(\d+)\s+HWND=(0x[0-9A-Fa-f]+)') {
      $exitA = [int]$Matches[1]; $forceKill = [int]$Matches[2]; $hwndA = $Matches[3]
    }
  }
}

$map8 = 'FAIL'
if ($Sha -eq $ExpectSha -and $load -eq '1' -and $act -eq '1' -and $deact -eq '1' `
    -and $forceKill -eq 0 -and $exitA -eq 0 -and $orphans -eq 0 -and $harnessExit -eq 0) {
  $map8 = 'PASS'
}

$receipt = Join-Path $OutDir 'ISSUE49_EXTENSION_LIFECYCLE_RECEIPT.txt'
@"
ISSUE49_EXTENSION_LIFECYCLE_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
ACTIVE_TRACK=ISSUE_49
MAP=8
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$Sha
TIP_EXE=$TipExe
SUITE_STAMP=$Stamp
RUN_ID=$RunId
MAIN_HWND=$hwndA
PID_A=$pidA
HARNESS=harness\ext_smoke_oneshot.ps1
WRAPPER=artifacts\_issue49_extension_lifecycle_e2e.ps1
FIXTURE=fixtures\ext_hello
EXTENSION_ID=rawrxd.ext-hello
RUNLOG=$runlog
SUMMARY=$($summary.FullName)
NO_CROSS_SHA_PASS=1
H51_REGISTER_NE_MAP8=1
PROMOTE=0
MATURITY=82
E6CF_RESTORE=HELD

## SHA gate
SHA_VERIFY=$(if($Sha -eq $ExpectSha){'PASS'}else{'FAIL'})
EXPECTED=$ExpectSha
MEASURED=$Sha
SUMMARY_SHA=$tipShaFromSummary

## Load → activate → deactivate
INIT_OK=$init
LOAD_OK=$load
ACTIVATE_OK=$act
CMD_OK=$cmd
DEACTIVATE_OK=$deact
RELOAD_OK=$reload

## Shutdown (FORCE_KILL=0)
SMOKE_A_EXIT=$exitA
FORCE_KILL=$forceKill
ORPHANS_POST=$orphans
HARNESS_EXIT=$harnessExit
MALFORMED_FAULT=$mal

## Disposition
MAP8=$map8
NEXT_GAP=$(if($map8 -eq 'PASS'){'Map #9 Clean exit (no orphan workers)'}else{'Map #8 Extension load -> activate -> deactivate -> shutdown (FORCE_KILL=0)'})
PROMOTE=0
"@ | Set-Content -Encoding ascii $receipt

Write-Host "RECEIPT=$receipt"
Write-Host "MAP8=$map8"
exit $(if ($map8 -eq 'PASS') { 0 } else { 1 })

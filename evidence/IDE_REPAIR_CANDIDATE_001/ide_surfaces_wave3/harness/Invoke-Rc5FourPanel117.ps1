# Wave3 wrapper: four_panel 1-17 against RC5/RC5B Ext.
# Non-conflicting: does not edit ComputerUse/AgentCommands; writes under ide_surfaces_wave3 only.
# PROMOTE=0 · NO_CROSS_SHA_PASS_INHERITANCE=1 · NOT_RUN!=PASS
param(
  [ValidateSet('rc5b','rc5','custom')]
  [string]$Lineage = 'rc5b',
  [string]$TipExe = '',
  [switch]$SkipIfIssue49Lock
)
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\ide_surfaces_wave3'
$Primary = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\four_panel_1_17_measure.ps1'
$OutDir = Join-Path $Root 'artifacts'
$LogDir = Join-Path $Root 'candidates\four_panel_run'
$Broken = Join-Path $Root 'fixtures\broken_multi.cpp'
$Fixed = Join-Path $Root 'fixtures\fixed_multi.cpp'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null

$lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
if ($SkipIfIssue49Lock -and (Test-Path -LiteralPath $lock)) {
  Write-Host 'SKIP: ISSUE49_EXCLUSIVE.lock present'
  exit 0
}

switch ($Lineage) {
  'rc5b' {
    if (-not $TipExe) {
      $TipExe = 'F:\rawrxd\release\RawrXD-readiness-rc5b\RawrXD-Win32IDE-Native-Ext.exe'
    }
  }
  'rc5' {
    if (-not $TipExe) {
      $TipExe = 'F:\rawrxd\release\RawrXD-readiness-rc5\RawrXD-Win32IDE-Native-Ext.exe'
    }
  }
  'custom' {
    if (-not $TipExe) { throw 'custom lineage requires -TipExe' }
  }
}
if (-not (Test-Path -LiteralPath $TipExe)) { throw "TipExe missing: $TipExe" }
if (-not (Test-Path -LiteralPath $Primary)) { throw "Primary harness missing: $Primary" }

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$bind = Join-Path $OutDir ("SHA_BIND_$stamp.txt")
@(
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
  "SWARM=W3"
  "LINEAGE=$Lineage"
  "TIP_EXE=$TipExe"
  "TIP_SHA256=$sha"
  "PRIMARY_HARNESS=$Primary"
  "OUT_DIR=$OutDir"
  "LOG_DIR=$LogDir"
  "PROMOTE=0"
  "NO_CROSS_SHA_PASS_INHERITANCE=1"
  "WAVE1_TU_EDIT=0"
) | Set-Content -LiteralPath $bind -Encoding ASCII

Write-Host "WAVE3_FOUR_PANEL_INVOKE SHA=$sha LINEAGE=$Lineage"
& powershell -NoProfile -ExecutionPolicy Bypass -File $Primary `
  -TipExe $TipExe `
  -BrokenCpp $Broken `
  -FixedCpp $Fixed `
  -OutDir $OutDir `
  -LogDir $LogDir
$code = $LASTEXITCODE

$generic = Join-Path $OutDir 'FOUR_PANEL_1_17_RECEIPT.txt'
$boundReceipt = Join-Path $OutDir ("FOUR_PANEL_1_17_RECEIPT_{0}.txt" -f $sha.Substring(0,8))
if (Test-Path -LiteralPath $generic) {
  Copy-Item -LiteralPath $generic -Destination $boundReceipt -Force
  Add-Content -LiteralPath $boundReceipt -Value "`r`nWAVE3_SHA256=$sha`r`nWAVE3_LINEAGE=$Lineage`r`nPROMOTE=0`r`nNO_INHERIT=1"
}

$disp = Join-Path $OutDir ("WAVE3_FOUR_PANEL_DISPOSITION_$stamp.txt")
$verdict = if ($code -eq 0) { 'HARNESS_EXIT_0_SEE_RECEIPT_SCENARIOS' } else { "HARNESS_EXIT_$code" }
@(
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
  "TIP_SHA256=$sha"
  "LINEAGE=$Lineage"
  "HARNESS_EXIT=$code"
  "VERDICT_CLASS=$verdict"
  "NOTE=Inspect FOUR_PANEL_1_17_RECEIPT / scenario marks; NOT_RUN!=PASS; do not invent 17/17"
  "BOUND_RECEIPT=$boundReceipt"
  "PROMOTE=0"
) | Set-Content -LiteralPath $disp -Encoding ASCII
exit $code

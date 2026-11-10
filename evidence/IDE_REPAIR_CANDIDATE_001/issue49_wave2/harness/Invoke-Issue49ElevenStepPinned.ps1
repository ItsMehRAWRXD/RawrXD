# Wave2 Issue #49 — 11-step runner pinned to ONE Wave1-published SHA only.
# Until WAVE1_PUBLISH_SHA is set (or -ExpectSha passed), exits NOT_RUN.
# Does not inherit PASS from RC4 / 35C22 / tip_004 A1C591A6 / orphan CU verify.
param(
  [string]$ExpectSha = $env:WAVE1_PUBLISH_SHA,
  [string]$TipExe = "",
  [string]$PackageDir = "F:\rawrxd\release\RawrXD-readiness-rc5b",
  [string]$OutDir = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\step_receipts",
  [string]$ProjectCpp = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\fixtures\bug.cpp",
  [switch]$ForceStructuralProbe
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$receipt = Join-Path $OutDir "ISSUE49_11STEP_PINNED_$stamp.txt"

function Emit([string]$text) {
  Set-Content -LiteralPath $receipt -Value $text -Encoding UTF8
  Write-Host $text
}

if ([string]::IsNullOrWhiteSpace($ExpectSha)) {
  Emit @"
ISSUE49_11STEP=NOT_RUN
REASON=WAVE1_PUBLISH_SHA_ABSENT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
LANE_CONTROLLING_IDE_SHA=6E59E91A2D23A3BC666345DF5168F66DDCAC1FD1C25F46A64E33773EC78A4C4C
NOTE=Wave2 waits for Wave1 to publish a NEW SHA after rc5b; do not remeasure 6E59 as Wave2 seal
RC4_SHA=78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596
NO_RC4_MUTATION=1
NO_CROSS_SHA_INHERIT=1
PROMOTE=0
CERTIFIED=0
MATURITY_UNCHANGED=1
NEXT=Set WAVE1_PUBLISH_SHA or -ExpectSha then re-run this harness only
"@
  exit 2
}

$ExpectSha = $ExpectSha.Trim().ToUpperInvariant()
if ([string]::IsNullOrWhiteSpace($TipExe)) {
  $TipExe = Join-Path $PackageDir 'RawrXD-Win32IDE-Native-Ext.exe'
}
if (-not (Test-Path -LiteralPath $TipExe)) {
  Emit @"
ISSUE49_11STEP=NOT_RUN
REASON=TIP_EXE_MISSING
EXPECT_SHA=$ExpectSha
TIP_EXE=$TipExe
PROMOTE=0
"@
  exit 2
}

$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash.ToUpperInvariant()
if ($sha -ne $ExpectSha) {
  Emit @"
ISSUE49_11STEP=NOT_RUN
REASON=SHA_DRIFT
TIP_SHA256=$sha
EXPECT_SHA=$ExpectSha
TIP_EXE=$TipExe
PROMOTE=0
NO_CROSS_SHA_INHERIT=1
"@
  exit 3
}

# Structural probe only unless ForceStructuralProbe — full agent E2E is Wave1+runtime owned.
$bytes = [IO.File]::ReadAllBytes($TipExe)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$hasAgentSession = [int]($ascii.Contains('AgentSession'))
$hasAgenticLoop = [int]($ascii.Contains('AgenticLoop'))
$hasComputerUse = [int]($ascii.Contains('computer_use'))
$projOk = [int](Test-Path -LiteralPath $ProjectCpp)
$projHash = if ($projOk) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }

$steps = [ordered]@{
  '01_LAUNCH' = 'NOT_RUN_STRUCTURAL_ONLY'
  '04_OPEN_PROJECT' = $(if ($projOk) { 'FIXTURE_PRESENT_RUNTIME_NOT_RUN' } else { 'BLOCKED_NO_FIXTURE' })
  '05_AGENT_PROMPT' = 'NOT_RUN'
  '06_AGENT_READS_PROJECT' = 'NOT_RUN'
  '08_TOOL_AUTHORITY' = 'NOT_RUN'
  '10_REAL_SOURCE_EDIT' = 'NOT_RUN'
  '11_BUILD_FAILURE_RECOVERY' = 'NOT_RUN'
  '12_MODEL_DIAGNOSES_FAILURE' = 'NOT_RUN'
  '13_SECOND_EDIT' = 'NOT_RUN'
  '14_FINAL_BUILD' = 'NOT_RUN'
  '15_FINAL_TESTS' = 'NOT_RUN'
  'H57_AGENTSESSION' = $(if ($hasAgentSession) { 'PRESENT_IN_EXE_RUNTIME_NOT_RUN' } else { 'BLOCKED_NOT_LINKED' })
  'EXACTLY_ONCE' = 'NOT_VERIFIED_PRODUCT_PATH'
}

$passCount = 0
$measured = 0
foreach ($k in $steps.Keys) {
  $v = $steps[$k]
  if ($v -eq 'PASS') { $passCount++; $measured++ }
  elseif ($v -notmatch '^NOT_RUN') { $measured++ }
}

Emit @"
ISSUE49_11STEP=FAIL_CLOSED_STRUCTURAL_PROBE
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA256=$sha
EXPECT_SHA=$ExpectSha
TIP_EXE=$TipExe
PROJECT=$ProjectCpp
PROJECT_SHA256=$projHash
AgentSession_IN_EXE=$hasAgentSession
AgenticLoop_IN_EXE=$hasAgenticLoop
computer_use_STRING=$hasComputerUse
ISSUE49_MEASURED=$passCount/11
FORCE_STRUCTURAL=$([int][bool]$ForceStructuralProbe)
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
MATURITY_UNCHANGED=1
NO_CROSS_SHA_INHERIT=1
NO_RC4_MUTATION=1
NOTE=Pinned SHA matched; full 11-step agent E2E still NOT_RUN (Wave2 does not invent PASS)
$(($steps.GetEnumerator() | ForEach-Object { "STEP_$($_.Key)=$($_.Value)" }) -join "`n")
"@
exit 0

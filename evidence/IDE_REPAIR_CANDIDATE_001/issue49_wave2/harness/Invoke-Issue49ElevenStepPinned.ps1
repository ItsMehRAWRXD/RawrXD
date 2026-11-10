# Wave2 Issue #49 — 11-step runner pinned to ONE SHA only.
# Candidate lane: rc5b 6E59… when WAVE1_PUBLISH_SEAL absent; else seal SHA.
# Does not inherit PASS from RC4 / 35C22 / tip_004 A1C591A6 / orphan CU verify.
param(
  [string]$ExpectSha = $env:WAVE1_PUBLISH_SHA,
  [string]$TipExe = "",
  [string]$PackageDir = "F:\rawrxd\release\RawrXD-readiness-rc5b",
  [string]$OutDir = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\step_receipts",
  [string]$ProjectCpp = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\fixtures\bug.cpp",
  [string]$SealPath = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\WAVE1_PUBLISH_SEAL.txt",
  [string]$CandidateSha = "6E59E91A2D23A3BC666345DF5168F66DDCAC1FD1C25F46A64E33773EC78A4C4C",
  [switch]$ForceStructuralProbe,
  [switch]$UseCandidateLane
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$receipt = Join-Path $OutDir "ISSUE49_11STEP_PINNED_$stamp.txt"

function Emit([string]$text) {
  Set-Content -LiteralPath $receipt -Value $text -Encoding UTF8
  Copy-Item -LiteralPath $receipt -Destination (Join-Path $OutDir 'ISSUE49_11STEP_PINNED_LATEST.txt') -Force
  Write-Host $text
}

$sealPresent = Test-Path -LiteralPath $SealPath
$pinSource = 'ENV_OR_ARG'
if ([string]::IsNullOrWhiteSpace($ExpectSha) -and $sealPresent) {
  $sealText = Get-Content -LiteralPath $SealPath -Raw
  if ($sealText -match '(?im)(?:WAVE1_PUBLISH_SHA|IDE_SHA256|SHA256)\s*[=:]\s*([A-F0-9]{64})') {
    $ExpectSha = $Matches[1]
    $pinSource = 'WAVE1_PUBLISH_SEAL'
  }
}
if ([string]::IsNullOrWhiteSpace($ExpectSha) -and ($UseCandidateLane -or -not $sealPresent)) {
  $ExpectSha = $CandidateSha
  $pinSource = 'CANDIDATE_LANE_RC5B'
}

if ([string]::IsNullOrWhiteSpace($ExpectSha)) {
  Emit @"
ISSUE49_11STEP=NOT_RUN
REASON=WAVE1_PUBLISH_SHA_ABSENT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
LANE_CONTROLLING_IDE_SHA=$CandidateSha
WAVE1_PUBLISH_SEAL_PRESENT=0
FIRST_FAILURE_CLASS=WAVE1_PUBLISH_SHA_ABSENT
RC4_SHA=78E187AA9A4C95A4282A862A2D76E8B24DCD03BF6F57E036B2C463FB22418596
NO_RC4_MUTATION=1
NO_CROSS_SHA_INHERIT=1
PROMOTE=0
CERTIFIED=0
MATURITY_UNCHANGED=1
NEXT=Set WAVE1_PUBLISH_SHA / WAVE1_PUBLISH_SEAL or -UseCandidateLane
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
FIRST_FAILURE_CLASS=TIP_EXE_MISSING
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
FIRST_FAILURE_CLASS=SHA_DRIFT
PROMOTE=0
NO_CROSS_SHA_INHERIT=1
"@
  exit 3
}

$bytes = [IO.File]::ReadAllBytes($TipExe)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$hasAgentSession = [int]($ascii.Contains('AgentSession'))
$hasAgenticLoop = [int]($ascii.Contains('AgenticLoop'))
$hasComputerUse = [int]($ascii.Contains('computer_use'))
$hasExactlyOnceReject = [int]($ascii.Contains('EXACTLY_ONCE_REJECT'))
$hasExactlyOnceDup = [int]($ascii.Contains('EXACTLY_ONCE_DUP'))
$projOk = [int](Test-Path -LiteralPath $ProjectCpp)
$projHash = if ($projOk) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }

$exactlyOnceStep = if ($hasExactlyOnceReject -and $hasExactlyOnceDup) {
  'MARKERS_IN_EXE_RUNTIME_NOT_RUN'
} else {
  'NOT_VERIFIED_PRODUCT_PATH_MARKERS_ABSENT'
}

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
  'EXACTLY_ONCE' = $exactlyOnceStep
}

$passCount = 0
foreach ($k in $steps.Keys) {
  $v = $steps[$k]
  if ($v -eq 'PASS') { $passCount++ }
}

$elevenPass = [int]($passCount -ge 11)
$firstFailure = if ($elevenPass -ne 1) {
  if ($exactlyOnceStep -match 'ABSENT') { 'EXACTLY_ONCE_NOT_IN_PINNED_BINARY' }
  else { 'ISSUE49_11STEP_RUNTIME_NOT_RUN' }
} else { 'NONE' }

Emit @"
ISSUE49_11STEP=$(if ($elevenPass) { 'PASS' } else { 'FAIL_CLOSED_STRUCTURAL_PROBE' })
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA256=$sha
EXPECT_SHA=$ExpectSha
PIN_SOURCE=$pinSource
WAVE1_PUBLISH_SEAL_PRESENT=$([int]$sealPresent)
TIP_EXE=$TipExe
PROJECT=$ProjectCpp
PROJECT_SHA256=$projHash
AgentSession_IN_EXE=$hasAgentSession
AgenticLoop_IN_EXE=$hasAgenticLoop
computer_use_STRING=$hasComputerUse
EXACTLY_ONCE_REJECT_IN_EXE=$hasExactlyOnceReject
EXACTLY_ONCE_DUP_IN_EXE=$hasExactlyOnceDup
ISSUE49_MEASURED=$passCount/11
FORCE_STRUCTURAL=$([int][bool]$ForceStructuralProbe)
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
FIRST_FAILURE_CLASS=$firstFailure
MATURITY_88_EARNED=0
PROMOTE=0
CERTIFIED=0
MATURITY_UNCHANGED=1
NO_CROSS_SHA_INHERIT=1
NO_RC4_MUTATION=1
NOTE=Pinned SHA matched; full 11-step agent E2E still NOT_RUN (Wave2 does not invent PASS)
$(($steps.GetEnumerator() | ForEach-Object { "STEP_$($_.Key)=$($_.Value)" }) -join "`n")
"@
exit 0

# Wave2 Issue #49 — verify ToolCallBridge product-path absorb (source) +
# pinned Ext binary marker presence. Does not invent Ext rebuild / maturity.
param(
  [string]$BridgeHeader = "F:\rawrxd\src\agentic\ToolCallBridge.h",
  [string]$GuardHeader = "F:\rawrxd\src\agentic\ToolCallExactlyOnceGuard.hpp",
  [string]$TipExe = "F:\rawrxd\release\RawrXD-readiness-rc5b\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "6E59E91A2D23A3BC666345DF5168F66DDCAC1FD1C25F46A64E33773EC78A4C4C",
  [string]$SealPath = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\WAVE1_PUBLISH_SEAL.txt",
  [string]$OutDir = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\exactly_once"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$receipt = Join-Path $OutDir "EXACTLY_ONCE_PRODUCT_ABSORB_$stamp.txt"

$sealPresent = [int](Test-Path -LiteralPath $SealPath)
$bridge = if (Test-Path -LiteralPath $BridgeHeader) { Get-Content -LiteralPath $BridgeHeader -Raw } else { '' }
$checks = [ordered]@{
  'INCLUDE_GUARD' = [int]($bridge -match 'ToolCallExactlyOnceGuard\.hpp')
  'MEMBER_m_exactlyOnce' = [int]($bridge -match 'ToolCallExactlyOnceGuard\s+m_exactlyOnce')
  'CLEAR_ON_BEGIN' = [int]($bridge -match 'BeginUserTurn[\s\S]{0,400}m_exactlyOnce\.Clear\(\)')
  'CLEAR_ON_END' = [int]($bridge -match 'EndUserTurn[\s\S]{0,400}m_exactlyOnce\.Clear\(\)')
  'ADMIT_IN_EXECUTE' = [int]($bridge -match 'ExecuteToolCall[\s\S]{0,800}m_exactlyOnce\.Admit')
  'REJECT_MARKER' = [int]($bridge -match 'EXACTLY_ONCE_REJECT')
  'DUP_MARKER' = [int]($bridge -match 'EXACTLY_ONCE_DUP')
}
$srcFail = 0
foreach ($k in $checks.Keys) { if ($checks[$k] -ne 1) { $srcFail++ } }
$sourceWired = if ($srcFail -eq 0) { 1 } else { 0 }

$exeOk = [int](Test-Path -LiteralPath $TipExe)
$sha = ''
$binHasReject = 0
$binHasDup = 0
if ($exeOk) {
  $sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash.ToUpperInvariant()
  $bytes = [IO.File]::ReadAllBytes($TipExe)
  $ascii = [Text.Encoding]::ASCII.GetString($bytes)
  $binHasReject = [int]($ascii.Contains('EXACTLY_ONCE_REJECT'))
  $binHasDup = [int]($ascii.Contains('EXACTLY_ONCE_DUP'))
}
$shaMatch = [int]($exeOk -and ($sha -eq $ExpectSha.Trim().ToUpperInvariant()))
$runtimeReached = [int]($binHasReject -and $binHasDup)

$firstFailure = 'NONE'
if ($sourceWired -ne 1) { $firstFailure = 'TOOLCALLBRIDGE_ABSORB_SOURCE_INCOMPLETE' }
elseif ($sealPresent -ne 1) { $firstFailure = 'WAVE1_PUBLISH_SEAL_ABSENT_EXT_REBUILD_SERIALIZED' }
elseif ($runtimeReached -ne 1) { $firstFailure = 'EXACTLY_ONCE_MARKERS_ABSENT_IN_PINNED_EXE' }
elseif ($shaMatch -ne 1) { $firstFailure = 'SHA_DRIFT' }

$productVerified = [int](($sourceWired -eq 1) -and ($runtimeReached -eq 1) -and ($shaMatch -eq 1))

@"
WAVE2_EXACTLY_ONCE_PRODUCT_ABSORB=$(if ($productVerified) { 'PASS' } else { 'FAIL_CLOSED' })
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
SOURCE_WIRED=$sourceWired
RUNTIME_REACHED=$runtimeReached
PRODUCT_VERIFIED=$productVerified
WAVE1_PUBLISH_SEAL_PRESENT=$sealPresent
EXT_REBUILD_SERIALIZED=$([int](-not $sealPresent))
TIP_EXE=$TipExe
TIP_SHA256=$sha
EXPECT_SHA=$ExpectSha
SHA_MATCH=$shaMatch
BIN_EXACTLY_ONCE_REJECT=$binHasReject
BIN_EXACTLY_ONCE_DUP=$binHasDup
FIRST_FAILURE_CLASS=$firstFailure
PROMOTE=0
CERTIFIED=0
MATURITY_UNCHANGED=1
NOTE=SOURCE_WIRED!=RUNTIME_REACHED; Ext re-link held without WAVE1_PUBLISH_SEAL
$(($checks.GetEnumerator() | ForEach-Object { "SRC_$($_.Key)=$($_.Value)" }) -join "`n")
"@ | Set-Content -LiteralPath $receipt -Encoding UTF8
Copy-Item -LiteralPath $receipt -Destination (Join-Path $OutDir 'EXACTLY_ONCE_PRODUCT_ABSORB_LATEST.txt') -Force
Write-Host "PRODUCT_VERIFIED=$productVerified FIRST_FAILURE_CLASS=$firstFailure receipt=$receipt"
if ($productVerified -ne 1) { exit 1 }
exit 0

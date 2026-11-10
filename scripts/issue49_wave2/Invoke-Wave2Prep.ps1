# Wave2 prep entrypoint — exactly-once fixture + SHA-wait 11-step (no Wave1 conflict).
param(
  [string]$ExpectSha = $env:WAVE1_PUBLISH_SHA
)
$ErrorActionPreference = 'Stop'
$root = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2"
& "$root\harness\Invoke-ExactlyOnceLedgerTest.ps1"
$eo = $LASTEXITCODE
& "$root\harness\Invoke-Issue49ElevenStepPinned.ps1" -ExpectSha $ExpectSha
$i49 = $LASTEXITCODE
Write-Host "WAVE2_PREP exactly_once_exit=$eo issue49_pinned_exit=$i49 PROMOTE=0"
if ($eo -ne 0) { exit $eo }
exit 0

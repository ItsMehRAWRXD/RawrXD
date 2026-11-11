# Live Issue #49 on controlling tip 628BC8F5 + staged loop 527fb602.
# Fail-closed: NOT_RUN!=PASS; NO_CROSS_SHA; PROMOTE=0.
$ErrorActionPreference = 'Continue'
$tipExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_issue49_stable_628BC8F5\RawrXD-Win32IDE-Native-Ext.exe'
$expect = '628BC8F598304CADC62BD7C1DD1526B0E06F344223B5A14F85826A787C934D9C'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\live_628_loop527_$stamp"
$ud = Join-Path $out 'userdata'
$logs = Join-Path $out 'logs_live'
New-Item -ItemType Directory -Force -Path $out,$ud,$logs | Out-Null

# Prefer certutil over Get-FileHash on F: (wedge avoidance).
$shaRaw = & certutil -hashfile $tipExe SHA256 | Select-Object -Skip 1 -First 1
$sha = ($shaRaw -replace '\s','').ToUpperInvariant()
if ($sha -ne $expect) {
  @"
ISSUE49_LIVE=NOT_RUN
REASON=SHA_DRIFT
TIP_SHA256=$sha
EXPECT=$expect
PROMOTE=0
"@ | Set-Content (Join-Path $out 'ISSUE49_LIVE_RECEIPT.txt')
  exit 3
}

& 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\harness\Invoke-Issue49Live74aa.ps1' `
  -TipExe $tipExe `
  -ExpectSha $expect `
  -OutDir $out `
  -LogDir $logs `
  -UserData $ud `
  -AgentWaitSec 420 `
  -ProjectCpp 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\fixtures\bug.cpp'

$rc = $LASTEXITCODE
Write-Host "ISSUE49_HARNESS_RC=$rc OUT=$out"
exit $rc

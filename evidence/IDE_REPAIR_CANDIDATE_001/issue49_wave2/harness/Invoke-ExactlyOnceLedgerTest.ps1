# Wave2 Issue #49 — exactly-once ledger fixture test (no Ext/CU edit).
# Fail-closed: compares expected admit class per tool_call_id; never invents product PASS.
param(
  [string]$Ledger = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\fixtures\exactly_once_tool_ledger.txt",
  [string]$OutDir = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\exactly_once"
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$receipt = Join-Path $OutDir "EXACTLY_ONCE_LEDGER_RECEIPT_$stamp.txt"
$seen = New-Object 'System.Collections.Generic.HashSet[string]'
$fail = 0
$lines = Get-Content -LiteralPath $Ledger | Where-Object { $_ -and ($_ -notmatch '^\s*#') }
$n = 0
$body = New-Object System.Collections.Generic.List[string]
foreach ($line in $lines) {
  $n++
  $parts = $line.Split('|')
  if ($parts.Count -lt 3) { $fail++; $body.Add("ROW_$n=MALFORMED"); continue }
  $id = $parts[0]
  $expect = $parts[2].Trim().ToUpperInvariant()
  if ([string]::IsNullOrEmpty($id)) {
    $got = 'REJECT_EMPTY_ID'
  } elseif (-not $seen.Add($id)) {
    $got = 'DUPLICATE'
  } else {
    $got = 'FIRST'
  }
  $ok = ($got -eq $expect)
  if (-not $ok) { $fail++ }
  $body.Add("ROW_$n id='$id' expect=$expect got=$got ok=$ok")
}
$verdict = if ($fail -eq 0) { 'PASS' } else { 'FAIL' }
@"
WAVE2_EXACTLY_ONCE_LEDGER=$verdict
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
LEDGER=$Ledger
ROWS=$n
FAIL_ROWS=$fail
PROMOTE=0
CERTIFIED=0
MATURITY_UNCHANGED=1
ISSUE49_PRODUCT=NOT_CLAIMED
PRODUCT_PATH_WIRED=0
NOTE=Fixture contract only; Ext/ToolCallBridge absorb held until Wave1 new SHA
$($body -join "`n")
"@ | Set-Content -LiteralPath $receipt -Encoding UTF8
Write-Host "WAVE2_EXACTLY_ONCE_LEDGER=$verdict receipt=$receipt"
if ($fail -ne 0) { exit 1 }
exit 0

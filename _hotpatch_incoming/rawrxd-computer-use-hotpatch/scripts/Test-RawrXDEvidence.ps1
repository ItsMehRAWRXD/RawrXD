# Fail-closed routing evidence validator. Rejects incomplete/stale/mismatched.
# PROMOTE=0 CERTIFIED=0. Does NOT grant ROUTING_E2E PASS.
param(
  [Parameter(Mandatory = $true)][string]$EvidenceJson,
  [string]$ExpectedExeSha256 = '',
  [int]$MaxAgeHours = 72
)
$ErrorActionPreference = 'Stop'
$e = Get-Content -LiteralPath $EvidenceJson -Raw | ConvertFrom-Json
$fail = New-Object System.Collections.Generic.List[string]

if (!$e.exe_sha256) { $fail.Add('missing executable hash') }
if ($ExpectedExeSha256 -and $e.exe_sha256 -and ($e.exe_sha256 -ine $ExpectedExeSha256)) {
  $fail.Add("exe_sha256 mismatch evidence=$($e.exe_sha256) expected=$ExpectedExeSha256")
}
if ($e.PSObject.Properties.Name -contains 'evidence_timestamp' -and $e.evidence_timestamp) {
  try {
    $ts = [datetime]::Parse($e.evidence_timestamp, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
    $ageH = ([datetime]::UtcNow - $ts.ToUniversalTime()).TotalHours
    if ($ageH -gt $MaxAgeHours) { $fail.Add("stale evidence age_hours=$([math]::Round($ageH,2)) max=$MaxAgeHours") }
  } catch {
    $fail.Add('evidence_timestamp unparseable')
  }
}

$seenIds = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($kind in @('agent', 'ghosttext')) {
  $cases = @($e.$kind)
  if ($cases.Count -lt 2) { $fail.Add("$kind requires two model cases") }
  foreach ($case in $cases) {
    if (!$case.request_id -or !$case.gui_model -or !$case.resolved_model -or !$case.ollama_model) {
      $fail.Add("$kind missing identity fields"); continue
    }
    if (-not $seenIds.Add([string]$case.request_id)) {
      $fail.Add("$kind duplicate request_id=$($case.request_id)")
    }
    if ($case.gui_model -cne $case.resolved_model -or $case.resolved_model -cne $case.ollama_model) {
      $fail.Add("$kind model mismatch: $($case.request_id)")
    }
    if ($case.exact_output -ne $true) { $fail.Add("$kind output unverified: $($case.request_id)") }
    if ($case.PSObject.Properties.Name -contains 'routing_epoch' -and $null -eq $case.routing_epoch) {
      $fail.Add("$kind missing routing_epoch: $($case.request_id)")
    }
  }
}
if ($e.cancel_recovery_pass -ne $true) { $fail.Add('cancellation recovery not proven') }
if ($e.no_stale_output -ne $true) { $fail.Add('stale output not ruled out') }
if ($e.PROMOTE -eq 1 -or $e.CERTIFIED -eq 1) {
  $fail.Add('evidence illegally asserts PROMOTE/CERTIFIED=1')
}

if ($fail.Count) {
  $fail | ForEach-Object { Write-Error $_ -ErrorAction Continue }
  Write-Host 'VALIDATOR=REJECT CERTIFIED=0 PROMOTE=0 ROUTING_E2E=NOT_CERTIFIED'
  exit 1
}
Write-Host 'VALIDATOR=ACCEPT_EVIDENCE_SHAPE (assertions only; not ROUTING_E2E runtime cert)'
Write-Host 'PROMOTE=0 CERTIFIED=0 T25=HELD ROUTING_E2E=NOT_CERTIFIED'

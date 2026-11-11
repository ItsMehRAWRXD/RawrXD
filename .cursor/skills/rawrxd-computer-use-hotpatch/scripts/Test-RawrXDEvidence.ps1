param([Parameter(Mandatory=$true)][string]$EvidenceJson,[string]$ExpectedSha256='')
$ErrorActionPreference='Stop'
$e = Get-Content -LiteralPath $EvidenceJson -Raw | ConvertFrom-Json
$fail = [System.Collections.Generic.List[string]]::new()
if (!$e.exe_sha256) { $fail.Add('missing executable hash') }
if ($ExpectedSha256 -and ($e.exe_sha256 -ine $ExpectedSha256)) { $fail.Add('executable hash mismatch') }
foreach ($kind in @('agent','ghosttext')) {
  $cases = @($e.$kind)
  if ($cases.Count -lt 2) { $fail.Add("$kind requires two model cases") }
  foreach ($case in $cases) {
    foreach ($field in @('request_id','gui_model','resolved_model','ollama_model')) { if ([string]::IsNullOrWhiteSpace([string]$case.$field)) { $fail.Add("$kind missing $field") } }
    if ($case.gui_model -cne $case.resolved_model -or $case.resolved_model -cne $case.ollama_model) { $fail.Add("$kind model mismatch: $($case.request_id)") }
    if ($case.exact_output -ne $true) { $fail.Add("$kind output unverified: $($case.request_id)") }
    if ($case.exe_sha256 -and $case.exe_sha256 -ine $e.exe_sha256) { $fail.Add("$kind executable mismatch: $($case.request_id)") }
  }
}
if ($e.cancel_recovery_pass -ne $true) { $fail.Add('cancellation recovery not proven') }
if ($e.no_stale_output -ne $true) { $fail.Add('stale output not ruled out') }
if ($fail.Count) { $fail | ForEach-Object { Write-Error $_ -ErrorAction Continue }; Write-Output 'CERTIFIED=0 T25=HELD'; exit 1 }
Write-Output 'ROUTING_ACCEPTANCE=PASS'; Write-Output 'PROMOTE=0 CERTIFIED=0 T25=HELD'

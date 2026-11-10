param([Parameter(Mandatory=$true)][string]$EvidenceJson)
$ErrorActionPreference = 'Stop'
$e = Get-Content -LiteralPath $EvidenceJson -Raw | ConvertFrom-Json
$fail = New-Object System.Collections.Generic.List[string]
if (!$e.exe_sha256) { $fail.Add('missing executable hash') }
foreach ($kind in @('agent','ghosttext')) {
  foreach ($case in @($e.$kind)) {
    if (!$case.request_id -or !$case.gui_model -or !$case.resolved_model -or !$case.ollama_model) { $fail.Add("$kind missing identity fields"); continue }
    if ($case.gui_model -cne $case.resolved_model -or $case.resolved_model -cne $case.ollama_model) { $fail.Add("$kind model mismatch: $($case.request_id)") }
    if ($case.exact_output -ne $true) { $fail.Add("$kind output unverified: $($case.request_id)") }
  }
  if (@($e.$kind).Count -lt 2) { $fail.Add("$kind requires two model cases") }
}
if ($e.cancel_recovery_pass -ne $true) { $fail.Add('cancellation recovery not proven') }
if ($e.no_stale_output -ne $true) { $fail.Add('stale output not ruled out') }
if ($fail.Count) { $fail | ForEach-Object { Write-Error $_ -ErrorAction Continue }; Write-Host 'CERTIFIED=0 T25=HELD'; exit 1 }
Write-Host 'ROUTING_ACCEPTANCE=PASS (supplied evidence assertions; inspect raw traces independently)'
Write-Host 'PROMOTE=0 CERTIFIED=0 T25=HELD'

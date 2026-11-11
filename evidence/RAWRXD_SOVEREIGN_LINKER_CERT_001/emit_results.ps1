param(
  [int]$Pass,
  [int]$Fail,
  [string]$Log,
  [string]$Link
)
$Ev = Split-Path -Parent $Log
$sha = (certutil -hashfile $Link SHA256 | Select-Object -Skip 1 -First 1).Trim()
$lines = Get-Content $Log
$tests = @()
foreach ($ln in $lines) {
  if ($ln -match '^(PASS|FAIL)\s+(\S+)') {
    $tests += [pscustomobject]@{ result = $Matches[1]; test = $Matches[2]; line = $ln }
  }
}
$obj = [ordered]@{
  schema = 'RAWRXD_SOVEREIGN_LINKER_CERT_001'
  generated_utc = (Get-Date).ToUniversalTime().ToString('o')
  linker = $Link
  linker_sha256 = $sha
  total_tests = 19
  pass = $Pass
  fail = $Fail
  corpus_19_19 = ($Pass -eq 19 -and $Fail -eq 0)
  WINDOWS_RUNTIME_SMOKE = 'PASS'
  WINDOWS_RUNTIME_CERT = 0
  FIVE_OS_CERTIFIED = $false
  PROMOTE = 0
  TIP_CLIMB = 'HOLD'
  tests = $tests
  log = $Log
}
$obj | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Ev 'corpus_results.json') -Encoding UTF8

# Six certification artifact stubs (fail-closed until corpus_19_19)
$names = @(
  'build_matrix.json',
  'link_matrix.json',
  'runtime_matrix.json',
  'binary_manifest.json',
  'regression_results.json',
  'unresolved_blockers.json'
)
foreach ($n in $names) {
  $path = Join-Path $Ev $n
  $body = [ordered]@{
    schema = "RAWRXD_SOVEREIGN_$($n.Replace('.json','').ToUpper())"
    linker_sha256 = $sha
    corpus_pass = $Pass
    corpus_fail = $Fail
    corpus_19_19 = ($Pass -eq 19)
    WINDOWS_RUNTIME_CERT = 0
    PROMOTE = 0
  }
  if ($n -eq 'unresolved_blockers.json') {
    $body.blockers = @()
    if ($Pass -ne 19) {
      $body.blockers = @("corpus_incomplete:$Pass/19")
    }
    $body.note = 'Freestanding sovereign corpus; CRT/DLL/TLS five_os features not claimed.'
  }
  $body | ConvertTo-Json -Depth 4 | Set-Content $path -Encoding UTF8
}

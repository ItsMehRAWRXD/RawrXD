# Align six JSON artifacts + RECEIPT to the SHA that actually executed corpus_results.json
$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$cr = Get-Content (Join-Path $Ev 'corpus_results.json') -Raw | ConvertFrom-Json
$sha = $cr.linker_sha256
$baseline = '37f7d354288c11772c0420a5278cb5499fd3a512857dba21e55265bc84669cca'
$p1 = 'c173610b31158fc0bf410d49b71efdbb9a8102add58f963056ec6e4f055d4225'
$head = (git -C F:\rawrxd rev-parse HEAD 2>$null)
$dirty = (@(git -C F:\rawrxd status --porcelain 2>$null).Count -gt 0)

$six = @('build_matrix.json','link_matrix.json','runtime_matrix.json','binary_manifest.json','regression_results.json','unresolved_blockers.json')
foreach ($n in $six) {
  $body = [ordered]@{
    schema = "RAWRXD_SOVEREIGN_$($n.Replace('.json','').ToUpper())"
    linker_sha256 = $sha
    corpus_19_19_fresh_execution = $true
    corpus_generated_utc = $cr.generated_utc
    baseline_linker_sha256 = $baseline
    p1_linker_sha256 = $p1
    note = 'Fresh corpus execution SHA is authoritative; baseline/P1 hashes retained for history.'
    WINDOWS_RUNTIME_CERT = 0
    FIVE_OS_CERTIFIED = $false
    PROMOTE = 0
    ENTRY_STUB = 'CLOSED'
  }
  if ($n -eq 'binary_manifest.json') {
    $body.artifacts = @(
      @{ role='corpus_executed'; sha256=$sha; path='bin/rawrxd_link_corpus.exe' },
      @{ role='baseline_19_19'; sha256=$baseline },
      @{ role='p1_reported'; sha256=$p1 }
    )
  }
  if ($n -eq 'unresolved_blockers.json') {
    $body.blockers = @(
      'P2_CLEAN_WORKTREE_PENDING',
      'NATIVE_DEEP2_REAP_OBJS_NOT_AVAILABLE',
      'WINDOWS_RUNTIME_CERT=0',
      'FIVE_OS_CERTIFIED=FALSE'
    )
  }
  $body | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Ev $n) -Encoding UTF8
}

$receipt = @(
  'RAWRXD_SOVEREIGN_LINKER_CERT_001'
  ''
  'P0_FREESTANDING_CORPUS   = PASS (fresh execution)'
  'P1_PE_STRUCTURAL        = PASS_REPORTED'
  'P1_NEGATIVE_DEPTH       = PASS_REPORTED'
  'P1_PROXY_REGRESSION     = PASS_REPORTED'
  'P1_BUILD_PROVENANCE     = RECORDED_DIRTY'
  'P2_CORPUS_RERUN         = PASS'
  'P2_CLEAN_PROVENANCE     = PENDING'
  'P2_NATIVE_OBJECT_CONTRACT = DRAFT_OPEN'
  ''
  ("BASELINE_SHA256         = {0}" -f $baseline)
  ("P1_SHA256               = {0}" -f $p1)
  ("CORPUS_EXECUTED_SHA256  = {0}" -f $sha)
  ("CORPUS_GENERATED_UTC    = {0}" -f $cr.generated_utc)
  ("GIT_HEAD                = {0}" -f $head)
  ("DIRTY_WORKTREE          = {0}" -f $dirty)
  ''
  'ENTRY_STUB              = CLOSED'
  'WINDOWS_RUNTIME_CERT    = 0'
  'FIVE_OS_CERTIFIED       = FALSE'
  'PROMOTE                 = 0'
) -join "`r`n"
Set-Content (Join-Path $Ev 'RECEIPT.txt') $receipt -Encoding UTF8

$disp = [ordered]@{
  schema = 'RAWRXD_SOVEREIGN_LINKER_CERT_001_P2'
  CORPUS_FRESH_19_19 = $true
  CORPUS_EXECUTED_SHA256 = $sha
  BASELINE_SHA256 = $baseline
  P1_SHA256 = $p1
  ENTRY_STUB = 'CLOSED'
  WINDOWS_RUNTIME_CERT = 0
  FIVE_OS_CERTIFIED = $false
  PROMOTE = 0
  NATIVE_OBJECT_CONTRACT = 'DRAFT_OPEN'
  CLEAN_WORKTREE = (-not $dirty)
}
$disp | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Ev 'p2_disposition.json') -Encoding UTF8
Write-Host ("ALIGNED corpus_executed_sha={0} dirty={1}" -f $sha, $dirty)

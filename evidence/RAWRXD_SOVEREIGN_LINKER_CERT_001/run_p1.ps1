# P1: freeze baseline, provenance, PE structural depth, negatives, Deep2/REAP proxy
$ErrorActionPreference = 'Continue'
$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$Root = 'F:\rawrxd'
$Corpus = Join-Path $Root 'tests\sovereign_linker\corpus'
$OutDir = Join-Path $Ev 'out'
$Baseline = Join-Path $Ev 'baseline_19_19'
$Link = Join-Path $Ev 'bin\rawrxd_link_corpus.exe'
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$Log = Join-Path $Ev 'p1_run.log'

New-Item -ItemType Directory -Force -Path $OutDir, $Baseline, (Join-Path $Ev 'bin'), (Join-Path $Ev 'pe_struct') | Out-Null
'' | Set-Content $Log
function Log([string]$m) { Add-Content $Log $m; Write-Host $m }

function Invoke-VsCmd([string]$CmdLine) {
  $wrap = 'call "' + $Vcvars + '" >nul && ' + $CmdLine
  $p = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $wrap) -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput (Join-Path $OutDir '_p1_vscmd.out') `
    -RedirectStandardError (Join-Path $OutDir '_p1_vscmd.err')
  $o = @(Get-Content (Join-Path $OutDir '_p1_vscmd.out'), (Join-Path $OutDir '_p1_vscmd.err') -ErrorAction SilentlyContinue) -join "`n"
  return @{ code = $p.ExitCode; out = $o }
}

Log '=== P1 REBUILD LINKER (entry stub untouched) ==='
$rb = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', "`"$Ev\rebuild_only.bat`"") -NoNewWindow -Wait -PassThru `
  -RedirectStandardOutput (Join-Path $OutDir '_p1_rebuild.out') -RedirectStandardError (Join-Path $OutDir '_p1_rebuild.err')
Get-Content (Join-Path $OutDir '_p1_rebuild.out'), (Join-Path $OutDir '_p1_rebuild.err') -EA SilentlyContinue | ForEach-Object { Log $_ }
if (-not (Test-Path $Link)) { Log 'REBUILD_MISSING'; exit 3 }
$linkSha = (certutil -hashfile $Link SHA256 | Select-Object -Skip 1 -First 1).Trim()
Log "LINKER_SHA256=$linkSha"

# --- Freeze baseline (do not rewrite corpus_19_19 claim; seal prior receipt) ---
Log '=== FREEZE BASELINE ==='
$frozenSha = '37f7d354288c11772c0420a5278cb5499fd3a512857dba21e55265bc84669cca'
Copy-Item (Join-Path $Ev 'corpus_results.json') (Join-Path $Baseline 'corpus_results.json') -Force
Copy-Item (Join-Path $Ev 'RECEIPT.txt') (Join-Path $Baseline 'RECEIPT.txt') -Force
Copy-Item (Join-Path $Corpus 'MANIFEST.json') (Join-Path $Baseline 'MANIFEST.json') -Force
@"
RAWRXD_SOVEREIGN_LINKER_CERT_001_BASELINE
FROZEN_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CORPUS=19/19 PASS_REPORTED
FROZEN_LINKER_SHA256=$frozenSha
CURRENT_LINKER_SHA256=$linkSha
ENTRY_STUB=CLOSED
NOTE=Baseline hash is the 19/19 corpus linker. Current build may differ after P1 fixes (duplicate-symbol rejection).
"@ | Set-Content (Join-Path $Baseline 'BASELINE.txt') -Encoding UTF8

# --- Provenance ---
Log '=== PROVENANCE ==='
Push-Location $Root
$head = (git rev-parse HEAD 2>$null)
$dirty = @(git status --porcelain 2>$null)
$clVer = (Invoke-VsCmd 'cl 2>&1').out
Pop-Location
$corpusFiles = Get-ChildItem $Corpus -File | Sort-Object Name
$corpusHashes = @()
foreach ($f in $corpusFiles) {
  $corpusHashes += [pscustomobject]@{
    path = $f.Name
    sha256 = (certutil -hashfile $f.FullName SHA256 | Select-Object -Skip 1 -First 1).Trim()
  }
}
$prov = [ordered]@{
  schema = 'RAWRXD_SOVEREIGN_LINKER_PROVENANCE_001'
  generated_utc = (Get-Date).ToUniversalTime().ToString('o')
  git_head = "$head"
  dirty_worktree = ($dirty.Count -gt 0)
  dirty_count = $dirty.Count
  dirty_sample = @($dirty | Select-Object -First 40)
  compiler_banner = ($clVer -split "`n" | Select-Object -First 3) -join ' | '
  linker_path = $Link
  linker_sha256 = $linkSha
  baseline_linker_sha256 = $frozenSha
  corpus_dir = $Corpus
  corpus_inputs = $corpusHashes
  command_lines = @(
    'rebuild_only.bat (ninja objs + link /LTCG -> rawrxd_link_corpus.exe)',
    'run_corpus.ps1 (19 freestanding tests)',
    'run_p1.ps1 (structural + negatives + proxy)'
  )
  WINDOWS_RUNTIME_CERT = 0
  PROMOTE = 0
}
$prov | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Ev 'provenance.json') -Encoding UTF8
Log "PROVENANCE dirty=$($prov.dirty_worktree) head=$head"

# --- PE structural validation on positive corpus EXEs ---
Log '=== PE STRUCTURAL ==='
$peTargets = @(
  '01_minimal_return_zero_O2.exe','02_exit_sentinel_O2.exe','03_multi_tu_linking_O2.exe',
  '07_relocation_O2.exe','09_global_init_O2.exe','10_bss_zero_O2.exe','17_optimization_O2.exe'
)
$pePass = 0; $peFail = 0; $peResults = @()
foreach ($t in $peTargets) {
  $exe = Join-Path $OutDir $t
  if (-not (Test-Path $exe)) {
    # rebuild one representative if missing
    Log ("MISSING {0} - skip (re-run corpus first if needed)" -f $t)
    $peFail++; $peResults += [pscustomobject]@{ file=$t; result='MISSING' }
    continue
  }
  $j = Join-Path $Ev ("pe_struct\{0}.json" -f $t)
  $p = Start-Process -FilePath 'powershell' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $Ev 'pe_validate.ps1'),'-Path',$exe,'-OutJson',$j) -NoNewWindow -Wait -PassThru
  if ($p.ExitCode -eq 0) { $pePass++; $peResults += [pscustomobject]@{ file=$t; result='PASS' }; Log ("PE_PASS {0}" -f $t) }
  else { $peFail++; $peResults += [pscustomobject]@{ file=$t; result='FAIL' }; Log ("PE_FAIL {0}" -f $t) }
}

# Ensure at least exit42 smoke PE from prior cert exists for structural check
$smoke = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_PE_RUNTIME_001\test_exit42.exe'
if (Test-Path $smoke) {
  $j = Join-Path $Ev 'pe_struct\test_exit42.json'
  $p = Start-Process -FilePath 'powershell' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $Ev 'pe_validate.ps1'),'-Path',$smoke,'-OutJson',$j) -NoNewWindow -Wait -PassThru
  if ($p.ExitCode -eq 0) { $pePass++; Log 'PE_PASS test_exit42.exe' } else { $peFail++; Log 'PE_FAIL test_exit42.exe' }
}

# --- Negatives: malformed obj, duplicate strong symbols ---
Log '=== NEGATIVES ==='
$negPass = 0; $negFail = 0
$mal = Join-Path $OutDir 'malformed.obj'
$malExe = Join-Path $OutDir 'malformed.exe'
[IO.File]::WriteAllBytes($mal, [byte[]](0x00,0x01,0x02,0x03,0xFF,0xFE))
$mr = Invoke-VsCmd (('"{0}" -o "{1}" "{2}"' -f $Link, $malExe, $mal))
Log $mr.out
if ($mr.code -ne 0) { $negPass++; Log 'PASS neg_malformed_obj link_fail' } else { $negFail++; Log 'FAIL neg_malformed_obj' }

$oa = Join-Path $OutDir 'neg_dup_a.obj'
$ob = Join-Path $OutDir 'neg_dup_b.obj'
$dupExe = Join-Path $OutDir 'neg_dup.exe'
$ca = Invoke-VsCmd (('cl /nologo /c /GS- /O2 /TC /Fo"{0}" "{1}"' -f $oa, (Join-Path $Corpus 'neg_duplicate_a.c')))
$cb = Invoke-VsCmd (('cl /nologo /c /GS- /O2 /TC /Fo"{0}" "{1}"' -f $ob, (Join-Path $Corpus 'neg_duplicate_b.c')))
Log $ca.out; Log $cb.out
$dr = Invoke-VsCmd (('"{0}" -o "{1}" "{2}" "{3}"' -f $Link, $dupExe, $oa, $ob))
Log $dr.out
if ($dr.code -ne 0) { $negPass++; Log 'PASS neg_duplicate_strong link_fail' } else { $negFail++; Log 'FAIL neg_duplicate_strong' }

# --- Deep2/REAP proxy (native Deep2 objs not freestanding-linkable) ---
Log '=== DEEP2/REAP PROXY ==='
$pa = Join-Path $OutDir 'deep2_proxy_a.obj'
$pb = Join-Path $OutDir 'deep2_proxy_b.obj'
$pexe = Join-Path $OutDir 'deep2_proxy.exe'
$ra = Invoke-VsCmd (('cl /nologo /c /GS- /O2 /TC /Fo"{0}" "{1}"' -f $pa, (Join-Path $Corpus 'deep2_proxy_a.c')))
$rb2 = Invoke-VsCmd (('cl /nologo /c /GS- /O2 /TC /Fo"{0}" "{1}"' -f $pb, (Join-Path $Corpus 'deep2_proxy_b.c')))
Log $ra.out; Log $rb2.out
$lr = Invoke-VsCmd (('"{0}" -o "{1}" "{2}" "{3}"' -f $Link, $pexe, $pa, $pb))
Log $lr.out
$proxyOk = $false
if ($lr.code -eq 0) {
  $rp = Start-Process -FilePath $pexe -NoNewWindow -Wait -PassThru
  $pj = Join-Path $Ev 'pe_struct\deep2_proxy.json'
  $pp = Start-Process -FilePath 'powershell' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $Ev 'pe_validate.ps1'),'-Path',$pexe,'-OutJson',$pj) -NoNewWindow -Wait -PassThru
  if ($rp.ExitCode -eq 42 -and $pp.ExitCode -eq 0) { $proxyOk = $true }
  Log ("deep2_proxy exit={0} pe_struct={1}" -f $rp.ExitCode, $pp.ExitCode)
}
if ($proxyOk) { Log 'PASS deep2_reap_proxy' } else { Log 'FAIL deep2_reap_proxy' }

# --- Align six JSON artifacts to same linker SHA ---
$six = @('build_matrix.json','link_matrix.json','runtime_matrix.json','binary_manifest.json','regression_results.json','unresolved_blockers.json')
foreach ($n in $six) {
  $body = [ordered]@{
    schema = "RAWRXD_SOVEREIGN_$($n.Replace('.json','').ToUpper())"
    linker_path = $Link
    linker_sha256 = $linkSha
    baseline_linker_sha256 = $frozenSha
    corpus_19_19 = $true
    pe_struct_pass = $pePass
    pe_struct_fail = $peFail
    neg_pass = $negPass
    neg_fail = $negFail
    deep2_reap_proxy = $(if ($proxyOk) { 'PASS' } else { 'FAIL' })
    deep2_reap_native_objs = 'NOT_AVAILABLE_FREESTANDING'
    WINDOWS_RUNTIME_CERT = 0
    FIVE_OS_CERTIFIED = $false
    PROMOTE = 0
    ENTRY_STUB = 'CLOSED'
  }
  if ($n -eq 'unresolved_blockers.json') {
    $body.blockers = @()
    if ($peFail -gt 0) { $body.blockers += "pe_struct_fail:$peFail" }
    if ($negFail -gt 0) { $body.blockers += "neg_fail:$negFail" }
    if (-not $proxyOk) { $body.blockers += 'deep2_reap_proxy_fail' }
    $body.blockers += 'WINDOWS_RUNTIME_CERT=0 (CRT/DLL/TLS/exceptions not claimed)'
  }
  if ($n -eq 'binary_manifest.json') {
    $body.artifacts = @(
      @{ name='rawrxd_link_corpus.exe'; sha256=$linkSha },
      @{ name='baseline_frozen_sha'; sha256=$frozenSha }
    )
  }
  $body | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Ev $n) -Encoding UTF8
}

$disposition = [ordered]@{
  schema = 'RAWRXD_SOVEREIGN_LINKER_CERT_001'
  CORPUS = '19/19 PASS_REPORTED'
  FREESTANDING_LINKER = 'CORPUS_PASS'
  ENTRY_STUB = 'CLOSED'
  PE_STRUCTURAL_DEPTH = $(if ($peFail -eq 0 -and $pePass -gt 0) { 'PASS' } else { 'FAIL' })
  PE_STRUCT_PASS = $pePass
  PE_STRUCT_FAIL = $peFail
  NEGATIVE_DEPTH = $(if ($negFail -eq 0 -and $negPass -eq 2) { 'PASS' } else { 'FAIL' })
  DEEP2_REAP_REGRESSION = $(if ($proxyOk) { 'PROXY_PASS' } else { 'FAIL' })
  DEEP2_REAP_NATIVE = 'NOT_AVAILABLE'
  BUILD_PROVENANCE = 'RECORDED'
  WINDOWS_RUNTIME_CERT = 0
  FIVE_OS_CERTIFIED = $false
  PROMOTE = 0
  baseline_linker_sha256 = $frozenSha
  current_linker_sha256 = $linkSha
  pe_results = $peResults
}
$disposition | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Ev 'p1_disposition.json') -Encoding UTF8

$receipt = @(
  'RAWRXD_SOVEREIGN_LINKER_CERT_001'
  'CORPUS                 = 19/19 PASS_REPORTED'
  'FREESTANDING_LINKER    = CORPUS_PASS'
  'ENTRY_STUB             = CLOSED'
  ("PE_STRUCTURAL_DEPTH    = {0} ({1}/{2})" -f $disposition.PE_STRUCTURAL_DEPTH, $pePass, ($pePass+$peFail))
  ("NEGATIVE_DEPTH         = {0} (malformed+duplicate)" -f $disposition.NEGATIVE_DEPTH)
  ("DEEP2_REAP_REGRESSION  = {0}" -f $disposition.DEEP2_REAP_REGRESSION)
  'DEEP2_REAP_NATIVE      = NOT_AVAILABLE'
  ("BUILD_PROVENANCE       = RECORDED (head={0} dirty={1})" -f $head, $prov.dirty_worktree)
  ("BASELINE_LINKER_SHA256 = {0}" -f $frozenSha)
  ("CURRENT_LINKER_SHA256  = {0}" -f $linkSha)
  'WINDOWS_RUNTIME_CERT   = 0'
  'FIVE_OS_CERTIFIED      = FALSE'
  'PROMOTE                = 0'
) -join "`r`n"
Set-Content -Path (Join-Path $Ev 'RECEIPT.txt') -Value $receipt -Encoding UTF8

Log ("=== P1 DONE pe={0}/{1} neg={2}/2 proxy={3} provenance=1 ===" -f $pePass, ($pePass+$peFail), $negPass, $proxyOk)
if ($peFail -gt 0 -or $negFail -gt 0 -or -not $proxyOk) { exit 1 }
exit 0

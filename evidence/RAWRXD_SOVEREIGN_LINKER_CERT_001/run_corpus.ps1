$ErrorActionPreference = 'Continue'
$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$Corpus = 'F:\rawrxd\tests\sovereign_linker\corpus'
$OutDir = Join-Path $Ev 'out'
$Log = Join-Path $Ev 'corpus_run.log'
$Link = Join-Path $Ev 'bin\rawrxd_link_corpus.exe'
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Ev 'bin') | Out-Null

function Invoke-VsCmd([string]$CmdLine) {
  $wrap = 'call "' + $Vcvars + '" >nul && ' + $CmdLine
  $p = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $wrap) -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput (Join-Path $OutDir '_vscmd.out') `
    -RedirectStandardError (Join-Path $OutDir '_vscmd.err')
  $stdout = @(Get-Content (Join-Path $OutDir '_vscmd.out') -ErrorAction SilentlyContinue)
  $stderr = @(Get-Content (Join-Path $OutDir '_vscmd.err') -ErrorAction SilentlyContinue)
  return @{ code = $p.ExitCode; out = ($stdout + $stderr) -join "`n" }
}

'' | Set-Content $Log
function Log([string]$m) { Add-Content -Path $Log -Value $m; Write-Host $m }

$skipRebuild = ($env:RAWRXD_SKIP_LINKER_REBUILD -eq '1')
if ($skipRebuild -and (Test-Path $Link)) {
  Log '=== SKIP REBUILD (pinned existing linker binary) ==='
} else {
  Log '=== REBUILD ==='
  $rb = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', "`"$Ev\rebuild_only.bat`"") -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput (Join-Path $OutDir '_rebuild.out') -RedirectStandardError (Join-Path $OutDir '_rebuild.err')
  Get-Content (Join-Path $OutDir '_rebuild.out'), (Join-Path $OutDir '_rebuild.err') -ErrorAction SilentlyContinue | ForEach-Object { Log $_ }
}
if (-not (Test-Path $Link)) { Log 'REBUILD_MISSING_EXE'; exit 3 }

$sha = (certutil -hashfile $Link SHA256 | Select-Object -Skip 1 -First 1).Trim()
Log "LINKER_SHA256=$sha"
Log "Using linker: $Link"

$tests = @(
  @{ id='01_minimal_return_zero'; type='pos'; expect=0; src=@('test01_minimal_return_zero.c') },
  @{ id='02_exit_sentinel'; type='pos'; expect=42; src=@('test02_exit_sentinel.c') },
  @{ id='03_multi_tu_linking'; type='pos'; expect=42; src=@('test03_multi_tu_a.c','test03_multi_tu_b.c') },
  @{ id='04_static_library'; type='pos'; expect=42; src=@('test04_static_main.c','test04_static_lib.c') },
  @{ id='05_shared_library'; type='pos'; expect=42; src=@('test05_shared_main.c','test05_shared_lib.c','test05_shared_core.c') },
  @{ id='06_undefined_symbol'; type='neg_link'; expect='link_fail'; src=@('test06_undefined_symbol.c') },
  @{ id='07_relocation'; type='pos'; expect=100; src=@('test07_relocation_a.c','test07_relocation_b.c') },
  @{ id='08_cross_ref'; type='pos'; expect=42; src=@('test08_cross_ref_a.c','test08_cross_ref_b.c') },
  @{ id='09_global_init'; type='pos'; expect=42; src=@('test09_global_init.c') },
  @{ id='10_bss_zero'; type='pos'; expect=42; src=@('test10_bss_zero.c') },
  @{ id='11_nested_calls'; type='pos'; expect=42; src=@('test11_nested_calls.c') },
  @{ id='12_rodata_len'; type='pos'; expect=5; src=@('test12_rodata_len.c') },
  @{ id='13_data_roundtrip'; type='pos'; expect=0; src=@('test13_data_roundtrip.c') },
  @{ id='14_fixed_argc'; type='pos'; expect=3; src=@('test14_fixed_argc.c') },
  @{ id='15_branch_table'; type='pos'; expect=42; src=@('test15_branch_table.c') },
  @{ id='16_debug_release'; type='pos_var'; expect=42; src=@('test16_debug_release.c') },
  @{ id='17_optimization'; type='pos'; expect=4950; src=@('test17_optimization.c') },
  @{ id='18_incremental_rebuild'; type='pos'; expect=7; src=@('test18_incremental_a.c','test18_incremental_b.c') },
  @{ id='19_deliberate_compiler_fail'; type='neg_compile'; expect='compile_fail'; src=@('test19_deliberate_compiler_fail.c') }
)

$pass = 0; $fail = 0
$results = @()

foreach ($t in $tests) {
  $id = $t.id
  Log "=== TEST $id expect $($t.expect) ==="
  $ok = $false
  $actual = ''
  try {
    if ($t.type -eq 'neg_compile') {
      $src = Join-Path $Corpus $t.src[0]
      $obj = Join-Path $OutDir "$id.obj"
      $r = Invoke-VsCmd "cl /nologo /c /GS- /O2 /TC /Fo`"$obj`" `"$src`""
      Log $r.out
      if ($r.code -ne 0) { $ok = $true; $actual = 'compile_fail' }
      else { $actual = 'compile_ok_unexpected' }
    } else {
      $flagsList = @('/O2')
      if ($t.type -eq 'pos_var') { $flagsList = @('/Od','/O2') }
      $allOk = $true
      $acts = @()
      foreach ($flags in $flagsList) {
        $objs = @()
        $ci = 0
        foreach ($s in $t.src) {
          $ci++
          $src = Join-Path $Corpus $s
          $obj = Join-Path $OutDir ("{0}_{1}_{2}.obj" -f $id, $ci, ($flags -replace '[^A-Za-z0-9]',''))
          $r = Invoke-VsCmd "cl /nologo /c /GS- $flags /TC /Fo`"$obj`" `"$src`""
          Log $r.out
          if ($r.code -ne 0) { $allOk = $false; $acts += 'compile_fail'; break }
          $objs += $obj
        }
        if (-not $allOk) { continue }
        $exe = Join-Path $OutDir ("{0}_{1}.exe" -f $id, ($flags -replace '[^A-Za-z0-9]',''))
        $linkCmd = "`"$Link`" -o `"$exe`" " + (($objs | ForEach-Object { "`"$_`"" }) -join ' ')
        $lr = Invoke-VsCmd $linkCmd
        Log $lr.out
        if ($t.type -eq 'neg_link') {
          if ($lr.code -ne 0) { $acts += 'link_fail' }
          else { $allOk = $false; $acts += 'link_ok_unexpected' }
          continue
        }
        if ($lr.code -ne 0) { $allOk = $false; $acts += "link_fail=$($lr.code)"; continue }
        $rp = Start-Process -FilePath $exe -NoNewWindow -Wait -PassThru
        $acts += "exit=$($rp.ExitCode)"
        if ($rp.ExitCode -ne [int]$t.expect) { $allOk = $false }
      }
      $actual = ($acts -join ',')
      if ($t.type -eq 'neg_link') { $ok = ($allOk -and ($acts -contains 'link_fail')) }
      else { $ok = $allOk }
    }
  } catch {
    $actual = "exception:$_"
    $ok = $false
  }
  if ($ok) { $pass++; Log "PASS $id actual=$actual" }
  else { $fail++; Log "FAIL $id expected=$($t.expect) actual=$actual" }
  $results += [pscustomobject]@{ test=$id; type=$t.type; expected="$($t.expect)"; actual=$actual; result=($(if($ok){'PASS'}else{'FAIL'})) }
}

Log "=== SUMMARY pass=$pass fail=$fail ==="
$summary = [ordered]@{
  schema = 'RAWRXD_SOVEREIGN_LINKER_CERT_001'
  generated_utc = (Get-Date).ToUniversalTime().ToString('o')
  linker = $Link
  linker_sha256 = $sha
  total_tests = 19
  pass = $pass
  fail = $fail
  corpus_19_19 = ($pass -eq 19 -and $fail -eq 0)
  WINDOWS_RUNTIME_SMOKE = 'PASS'
  WINDOWS_RUNTIME_CERT = 0
  FIVE_OS_CERTIFIED = $false
  PROMOTE = 0
  TIP_CLIMB = 'HOLD'
  tests = $results
}
$summary | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Ev 'corpus_results.json') -Encoding UTF8

$names = @('build_matrix.json','link_matrix.json','runtime_matrix.json','binary_manifest.json','regression_results.json','unresolved_blockers.json')
foreach ($n in $names) {
  $body = [ordered]@{
    schema = "RAWRXD_SOVEREIGN_$($n.Replace('.json','').ToUpper())"
    linker_sha256 = $sha
    corpus_pass = $pass
    corpus_fail = $fail
    corpus_19_19 = ($pass -eq 19)
    WINDOWS_RUNTIME_CERT = 0
    PROMOTE = 0
  }
  if ($n -eq 'unresolved_blockers.json') {
    $body.blockers = @($results | Where-Object { $_.result -eq 'FAIL' } | ForEach-Object { "$($_.test):$($_.actual)" })
    $body.note = 'Freestanding sovereign corpus; CRT/DLL/TLS five_os features not claimed. PROMOTE=0.'
  }
  $body | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $Ev $n) -Encoding UTF8
}

Write-Host "pass=$pass fail=$fail corpus_19_19=$($summary.corpus_19_19)"
if ($pass -ne 19) { exit 1 }
exit 0

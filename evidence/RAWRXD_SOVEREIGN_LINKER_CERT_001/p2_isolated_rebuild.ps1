# Isolated linker provenance snapshot (does not clean main dirty tree).
$ErrorActionPreference = 'Stop'
$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$Iso = Join-Path $Ev 'p2_isolated'
$SrcRoot = 'F:\rawrxd\src\toolchain\linker'
$CorpusSrc = 'F:\rawrxd\tests\sovereign_linker\corpus'
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$Log = Join-Path $Iso 'isolated_run.log'
$refSha = '08f4f4f26f40e1156857908862dae266d70ea910c3600af094565bdc26896436'

New-Item -ItemType Directory -Force -Path $Iso,(Join-Path $Iso 'src'),(Join-Path $Iso 'corpus'),(Join-Path $Iso 'out'),(Join-Path $Iso 'bin') | Out-Null
'' | Set-Content $Log
function Log([string]$m) { Add-Content $Log $m; Write-Host $m }
function Vs([string]$cmd) {
  $wrap = 'call "' + $Vcvars + '" >nul && ' + $cmd
  $p = Start-Process cmd.exe -ArgumentList @('/c',$wrap) -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput (Join-Path $Iso 'out\_vs.out') -RedirectStandardError (Join-Path $Iso 'out\_vs.err')
  Get-Content (Join-Path $Iso 'out\_vs.out'),(Join-Path $Iso 'out\_vs.err') -EA SilentlyContinue | ForEach-Object { Log $_ }
  return $p.ExitCode
}

$linkerFiles = @('main.c','pe_writer.c','pe_writer.h','entry_stub.c','coff_reader.c','coff_reader.h','section_merge.c','section_merge.h','reloc_resolver.c')
$srcHashes = @()
foreach ($f in $linkerFiles) {
  $src = Join-Path $SrcRoot $f
  Copy-Item $src (Join-Path (Join-Path $Iso 'src') $f) -Force
  $srcHashes += [pscustomobject]@{ file=$f; sha256=((certutil -hashfile $src SHA256 | Select-Object -Skip 1 -First 1).Trim()) }
}
Copy-Item (Join-Path $CorpusSrc '*') (Join-Path $Iso 'corpus') -Force
$head = git -C F:\rawrxd rev-parse HEAD
# Avoid full porcelain on a huge dirty tree (previously stalled host).
git -C F:\rawrxd diff --quiet -- src/toolchain/linker tests/sovereign_linker
$linkerDirty = ($LASTEXITCODE -ne 0)
git -C F:\rawrxd diff --quiet
$mainDirtyQuick = ($LASTEXITCODE -ne 0)
Log ("GIT_HEAD={0}" -f $head)
Log ("LINKER_TREE_DIRTY={0}" -f $linkerDirty)
Log ("MAIN_TREE_DIRTY_QUICK={0}" -f $mainDirtyQuick)
$dirty = $linkerDirty

$objs = @()
foreach ($f in @('main.c','coff_reader.c','section_merge.c','reloc_resolver.c','pe_writer.c','entry_stub.c')) {
  $obj = Join-Path (Join-Path $Iso 'out') ($f.Replace('.c','.obj'))
  $src = Join-Path (Join-Path $Iso 'src') $f
  $inc = Join-Path $Iso 'src'
  $rc = Vs ('cl /nologo /c /O2 /TC /I"{0}" /Fo"{1}" "{2}"' -f $inc,$obj,$src)
  if ($rc -ne 0) { throw "compile failed $f" }
  $objs += $obj
}
$linkOut = Join-Path (Join-Path $Iso 'bin') 'rawrxd_link_isolated.exe'
$rc = Vs (('link /nologo /subsystem:console /DYNAMICBASE /NXCOMPAT /MACHINE:X64 /out:"{0}" {1} kernel32.lib' -f $linkOut, (($objs | ForEach-Object { '"{0}"' -f $_ }) -join ' ')))
if ($rc -ne 0) { throw 'link failed' }
$linkSha = (certutil -hashfile $linkOut SHA256 | Select-Object -Skip 1 -First 1).Trim()
Log ("ISOLATED_LINKER_SHA256={0}" -f $linkSha)
Log ("DIFFERS_FROM_CORPUS_EXECUTED={0}" -f ($linkSha -ne $refSha))

$all = @(
  @{id='01_minimal_return_zero'; expect=0; src=@('test01_minimal_return_zero.c')},
  @{id='02_exit_sentinel'; expect=42; src=@('test02_exit_sentinel.c')},
  @{id='03_multi_tu_linking'; expect=42; src=@('test03_multi_tu_a.c','test03_multi_tu_b.c')},
  @{id='04_static_library'; expect=42; src=@('test04_static_main.c','test04_static_lib.c')},
  @{id='05_shared_library'; expect=42; src=@('test05_shared_main.c','test05_shared_lib.c','test05_shared_core.c')},
  @{id='06_undefined_symbol'; expect='link_fail'; neg='link'; src=@('test06_undefined_symbol.c')},
  @{id='07_relocation'; expect=100; src=@('test07_relocation_a.c','test07_relocation_b.c')},
  @{id='08_cross_ref'; expect=42; src=@('test08_cross_ref_a.c','test08_cross_ref_b.c')},
  @{id='09_global_init'; expect=42; src=@('test09_global_init.c')},
  @{id='10_bss_zero'; expect=42; src=@('test10_bss_zero.c')},
  @{id='11_nested_calls'; expect=42; src=@('test11_nested_calls.c')},
  @{id='12_rodata_len'; expect=5; src=@('test12_rodata_len.c')},
  @{id='13_data_roundtrip'; expect=0; src=@('test13_data_roundtrip.c')},
  @{id='14_fixed_argc'; expect=3; src=@('test14_fixed_argc.c')},
  @{id='15_branch_table'; expect=42; src=@('test15_branch_table.c')},
  @{id='16_debug_release'; expect=42; src=@('test16_debug_release.c'); variants=@('/Od','/O2')},
  @{id='17_optimization'; expect=4950; src=@('test17_optimization.c')},
  @{id='18_incremental_rebuild'; expect=7; src=@('test18_incremental_a.c','test18_incremental_b.c')},
  @{id='19_deliberate_compiler_fail'; expect='compile_fail'; neg='compile'; src=@('test19_deliberate_compiler_fail.c')}
)

$pass=0; $fail=0; $results=@()
foreach ($t in $all) {
  Log ("=== {0} ===" -f $t.id)
  if ($t.neg -eq 'compile') {
    $o = Join-Path (Join-Path $Iso 'out') ($t.id + '.obj')
    $src = Join-Path (Join-Path $Iso 'corpus') $t.src[0]
    $rc = Vs ('cl /nologo /c /GS- /O2 /TC /Fo"{0}" "{1}"' -f $o,$src)
    if ($rc -ne 0) { $pass++; $results += [pscustomobject]@{test=$t.id;result='PASS';actual='compile_fail'}; Log 'PASS' }
    else { $fail++; $results += [pscustomobject]@{test=$t.id;result='FAIL';actual='compile_ok'}; Log 'FAIL' }
    continue
  }
  $variants = @('/O2'); if ($t.variants) { $variants = $t.variants }
  $ok=$true; $acts=@()
  foreach ($vf in $variants) {
    $olist=@(); $n=0
    foreach ($s in $t.src) {
      $n++
      $o = Join-Path (Join-Path $Iso 'out') ('{0}_{1}_{2}.obj' -f $t.id,$n,($vf -replace '[^A-Za-z0-9]',''))
      $src = Join-Path (Join-Path $Iso 'corpus') $s
      $rc = Vs ('cl /nologo /c /GS- {0} /TC /Fo"{1}" "{2}"' -f $vf,$o,$src)
      if ($rc -ne 0) { $ok=$false; $acts+='compile_fail'; break }
      $olist += $o
    }
    if (-not $ok) { break }
    $exe = Join-Path (Join-Path $Iso 'out') ('{0}_{1}.exe' -f $t.id,($vf -replace '[^A-Za-z0-9]',''))
    $linkCmd = '"{0}" -o "{1}" {2}' -f $linkOut,$exe,(($olist | ForEach-Object { '"{0}"' -f $_ }) -join ' ')
    if ($t.neg -eq 'link') {
      $rc = Vs $linkCmd
      if ($rc -ne 0) { $acts += 'link_fail' } else { $ok=$false; $acts += 'link_ok' }
      continue
    }
    $rc = Vs $linkCmd
    if ($rc -ne 0) { $ok=$false; $acts += ('link_fail={0}' -f $rc); continue }
    $rp = Start-Process $exe -NoNewWindow -Wait -PassThru
    $acts += ('exit={0}' -f $rp.ExitCode)
    if ($rp.ExitCode -ne [int]$t.expect) { $ok=$false }
  }
  if ($t.neg -eq 'link') { $ok = ($acts -contains 'link_fail') }
  if ($ok) { $pass++; Log ('PASS ' + ($acts -join ',')); $results += [pscustomobject]@{test=$t.id;result='PASS';actual=($acts -join ',')} }
  else { $fail++; Log ('FAIL ' + ($acts -join ',')); $results += [pscustomobject]@{test=$t.id;result='FAIL';actual=($acts -join ',')} }
}

$clBanner = ((cmd /c ('call "{0}" >nul && cl 2>&1' -f $Vcvars)) | Select-Object -First 2) -join ' | '
$prov = [ordered]@{
  schema='RAWRXD_SOVEREIGN_LINKER_P2_ISOLATED_PROVENANCE'
  generated_utc=(Get-Date).ToUniversalTime().ToString('o')
  method='isolated_source_snapshot_rebuild'
  note='Copies linker sources+corpus into evidence; does not clean main dirty worktree.'
  git_head="$head"
  main_tree_dirty=$dirty
  compiler_banner=$clBanner
  linker_build='cl /c /O2 units; link console (no /LTCG)'
  linker_path=$linkOut
  linker_sha256=$linkSha
  corpus_executed_sha_reference=$refSha
  hash_differs_from_corpus_executed=($linkSha -ne $refSha)
  hash_diff_interpretation='Expected if flags/LTCG/path differ; investigate only if isolated corpus fails or source hashes diverge from intent.'
  source_file_sha256=$srcHashes
  corpus_pass=$pass
  corpus_fail=$fail
  corpus_19_19=($pass -eq 19 -and $fail -eq 0)
  tests=$results
  WINDOWS_RUNTIME_CERT=0
  PROMOTE=0
  ENTRY_STUB='CLOSED'
}
$prov | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $Iso 'isolated_provenance.json') -Encoding UTF8
Log ("DONE pass={0} fail={1} sha={2}" -f $pass,$fail,$linkSha)
if ($pass -ne 19) { exit 1 }
exit 0

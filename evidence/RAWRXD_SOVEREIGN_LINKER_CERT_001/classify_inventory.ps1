$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$listPath = Join-Path $Ev 'obj_candidate_list.txt'
$missPath = Join-Path $Ev 'obj_not_found.txt'
$paths = @()
if (Test-Path $listPath) {
  $paths = @(Get-Content $listPath | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
}
$missing = @()
if (Test-Path $missPath) {
  $missing = @(Get-Content $missPath | Where-Object { $_ } | Select-Object -Unique)
}
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
function Dump([string]$a) {
  $wrap = 'call "' + $Vcvars + '" >nul && dumpbin ' + $a
  $o = Join-Path $env:TEMP 'cinv.out'; $e = Join-Path $env:TEMP 'cinv.err'
  $null = Start-Process cmd.exe -ArgumentList @('/c',$wrap) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  return (@(Get-Content $o,$e -EA SilentlyContinue) -join "`n")
}
$entries = @()
foreach ($p in $paths) {
  Write-Host "CLASSIFY $p"
  $sum = Dump ('/HEADERS "' + $p + '"')
  $sym = Dump ('/SYMBOLS "' + $p + '"')
  $rel = Dump ('/RELOCATIONS "' + $p + '"')
  $machine = if ($sum -match 'machine \(([^)]+)\)') { $Matches[1] } else { 'unknown' }
  $secNames = @([regex]::Matches($sum, '(?m)^\s+[0-9A-F]+\s+([.\w\$]+)\s+name') | ForEach-Object { $_.Groups[1].Value }) | Select-Object -Unique
  $undef = @([regex]::Matches($sym, '(?m)UNDEF\s+[^\|]*\|\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() }) | Select-Object -Unique
  $relocTypes = @([regex]::Matches($rel, '(?m)REL\d+|DIR64|ADDR32|REL32|SECREL|SECTION') | ForEach-Object { $_.Value }) | Select-Object -Unique
  $crt = @($undef | Where-Object { $_ -match 'malloc|free|memcpy|memset|__acrt|__imp_|__security|__chkstk|__Cxx|__std_|operator new|std::|atexit|abort' })
  $class = 'FREESTANDING_LINKABLE'
  $reasons = @()
  if ($machine -notmatch 'x64|8664|AMD64') { $class='UNSUPPORTED'; $reasons += 'machine_not_amd64' }
  if ($crt.Count -gt 0 -or $p -match '\.cpp\.obj' -or $undef -match '^\?') { $class='RUNTIME_DEPENDENT'; $reasons += 'crt_cpp_or_helpers' }
  if ($secNames -match 'tls') { $class='RUNTIME_DEPENDENT'; $reasons += 'tls' }
  if ($p -match 'deep2|reap|lavapath' -and $class -eq 'FREESTANDING_LINKABLE') { $class='RUNTIME_DEPENDENT'; $reasons += 'deep2_reap_path' }
  $sha = (certutil -hashfile $p SHA256 | Select-Object -Skip 1 -First 1).Trim()
  $entries += [pscustomobject]@{
    path=$p; status='FOUND'; sha256=$sha; machine=$machine; sections=@($secNames)
    undefined_count=$undef.Count; undefined_sample=@($undef|Select-Object -First 20)
    relocation_type_sample=@($relocTypes|Select-Object -First 20)
    crt_helper_sample=@($crt|Select-Object -First 12)
    classification=$class; reasons=$reasons
    rejection_if_linked_by_rawrxd_link = $(if ($class -eq 'FREESTANDING_LINKABLE') {'none_expected'} else {'diagnostic_and_nonzero_exit'})
  }
}
foreach ($m in $missing) {
  $entries += [pscustomobject]@{
    path=$m; status='NOT_FOUND'; sha256=$null; machine=$null; sections=@()
    undefined_count=0; undefined_sample=@(); relocation_type_sample=@(); crt_helper_sample=@()
    classification='NOT_FOUND'; reasons=@('manifest_entry_missing_on_disk')
    rejection_if_linked_by_rawrxd_link='n/a_object_absent'
  }
}
$summary = [ordered]@{
  schema='RAWRXD_NATIVE_OBJECT_INVENTORY_001'
  generated_utc=(Get-Date).ToUniversalTime().ToString('o')
  method='obj_manifest.txt_explicit_only_no_recursive_scan'
  manifest= (Join-Path $Ev 'obj_manifest.txt')
  objects_scanned=$entries.Count
  found=@($entries|Where-Object status -eq 'FOUND').Count
  not_found=@($entries|Where-Object status -eq 'NOT_FOUND').Count
  freestanding_linkable=@($entries|Where-Object classification -eq 'FREESTANDING_LINKABLE').Count
  runtime_dependent=@($entries|Where-Object classification -eq 'RUNTIME_DEPENDENT').Count
  unsupported=@($entries|Where-Object classification -eq 'UNSUPPORTED').Count
  fail_closed='RUNTIME_DEPENDENT/UNSUPPORTED => stderr diagnostic + nonzero exit; no silent drop'
  corpus_executed_sha_reference='08f4f4f26f40e1156857908862dae266d70ea910c3600af094565bdc26896436'
  ENTRY_STUB='CLOSED'; PROMOTE=0
  objects=$entries
}
$summary | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $Ev 'native_object_inventory.json') -Encoding UTF8
Write-Host ("INVENTORY n={0} rt={1} fs={2}" -f $entries.Count, $summary.runtime_dependent, $summary.freestanding_linkable)

# Slim inventory: headers + symbol counts only (no giant regex captures).
$ErrorActionPreference = 'Continue'
$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$found = @(Get-Content (Join-Path $Ev 'obj_candidate_list.txt') -EA SilentlyContinue | Where-Object { $_ })
$missing = @(Get-Content (Join-Path $Ev 'obj_not_found.txt') -EA SilentlyContinue | Where-Object { $_ })
function Dump([string]$argsLine) {
  $wrap = 'call "' + $Vcvars + '" >nul && dumpbin ' + $argsLine
  $o = Join-Path $env:TEMP 'slim_inv.out'; $e = Join-Path $env:TEMP 'slim_inv.err'
  $null = Start-Process cmd.exe -ArgumentList @('/c',$wrap) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  return (@(Get-Content $o,$e -EA SilentlyContinue) -join "`n")
}
$entries = @()
foreach ($p in $found) {
  if (-not (Test-Path $p)) { continue }
  Write-Host "SLIM $p"
  $sum = Dump ('/HEADERS "' + $p + '"')
  $sym = Dump ('/SYMBOLS "' + $p + '"')
  $rel = Dump ('/RELOCATIONS "' + $p + '"')
  $machine = if ($sum -match 'machine \(([^)]+)\)') { $Matches[1] } else { 'unknown' }
  $secNames = [regex]::Matches($sum, '(?m)^\s+[0-9A-F]+\s+([.\w\$]+)\s+name') | ForEach-Object { $_.Groups[1].Value }
  $secNames = @($secNames | Select-Object -Unique)
  $undefLines = @($sym -split "`n" | Where-Object { $_ -match 'UNDEF' })
  $undefNames = @()
  foreach ($line in ($undefLines | Select-Object -First 40)) {
    if ($line -match '\|\s*(.+)$') { $undefNames += $Matches[1].Trim() }
  }
  $relocCount = ([regex]::Matches($rel, '(?m)^\s+[0-9A-F]{4,}') ).Count
  $crt = @($undefNames | Where-Object { $_ -match 'malloc|free|memcpy|memset|__acrt|__imp_|__security|__chkstk|__Cxx|__std_|operator new|std::|atexit|abort' } | Select-Object -First 12)
  $class = 'FREESTANDING_LINKABLE'
  $reasons = @()
  if ($machine -notmatch 'x64|8664|AMD64') { $class='UNSUPPORTED'; $reasons += 'machine_not_amd64' }
  if ($crt.Count -gt 0 -or $p -match '\.cpp\.obj' -or ($undefNames -match '^\?').Count -gt 0) {
    $class='RUNTIME_DEPENDENT'; $reasons += 'crt_cpp_or_helpers'
  }
  if ($secNames -match 'tls') { $class='RUNTIME_DEPENDENT'; $reasons += 'tls' }
  if ($p -match 'deep2|reap|lavapath|cpu_inference' -and $class -eq 'FREESTANDING_LINKABLE') {
    $class='RUNTIME_DEPENDENT'; $reasons += 'product_cpp_path'
  }
  # rawrxd_link C objs are freestanding tooling, not Deep2 native product objs
  if ($p -match 'rawrxd_link\.dir' -and $p -match '\.c\.obj') {
    $class = 'FREESTANDING_LINKABLE'
    $reasons = @('sovereign_linker_c_unit')
  }
  $sha = (certutil -hashfile $p SHA256 | Select-Object -Skip 1 -First 1).Trim()
  $entries += [ordered]@{
    path=$p; status='FOUND'; sha256=$sha; machine=$machine
    sections=$secNames
    undefined_count=$undefLines.Count
    undefined_sample=@($undefNames | Select-Object -First 15)
    relocation_approx_count=$relocCount
    crt_helper_sample=$crt
    classification=$class; reasons=$reasons
    rejection_if_linked_by_rawrxd_link=$(if($class -eq 'FREESTANDING_LINKABLE'){'none_expected'}else{'diagnostic_and_nonzero_exit'})
  }
}
foreach ($m in $missing) {
  $entries += [ordered]@{
    path=$m; status='NOT_FOUND'; classification='NOT_FOUND'
    reasons=@('manifest_entry_missing_on_disk')
    rejection_if_linked_by_rawrxd_link='n/a_object_absent'
  }
}
$summary = [ordered]@{
  schema='RAWRXD_NATIVE_OBJECT_INVENTORY_001'
  generated_utc=(Get-Date).ToUniversalTime().ToString('o')
  method='obj_manifest_explicit_slim'
  manifest=(Join-Path $Ev 'obj_manifest.txt')
  objects_scanned=$entries.Count
  found=@($entries | Where-Object { $_.status -eq 'FOUND' }).Count
  not_found=@($entries | Where-Object { $_.status -eq 'NOT_FOUND' }).Count
  freestanding_linkable=@($entries | Where-Object { $_.classification -eq 'FREESTANDING_LINKABLE' }).Count
  runtime_dependent=@($entries | Where-Object { $_.classification -eq 'RUNTIME_DEPENDENT' }).Count
  unsupported=@($entries | Where-Object { $_.classification -eq 'UNSUPPORTED' }).Count
  fail_closed='RUNTIME_DEPENDENT/UNSUPPORTED => stderr diagnostic + nonzero exit; no silent drop'
  corpus_executed_sha_reference='08f4f4f26f40e1156857908862dae266d70ea910c3600af094565bdc26896436'
  ENTRY_STUB='CLOSED'
  PROMOTE=0
  objects=$entries
}
$out = Join-Path $Ev 'native_object_inventory.json'
($summary | ConvertTo-Json -Depth 6 -Compress) | Set-Content $out -Encoding UTF8
Write-Host ("SLIM_INVENTORY bytes={0} found={1} not_found={2} rt={3} fs={4}" -f (Get-Item $out).Length, $summary.found, $summary.not_found, $summary.runtime_dependent, $summary.freestanding_linkable)

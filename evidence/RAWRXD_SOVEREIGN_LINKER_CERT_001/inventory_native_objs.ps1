# Fast inventory: targeted CMakeFiles dirs + dumpbin sample (max 40 objs).
$ErrorActionPreference = 'Continue'
$Ev = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001'
$OutJson = Join-Path $Ev 'native_object_inventory.json'
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$dirs = @(
  'F:\rawrxd\build_5os_win\CMakeFiles',
  'F:\rawrxd\build_reap\CMakeFiles',
  'F:\rawrxd\build_ide\CMakeFiles'
)
function VsDump([string]$argsLine) {
  $wrap = 'call "' + $Vcvars + '" >nul && dumpbin ' + $argsLine
  $tmpo = Join-Path $env:TEMP 'dumpbin_inv.out'
  $tmpe = Join-Path $env:TEMP 'dumpbin_inv.err'
  $null = Start-Process cmd.exe -ArgumentList @('/c', $wrap) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmpo -RedirectStandardError $tmpe
  return (@(Get-Content $tmpo, $tmpe -ErrorAction SilentlyContinue) -join "`n")
}

$files = New-Object System.Collections.Generic.List[object]
foreach ($d in $dirs) {
  if (-not (Test-Path $d)) { continue }
  Write-Host ("SCAN {0}" -f $d)
  Get-ChildItem -Path $d -Recurse -Filter '*.obj' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = $_.FullName
    if ($p -match 'deep2|reap|lavapath|quant_dot|gguf|GpuDevice|streaming_gguf|PrefillBatch|runtime_graph') {
      $files.Add($_)
    }
  }
}
$files = @($files | Sort-Object FullName -Unique | Select-Object -First 40)
Write-Host ("FOUND_OBJS={0}" -f $files.Count)

$entries = @()
foreach ($f in $files) {
  Write-Host ("DUMP {0}" -f $f.Name)
  $sum = VsDump ('/HEADERS "' + $f.FullName + '"')
  $sym = VsDump ('/SYMBOLS "' + $f.FullName + '"')
  $machine = if ($sum -match 'machine \(([^)]+)\)') { $Matches[1] } else { 'unknown' }
  $secNames = @([regex]::Matches($sum, '(?m)^\s+[0-9A-F]+\s+([.\w\$]+)\s+name') | ForEach-Object { $_.Groups[1].Value }) | Select-Object -Unique
  $undef = @([regex]::Matches($sym, '(?m)UNDEF\s+[^\|]*\|\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() }) | Select-Object -Unique
  $crtHits = @($undef | Where-Object {
    $_ -match 'malloc|free|memcpy|memset|memmove|strlen|printf|atexit|__acrt|__imp_|__security_cookie|__chkstk|__Cxx|__std_|__GSHandler|___CxxFrameHandler|__C_specific_handler|abort|operator new|operator delete|std::'
  })
  $needsCpp = [bool]($undef -match '^\?' -or $secNames -contains '.xdata' -or $f.Name -match '\.cpp\.obj')
  $needsTls = [bool]($secNames -match 'tls' -or $undef -match '_tls_')
  $needsPdata = [bool]($secNames -contains '.pdata')

  $class = 'FREESTANDING_LINKABLE'
  $reasons = New-Object System.Collections.Generic.List[string]
  if ($machine -notmatch 'x64|8664|AMD64') { $class = 'UNSUPPORTED'; [void]$reasons.Add('machine_not_amd64') }
  if ($crtHits.Count -gt 0) { $class = 'RUNTIME_DEPENDENT'; [void]$reasons.Add('crt_or_helpers') }
  if ($needsCpp) { $class = 'RUNTIME_DEPENDENT'; [void]$reasons.Add('cpp_runtime_or_xdata') }
  if ($needsTls) { $class = 'RUNTIME_DEPENDENT'; [void]$reasons.Add('tls') }
  if ($needsPdata) { [void]$reasons.Add('pdata_present') }
  if ($undef.Count -gt 25) { $class = 'RUNTIME_DEPENDENT'; [void]$reasons.Add('many_undefined_symbols') }
  if ($f.FullName -match 'deep2|lavapath|reap' -and $class -eq 'FREESTANDING_LINKABLE') {
    $class = 'RUNTIME_DEPENDENT'; [void]$reasons.Add('deep2_reap_path_heuristic')
  }

  $sha = (certutil -hashfile $f.FullName SHA256 | Select-Object -Skip 1 -First 1).Trim()
  $entries += [pscustomobject]@{
    path = $f.FullName
    size = $f.Length
    sha256 = $sha
    machine = $machine
    sections = @($secNames)
    undefined_count = $undef.Count
    undefined_sample = @($undef | Select-Object -First 20)
    crt_helper_sample = @($crtHits | Select-Object -First 12)
    classification = $class
    reasons = @($reasons)
    rejection_if_linked_by_rawrxd_link = $(
      if ($class -eq 'FREESTANDING_LINKABLE') { 'none_expected' }
      elseif ($class -eq 'RUNTIME_DEPENDENT') { 'unresolved_crt_cpp_tls_or_helper_symbols_nonzero_exit' }
      else { 'unsupported_machine_or_format_nonzero_exit' }
    )
  }
}

$summary = [ordered]@{
  schema = 'RAWRXD_NATIVE_OBJECT_INVENTORY_001'
  generated_utc = (Get-Date).ToUniversalTime().ToString('o')
  objects_scanned = $entries.Count
  freestanding_linkable = @($entries | Where-Object classification -eq 'FREESTANDING_LINKABLE').Count
  runtime_dependent = @($entries | Where-Object classification -eq 'RUNTIME_DEPENDENT').Count
  unsupported = @($entries | Where-Object classification -eq 'UNSUPPORTED').Count
  fail_closed = 'RUNTIME_DEPENDENT/UNSUPPORTED => diagnostic + nonzero exit; no silent drop'
  corpus_executed_sha_reference = '08f4f4f26f40e1156857908862dae266d70ea910c3600af094565bdc26896436'
  ENTRY_STUB = 'CLOSED'
  PROMOTE = 0
  objects = $entries
}
$summary | ConvertTo-Json -Depth 8 | Set-Content $OutJson -Encoding UTF8
Write-Host ("INVENTORY fs={0} rt={1} un={2} file={3}" -f $summary.freestanding_linkable, $summary.runtime_dependent, $summary.unsupported, $OutJson)

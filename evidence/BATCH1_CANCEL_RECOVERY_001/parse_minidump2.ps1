param([string]$Dump = "$env:LOCALAPPDATA\RawrXD\crashes\rawrxd-20261103-010807.dmp")
$b = [IO.File]::ReadAllBytes($Dump)
$n = [BitConverter]::ToUInt32($b, 8)
$rva = [BitConverter]::ToUInt32($b, 12)
$fault = [uint64]0
for ($i = 0; $i -lt $n; $i++) {
  $off = $rva + $i * 12
  if ([BitConverter]::ToUInt32($b, $off) -ne 6) { continue }
  $srva = [BitConverter]::ToUInt32($b, $off + 8)
  $tid = [BitConverter]::ToUInt32($b, $srva)
  $code = [BitConverter]::ToUInt32($b, $srva + 8)
  $fault = [BitConverter]::ToUInt64($b, $srva + 24)
  $access = [BitConverter]::ToUInt64($b, $srva + 40)
  $target = [BitConverter]::ToUInt64($b, $srva + 48)
  "EXCEPTION tid=$tid code=0x$($code.ToString('X8')) rip=0x$($fault.ToString('X')) write=$access target=0x$($target.ToString('X'))"
}
for ($i = 0; $i -lt $n; $i++) {
  $off = $rva + $i * 12
  if ([BitConverter]::ToUInt32($b, $off) -ne 4) { continue }
  $srva = [BitConverter]::ToUInt32($b, $off + 8)
  $num = [BitConverter]::ToUInt32($b, $srva)
  $ptr = $srva + 8
  if (($ptr % 8) -ne 0) { $ptr += (8 - ($ptr % 8)) }
  $rows = @()
  for ($m = 0; $m -lt $num; $m++) {
    $modBase = [BitConverter]::ToUInt64($b, $ptr)
    $modSize = [BitConverter]::ToUInt32($b, $ptr + 8)
    $nameRva = [BitConverter]::ToUInt32($b, $ptr + 20)
    $slen = [BitConverter]::ToUInt32($b, $nameRva)
    $name = [Text.Encoding]::Unicode.GetString($b, ($nameRva + 4), [Math]::Min([int]$slen, 520))
    $leaf = $name
    if ($leaf.Contains('\')) { $leaf = $leaf.Substring($leaf.LastIndexOf('\') + 1) }
    $rows += [pscustomobject]@{ Name = $leaf; Base = $modBase; Size = $modSize; End = ($modBase + $modSize) }
    $ptr += 108
  }
  "modules=$($rows.Count)"
  $hit = $rows | Where-Object { $fault -ge $_.Base -and $fault -lt $_.End }
  if ($hit) {
    foreach ($h in $hit) {
      "FAULT_MODULE=$($h.Name)"
      "FAULT_RVA=0x$(($fault - $h.Base).ToString('X'))"
      "FAULT_BASE=0x$($h.Base.ToString('X'))"
    }
  } else {
    "FAULT_MODULE=UNMAPPED"
  }
  "NEAR:"
  $rows | Sort-Object { [Math]::Abs([int64]($_.Base - $fault)) } | Select-Object -First 10 | ForEach-Object {
    $delta = [int64]($_.Base - $fault)
    "  $($_.Name) base=0x$($_.Base.ToString('X')) size=0x$($_.Size.ToString('X')) delta=$delta"
  }
  "KEY:"
  $rows | Where-Object { $_.Name -match 'RawrXD|RichEd|msftedit|user32|ntdll|ucrtbase|winhttp' } | ForEach-Object {
    "  $($_.Name) 0x$($_.Base.ToString('X'))-0x$($_.End.ToString('X'))"
  }
}
"EXIT_STATUS=0xC000041D STATUS_FATAL_USER_CALLBACK_EXCEPTION"

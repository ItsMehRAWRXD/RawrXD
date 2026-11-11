# Parse minidump ExceptionStream + ModuleList for Request A crash
param(
  [string]$Dump = "$env:LOCALAPPDATA\RawrXD\crashes\rawrxd-20261103-010807.dmp"
)
$ErrorActionPreference = 'Stop'
$b = [IO.File]::ReadAllBytes($Dump)
$n = [BitConverter]::ToUInt32($b, 8)
$rva = [BitConverter]::ToUInt32($b, 12)
$fault = [uint64]0
$tid = 0
$code = 0
$target = [uint64]0
Write-Output "DUMP=$Dump size=$($b.Length) streams=$n"
for ($i = 0; $i -lt $n; $i++) {
  $off = $rva + $i * 12
  $stype = [BitConverter]::ToUInt32($b, $off)
  $size = [BitConverter]::ToUInt32($b, $off + 4)
  $srva = [BitConverter]::ToUInt32($b, $off + 8)
  if ($stype -eq 6) {
    $tid = [BitConverter]::ToUInt32($b, $srva)
    $code = [BitConverter]::ToUInt32($b, $srva + 8)
    $fault = [BitConverter]::ToUInt64($b, $srva + 24)
    $nparams = [BitConverter]::ToUInt32($b, $srva + 32)
    $access = [BitConverter]::ToUInt64($b, $srva + 40)
    $target = [BitConverter]::ToUInt64($b, $srva + 48)
    Write-Output ("EXCEPTION tid={0} code=0x{1:X8} rip=0x{2:X} access={3} target=0x{4:X}" -f $tid, $code, $fault, $access, $target)
  }
}
for ($i = 0; $i -lt $n; $i++) {
  $off = $rva + $i * 12
  $stype = [BitConverter]::ToUInt32($b, $off)
  $srva = [BitConverter]::ToUInt32($b, $off + 8)
  if ($stype -ne 4) { continue }
  $num = [BitConverter]::ToUInt32($b, $srva)
  $ptr = $srva + 8
  if (($ptr % 8) -ne 0) { $ptr += (8 - ($ptr % 8)) }
  Write-Output "ModuleList count=$num"
  $hit = $false
  for ($m = 0; $m -lt $num; $m++) {
    $modBase = [BitConverter]::ToUInt64($b, $ptr)
    $modSize = [BitConverter]::ToUInt32($b, $ptr + 8)
    $nameRva = [BitConverter]::ToUInt32($b, $ptr + 20)
    $slen = [BitConverter]::ToUInt32($b, $nameRva)
    $name = [Text.Encoding]::Unicode.GetString($b, $nameRva + 4, [Math]::Min([int]$slen, 512))
    $end = $modBase + $modSize
    if ($fault -ge $modBase -and $fault -lt $end) {
      Write-Output ("FAULT_MODULE={0}" -f $name)
      Write-Output ("FAULT_BASE=0x{0:X}" -f $modBase)
      Write-Output ("FAULT_SIZE=0x{0:X}" -f $modSize)
      Write-Output ("FAULT_RVA=0x{0:X}" -f ($fault - $modBase))
      $hit = $true
    }
    # Always print exe / richedit / ntdll / user32 / ucrt
    if ($name -match 'RawrXD-Win32IDE-Native|RichEd|msftedit|user32|ntdll|ucrtbase|vcruntime|winhttp') {
      Write-Output ("MOD {0} base=0x{1:X} size=0x{2:X}" -f $name, $modBase, $modSize)
    }
    $ptr += 108
  }
  if (-not $hit) { Write-Output 'FAULT_MODULE=UNMAPPED' }
}
Write-Output ("EXIT_CODE_FROM_HARNESS=-1073740771 = 0x{0:X8} (STATUS_FATAL_USER_CALLBACK_EXCEPTION)" -f ([uint32]-1073740771))

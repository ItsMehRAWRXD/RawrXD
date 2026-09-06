$path = 'F:\~dev\rawrxd\build-win32ide-fresh\bin\crash_dumps\RawrXD_20260901_212315_C0000005.dmp'
$b = [IO.File]::ReadAllBytes($path)
$off = 0x648
$threadId = [BitConverter]::ToUInt32($b, $off)
$exCode = [BitConverter]::ToUInt32($b, $off + 12)
$exAddr = [BitConverter]::ToUInt64($b, $off + 24)
$ctxSize = [BitConverter]::ToUInt32($b, $off + 12 + 4 + 8 + 8 + 4 + 120) # need correct layout

# MINIDUMP_EXCEPTION_STREAM:
# ThreadId u32 @0
# __alignment u32 @4
# ExceptionRecord MINIDUMP_EXCEPTION @8
#   ExceptionCode u32
#   ExceptionFlags u32
#   ExceptionRecord u64
#   ExceptionAddress u64
#   NumberParameters u32
#   __unusedAlignment u32
#   ExceptionInformation[15] u64 each = 120 bytes
# ThreadContext MINIDUMP_LOCATION_DESCRIPTOR @8+4+8+8+8+4+4+120 = 164? 
# Let me compute: offset 8 + 4+4+8+8+4+4 = 36 + 120 = 156 from stream start
$ctxDescOff = $off + 8 + 4 + 4 + 8 + 8 + 4 + 4 + 120
$ctxSize = [BitConverter]::ToUInt32($b, $ctxDescOff)
$ctxRva = [BitConverter]::ToUInt32($b, $ctxDescOff + 4)
Write-Host "threadId=$threadId exCode=0x$($exCode.ToString('X')) exAddr=0x$($exAddr.ToString('X'))"
Write-Host "ctxSize=$ctxSize ctxRva=0x$($ctxRva.ToString('X'))"
if ($ctxSize -ge 0x100) {
  $ctxOff = $ctxRva
  $rip = [BitConverter]::ToUInt64($b, $ctxOff + 0xF8)
  $rsp = [BitConverter]::ToUInt64($b, $ctxOff + 0x98)
  $rcx = [BitConverter]::ToUInt64($b, $ctxOff + 0x80)
  $rdx = [BitConverter]::ToUInt64($b, $ctxOff + 0x88)
  Write-Host "Rip=0x$($rip.ToString('X')) Rsp=0x$($rsp.ToString('X')) Rcx=0x$($rcx.ToString('X')) Rdx=0x$($rdx.ToString('X'))"
}

# Module list at rva 0x880
$modOff = 0x880
$nmod = [BitConverter]::ToUInt32($b, $modOff)
Write-Host "modules=$nmod"
for ($i=0; $i -lt [Math]::Min($nmod, 8); $i++) {
  $m = $modOff + 4 + $i * 108
  $base = [BitConverter]::ToUInt64($b, $m)
  $size = [BitConverter]::ToUInt32($b, $m + 8)
  $nameRva = [BitConverter]::ToUInt32($b, $m + 20)
  $npos = $nameRva
  $chars = New-Object System.Collections.Generic.List[byte]
  while ($true) {
    $ch = [BitConverter]::ToUInt16($b, $npos)
    $npos += 2
    if ($ch -eq 0) { break }
    $chars.Add([byte]($ch -band 0xFF))
    $chars.Add([byte](($ch -shr 8) -band 0xFF))
  }
  $name = [Text.Encoding]::Unicode.GetString($chars.ToArray())
  $leaf = Split-Path $name -Leaf
  if ($rip -ge $base -and $rip -lt ($base + $size)) {
    $rva = $rip - $base
    Write-Host "FAULT IN $leaf base=0x$($base.ToString('X')) rva=0x$($rva.ToString('X'))"
  }
  if ($leaf -match 'RawrXD|ntdll|KERNEL32|atiadl') {
    Write-Host "$leaf base=0x$($base.ToString('X')) size=0x$($size.ToString('X'))"
  }
}

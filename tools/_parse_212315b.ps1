$path = 'F:\~dev\rawrxd\build-win32ide-fresh\bin\crash_dumps\RawrXD_20260901_212315_C0000005.dmp'
$b = [IO.File]::ReadAllBytes($path)
$rip = 0x3DCBC4
$modOff = 0x880
$nmod = [BitConverter]::ToUInt32($b, $modOff)
foreach ($i in 0..($nmod-1)) {
  $m = $modOff + 4 + $i * 108
  $base = [BitConverter]::ToUInt64($b, $m)
  $size = [BitConverter]::ToUInt32($b, $m + 8)
  $nameRva = [BitConverter]::ToUInt32($b, $m + 20)
  $npos = $nameRva
  $sb = New-Object System.Text.StringBuilder
  while ($true) {
    $ch = [BitConverter]::ToUInt16($b, $npos)
    $npos += 2
    if ($ch -eq 0) { break }
    $sb.Append([char]$ch) | Out-Null
  }
  $name = $sb.ToString()
  if ($rip -ge $base -and $rip -lt ($base + $size)) {
    $rva = $rip - $base
    Write-Host "FAULT_MODULE=$name"
    Write-Host "BASE=0x$($base.ToString('X')) RVA=0x$($rva.ToString('X'))"
  }
}

# stack walk from rsp 0x151FF980 - find thread memory stream
$rsp = 0x151FF980
$fs = [IO.File]::OpenRead($path)
$br = New-Object IO.BinaryReader($fs)
$fs.Position = 0x20
$mods = @()
for ($s=0; $s -lt 13; $s++) {
  $t = $br.ReadUInt32(); $sz = $br.ReadUInt32(); $rva = $br.ReadUInt32()
  if ($t -eq 3) {
    $fs.Position = $rva
    $nt = $br.ReadUInt32()
    for ($i=0; $i -lt $nt; $i++) {
      $tid = $br.ReadUInt32()
      [void]$br.ReadUInt32(); [void]$br.ReadUInt32(); [void]$br.ReadUInt32(); [void]$br.ReadUInt64()
      $stkSz = $br.ReadUInt32(); $stkRva = $br.ReadUInt32()
      [void]$br.ReadUInt32(); [void]$br.ReadUInt32()
      if ($tid -eq 31804) {
        $mem = New-Object byte[] ([Math]::Min($stkSz, 4096))
        $fs.Position = $stkRva
        [void]$fs.Read($mem, 0, $mem.Length)
        Write-Host "STACK_SCAN tid=$tid"
        for ($o=0; $o -lt $mem.Length-8; $o+=8) {
          $v = [BitConverter]::ToUInt64($mem, $o)
          if ($v -gt 0x10000 -and $v -lt 0x7FFFFFFFFFFF) {
            foreach ($j in 0..($nmod-1)) {
              $mb = $modOff + 4 + $j * 108
              $base = [BitConverter]::ToUInt64($b, $mb)
              $size = [BitConverter]::ToUInt32($b, $mb + 8)
              if ($v -ge $base -and $v -lt ($base + $size)) {
                $nr = [BitConverter]::ToUInt32($b, $mb + 20)
                $np = $nr
                $sb2 = New-Object System.Text.StringBuilder
                while ($true) {
                  $ch = [BitConverter]::ToUInt16($b, $np); $np += 2
                  if ($ch -eq 0) { break }
                  $sb2.Append([char]$ch) | Out-Null
                }
                $leaf = Split-Path $sb2.ToString() -Leaf
                if ($leaf -match 'RawrXD|ntdll|KERNEL|msvc|atiadl|GpuDecode|AmdGpu') {
                  Write-Host ("  +{0:X3} {1}+0x{2:X}" -f $o, $leaf, ($v-$base))
                }
              }
            }
          }
        }
      }
    }
  }
}
$br.Close(); $fs.Close()

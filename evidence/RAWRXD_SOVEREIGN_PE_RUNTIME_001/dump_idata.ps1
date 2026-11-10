$p = 'F:\rawrxd\evidence\RAWRXD_SOVEREIGN_PE_RUNTIME_001\test_exit42.exe'
$d = [IO.File]::ReadAllBytes($p)
$e_lfanew = [BitConverter]::ToInt32($d, 0x3C)
$numSec = [BitConverter]::ToUInt16($d, $e_lfanew + 6)
$optSize = [BitConverter]::ToUInt16($d, $e_lfanew + 20)
$secOff = $e_lfanew + 24 + $optSize
$opt = $e_lfanew + 24
Write-Output ("e_lfanew=0x{0:x} numSec={1} SizeOfHeaders=0x{2:x} secOff=0x{3:x}" -f $e_lfanew,$numSec,[BitConverter]::ToUInt32($d,$opt+60),$secOff)
Write-Output ("headersEndExclusive=0x{0:x} (secHdrs need {1} bytes)" -f ($secOff + $numSec*40), ($numSec*40))
for ($i=0; $i -lt $numSec; $i++) {
  $o = $secOff + $i*40
  $nameBytes = $d[$o..($o+7)]
  $name = -join ($nameBytes | ForEach-Object { if ($_ -eq 0) { '' } else { [char]$_ } })
  $vsize = [BitConverter]::ToUInt32($d, $o+8)
  $rva = [BitConverter]::ToUInt32($d, $o+12)
  $rawsz = [BitConverter]::ToUInt32($d, $o+16)
  $rawoff = [BitConverter]::ToUInt32($d, $o+20)
  $ch = [BitConverter]::ToUInt32($d, $o+36)
  Write-Output ("SEC {0} RVA=0x{1:x} VSize=0x{2:x} RawOff=0x{3:x} RawSz=0x{4:x} Ch=0x{5:x}" -f $name,$rva,$vsize,$rawoff,$rawsz,$ch)
  if ($name -eq '.idata') {
    $end = [Math]::Min($rawoff + $rawsz, $rawoff + 0x80) - 1
    $bytes = $d[$rawoff..$end]
    $hx = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ' '
    Write-Output ("IDATA_HEX $hx")
    for ($didx=0; $didx -lt 4; $didx++) {
      $do = $rawoff + $didx*20
      $ilt = [BitConverter]::ToUInt32($d, $do+0)
      $nameRva = [BitConverter]::ToUInt32($d, $do+12)
      $ft = [BitConverter]::ToUInt32($d, $do+16)
      Write-Output ("DESC[$didx] ILT=0x{0:x} NameRVA=0x{1:x} FT=0x{2:x}" -f $ilt,$nameRva,$ft)
      if ($ilt -eq 0 -and $ft -eq 0) { break }
      if ($nameRva -ge $rva -and $nameRva -lt ($rva+$vsize)) {
        $no = $rawoff + ($nameRva - $rva)
        $ns = New-Object System.Text.StringBuilder
        while ($d[$no] -ne 0) { [void]$ns.Append([char]$d[$no]); $no++ }
        Write-Output ("  DLL=$ns")
      }
      if ($ft -ge $rva -and $ft -lt ($rva+$vsize)) {
        $io = $rawoff + ($ft - $rva)
        $thunk = [BitConverter]::ToUInt64($d, $io)
        Write-Output ("  IAT[0]=0x{0:x}" -f $thunk)
        if ($thunk -ne 0 -and ($thunk -band 0x8000000000000000) -eq 0) {
          $hnRva = [uint32]($thunk -band 0x7FFFFFFF)
          if ($hnRva -ge $rva -and $hnRva -lt ($rva+$vsize)) {
            $ho = $rawoff + ($hnRva - $rva)
            $hint = [BitConverter]::ToUInt16($d, $ho)
            $fo = $ho + 2
            $fn = New-Object System.Text.StringBuilder
            while ($d[$fo] -ne 0) { [void]$fn.Append([char]$d[$fo]); $fo++ }
            Write-Output ("  HintName hint=$hint name=$fn")
          }
        }
      }
    }
  }
}
$impRva = [BitConverter]::ToUInt32($d, $opt + 120)
$impSz = [BitConverter]::ToUInt32($d, $opt + 124)
$iatRva = [BitConverter]::ToUInt32($d, $opt + 112 + 12*8)
$iatSz = [BitConverter]::ToUInt32($d, $opt + 112 + 12*8 + 4)
Write-Output ("ImportDir RVA=0x{0:x} Size=0x{1:x}" -f $impRva,$impSz)
Write-Output ("IAT_DIR RVA=0x{0:x} Size=0x{1:x}" -f $iatRva,$iatSz)
Write-Output ("Entry=0x{0:x} DllChar=0x{1:x}" -f [BitConverter]::ToUInt32($d,$opt+16), [BitConverter]::ToUInt16($d,$opt+70))

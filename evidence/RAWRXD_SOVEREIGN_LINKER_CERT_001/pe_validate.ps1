# Independent PE32+ structural validator (does not use rawrxd_check / pe_writer).
param(
  [Parameter(Mandatory=$true)][string]$Path,
  [string]$OutJson = ''
)
$ErrorActionPreference = 'Stop'
$d = [IO.File]::ReadAllBytes($Path)
$issues = New-Object System.Collections.Generic.List[string]
function Fail([string]$m) { [void]$issues.Add($m) }

if ($d.Length -lt 64) { Fail 'file_too_small' }
if ($d[0] -ne 0x4D -or $d[1] -ne 0x5A) { Fail 'missing_mz' }
$e_lfanew = [BitConverter]::ToInt32($d, 0x3C)
if ($e_lfanew -lt 64 -or ($e_lfanew + 24) -gt $d.Length) { Fail 'bad_e_lfanew' }
if ($d[$e_lfanew] -ne 0x50 -or $d[$e_lfanew+1] -ne 0x45 -or $d[$e_lfanew+2] -ne 0 -or $d[$e_lfanew+3] -ne 0) {
  Fail 'missing_pe_sig'
}
$coff = $e_lfanew + 4
$machine = [BitConverter]::ToUInt16($d, $coff + 0)
$numSec = [BitConverter]::ToUInt16($d, $coff + 2)
$optSize = [BitConverter]::ToUInt16($d, $coff + 16)
$chars = [BitConverter]::ToUInt16($d, $coff + 18)
if ($machine -ne 0x8664) { Fail ("machine_not_amd64=0x{0:x}" -f $machine) }
if (($chars -band 0x0002) -eq 0) { Fail 'not_executable_image' }
if ($optSize -lt 112) { Fail 'opt_header_too_small' }
$opt = $coff + 20
$magic = [BitConverter]::ToUInt16($d, $opt + 0)
if ($magic -ne 0x020B) { Fail ("not_pe32plus=0x{0:x}" -f $magic) }
$entry = [BitConverter]::ToUInt32($d, $opt + 16)
$secAlign = [BitConverter]::ToUInt32($d, $opt + 32)
$fileAlign = [BitConverter]::ToUInt32($d, $opt + 36)
$sizeImage = [BitConverter]::ToUInt32($d, $opt + 56)
$sizeHeaders = [BitConverter]::ToUInt32($d, $opt + 60)
$numDirs = [BitConverter]::ToUInt32($d, $opt + 108)
$impRva = [BitConverter]::ToUInt32($d, $opt + 120)
$impSize = [BitConverter]::ToUInt32($d, $opt + 124)
if ($secAlign -eq 0 -or ($secAlign -band ($secAlign - 1)) -ne 0) { Fail 'section_align_not_pow2' }
if ($fileAlign -eq 0 -or ($fileAlign -band ($fileAlign - 1)) -ne 0) { Fail 'file_align_not_pow2' }
if (($sizeHeaders % $fileAlign) -ne 0) { Fail 'size_of_headers_unaligned' }
if (($sizeImage % $secAlign) -ne 0) { Fail 'size_of_image_unaligned' }
if ($numDirs -lt 2) { Fail 'too_few_data_dirs' }

$secOff = $opt + $optSize
$headerEnd = $secOff + ($numSec * 40)
if ($headerEnd -gt $sizeHeaders) { Fail 'section_headers_overflow_size_of_headers' }
if ($headerEnd -gt $d.Length) { Fail 'section_headers_past_eof' }

$sections = @()
$execEntryHit = $false
for ($i = 0; $i -lt $numSec; $i++) {
  $o = $secOff + $i * 40
  $nameBytes = $d[$o..($o+7)]
  $name = -join ($nameBytes | ForEach-Object { if ($_ -eq 0) { '' } else { [char]$_ } })
  $vsize = [BitConverter]::ToUInt32($d, $o+8)
  $rva = [BitConverter]::ToUInt32($d, $o+12)
  $rawsz = [BitConverter]::ToUInt32($d, $o+16)
  $rawoff = [BitConverter]::ToUInt32($d, $o+20)
  $ch = [BitConverter]::ToUInt32($d, $o+36)
  if (($rva % $secAlign) -ne 0) { Fail ("section_rva_unaligned:$name") }
  if ($rawsz -gt 0 -and ($rawoff % $fileAlign) -ne 0) { Fail ("raw_off_unaligned:$name") }
  if ($rawsz -gt 0 -and ($rawsz % $fileAlign) -ne 0) { Fail ("raw_size_unaligned:$name") }
  if ($rawsz -gt 0 -and ($rawoff + $rawsz) -gt $d.Length) { Fail ("raw_past_eof:$name") }
  if ($rawoff -gt 0 -and $rawoff -lt $sizeHeaders) { Fail ("raw_overlaps_headers:$name") }
  if ($rva -ge $sizeImage) { Fail ("rva_past_image:$name") }
  if (($ch -band 0x20000000) -ne 0 -and ($ch -band 0x00000020) -eq 0) {
    Fail ("execute_without_code:$name")
  }
  if ($entry -ge $rva -and $entry -lt ($rva + [Math]::Max($vsize,1))) {
    if (($ch -band 0x20000000) -eq 0) { Fail ("entry_not_in_executable_section:$name") }
    else { $execEntryHit = $true }
  }
  $sections += [pscustomobject]@{ name=$name; rva=$rva; vsize=$vsize; rawoff=$rawoff; rawsz=$rawsz; ch=('0x{0:x}' -f $ch) }
}
if (-not $execEntryHit) { Fail 'entry_rva_not_inside_any_executable_section' }
if ($impRva -eq 0 -or $impSize -eq 0) { Fail 'import_directory_missing' }

$impOk = $false
foreach ($s in $sections) {
  if ($impRva -ge $s.rva -and $impRva -lt ($s.rva + [Math]::Max([int]$s.vsize,1))) {
    $off = [int]$s.rawoff + [int]($impRva - $s.rva)
    if (($off + 20) -le $d.Length) {
      $nameRva = [BitConverter]::ToUInt32($d, $off + 12)
      $ft = [BitConverter]::ToUInt32($d, $off + 16)
      if ($nameRva -ne 0 -and $ft -ne 0) { $impOk = $true }
    }
  }
}
if (-not $impOk) { Fail 'import_descriptor_incomplete' }

$result = [ordered]@{
  schema = 'RAWRXD_PE_STRUCTURAL_VALIDATE_001'
  path = $Path
  sha256 = (certutil -hashfile $Path SHA256 | Select-Object -Skip 1 -First 1).Trim()
  pass = ($issues.Count -eq 0)
  issues = @($issues)
  machine = ('0x{0:x}' -f $machine)
  sections = $numSec
  entry_rva = ('0x{0:x}' -f $entry)
  size_of_headers = ('0x{0:x}' -f $sizeHeaders)
  size_of_image = ('0x{0:x}' -f $sizeImage)
  import_rva = ('0x{0:x}' -f $impRva)
  import_size = ('0x{0:x}' -f $impSize)
  section_table = $sections
}
if ($OutJson) { ($result | ConvertTo-Json -Depth 6) | Set-Content $OutJson -Encoding UTF8 }
if ($issues.Count -eq 0) { Write-Output 'PE_STRUCT_PASS'; exit 0 }
Write-Output ('PE_STRUCT_FAIL: ' + ($issues -join '; '))
exit 1

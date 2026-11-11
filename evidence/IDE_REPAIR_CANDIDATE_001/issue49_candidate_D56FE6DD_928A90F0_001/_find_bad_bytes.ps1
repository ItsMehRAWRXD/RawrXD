$ErrorActionPreference = 'Stop'
$path = 'F:\rawrxd\tools\deep2_agentic_loop.cpp'
$bytes = [System.IO.File]::ReadAllBytes($path)
$text = [System.IO.File]::ReadAllText($path)
$out = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_bad_bytes_report.txt'
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("FILE_BYTES=$($bytes.Length)")

# Find non-ASCII bytes
$nonAscii = 0
$samples = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $bytes.Length; $i++) {
  $b = $bytes[$i]
  if ($b -gt 127) {
    $nonAscii++
    if ($samples.Count -lt 40) {
      $ctxStart = [Math]::Max(0, $i - 20)
      $ctxLen = [Math]::Min(60, $bytes.Length - $ctxStart)
      $ctx = [System.Text.Encoding]::GetEncoding(1252).GetString($bytes, $ctxStart, $ctxLen)
      $samples.Add(("ofs=$i byte=0x{0:X2} ctx=[{1}]" -f $b, ($ctx -replace "`r|`n",' ')))
    }
  }
}
$lines.Add("NON_ASCII_BYTE_COUNT=$nonAscii")
$lines.AddRange($samples)

# Specifically search for 0x97
$count97 = 0
for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -eq 0x97) { $count97++; $lines.Add("HIT_0x97_OFS=$i") } }
$lines.Add("COUNT_0x97=$count97")

# Search for UTF-8 em-dash E2 80 94
$em = 0
for ($i = 0; $i -lt $bytes.Length - 2; $i++) {
  if ($bytes[$i] -eq 0xE2 -and $bytes[$i+1] -eq 0x80 -and $bytes[$i+2] -eq 0x94) {
    $em++
    $lines.Add("HIT_UTF8_EMDASH_OFS=$i")
  }
}
$lines.Add("COUNT_UTF8_EMDASH=$em")

# Also check binary deep2_agentic_loop.exe for 0x97 near C4100 string
$exe = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\bin\deep2_agentic_loop.exe'
if (Test-Path $exe) {
  $eb = [System.IO.File]::ReadAllBytes($exe)
  $needle = [System.Text.Encoding]::ASCII.GetBytes('C4100 unused parameter')
  $found = -1
  for ($i = 0; $i -lt $eb.Length - $needle.Length; $i++) {
    $ok = $true
    for ($j = 0; $j -lt $needle.Length; $j++) { if ($eb[$i+$j] -ne $needle[$j]) { $ok = $false; break } }
    if ($ok) { $found = $i; break }
  }
  $lines.Add("EXE_C4100_OFS=$found")
  if ($found -ge 0) {
    $s = [Math]::Max(0, $found - 40)
    $l = [Math]::Min(160, $eb.Length - $s)
    $hex = ($eb[$s..($s+$l-1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
    $ascii = -join ($eb[$s..($s+$l-1)] | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })
    $lines.Add("EXE_CTX_HEX=$hex")
    $lines.Add("EXE_CTX_ASC=$ascii")
    # bytes immediately before 'either'
    $either = [System.Text.Encoding]::ASCII.GetBytes(' either use')
    for ($i = $found; $i -lt [Math]::Min($eb.Length - $either.Length, $found + 200); $i++) {
      $ok = $true
      for ($j = 0; $j -lt $either.Length; $j++) { if ($eb[$i+$j] -ne $either[$j]) { $ok = $false; break } }
      if ($ok) {
        $prev = $eb[$i-1]
        $lines.Add(("BYTE_BEFORE_EITHER=0x{0:X2} ofs={1}" -f $prev, ($i-1)))
        break
      }
    }
  }
}

$lines | Out-File $out -Encoding utf8
Write-Output 'BADBYTES_OK'
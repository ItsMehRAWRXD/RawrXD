$path = 'F:\rawrxd\tmp_remeasure_016_div\stdout.txt'
$bytes = [IO.File]::ReadAllBytes($path)
$textAsciiHint = [Text.Encoding]::GetEncoding(1252).GetString($bytes)
$idx = $textAsciiHint.IndexOf('[Deep2Engine] Formatted prompt:')
Write-Output ("IDX1252=" + $idx)
# Also try UTF8 index via string from raw
$utf8 = New-Object Text.UTF8Encoding $false, $false
# Find ASCII marker bytes
$needle = [Text.Encoding]::ASCII.GetBytes('[Deep2Engine] Formatted prompt:')
$found = -1
for ($i = 0; $i -le $bytes.Length - $needle.Length; $i++) {
  $ok = $true
  for ($j = 0; $j -lt $needle.Length; $j++) {
    if ($bytes[$i + $j] -ne $needle[$j]) { $ok = $false; break }
  }
  if ($ok) { $found = $i; break }
}
Write-Output ("FOUND=" + $found)
if ($found -lt 0) { exit 1 }
# Start after marker + CRLF/LF
$start = $found + $needle.Length
while ($start -lt $bytes.Length -and ($bytes[$start] -eq 10 -or $bytes[$start] -eq 13)) { $start++ }
# End at blank line after model turn: look for "`n[GREEDY]" or similar
$endNeedle = [Text.Encoding]::ASCII.GetBytes('[GREEDY]')
$end = -1
for ($i = $start; $i -le $bytes.Length - $endNeedle.Length; $i++) {
  $ok = $true
  for ($j = 0; $j -lt $endNeedle.Length; $j++) {
    if ($bytes[$i + $j] -ne $endNeedle[$j]) { $ok = $false; break }
  }
  if ($ok) { $end = $i; break }
}
Write-Output ("END=" + $end)
# Trim trailing newlines before [GREEDY]
while ($end -gt $start -and ($bytes[$end - 1] -eq 10 -or $bytes[$end - 1] -eq 13)) { $end-- }
$len = $end - $start
$slice = New-Object byte[] $len
[Array]::Copy($bytes, $start, $slice, 0, $len)
[IO.File]::WriteAllBytes('F:\rawrxd\tmp_trusted_ref\tip_prompt_bytes.bin', $slice)
Write-Output ("SLICE_LEN=" + $len)
Write-Output '---HEX---'
($slice | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
Write-Output '---AS_1252---'
[Text.Encoding]::GetEncoding(1252).GetString($slice)
Write-Output '---AS_UTF8_lossy---'
$utf8.GetString($slice)

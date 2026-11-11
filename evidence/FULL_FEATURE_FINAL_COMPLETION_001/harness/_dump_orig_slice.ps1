$path = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_ORIG.ps1'
$lines = [IO.File]::ReadAllLines($path)
for ($i = 79; $i -lt [Math]::Min(331, $lines.Length); $i++) {
  Write-Host ("{0,4}|{1}" -f ($i+1), $lines[$i])
}

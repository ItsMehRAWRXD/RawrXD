$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$raw = Get-Content -LiteralPath (Join-Path $ev 'missing_raw.txt') -ErrorAction SilentlyContinue
$oids = New-Object 'System.Collections.Generic.List[string]'
foreach ($line in $raw) {
  if ($line -match '([0-9a-f]{40})') { [void]$oids.Add($Matches[1]) }
}
$unique = @($oids | Sort-Object -Unique)
$unique | Set-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') -Encoding UTF8
'MISSING_UNIQUE_COUNT=' + $unique.Count | Set-Content -LiteralPath (Join-Path $ev 'missing_count.txt') -Encoding UTF8
'MISSING_UNIQUE_COUNT=' + $unique.Count
$unique | Select-Object -First 40

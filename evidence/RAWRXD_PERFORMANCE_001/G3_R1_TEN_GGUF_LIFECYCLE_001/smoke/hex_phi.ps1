$lines = Get-Content -LiteralPath 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\run_r1_matrix.ps1'
foreach ($i in 21,22,25,26) {
  $line = $lines[$i]
  if ($line -match "Path='([^']+)'") {
    $path = $Matches[1]
    Write-Host ("L$($i+1) exists=$(Test-Path -LiteralPath $path)")
    Write-Host ("  path=$path")
    $idx = $path.IndexOf('phi3')
    if ($idx -ge 0) {
      $slice = $path.Substring([Math]::Max(0,$idx), [Math]::Min(40, $path.Length-$idx))
      Write-Host ("  slice=$slice")
      Write-Host ("  hex=" + [BitConverter]::ToString([Text.Encoding]::ASCII.GetBytes($slice)))
    }
  }
}

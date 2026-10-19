$ev="G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_MULTI_MODEL_E2E_001"
$runnerId=9484
while ($true) {
  $runner = Get-Process -Id $runnerId -EA SilentlyContinue
  $rawr = Get-Process rawr -EA SilentlyContinue | Select-Object -First 1
  $live = if (Test-Path "$ev\MATRIX_RAWR_LIVE.txt") { Get-Content "$ev\MATRIX_RAWR_LIVE.txt" } else { @() }
  $gb = if ($rawr) { [math]::Round($rawr.WorkingSet64/1GB,2) } else { 0 }
  $status = "[{0}] runner={1} rawrGB={2} rows={3}`n{4}" -f (Get-Date -Format o), [bool]$runner, $gb, @($live).Count, ($live -join "`n")
  Set-Content "$ev\STATUS.txt" $status
  if (-not $runner -and (Test-Path "$ev\RECEIPT.txt")) { break }
  if (-not $runner) { Start-Sleep 10; if (-not (Get-Process -Id $runnerId -EA SilentlyContinue)) { break } }
  Start-Sleep 120
}

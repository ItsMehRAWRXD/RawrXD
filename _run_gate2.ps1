$exe = 'f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe'
$model = 'D:\rawrxd\gemma3-1b-Q2_K.gguf'
$receipt = 'f:\~dev\cert_receipt_agentic.txt'
$log = 'f:\~dev\autoclose_gate_run2.log'

if (Test-Path $receipt) { Remove-Item $receipt }
if (Test-Path $log) { Remove-Item $log }

# Capture both stdout and stderr, plus pass explicit receipt path
& $exe '--autoclose' '--model' $model '--receipt' $receipt 2>&1 | Out-File -FilePath $log -Encoding UTF8

$exitCode = $LASTEXITCODE
Write-Host ('EXIT_CODE=' + $exitCode)

if (Test-Path $receipt) {
  Write-Host 'RECEIPT_FOUND'
  Get-Content $receipt | ForEach-Object { Write-Host $_ }
} else {
  Write-Host 'NO_RECEIPT'
}

if (Test-Path $log) {
  Write-Host '--- LOG TAIL ---'
  Get-Content $log | Select-Object -Last 60 | ForEach-Object { Write-Host $_ }
}

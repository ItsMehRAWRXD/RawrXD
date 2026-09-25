$exe = 'f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe'
$model = 'D:\rawrxd\gemma3-1b-Q2_K.gguf'
$receipt = 'f:\~dev\cert_receipt_agentic.txt'
$log = 'f:\~dev\autoclose_gate_run.log'

if (Test-Path $receipt) { Remove-Item $receipt }

$proc = Start-Process -FilePath $exe -ArgumentList '--autoclose','--model',$model -RedirectStandardOutput $log -PassThru -NoNewWindow
$proc | Wait-Process -Timeout 180 -ErrorAction SilentlyContinue

if (!$proc.HasExited) {
  $proc | Stop-Process -Force
  Write-Host 'TIMEOUT'
}
Write-Host ('EXIT_CODE=' + $proc.ExitCode)

if (Test-Path $receipt) {
  Write-Host 'RECEIPT_FOUND'
  Get-Content $receipt | ForEach-Object { Write-Host $_ }
} else {
  Write-Host 'NO_RECEIPT'
}

if (Test-Path $log) {
  Write-Host '--- LOG TAIL ---'
  Get-Content $log | Select-Object -Last 50 | ForEach-Object { Write-Host $_ }
}

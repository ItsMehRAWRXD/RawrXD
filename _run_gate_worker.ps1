$exe = 'f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe'
$model = 'D:\rawrxd\gemma3-1b-Q2_K.gguf'
$receipt = 'f:\~dev\cert_receipt_agentic.txt'
$err = 'f:\~dev\autoclose_worker_stderr.txt'

if (Test-Path $receipt) { Remove-Item $receipt }
if (Test-Path $err) { Remove-Item $err }

# Run as worker directly so stderr is captured (no watchdog parent)
& $exe '--autoclose-worker' '--model' $model '--receipt' $receipt '--strict-gpu' '--require-real-gpu' '--require-zero-fallback' '--gate-prompt' 'Hello world' '--gate-tokens' '4' '--nonce' '7E91B462' 2> $err

$exitCode = $LASTEXITCODE
Write-Host ('EXIT_CODE=' + $exitCode)

if (Test-Path $receipt) {
  Write-Host 'RECEIPT_FOUND'
  Get-Content $receipt | ForEach-Object { Write-Host $_ }
} else {
  Write-Host 'NO_RECEIPT'
}

if (Test-Path $err) {
  Write-Host '--- STDERR TAIL ---'
  Get-Content $err | Select-Object -Last 200 | ForEach-Object { Write-Host $_ }
}

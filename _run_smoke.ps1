$exe = 'f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe'
$log = 'f:\~dev\smoke_out.txt'
$proc = Start-Process -FilePath $exe -ArgumentList '--autoclose','--model','D:\rawrxd\gemma3-1b-Q2_K.gguf' -RedirectStandardOutput $log -PassThru -NoNewWindow
Start-Sleep -Seconds 10
if ($proc.HasExited) {
    Write-Host ('EXIT_CODE=' + $proc.ExitCode)
    if ($proc.ExitCode -eq -1073741571) { Write-Host 'STATUS_STACK_OVERFLOW' }
} else {
    $proc | Stop-Process -Force
    Write-Host 'TIMEOUT'
}
Write-Host '--- LOG TAIL ---'
if (Test-Path $log) { Get-Content $log | Select-Object -Last 30 | ForEach-Object { Write-Host $_ } }

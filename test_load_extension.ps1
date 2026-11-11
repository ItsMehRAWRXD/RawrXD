$env:RAWRXD_PROBLEMS_FIXTURE = 'F:\rawrxd\T080_test_bad.cpp'
$process = Start-Process -FilePath 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe' `
    -ArgumentList '--cli', '--batch', 'F:\rawrxd\test_cli_rawrxd-extension.txt' `
    -Wait -NoNewWindow `
    -RedirectStandardOutput 'd:\rawrxd\test_rawrxd_load_out.txt' `
    -RedirectStandardError 'd:\rawrxd\test_rawrxd_load_err.txt' `
    -PassThru

Start-Sleep -Seconds 5
if (-not $process.HasExited) {
    Stop-Process -Id $process.Id -Force
}
Write-Host "Process completed"
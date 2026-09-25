$ErrorActionPreference = "Stop"
$exe = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe"
$stderr = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\stderr_log.txt"
$receipt = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\cert_receipt_agentic.txt"
$gendbg = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\gen_debug.txt"

if (Test-Path $stderr) { Remove-Item $stderr -Force }
if (Test-Path $receipt) { Remove-Item $receipt -Force }
if (Test-Path $gendbg) { Remove-Item $gendbg -Force }

$p = Start-Process -FilePath $exe -ArgumentList @("--cert-agent","--headless") -PassThru -RedirectStandardError $stderr -WindowStyle Hidden
Write-Host ("PID=" + $p.Id)
$p.WaitForExit(600000)
Write-Host ("EXIT_CODE=" + $p.ExitCode)
Write-Host ("RECEIPT=" + (Test-Path $receipt))
if (Test-Path $stderr) {
    Write-Host ("STDERR_SIZE=" + ((Get-Item $stderr).Length))
    Write-Host "---STDERR_BEGIN---"
    Get-Content $stderr -Raw
    Write-Host "---STDERR_END---"
} else {
    Write-Host "STDERR_MISSING"
}

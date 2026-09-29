Set-Location "F:\~dev\rawrxd\build_w1\bin\Release"
$p = Start-Process -FilePath ".\RawrXD-Win32IDE.exe" -ArgumentList "--cert-stay-alive","--cert-duration-sec","1800","--headless" -PassThru -WindowStyle Hidden
$procId = $p.Id
"PID=$procId STARTED=$(Get-Date -Format 'HH:mm:ss')" | Out-File "F:\~dev\_w8_full_status.txt" -Encoding UTF8
$p.WaitForExit()
$exitCode = $p.ExitCode
"EXIT=$exitCode ENDED=$(Get-Date -Format 'HH:mm:ss')" | Out-File "F:\~dev\_w8_full_status.txt" -Append -Encoding UTF8

# chat_smoke_harness.ps1 — 20 cold-start chat smokes with process-exit sync
# (no fixed sleeps; bounded file-availability check instead).
$exe = "F:\rawrxd\build\cmake-preset-ninja-release\bin\RawrXD-Win32IDE-Native.exe"
$receiptDir = "F:\rawrxd\evidence\crash_dumps"
$pass = 0; $crash = 0; $other = 0; $locked = 0
for ($i = 1; $i -le 20; $i++) {
    Get-Process RawrXD-Win32IDE-Native -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # Bounded file-availability: wait until the exe is openable for write (lock released).
    $ok = $false
    for ($t = 0; $t -lt 60; $t++) {
        try { $fs = [IO.File]::Open($exe, 'Open', 'ReadWrite', 'None'); $fs.Close(); $ok = $true; break }
        catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $ok) { $locked++; Write-Output "RUN$i LOCKED"; continue }
    $env:RAWRXD_CHAT_SMOKE_RECEIPT = "$receiptDir\chat_r$i.txt"
    if (Test-Path $env:RAWRXD_CHAT_SMOKE_RECEIPT) { Remove-Item $env:RAWRXD_CHAT_SMOKE_RECEIPT -Force }
    $p = Start-Process -FilePath $exe -ArgumentList "--chat-smoke" -Wait -PassThru -WindowStyle Hidden
    switch ($p.ExitCode) {
        0 { $pass++; Write-Output "RUN$i PASS" }
        -1 { $crash++; Write-Output "RUN$i CRASH(-1)" }
        default { $other++; Write-Output "RUN$i EXIT=$($p.ExitCode)" }
    }
}
Write-Output "SUMMARY pass=$pass crash=$crash other=$other locked=$locked of 20"
$targetPid = 16308
$receiptPath = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\cert_receipt_agentic.txt"
$stderrPath = "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\stderr_log.txt"
$logFile = "F:\~dev\_gate_monitor_log.txt"

for ($i = 1; $i -le 60; $i++) {
    $ts = Get-Date -Format "HH:mm:ss"
    $proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
    $receipt = Test-Path $receiptPath
    $stderr = Test-Path $stderrPath
    $stderrSize = 0
    if ($stderr) { $stderrSize = (Get-Item $stderrPath).Length }
    $line = "[$ts] Iter=$i Proc=$($proc -ne $null) Receipt=$receipt StderrExists=$stderr StderrSize=$stderrSize"
    Write-Host $line
    Add-Content -Path $logFile -Value $line
    Start-Sleep -Seconds 30
}
Write-Host "MONITOR_DONE"

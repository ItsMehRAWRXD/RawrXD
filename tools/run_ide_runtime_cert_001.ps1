<#
RAWRXD_IDE_RUNTIME_CERT_001 -- run the IDE's own runtime cert on THIS build and read it.

A prior receipt exists from a different tree
(F:\~dev\.kilo\worktrees\festive-wakeboard\rawrxd\ide_runtime_cert_receipt.txt,
 EXE_DIR=F:\~dev\rawrxd\certbuild\bin\Release, generated 2026-10-01).
This run uses build_ide_probe\bin\RawrXD-Win32IDE.exe, so the two are comparable only as
"same instrument, different binary" -- and any difference is a real difference between
binaries, not noise.

Bounded: one PID, polled for the receipt, then terminated. No image-name kill.
#>

$Exe  = 'F:\~dev\build_ide_probe\bin\RawrXD-Win32IDE.exe'
$Work = 'F:\dev_ide_cert'
$Rec  = Join-Path $Work 'ide_runtime_cert_receipt.txt'
$MaxWait = 300

New-Item -ItemType Directory -Path $Work -Force | Out-Null
Remove-Item $Rec -Force -ErrorAction SilentlyContinue

Write-Output "EXE=$Exe"
Write-Output ("EXE_SHA256=" + (Get-FileHash $Exe -Algorithm SHA256).Hash)
Write-Output "RECEIPT=$Rec"
Write-Output "MAX_WAIT_SECONDS=$MaxWait"

$p = Start-Process -FilePath $Exe -PassThru -WindowStyle Normal -WorkingDirectory $Work `
     -ArgumentList @('--ide-runtime-cert', '--ide-cert-receipt', $Rec)
Write-Output "PID=$($p.Id)"

$appeared = $false
$stableAt = $null
$lastLen = -1
for ($i = 0; $i -lt $MaxWait; $i++) {
    Start-Sleep -Seconds 2
    if ($p.HasExited) { Write-Output "EXITED_AT=${i}s  EXIT_CODE=$($p.ExitCode)"; break }
    if (Test-Path $Rec) {
        $len = (Get-Item $Rec).Length
        if ($len -gt 0 -and $len -eq $lastLen) { if ($null -eq $stableAt) { $stableAt = $i } }
        else { $stableAt = $null }
        $lastLen = $len
        if ($null -ne $stableAt -and ($i - $stableAt) -ge 6) { $appeared = $true; break }
    }
}
Write-Output "RECEIPT_APPEARED=$appeared  WAITED_SECONDS=$(([int]($i))*2)"
Write-Output "STILL_RUNNING=$(if (-not $p.HasExited) { 'YES' } else { 'NO' })"

if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(20000) | Out-Null }
Write-Output "KILLED_ONLY_THIS_PID=$(if (-not $p.HasExited) { 'NO' } else { 'YES' })"

Write-Output ''
Write-Output '================ RECEIPT ================'
if (Test-Path $Rec) { Get-Content $Rec } else { Write-Output 'NO RECEIPT WRITTEN' }

param(
    [int]$MaxAttempts = 25,
    [string]$ExePath = "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe",
    [string]$Args = "--iterations 50000 --mode=guards-off",
    [string]$OutDir = "D:\rawrxd\bench\vulkan_validation_tax\cdb_retry"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
if (-not (Test-Path $cdbPath)) {
    throw "cdb not found at $cdbPath"
}
if (-not (Test-Path $ExePath)) {
    throw "benchmark executable not found at $ExePath"
}

$scriptCmd = "sxe av; sxe ch; g; .echo ====FATAL SIGNAL====; .lastevent; .ecxr; kb 80; r; u @rip-24 @rip+24; !gle; q"

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logPath = Join-Path $OutDir ("cdb_attempt_{0}_{1}.log" -f $attempt, $stamp)

    Write-Host "--- Attempt #$attempt ---" -ForegroundColor Cyan
    $benchProc = Start-Process -FilePath $ExePath -ArgumentList $Args -PassThru
    $targetPid = $benchProc.Id

    & $cdbPath -p $targetPid -logo $logPath -c $scriptCmd | Out-Null

    $logText = if (Test-Path $logPath) { Get-Content -Path $logPath -Raw } else { "" }

    # Normal completion in current repros: "Exit process ... code 0".
    $cleanExit = $logText -match "Exit process .* code 0"
    $hasCrashSignal = $logText -match "Access violation|second chance|ExceptionCode|EXCEPTION_RECORD"

    if ($hasCrashSignal -or -not $cleanExit) {
        Write-Host "Potential crash/non-clean termination captured at $logPath" -ForegroundColor Red
        exit 1
    }

    Write-Host "Clean exit observed; continuing." -ForegroundColor DarkGray
}

Write-Host "Completed $MaxAttempts attempts with clean exits." -ForegroundColor Green
exit 0

# ==============================================================================
# loop_procdump_capture.ps1
# Passive crash capture loop for RawrXD-VulkanValidationTax.exe
# Uses procdump (Sysinternals) to capture dumps without debugger attachment
# ==============================================================================
param(
    [string]$ExePath = "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe",
    [string]$ExeArgs = "--iterations 50000 --mode=guards-off",
    [string]$DumpDir = "D:\rawrxd\bench\vulkan_validation_tax\dumps",
    [string]$ProcdumpPath = "D:\rawrxd\bench\vulkan_validation_tax\procdump64.exe",
    [int]$MaxLoops = 100
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $DumpDir -Force | Out-Null

if (-not (Test-Path $ProcdumpPath)) {
    # Fallback to PATH
    $ProcdumpPath = "procdump64.exe"
}
if (-not (Test-Path $ExePath)) {
    throw "Benchmark executable not found: $ExePath"
}

# Clean-room environment: strip compatibility shims that force DLL injection
$env:__COMPAT_LAYER = "RunAsInvoker"
$env:DISABLE_AMD_OVERLAY = "1"

Write-Host "=== Passive Procdump Capture Loop ===" -ForegroundColor Cyan
Write-Host "Exe:    $ExePath"
Write-Host "Args:   $ExeArgs"
Write-Host "Dump:   $DumpDir"
Write-Host "Max:    $MaxLoops attempts"
Write-Host ""

$loop = 1
$crashCount = 0

while ($loop -le $MaxLoops) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dumpFile = Join-Path $DumpDir ("crash_{0:D4}_{1}.dmp" -f $loop, $stamp)
    $logFile = Join-Path $DumpDir ("passive_{0:D4}_{1}.log" -f $loop, $stamp)

    Write-Host "--- Attempt #$loop : Passive capture active ---" -ForegroundColor DarkGray

    # Launch benchmark in background
    $benchProc = Start-Process -FilePath $ExePath -ArgumentList $ExeArgs -PassThru
    $benchPid = $benchProc.Id
    Write-Host "  Benchmark started (PID $benchPid)" -ForegroundColor DarkGray

    # procdump flags:
    #   -ma   = full memory dump
    #   -e 1  = capture on process exit with error code
    #   -n 1  = capture one dump then exit
    #   -o    = overwrite existing
    #   -p    = PID to monitor
    & $ProcdumpPath -ma -e 1 -n 1 -o -p $benchPid $dumpFile *> $logFile
    $procExit = $LASTEXITCODE

    # Wait for benchmark to finish if procdump didn't catch it
    if (-not $benchProc.HasExited) {
        $benchProc.WaitForExit()
    }
    $benchExit = $benchProc.ExitCode

    # procdump returns 0 if it captured a dump (process exited with error)
    # procdump returns non-zero if process exited cleanly or other issue
    $dumpCreated = Test-Path $dumpFile

    if ($dumpCreated -and (Get-Item $dumpFile).Length -gt 0) {
        $crashCount++
        $dumpSize = (Get-Item $dumpFile).Length
        Write-Host "CRASH CAPTURED: $dumpFile ($dumpSize bytes)" -ForegroundColor Red
        Write-Host "  Crash #$crashCount at attempt #$loop"
        Write-Host "  Analyze with: windbg -z $dumpFile"
        Write-Host "  Or run: !analyze -v"
        break
    }

    # Check log for "Dump count not reached" = clean exit
    $logText = Get-Content -Path $logFile -Raw -ErrorAction SilentlyContinue
    $cleanExit = $logText -match "Dump count not reached|Exit Code 0x00000000"

    if ($cleanExit) {
        Write-Host "Clean exit (no crash). Continuing..." -ForegroundColor DarkGreen
    } else {
        Write-Host "Unclear result. Log: $logFile" -ForegroundColor Yellow
    }

    $loop++
    Start-Sleep -Milliseconds 100
}

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "PASSIVE CAPTURE LOOP COMPLETE" -ForegroundColor Cyan
Write-Host "  Attempts:    $loop"
Write-Host "  Crashes:     $crashCount"
Write-Host "  Dump dir:    $DumpDir"
Write-Host "===============================================================" -ForegroundColor Cyan

if ($crashCount -gt 0) {
    Write-Host ""
    Write-Host "Next step: Analyze the dump with WinDbg" -ForegroundColor Yellow
    Write-Host "  windbg -z $DumpDir\crash_*.dmp" -ForegroundColor Yellow
    Write-Host "  In WinDbg: !analyze -v" -ForegroundColor Yellow
    Write-Host "  In WinDbg: .ecxr ; kb" -ForegroundColor Yellow
}

exit $crashCount

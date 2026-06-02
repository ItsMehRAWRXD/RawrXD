param(
    [int]$MaxAttempts = 25,
    [string]$ExePath = "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe",
    [string[]]$ExeArgs = @("--iterations", "50000", "--mode=guards-off"),
    [string]$DumpDir = "D:\rawrxd\bench\vulkan_validation_tax\dumps",
    [string]$ProcDumpPath = "D:\rawrxd\bench\vulkan_validation_tax\procdump64.exe",
    [switch]$SetCompatLayer,
    [switch]$VerifyHookOnce,
    [string]$ListDllsPath = "D:\rawrxd\bench\vulkan_validation_tax\listdlls64.exe"
)

$ErrorActionPreference = "Stop"
# In PowerShell 7, native stderr can be promoted to ErrorActionPreference.
# Disable that behavior for this script so benchmark trace lines do not abort the loop.
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if (-not (Test-Path $ExePath)) {
    throw "Benchmark executable not found: $ExePath"
}
if (-not (Test-Path $ProcDumpPath)) {
    throw "ProcDump executable not found: $ProcDumpPath"
}

New-Item -ItemType Directory -Path $DumpDir -Force | Out-Null

if ($SetCompatLayer) {
    # Optional clean-room hint to reduce compatibility shim side-effects.
    $env:__COMPAT_LAYER = "RunAsInvoker"
    Write-Host "Set __COMPAT_LAYER=RunAsInvoker for this session." -ForegroundColor Yellow
}

if ($VerifyHookOnce -and (Test-Path $ListDllsPath)) {
    $probe = Start-Process -FilePath $ExePath -ArgumentList "--iterations 2000 --mode=guards-off" -PassThru
    & $ListDllsPath -accepteula RawrXD-VulkanValidationTax.exe > (Join-Path $DumpDir "dll_probe_attempt0.txt") 2>&1
    try { Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue } catch {}
    Write-Host "Wrote one-time DLL probe: $(Join-Path $DumpDir 'dll_probe_attempt0.txt')" -ForegroundColor DarkCyan
}

for ($i = 1; $i -le $MaxAttempts; $i++) {
    $logPath = Join-Path $DumpDir ("procdump_attempt_{0}.log" -f $i)
    $summaryPath = Join-Path (Split-Path -Parent $DumpDir) "summary_report.json"
    $startedUtc = (Get-Date).ToUniversalTime()
    $before = @(Get-ChildItem -Path $DumpDir -Filter "*.dmp" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)

    Write-Host "--- Attempt #${i}: Passive Capture Mode Active ---" -ForegroundColor Cyan

    # -ma full dump; -e 1 first-chance unhandled exception capture; -n 1 one dump; -o overwrite.
    # Use launch mode (-x <dump folder> <image> [args]) to monitor the target passively.
    $pdArgs = @('-accepteula', '-ma', '-e', '1', '-n', '1', '-o', '-x', $DumpDir, $ExePath) + $ExeArgs
    & $ProcDumpPath @pdArgs *> $logPath
    $exitCode = $LASTEXITCODE

    $after = @(Get-ChildItem -Path $DumpDir -Filter "*.dmp" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $newDumps = @($after | Where-Object { $_ -notin $before })

    if ($newDumps.Count -gt 0) {
        $payload = [ordered]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Status = "NonClean"
            Attempt = $i
            ExitCode = $exitCode
            DumpFiles = $newDumps
            ProcDumpLog = $logPath
            ExePath = $ExePath
            Args = ($ExeArgs -join " ")
            OBSInjected = (Test-Path (Join-Path $DumpDir "dll_probe_attempt0.txt"))
        }
        $payload | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding utf8
        Write-Host "CRITICAL: Dump captured at $($newDumps -join ', ')" -ForegroundColor Red
        exit 1
    }

    $cleanPayload = [ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        Status = "Clean"
        Attempt = $i
        ExitCode = $exitCode
        DumpFiles = @()
        ProcDumpLog = $logPath
        ExePath = $ExePath
        Args = ($ExeArgs -join " ")
        OBSInjected = (Test-Path (Join-Path $DumpDir "dll_probe_attempt0.txt"))
    }
    $cleanPayload | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding utf8

    if ($exitCode -ne 0) {
        Write-Host "ProcDump returned exit code $exitCode (no dump file). See $logPath" -ForegroundColor Yellow
    } else {
        Write-Host "Attempt #$i finished without dump." -ForegroundColor DarkGray
    }
}

Write-Host "Completed $MaxAttempts attempts with no crash dump captured." -ForegroundColor Green
exit 0

# ==============================================================================
# Sovereign Full-Cycle Pipeline
# Orchestrates: Orchestrator -> Sidecar -> Regression Gate -> Analyzer
# Produces atomic per-run artifacts under runs\soak_YYYYMMDD_HHMMSS
# ==============================================================================
param(
    [int]$RequestCount = 1000,
    [int]$CancelPercent = 15,
    [int]$Seed = 42,
    [int]$Streamer = -1,
    [int]$BurnInSamples = 100,
    [string]$ExePath = "d:\rawrxd-ci-bootstrap\SovereignOrchestrator.exe",
    [string]$ModelPath = "F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf",
    [int]$SidecarIntervalMs = 25,
    [switch]$IncludeSlotMetadata = $true,
    [int]$SaturationThreshold = 48,
    [string]$RunsRoot = "d:\rawrxd-ci-bootstrap\runs"
)

$ErrorActionPreference = "Stop"

function Ensure-Dir([string]$path) {
    if (-not (Test-Path $path)) {
        [void](New-Item -ItemType Directory -Path $path -Force)
    }
}

function Get-PowerShellExe {
    $winPs = Join-Path $PSHOME "powershell.exe"
    if (Test-Path $winPs) { return $winPs }

    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCmd) { return $pwshCmd.Source }

    $psCmd = Get-Command powershell -ErrorAction SilentlyContinue
    if ($psCmd) { return $psCmd.Source }

    throw "No PowerShell executable found"
}

function Wait-ForFileMap([int]$timeoutMs) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeMap {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenFileMappingA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr hObject);
    public const uint FILE_MAP_ALL_ACCESS = 0xF001F;
}
"@

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.ElapsedMilliseconds -lt $timeoutMs) {
        $hMap = [NativeMap]::OpenFileMappingA([NativeMap]::FILE_MAP_ALL_ACCESS, $false, "SOVEREIGN_BEACON_V1")
        if ($hMap -ne [IntPtr]::Zero) {
            [void][NativeMap]::CloseHandle($hMap)
            return $true
        }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

$orchestratorProc = $null
$sidecarProc = $null
$gateExit = 1
$sidecarExit = $null

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runDir = Join-Path $RunsRoot ("soak_" + $stamp)
$stopSignalPath = Join-Path $runDir "sidecar.stop"
$gateLogPath = Join-Path $runDir "gate.log"
$sidecarCsvPath = Join-Path $runDir "sidecar_metrics.csv"
$analyzerCsvPath = Join-Path $runDir "correlation_report.csv"
$analyzerJsonPath = Join-Path $runDir "correlation_report.json"
$pipelineSummaryPath = Join-Path $runDir "pipeline_summary.txt"
$sidecarStdOutPath = Join-Path $runDir "sidecar.stdout.log"
$sidecarStdErrPath = Join-Path $runDir "sidecar.stderr.log"

$sidecarScript = "d:\rawrxd-ci-bootstrap\sovereign_metrics_sidecar_passive.ps1"
$gateScript = "d:\rawrxd-ci-bootstrap\sovereign_regression_gate_v5.ps1"
$analyzerScript = "d:\rawrxd-ci-bootstrap\sovereign_analyze_correlation.ps1"

Ensure-Dir $RunsRoot
Ensure-Dir $runDir

try {
    if (-not (Test-Path $ExePath)) { throw "Missing orchestrator: $ExePath" }
    if (-not (Test-Path $ModelPath)) { throw "Missing model: $ModelPath" }
    if (-not (Test-Path $sidecarScript)) { throw "Missing sidecar script: $sidecarScript" }
    if (-not (Test-Path $gateScript)) { throw "Missing gate script: $gateScript" }
    if (-not (Test-Path $analyzerScript)) { throw "Missing analyzer script: $analyzerScript" }

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Sovereign Full-Cycle Pipeline" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "RunDir: $runDir"

    # Safety: clear stale stop signal
    if (Test-Path $stopSignalPath) {
        Remove-Item $stopSignalPath -Force
    }

    # 1) Start orchestrator
    $orchestratorProc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
    if (-not (Wait-ForFileMap 10000)) {
        throw "Orchestrator did not publish MMF within timeout"
    }

    # Resolve shell executable once for all child script invocations.
    $psExe = Get-PowerShellExe

    # 2) Start sidecar with long window; wrapper controls shutdown via stop signal
    $sidecarArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $sidecarScript,
        "-DurationSec", "86400",
        "-IntervalMs", $SidecarIntervalMs,
        "-FlushEvery", "32",
        "-CsvPath", $sidecarCsvPath,
        "-StopSignalPath", $stopSignalPath
    )
    if ($IncludeSlotMetadata) {
        $sidecarArgs += "-IncludeSlotMetadata"
    }

    $sidecarProc = Start-Process -FilePath $psExe -ArgumentList $sidecarArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $sidecarStdOutPath -RedirectStandardError $sidecarStdErrPath

    Start-Sleep -Milliseconds 500
    if ($sidecarProc.HasExited) {
        $sideErr = ""
        if (Test-Path $sidecarStdErrPath) {
            $sideErr = (Get-Content -Path $sidecarStdErrPath -Raw)
        }
        throw "Sidecar exited early with code $($sidecarProc.ExitCode). Error log: $sideErr"
    }

    # 3) Run regression gate as master process and archive output atomically
    $gateArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $gateScript,
        "-RequestCount", $RequestCount,
        "-CancelPercent", $CancelPercent,
        "-Seed", $Seed,
        "-Streamer", $Streamer,
        "-ExePath", $ExePath,
        "-ModelPath", $ModelPath,
        "-AttachExisting"
    )
    $gateOutput = & $psExe @gateArgs 2>&1
    $gateOutput | Tee-Object -FilePath $gateLogPath | Out-Null
    $gateExit = $LASTEXITCODE

    # 4) Signal sidecar to stop and wait for clean flush
    Set-Content -Path $stopSignalPath -Value "stop" -Encoding ASCII
    if ($sidecarProc -and -not $sidecarProc.HasExited) {
        if (-not $sidecarProc.WaitForExit(15000)) {
            Stop-Process -Id $sidecarProc.Id -Force
            $sidecarProc.WaitForExit()
        }
    }
    if ($sidecarProc) {
        $sidecarProc.WaitForExit()
        $sidecarProc.Refresh()
        if ($sidecarProc.HasExited) {
            $sidecarExit = $sidecarProc.ExitCode
        }
    }
    if ($null -eq $sidecarExit -or [string]::IsNullOrWhiteSpace([string]$sidecarExit)) {
        $sidecarExit = if (Test-Path $sidecarCsvPath) { 0 } else { 1 }
    }

    # 5) Run analyzer immediately after sidecar finalizes
    $analyzerArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $analyzerScript,
        "-MetricsCsvPath", $sidecarCsvPath,
        "-GateLogPath", $gateLogPath,
        "-OutputCsvPath", $analyzerCsvPath,
        "-OutputJsonPath", $analyzerJsonPath,
        "-BurnInSamples", $BurnInSamples,
        "-SaturationThreshold", $SaturationThreshold
    )
    & $psExe @analyzerArgs

    $analyzerExit = $LASTEXITCODE

    # 6) Persist pipeline summary
    $summary = @(
        "RunDir=$runDir",
        "TimestampUtc=$([DateTime]::UtcNow.ToString('o'))",
        "RequestCount=$RequestCount",
        "CancelPercent=$CancelPercent",
        "Seed=$Seed",
        "Streamer=$Streamer",
        "BurnInSamples=$BurnInSamples",
        "GateExitCode=$gateExit",
        "SidecarExitCode=$sidecarExit",
        "AnalyzerExitCode=$analyzerExit",
        "Artifacts:",
        "  GateLog=$gateLogPath",
        "  SidecarCsv=$sidecarCsvPath",
        "  SidecarStdOut=$sidecarStdOutPath",
        "  SidecarStdErr=$sidecarStdErrPath",
        "  AnalyzerCsv=$analyzerCsvPath",
        "  AnalyzerJson=$analyzerJsonPath"
    )
    Set-Content -Path $pipelineSummaryPath -Value $summary -Encoding UTF8

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "PIPELINE COMPLETE" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "GateExitCode: $gateExit"
    Write-Host "SidecarExitCode: $sidecarExit"
    Write-Host "AnalyzerExitCode: $analyzerExit"
    Write-Host "RunDir: $runDir"

    if ($gateExit -ne 0 -or $analyzerExit -ne 0) {
        exit 1
    }

    exit 0
}
finally {
    # Ensure no process leaks even on failure/abort.
    if ($sidecarProc -and -not $sidecarProc.HasExited) {
        try {
            Set-Content -Path $stopSignalPath -Value "stop" -Encoding ASCII
            if (-not $sidecarProc.WaitForExit(3000)) {
                Stop-Process -Id $sidecarProc.Id -Force
            }
        } catch {}
    }

    if ($orchestratorProc -and -not $orchestratorProc.HasExited) {
        try {
            Stop-Process -Id $orchestratorProc.Id -Force
        } catch {}
    }
}

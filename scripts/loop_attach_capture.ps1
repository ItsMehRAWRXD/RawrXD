#!/usr/bin/env pwsh
param(
    [string]$TargetExe = "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe",
    [string]$OutDir = "D:\rawrxd\bench\vulkan_validation_tax",
    [int]$Iterations = 100000,
    [int]$AttachDelaySec = 5,
    [int]$MaxAttempts = 0,
    [switch]$WideNet,
    [switch]$KeepCleanLogs,
    [switch]$DisableAmdOverlay,
    [switch]$SetCompatLayer,
    [switch]$FailFastOnForbiddenModules,
    [string]$ListDllsPath = "D:\rawrxd\bench\vulkan_validation_tax\listdlls64.exe",
    [string[]]$ForbiddenModules = @("graphics-hook64.dll", "amdihk64.dll"),
    [string]$AnalyzerPath = (Join-Path $PSScriptRoot "Analyze-Failure.ps1"),
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $TargetExe)) {
    throw "Target executable not found: $TargetExe"
}

$cdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
if (-not (Test-Path $cdbPath)) {
    throw "cdb not found: $cdbPath"
}

if ($FailFastOnForbiddenModules -and -not (Test-Path $ListDllsPath)) {
    throw "Fail-fast module scan requested but listdlls not found: $ListDllsPath"
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$summaryPath = Join-Path $OutDir "capture_loop_summary.log"
$finalReportPath = if ($ReportPath) { $ReportPath } else { Join-Path $OutDir "summary_report.json" }
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
"[INFO] loop-start $stamp iterations=$Iterations wideNet=$WideNet maxAttempts=$MaxAttempts" | Add-Content $summaryPath
"[INFO] analyzer path=$AnalyzerPath report=$finalReportPath" | Add-Content $summaryPath

if ($DisableAmdOverlay) {
    # Propagate an explicit opt-out hint for driver overlay injection.
    $env:DISABLE_AMD_OVERLAY = "1"
    "[INFO] env DISABLE_AMD_OVERLAY=1" | Add-Content $summaryPath
}

if ($SetCompatLayer) {
    $env:__COMPAT_LAYER = "RunAsInvoker"
    "[INFO] env __COMPAT_LAYER=RunAsInvoker" | Add-Content $summaryPath
}

if (-not (Test-Path $AnalyzerPath)) {
    "[WARN] analyzer-not-found path=$AnalyzerPath" | Add-Content $summaryPath
}

function Get-LastEventLine {
    param([string]$LogPath)

    if (-not (Test-Path $LogPath)) {
        return ""
    }

    $last = Get-Content -Path $LogPath | Where-Object { $_ -like "Last event:*" } | Select-Object -Last 1
    if ($null -eq $last) {
        return ""
    }
    return [string]$last
}

function Is-FatalCapture {
    param([string]$LogPath)

    if (-not (Test-Path $LogPath)) {
        return $false
    }

    $text = Get-Content -Path $LogPath -Raw
    $lastEvent = Get-LastEventLine -LogPath $LogPath

    if ($text -match "Cannot debug pid" -or $text -match "already being debugged") {
        return $false
    }

    if (-not $lastEvent) {
        return $false
    }

    if ($lastEvent -match "Exit process .* code 0") {
        return $false
    }

    return $true
}

function Build-CdbCommand {
    param([switch]$Wide)

    if ($Wide) {
        return "sxe av; sxe ch; sxe clr; sxe eh; bm KERNELBASE!RaiseException; bm ucrtbase!abort; g; .echo ====FATAL SIGNAL====; .lastevent; .ecxr; k; r; u rip; q"
    }

    return "sxe av; sxe ch; sxe clr; g; .echo ====FATAL SIGNAL====; .lastevent; .ecxr; k; r; u rip; q"
}

function Get-ForbiddenModuleHits {
    param(
        [int]$TargetPid,
        [string]$ToolPath,
        [string[]]$Forbidden
    )

    $hits = @()

    if (-not (Test-Path $ToolPath)) {
        return $hits
    }

    $raw = & $ToolPath -accepteula -p $TargetPid 2>&1 | Out-String
    foreach ($name in $Forbidden) {
        if ($raw -match [Regex]::Escape($name)) {
            $hits += $name
        }
    }

    return ($hits | Select-Object -Unique)
}

function Get-ForbiddenModuleHitsCdbProbe {
    param(
        [int]$TargetPid,
        [string]$CdbPath,
        [string[]]$Forbidden,
        [string]$ProbeLogPath
    )

    $hits = @()
    $probeCmd = ""
    foreach ($name in $Forbidden) {
        $probeCmd += "lm m $name; "
    }
    $probeCmd += "q"

    & $CdbPath -p $TargetPid -logo $ProbeLogPath -c $probeCmd | Out-Null

    if (-not (Test-Path $ProbeLogPath)) {
        return $hits
    }

    $raw = Get-Content -Path $ProbeLogPath -Raw
    foreach ($name in $Forbidden) {
        if ($raw -match [Regex]::Escape($name)) {
            $hits += $name
        }
    }

    return ($hits | Select-Object -Unique)
}

$attempt = 1
while ($true) {
    if ($MaxAttempts -gt 0 -and $attempt -gt $MaxAttempts) {
        "[INFO] max-attempts-reached attempts=$MaxAttempts" | Add-Content $summaryPath
        break
    }

    Write-Host ("--- Starting Capture Attempt #{0} ---" -f $attempt) -ForegroundColor Cyan
    "[INFO] attempt-start n=$attempt time=$((Get-Date).ToString("o"))" | Add-Content $summaryPath

    Get-Process RawrXD-VulkanValidationTax -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process obs64,obs -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $argList = @("--iterations", $Iterations.ToString(), "--mode=guards-off")
    $proc = Start-Process -FilePath $TargetExe -ArgumentList $argList -PassThru

    Start-Sleep -Seconds $AttachDelaySec

    if ($proc.HasExited) {
        "[WARN] pre-attach-exit attempt=$attempt exitCode=$($proc.ExitCode)" | Add-Content $summaryPath
        $attempt++
        continue
    }

    if ($FailFastOnForbiddenModules) {
        $hits = Get-ForbiddenModuleHits -TargetPid $proc.Id -ToolPath $ListDllsPath -Forbidden $ForbiddenModules
        if ($hits.Count -eq 0) {
            $probeLog = Join-Path $OutDir ("preflight_probe_{0:D4}.log" -f $attempt)
            $hits = Get-ForbiddenModuleHitsCdbProbe -TargetPid $proc.Id -CdbPath $cdbPath -Forbidden $ForbiddenModules -ProbeLogPath $probeLog
        }
        if ($hits.Count -gt 0) {
            $hitCsv = ($hits -join ",")
            "[CRITICAL] contaminated-run attempt=$attempt pid=$($proc.Id) forbidden=$hitCsv" | Add-Content $summaryPath
            Write-Host ("FATAL: Hook detected ({0}). Aborting clean-room run." -f $hitCsv) -ForegroundColor Red

            $payload = [ordered]@{
                TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
                Status = "Contaminated"
                Attempt = $attempt
                Pid = $proc.Id
                ForbiddenModules = $hits
                Message = "FATAL: Hook detected before debugger attach"
            }
            $payload | ConvertTo-Json -Depth 5 | Set-Content -Path $finalReportPath -Encoding utf8

            Get-Process -Id $proc.Id -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            break
        }
    }

    $logPath = Join-Path $OutDir ("capture_attempt_{0:D4}.log" -f $attempt)
    $cdbCommand = Build-CdbCommand -Wide:$WideNet

    & $cdbPath -p $proc.Id -logo $logPath -c $cdbCommand
    $cdbExit = $LASTEXITCODE

    $lastEvent = Get-LastEventLine -LogPath $logPath
    $isFatal = Is-FatalCapture -LogPath $logPath

    if ($isFatal) {
        Write-Host ("CRITICAL: Captured failure in attempt #{0}" -f $attempt) -ForegroundColor Red
        "[CRITICAL] fatal-capture attempt=$attempt pid=$($proc.Id) cdbExit=$cdbExit" | Add-Content $summaryPath
        "[CRITICAL] last-event $lastEvent" | Add-Content $summaryPath
        "[CRITICAL] log $logPath" | Add-Content $summaryPath

        if (Test-Path $AnalyzerPath) {
            try {
                $analysis = & $AnalyzerPath -LogPath $logPath -OutReportPath $finalReportPath
                if ($analysis) {
                    "[CRITICAL] analysis verdict=$($analysis.Verdict) exception=$($analysis.ExceptionCode) module=$($analysis.FaultingModule)" | Add-Content $summaryPath
                    "[CRITICAL] report $finalReportPath" | Add-Content $summaryPath
                }
            } catch {
                "[WARN] analyzer-failed error=$($_.Exception.Message)" | Add-Content $summaryPath
            }
        }

        break
    }

    "[INFO] clean-exit attempt=$attempt pid=$($proc.Id) cdbExit=$cdbExit last-event=$lastEvent" | Add-Content $summaryPath

    if ((-not $KeepCleanLogs) -and (Test-Path $logPath)) {
        Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
    }

    Get-Process -Id $proc.Id -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $attempt++
}

"[INFO] loop-end time=$((Get-Date).ToString("o"))" | Add-Content $summaryPath
Write-Host ("Summary: {0}" -f $summaryPath) -ForegroundColor Green

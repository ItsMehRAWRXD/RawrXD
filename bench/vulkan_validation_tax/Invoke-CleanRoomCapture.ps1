# ==============================================================================
# Invoke-CleanRoomCapture.ps1
# Pre-Flight / Execution / Artifact-Archive pipeline for Vulkan validation tax
# benchmarking with TIERED GUARDING (Cold-Warm-Hot stochastic validation).
# ==============================================================================
param(
    [int]$Iterations = 50000,
    [int]$ValidationFrequency = 50,   # Steady-state: validate every Nth chunk (default 50)
    [int]$WarmUpIterations = 100,       # Phase 1: validate every call for first N iterations
    [int]$PanicWindow = 1000,           # Phase 3: if error, validate next N iterations
    [string]$ExePath = "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe",
    [string]$OutDir = "D:\rawrxd\bench\vulkan_validation_tax\runs",
    [switch]$FailFastOnForbiddenModules,
    [switch]$DisableAmdOverlay,
    [switch]$SetCompatLayer,
    [switch]$WideNet
)

$ErrorActionPreference = 'Stop'

# ==============================================================================
# Stage 1: Service/Process Purge (Clean-Room)
# ==============================================================================
function Invoke-CleanRoomPurge {
    $injectors = @(
        "RadeonSoftware",
        "amddvr64",
        "obs64",
        "obs32",
        "amdow",
        "AMDRSServ",
        "jusched"
    )
    foreach ($proc in $injectors) {
        $p = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($p) {
            Write-Host "[PURGE] Stopping $proc (PID:$($p.Id))" -ForegroundColor Yellow
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Milliseconds 500
}

# ==============================================================================
# Stage 2: Environment Enforcement
# ==============================================================================
function Set-CleanRoomEnvironment {
    if ($DisableAmdOverlay) {
        $env:DISABLE_AMD_OVERLAY = "1"
        Write-Host "[ENV] DISABLE_AMD_OVERLAY=1" -ForegroundColor DarkGray
    }
    if ($SetCompatLayer) {
        $env:__COMPAT_LAYER = "RunAsInvoker"
        Write-Host "[ENV] __COMPAT_LAYER=RunAsInvoker" -ForegroundColor DarkGray
    }
    if ($WideNet) {
        $env:WIDE_NET_PROBE = "1"
        Write-Host "[ENV] WIDE_NET_PROBE=1" -ForegroundColor DarkGray
    }
}

# ==============================================================================
# Stage 3: Forbidden Module Check
# ==============================================================================
function Test-ForbiddenModules {
    param([int]$Pid)
    $forbidden = @("amdihk64.dll", "graphics-hook64.dll", "aticfx64.dll")
    $modules = try { Get-Process -Id $Pid -ErrorAction Stop | Select-Object -ExpandProperty Modules } catch { $null }
    if (-not $modules) { return $false }
    foreach ($mod in $modules) {
        foreach ($f in $forbidden) {
            if ($mod.ModuleName -like $f) {
                Write-Host "[FAIL] Forbidden module detected: $($mod.ModuleName)" -ForegroundColor Red
                return $true
            }
        }
    }
    return $false
}

# ==============================================================================
# Stage 4: Stochastic Validation Runner
# ==============================================================================
function Invoke-StochasticBenchmark {
    param(
        [int]$TotalIterations,
        [int]$Freq,
        [string]$Exe
    )

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $sessionDir = Join-Path $OutDir $stamp
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null

    $chunkSize = 1000
    $chunks = [math]::Ceiling($TotalIterations / $chunkSize)
    $allStdout = @()
    $allStderr = @()
    $totalMs = 0
    $validatedIters = 0
    $unvalidatedIters = 0
    $panicRemaining = 0
    $warmUpRemaining = $WarmUpIterations

    for ($c = 0; $c -lt $chunks; $c++) {
        $iterInChunk = [math]::Min($chunkSize, $TotalIterations - ($c * $chunkSize))
        $globalIterBase = $c * $chunkSize

        # ==============================================================================
        # TIERED GUARDING: Cold-Warm-Hot
        # ==============================================================================
        # Phase 1: Warm-up (validate every call)
        # Phase 2: Steady-state (stochastic validation)
        # Phase 3: Panic mode (validate every call after error)
        # ==============================================================================
        $shouldValidate = $false
        if ($panicRemaining -gt 0) {
            $shouldValidate = $true
            $panicRemaining -= $iterInChunk
            $mode = "guards-on-panic"
        }
        elseif ($warmUpRemaining -gt 0) {
            $shouldValidate = $true
            $warmUpRemaining -= $iterInChunk
            $mode = "guards-on-warmup"
        }
        else {
            # Steady-state: stochastic frequency
            $shouldValidate = ($Freq -gt 0) -and ((($globalIterBase / $chunkSize) % $Freq) -eq 0)
            $mode = if ($shouldValidate) { "guards-on" } else { "guards-off" }
        }

        $stdoutFile = Join-Path $sessionDir ("chunk_{0:D4}_{1}_stdout.txt" -f $c, $mode)
        $stderrFile = Join-Path $sessionDir ("chunk_{0:D4}_{1}_stderr.txt" -f $c, $mode)

        Write-Host "[RUN] Chunk $c/$chunks : iterations=$iterInChunk mode=$mode" -ForegroundColor Cyan

        $proc = Start-Process -FilePath $Exe `
            -ArgumentList "--iterations $iterInChunk --mode=$mode" `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile `
            -PassThru

        $proc.WaitForExit()
        $exitCode = $proc.ExitCode

        if ($FailFastOnForbiddenModules -and (Test-ForbiddenModules -Pid $proc.Id)) {
            Write-Host "[FAILFAST] Forbidden module detected. Aborting." -ForegroundColor Red
            exit 1
        }

        $stdoutText = Get-Content -Path $stdoutFile -Raw -ErrorAction SilentlyContinue
        $stderrText = Get-Content -Path $stderrFile -Raw -ErrorAction SilentlyContinue

        # Parse timing from stdout
        $timingMatch = $stdoutText | Select-String 'total=(\d+\.?\d*)\s+ms\s+per-iter=(\d+\.?\d*)\s+us'
        if ($timingMatch) {
            $chunkMs = [double]$timingMatch.Matches[0].Groups[1].Value
            $chunkUs = [double]$timingMatch.Matches[0].Groups[2].Value
            $totalMs += $chunkMs
            if ($shouldValidate) {
                $validatedIters += $iterInChunk
            } else {
                $unvalidatedIters += $iterInChunk
            }
        }

        $allStdout += $stdoutText
        $allStderr += $stderrText

        if ($exitCode -ne 0) {
            Write-Host "[WARN] Chunk $c exited with code $exitCode" -ForegroundColor Yellow
            # PANIC TRIGGER: Error detected, switch to full validation
            $panicRemaining = $PanicWindow
            Write-Host "[PANIC] Error at iteration $globalIterBase. Enabling full validation for next $PanicWindow iterations." -ForegroundColor Red
        }
    }

    # ==============================================================================
    # Stage 5: Summary & Artifact Routing
    # ==============================================================================
    $summary = @{
        timestamp = Get-Date -Format "o"
        iterations = $TotalIterations
        validation_frequency = $Freq
        validated_iterations = $validatedIters
        unvalidated_iterations = $unvalidatedIters
        total_ms = $totalMs
        per_iter_us = if ($TotalIterations -gt 0) { $totalMs * 1000.0 / $TotalIterations } else { 0 }
        session_dir = $sessionDir
        chunks = $chunks
    }

    $summaryJson = $summary | ConvertTo-Json -Depth 4
    $summaryPath = Join-Path $sessionDir "summary.json"
    Set-Content -Path $summaryPath -Value $summaryJson

    # Route to clean or contaminated based on exit codes and module checks
    $hasErrors = $allStderr | Where-Object { $_ -match "error|assert|violation|EXCEPTION" }
    $isClean = (-not $hasErrors) -and ($allStdout | Where-Object { $_ -match "guards-(on|off).*end" })

    $finalDir = if ($isClean) {
        Join-Path $OutDir "clean"
    } else {
        Join-Path $OutDir "contaminated"
    }
    New-Item -ItemType Directory -Path $finalDir -Force | Out-Null

    $finalSessionDir = Join-Path $finalDir $stamp
    if (Test-Path $finalSessionDir) { Remove-Item -Path $finalSessionDir -Recurse -Force }
    Move-Item -Path $sessionDir -Destination $finalSessionDir

    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Green
    Write-Host "STOCHASTIC BENCHMARK COMPLETE" -ForegroundColor Green
    Write-Host "  Total iterations : $TotalIterations"
    Write-Host "  Validation freq  : 1/$Freq"
    Write-Host "  Validated iters  : $validatedIters"
    Write-Host "  Unvalidated iters: $unvalidatedIters"
    Write-Host "  Total time       : $($totalMs.ToString('F2')) ms"
    Write-Host "  Per-iter avg     : $($summary.per_iter_us.ToString('F2')) us"
    Write-Host "  Artifacts        : $finalSessionDir"
    Write-Host "  Status           : $(if ($isClean) { 'CLEAN' } else { 'CONTAMINATED' })"
    Write-Host "===============================================================" -ForegroundColor Green

    return $summary
}

# ==============================================================================
# Main
# ==============================================================================
Write-Host "=== Sovereign Clean-Room Capture ===" -ForegroundColor Cyan
Write-Host "Iterations          : $Iterations"
Write-Host "ValidationFrequency : 1/$ValidationFrequency (1=always, 0=never, N=every Nth chunk)"
Write-Host "ExePath             : $ExePath"
Write-Host "OutDir              : $OutDir"
Write-Host ""

Invoke-CleanRoomPurge
Set-CleanRoomEnvironment

if (-not (Test-Path $ExePath)) {
    throw "Benchmark executable not found: $ExePath"
}

$result = Invoke-StochasticBenchmark -TotalIterations $Iterations -Freq $ValidationFrequency -Exe $ExePath

exit 0

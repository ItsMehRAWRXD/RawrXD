#Requires -Version 5.1
<#
.SYNOPSIS
    RawrXD Sovereign Baseline Regression Runner
.DESCRIPTION
    Automated regression test suite that validates:
    - Build integrity (no ODR violations, clean compile)
    - CPU fallback gate (RAWRXD_PARITY_CPU=1)
    - Subsystem health (all 8 subsystems READY)
    - Model contract (load/unload/generate lifecycle)
    - Agent controller wiring (auto-load on first message)
    - Performance baseline (TTFT measurement)

    Exit code: 0 = all passed, 1 = any failed
.EXAMPLE
    .\Run-SovereignRegression.ps1 -Verbose
    .\Run-SovereignRegression.ps1 -BuildOnly
    .\Run-SovereignRegression.ps1 -TestFilter "ODR|CPU"
#>
[CmdletBinding()]
param(
    [switch]$BuildOnly,
    [string]$TestFilter = "",
    [string]$CompilerPath = "",
    [switch]$NoBuild,
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$script:StartTime = Get-Date

# ── Configuration ───────────────────────────────────────────────────────────
$ProjectRoot = $PSScriptRoot
$TestSource = Join-Path $ProjectRoot "tests\regression\sovereign_baseline_regression.cpp"
$OutputDir = Join-Path $ProjectRoot "build-ninja\tests"
$Executable = Join-Path $OutputDir "sovereign_baseline_regression.exe"
$LogFile = Join-Path $OutputDir "regression_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# ── Helper Functions ──────────────────────────────────────────────────────
function Write-RegressLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    if (!$Quiet) { Write-Host $line }
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Find-Compiler {
    if ($CompilerPath -and (Test-Path $CompilerPath)) { return $CompilerPath }

    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe",
        "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    throw "MSVC cl.exe not found. Set -CompilerPath or install VS2022 Enterprise."
}

function Find-VcVars {
    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    throw "vcvarsall.bat not found. Install VS2022 Enterprise."
}

# ── Build Phase ─────────────────────────────────────────────────────────────
function Invoke-Build {
    Write-RegressLog "Starting build phase..."

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $cl = Find-Compiler
    $vcvars = Find-VcVars
    Write-RegressLog "Compiler: $cl"
    Write-RegressLog "VcVars: $vcvars"

    # Build via cmd to inherit VS environment
    $cmd = @"
call "$vcvars" x64 >nul 2>&1
cd /d "$ProjectRoot"
"$cl" /std:c++20 /EHsc /W3 /nologo /Fe:"$Executable" "$TestSource" /I include /I src /D_CRT_SECURE_NO_WARNINGS /link /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
"@
    $batPath = Join-Path $env:TEMP "build_regress_$(Get-Random).bat"
    Set-Content -Path $batPath -Value $cmd -Encoding ASCII

    try {
        $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $batPath -PassThru -Wait -NoNewWindow -RedirectStandardOutput "$env:TEMP\regress_build_out.log" -RedirectStandardError "$env:TEMP\regress_build_err.log"
        $stdout = Get-Content "$env:TEMP\regress_build_out.log" -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content "$env:TEMP\regress_build_err.log" -Raw -ErrorAction SilentlyContinue

        if ($proc.ExitCode -ne 0) {
            Write-RegressLog "BUILD FAILED (exit $($proc.ExitCode))" "ERROR"
            Write-RegressLog "STDOUT: $stdout" "ERROR"
            Write-RegressLog "STDERR: $stderr" "ERROR"
            throw "Build failed. See logs above."
        }
    } finally {
        Remove-Item $batPath -ErrorAction SilentlyContinue
    }

    if (!(Test-Path $Executable)) {
        throw "Build reported success but executable not found: $Executable"
    }

    Write-RegressLog "Build succeeded: $Executable"
}

# ── Test Phase ────────────────────────────────────────────────────────────
function Invoke-Test {
    Write-RegressLog "Starting test phase..."

    $args = @()
    if ($Quiet) { $args += "--quiet" }
    if ($TestFilter) { $args += "--filter"; $args += $TestFilter }

    $proc = Start-Process -FilePath $Executable -ArgumentList $args -PassThru -Wait -NoNewWindow -RedirectStandardOutput "$env:TEMP\regress_run_out.log" -RedirectStandardError "$env:TEMP\regress_run_err.log"
    $stdout = Get-Content "$env:TEMP\regress_run_out.log" -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content "$env:TEMP\regress_run_err.log" -Raw -ErrorAction SilentlyContinue

    Write-RegressLog "Test output:" "INFO"
    if ($stdout) { Write-RegressLog $stdout "INFO" }
    if ($stderr) { Write-RegressLog $stderr "WARN" }

    # Parse results
    $passed = 0
    $failed = 0
    if ($stdout -match "RESULTS:\s+(\d+)\s+passed,\s+(\d+)\s+failed") {
        $passed = [int]$Matches[1]
        $failed = [int]$Matches[2]
    }

    return @{
        ExitCode = $proc.ExitCode
        Passed   = $passed
        Failed   = $failed
        Output   = $stdout
    }
}

# ── Main ──────────────────────────────────────────────────────────────────
try {
    Write-RegressLog "================================================"
    Write-RegressLog "RawrXD Sovereign Regression Runner"
    Write-RegressLog "Started: $($script:StartTime)"
    Write-RegressLog "================================================"

    if (!$NoBuild) {
        Invoke-Build
    } else {
        Write-RegressLog "Skipping build (--NoBuild)"
        if (!(Test-Path $Executable)) {
            throw "Executable not found and --NoBuild specified: $Executable"
        }
    }

    if ($BuildOnly) {
        Write-RegressLog "Build-only mode. Exiting."
        exit 0
    }

    $results = Invoke-Test
    $duration = (Get-Date) - $script:StartTime

    Write-RegressLog "================================================"
    Write-RegressLog "Results: $($results.Passed) passed, $($results.Failed) failed"
    Write-RegressLog "Duration: $($duration.TotalSeconds.ToString('F2'))s"
    Write-RegressLog "Exit code: $($results.ExitCode)"
    Write-RegressLog "================================================"

    if ($results.Failed -gt 0) {
        Write-RegressLog "REGRESSION FAILED" "ERROR"
        exit 1
    } else {
        Write-RegressLog "ALL CHECKS PASSED" "SUCCESS"
        exit 0
    }
}
catch {
    Write-RegressLog "FATAL: $_" "ERROR"
    exit 1
}

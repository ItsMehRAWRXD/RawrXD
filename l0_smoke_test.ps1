# ============================================================================
# l0_smoke_test.ps1
# L0 Smoke Test Runner — validates RawrXD-Win32IDE.exe can initialize
# critical subsystems without launching GUI
# ============================================================================
# Usage:
#   .\l0_smoke_test.ps1
#   .\l0_smoke_test.ps1 -ExePath "D:\\rawrxd\\build\\RawrXD-Win32IDE.exe"
#   .\l0_smoke_test.ps1 -Verbose
# ============================================================================

param(
    [string]$ExePath = "",
    [switch]$Verbose,
    [switch]$WaitForInput
)

$ErrorActionPreference = "Stop"

# --- Auto-detect exe if not specified ---
if (-not $ExePath) {
    $candidates = @(
        "build\RawrXD-Win32IDE.exe",
        "build-ninja\RawrXD-Win32IDE.exe",
        "build-ninja\bin\RawrXD-Win32IDE.exe",
        "agentic_build\RawrXD-Win32IDE.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $ExePath = Resolve-Path $c
            break
        }
    }
}

if (-not $ExePath -or -not (Test-Path $ExePath)) {
    Write-Error "RawrXD-Win32IDE.exe not found. Specify -ExePath or build first."
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD L0 Smoke Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Executable: $ExePath"
Write-Host ""

# --- Set environment for deterministic test ---
$env:RAWRXD_PARITY_CPU = "1"
$env:RAWRXD_DISABLE_VULKAN_PROBE_STARTUP = "1"

# --- Run the test ---
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $proc = Start-Process -FilePath $ExePath -ArgumentList "--test-mode" `
        -PassThru -Wait -WindowStyle Hidden `
        -RedirectStandardOutput "l0_smoke_stdout.txt" `
        -RedirectStandardError "l0_smoke_stderr.txt"
    $exitCode = $proc.ExitCode
} catch {
    Write-Error "Failed to launch ${ExePath}: $_"
    exit 1
}
$sw.Stop()

# --- Read output ---
$stdout = if (Test-Path "l0_smoke_stdout.txt") { Get-Content "l0_smoke_stdout.txt" -Raw } else { "" }
$stderr = if (Test-Path "l0_smoke_stderr.txt") { Get-Content "l0_smoke_stderr.txt" -Raw } else { "" }

# --- Evaluate ---
$hasSuccessReady = $stdout -match "SUCCESS_READY"
$hasFailureDetected = $stdout -match "FAILURE_DETECTED" -or $stderr -match "FAIL"

if ($Verbose) {
    Write-Host "--- STDOUT ---" -ForegroundColor Gray
    Write-Host $stdout
    Write-Host "--- STDERR ---" -ForegroundColor Gray
    Write-Host $stderr
    Write-Host "--------------" -ForegroundColor Gray
}

Write-Host "Exit code: $exitCode"
Write-Host "Duration: $($sw.ElapsedMilliseconds)ms"
Write-Host ""

# --- Report ---
if ($exitCode -eq 0 -and $hasSuccessReady -and -not $hasFailureDetected) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "L0 SMOKE TEST PASSED" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "All critical subsystems initialized successfully:"
    Write-Host "  ✓ snmalloc shim (CRT heap forwarding)"
    Write-Host "  ✓ SubsystemRegistry"
    Write-Host "  ✓ InferenceEngine shared instance"
    Write-Host "  ✓ File I/O sanity"
    Write-Host ""
    $result = 0
} else {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "L0 SMOKE TEST FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Exit code: $exitCode"
    if ($hasFailureDetected) {
        Write-Host "Failure markers detected in output."
    }
    if (-not $hasSuccessReady) {
        Write-Host "SUCCESS_READY marker not found in stdout."
    }
    Write-Host ""
    Write-Host "--- STDOUT ---"
    Write-Host $stdout
    Write-Host "--- STDERR ---"
    Write-Host $stderr
    $result = 1
}

# Cleanup
Remove-Item -ErrorAction SilentlyContinue "l0_smoke_stdout.txt", "l0_smoke_stderr.txt"

if ($WaitForInput) {
    Write-Host "Press Enter to exit..."
    $null = Read-Host
}

exit $result

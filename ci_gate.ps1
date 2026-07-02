# ci_gate.ps1
# 
# Sovereign Inference Orchestration (SIO) Infrastructure Lock Gate
# 
# This script validates the entire infrastructure stack before releasing an application build.
# Exits with 0 if all gates pass; exits with non-zero if any gate fails.
# 
# Usage: .\ci_gate.ps1
# 
# Gates:
# 1. Build Gate: Compile engine binary (C++ / MSVC).
# 2. Infrastructure Gate: Run hexmag_client_handshake.py (policy-authoritative orchestration).
# 3. Application Gate: Run test_ui_api_connection.py (UI-to-engine connectivity).
# 4. Packaging: Create alpha release artifact.

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

# Configuration
$WORK_DIR = "d:\rawrxd-ci-bootstrap"
$VENV = "d:\.venv\Scripts\python.exe"
$BUILD_SCRIPT = Join-Path $WORK_DIR "_build_ide_integration.cmd"
$HANDSHAKE_SCRIPT = Join-Path $WORK_DIR "hexmag_client_handshake.py"
$UI_TEST_SCRIPT = Join-Path $WORK_DIR "test_ui_api_connection.py"
$GUARD_SCRIPT = Join-Path $WORK_DIR "guard.py"
$BUILD_LOG = Join-Path $WORK_DIR "_ci_build.log"
$HANDSHAKE_LOG = Join-Path $WORK_DIR "_ci_handshake.log"
$UI_TEST_LOG = Join-Path $WORK_DIR "_ci_ui_test.log"
$GUARD_LOG = Join-Path $WORK_DIR "_ci_guard.log"

function Log-Header {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $args[0] -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Log-Pass {
    Write-Host "[PASS] $($args[0])" -ForegroundColor Green
}

function Log-Fail {
    Write-Host "[FAIL] $($args[0])" -ForegroundColor Red
}

function Log-Info {
    Write-Host "[INFO] $($args[0])" -ForegroundColor Yellow
}

# ============================================================================
# GATE 1: Build Gate
# ============================================================================
Log-Header "GATE 1: Engine Build (C++ / MSVC)"

Log-Info "Building IDE_Integration.exe..."
cmd.exe /c $BUILD_SCRIPT | Tee-Object -FilePath $BUILD_LOG

if ($LASTEXITCODE -ne 0) {
    Log-Fail "Engine build failed. See $BUILD_LOG for details."
    exit 1
}

Log-Pass "Engine build completed successfully."

# ============================================================================
# GATE 1.2: SDK Package Type-Check Gate
# ============================================================================
Log-Header "GATE 1.2: SDK Package Type-Check Gate"

$packages = @(
    "security-engine",
    "security-express",
    "security-redis",
    "security-telemetry-verify",
    "security-ipc",
    "security-sandbox"
)

foreach ($pkg in $packages) {
    $pkgPath = Join-Path $WORK_DIR "packages" $pkg
    if (-not (Test-Path $pkgPath)) {
        Log-Info "Package $pkg not found at $pkgPath; skipping."
        continue
    }
    Log-Info "Type-checking package: $pkg..."
    $proc = Start-Process -FilePath "npx" -ArgumentList "tsc","-p","tsconfig.json","--noEmit" -WorkingDirectory $pkgPath -PassThru -Wait -WindowStyle Hidden
    if ($proc.ExitCode -ne 0) {
        Log-Fail "Type-check failed for package: $pkg"
        exit 1
    }
    Log-Pass "Type-check passed: $pkg"
}

# ============================================================================
# GATE 1.3: Sovereign Regression Test Gate
# ============================================================================
Log-Header "GATE 1.3: Sovereign Regression Test Gate"

$regressionScripts = @(
    (Join-Path $WORK_DIR "regression_test_pe.py"),
    (Join-Path $WORK_DIR "packages" "security-sandbox" "tests" "malicious-extension-regression.ts"),
    (Join-Path $WORK_DIR "packages" "security-sandbox" "tests" "toolchain-integration.ts")
)

foreach ($script in $regressionScripts) {
    if (-not (Test-Path $script)) {
        Log-Info "Regression script not found: $script; skipping."
        continue
    }
    Log-Info "Running regression: $script..."
    if ($script.EndsWith(".py")) {
        & $VENV $script 2>&1 | Tee-Object -FilePath (Join-Path $WORK_DIR "_ci_regression.log") -Append
    } else {
        npx tsx $script 2>&1 | Tee-Object -FilePath (Join-Path $WORK_DIR "_ci_regression.log") -Append
    }
    if ($LASTEXITCODE -ne 0) {
        Log-Fail "Regression failed: $script"
        exit 1
    }
    Log-Pass "Regression passed: $(Split-Path $script -Leaf)"
}

# ============================================================================
# GATE 1.5: Immutable Binary Guard Gate (MASM W^X)
# ============================================================================
Log-Header "GATE 1.5: Immutable Binary Guard (W^X Enforcement)"

if (-not (Test-Path $GUARD_SCRIPT)) {
    Log-Fail "Guard script not found at $GUARD_SCRIPT"
    exit 1
}

$targets = @(
    (Join-Path $WORK_DIR "IDE_Integration.exe"),
    (Join-Path $WORK_DIR "Sovereign_SDK.dll")
) | Where-Object { Test-Path $_ }

if ($targets.Count -eq 0) {
    Log-Info "No build artifacts present for guard validation at this stage."
} else {
    foreach ($target in $targets) {
        Log-Info "Running MASM guard verify on: $target"
        & $VENV $GUARD_SCRIPT verify $target 2>&1 | Tee-Object -FilePath $GUARD_LOG -Append
        if ($LASTEXITCODE -ne 0) {
            Log-Fail "Immutable guard failed for $target. See $GUARD_LOG for details."
            exit 1
        }
        Log-Pass "Immutable guard passed: $target"
    }
}

# ============================================================================
# GATE 2: Infrastructure Gate (Handshake Test)
# ============================================================================
Log-Header "GATE 2: Infrastructure Backbone Test (Handshake)"

Log-Info "Running hexmag_client_handshake.py with launch flag..."
$handshakeCmd = @(
    $VENV,
    $HANDSHAKE_SCRIPT,
    "--launch",
    "--host-args=--headless-soak=20",
    "--timeout-seconds=45",
    "--probe-port=11435",
    "--kill-on-fault"
)

& $handshakeCmd | Tee-Object -FilePath $HANDSHAKE_LOG
$handshakeExit = $LASTEXITCODE

if ($handshakeExit -ne 0) {
    Log-Fail "Handshake infrastructure test failed (exit code: $handshakeExit). See $HANDSHAKE_LOG for details."
    exit 1
}

Log-Pass "Handshake infrastructure test passed."

# ============================================================================
# GATE 3: Application Gate (UI-API Connectivity Test)
# ============================================================================
Log-Header "GATE 3: Application Layer Test (UI-API Connectivity)"

Log-Info "Running test_ui_api_connection.py..."

if (-not (Test-Path $UI_TEST_SCRIPT)) {
    Log-Info "UI connectivity test script not found at $UI_TEST_SCRIPT. Skipping (will be available Day 10)."
} else {
    $uiTestCmd = @(
        $VENV,
        $UI_TEST_SCRIPT
    )

    & $uiTestCmd | Tee-Object -FilePath $UI_TEST_LOG
    $uiTestExit = $LASTEXITCODE

    if ($uiTestExit -ne 0) {
        Log-Fail "UI-API connectivity test failed (exit code: $uiTestExit). See $UI_TEST_LOG for details."
        exit 1
    }

    Log-Pass "UI-API connectivity test passed."
}

# ============================================================================
# GATE 4: Packaging & Release
# ============================================================================
Log-Header "GATE 4: Packaging Alpha Release"

$releaseDir = Join-Path $WORK_DIR "release" "v1.1-alpha-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

Log-Info "Copying artifacts to $releaseDir..."

@(
    "IDE_Integration.exe",
    "IDE_Integration.obj",
    "Sovereign_SDK.dll",
    "hexmag_client_handshake.py",
    "Sovereign_Network.h",
    "Sovereign_LoadResult.h"
) | ForEach-Object {
    $src = Join-Path $WORK_DIR $_
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $releaseDir -Force | Out-Null
        Log-Info "Packaged: $_"
    } else {
        Log-Info "Skipped (not found): $_"
    }
}

Log-Pass "Alpha release packaged at: $releaseDir"

# ============================================================================
# FINAL RESULT
# ============================================================================
Log-Header "CI/CD INFRASTRUCTURE LOCK: PASSED"

Write-Host @"
All infrastructure gates have passed. The following are ready for deployment:

1. Engine Binary:       IDE_Integration.exe
2. Handshake Script:    hexmag_client_handshake.py
3. SDK DLL:             Sovereign_SDK.dll
4. Release Package:     $releaseDir

Next Steps:
- Deploy the release package to your IDE application layer.
- Begin application-layer testing (Days 1-10 sprint).
- All application-level features must respect engine policy (suggested_action, can_retry, fault_class).

Release Status: ALPHA (v1.1-alpha-$(Get-Date -Format 'yyyyMMdd-HHmmss'))

"@ -ForegroundColor Green

exit 0

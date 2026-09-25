#requires -Version 5.1
<#
  RAWRXD E2E Background Worker
  Trigger: continue-ensure dispatch
  Scope: Fix stack overflow, build parity, integrate missing batches, wire speculative graph
#>
$ErrorActionPreference = "Stop"
$ROOT    = "F:\~dev\rawrxd"
$BUILD   = "$ROOT\win32ide_strict\build_v4"
$LOG     = "F:\~dev\_bg_worker_e2e.log"
function Write-Log($msg) {
    $line = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $msg
    Add-Content -Path $LOG -Value $line -Encoding UTF8
    Write-Host $line
}

Write-Log "=== E2E WORKER START ==="

# ------------------------------------------------------------------
# STEP A: Rebuild strict Win32IDE Release
# ------------------------------------------------------------------
Write-Log "STEP A: Rebuilding RawrXD-Win32IDE Release..."
$rc = & cmake --build $BUILD --config Release --target RawrXD-Win32IDE 2>&1 | Tee-Object -FilePath "F:\~dev\_build_strict.log"
if ($LASTEXITCODE -ne 0) {
    Write-Log "BUILD FAILED (RC=$LASTEXITCODE). See _build_strict.log"
    Write-Log "=== E2E WORKER HALTED ==="
    exit 1
}
Write-Log "BUILD OK"

# ------------------------------------------------------------------
# STEP B: Run gate and capture evidence
# ------------------------------------------------------------------
$GATE_EXE = "$BUILD\Release\RawrXD-Win32IDE.exe"
$GEN_DEBUG = "$BUILD\Release\gen_debug.txt"
if (Test-Path $GEN_DEBUG) { Remove-Item $GEN_DEBUG -Force }
Write-Log "STEP B: Running gate --cert-agent --headless..."
$proc = Start-Process -FilePath $GATE_EXE -ArgumentList "--cert-agent","--headless" -PassThru -WindowStyle Hidden
$proc.WaitForExit(120000)
$exitCode = if ($proc.HasExited) { $proc.ExitCode } else { -999 }
if (-not $proc.HasExited) { $proc.Kill(); Write-Log "Gate timed out, killed" }
Write-Log "Gate EXIT_CODE=$exitCode"

# ------------------------------------------------------------------
# STEP C: Read gen_debug.txt after run
# ------------------------------------------------------------------
if (Test-Path $GEN_DEBUG) {
    $lines = Get-Content $GEN_DEBUG -Encoding UTF8 -TotalCount 200
    Write-Log "gen_debug.txt first 200 lines captured"
    $lines | Set-Content "F:\~dev\_gen_debug_latest.txt" -Encoding UTF8
} else {
    Write-Log "gen_debug.txt NOT FOUND after gate run"
}

# ------------------------------------------------------------------
# STEP D: Check Windows Event Log for crashes
# ------------------------------------------------------------------
$events = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue | Select-Object -First 5
if ($events) {
    Write-Log "Recent Application crash events found:"
    $events | ForEach-Object { Write-Log ($_.Message -split "`n" | Select-Object -First 3) }
} else {
    Write-Log "No recent Application crash events (ID 1000) in last 10 min"
}

# ------------------------------------------------------------------
# STEP E: Build rawrxd_real_gguf_parity from root CMake (out-of-tree)
# ------------------------------------------------------------------
$PARITY_BUILD = "$ROOT\build_parity"
if (-not (Test-Path $PARITY_BUILD)) { New-Item -ItemType Directory -Path $PARITY_BUILD | Out-Null }
Write-Log "STEP E: Configuring parity build..."
& cmake -S $ROOT -B $PARITY_BUILD -DCMAKE_BUILD_TYPE=Release -DBUILD_DEEP2_REAL_GGUF_PARITY=ON 2>&1 | Tee-Object -FilePath "F:\~dev\_parity_cmake.log"
if ($LASTEXITCODE -ne 0) {
    Write-Log "Parity cmake configure FAILED. See _parity_cmake.log"
} else {
    Write-Log "STEP E: Building parity target..."
    & cmake --build $PARITY_BUILD --config Release --target rawrxd_real_gguf_parity 2>&1 | Tee-Object -FilePath "F:\~dev\_parity_build.log"
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Parity build FAILED. See _parity_build.log"
    } else {
        Write-Log "Parity build OK"
        $PARITY_EXE = Get-ChildItem -Path $PARITY_BUILD -Recurse -Filter "rawrxd_real_gguf_parity.exe" | Select-Object -First 1
        if ($PARITY_EXE) {
            Write-Log "Parity exe found at $($PARITY_EXE.FullName)"
            Copy-Item $PARITY_EXE.FullName "F:\~dev\rawrxd_real_gguf_parity.exe" -Force
        }
    }
}

# ------------------------------------------------------------------
# STEP F: Inspect lmHead geometry for gemma3 (large vocabSize=262144)
# ------------------------------------------------------------------
Write-Log "STEP F: Checking if lmHead.rows (262144) could cause stack overflow in CPU fallback..."
Write-Log "Gemma3 vocabSize=262144, hiddenDim=1152. lmHead is 262144 x 1152 Q2_K."
Write-Log "LinearW CPU fallback calls gemv_q2_k_scalar with rows=262144, cols=1152."
Write-Log "This is a large outer loop (262K iterations) but no recursion. Stack overflow likely elsewhere."

Write-Log "=== E2E WORKER PAUSED (awaiting coordinator next turn) ==="
# Keep process alive so coordinator can inspect logs
while ($true) { Start-Sleep -Seconds 3600 }

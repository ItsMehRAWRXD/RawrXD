# RAWRXD_WIN32IDE_E2E_001 — Background Worker
$BUILD_DIR = "f:\~dev\rawrxd\win32ide_strict\build_v4"
$RELEASE_DIR = Join-Path $BUILD_DIR "Release"
$EXE = Join-Path $RELEASE_DIR "RawrXD-Win32IDE.exe"
$MODEL_A = "D:\rawrxd\gemma3-1b-Q2_K.gguf"
$MODEL_B = "G:\~dev\test_model.gguf"
$RECEIPT = Join-Path $RELEASE_DIR "cert_receipt_autoclose.txt"

function Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $msg"
}

# Kill any existing zombies
Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Log "WORKER_START"

# === GATE 1: STRICT_RELEASE_BUILD ===
Log "=== GATE 1: STRICT_RELEASE_BUILD ==="
$proc = Start-Process -FilePath "cmake" -ArgumentList "--build", $BUILD_DIR, "--config", "Release", "--target", "RawrXD-Win32IDE" -Wait -PassThru -NoNewWindow
Log "BUILD_RC=$($proc.ExitCode)"
if ($proc.ExitCode -ne 0 -or !(Test-Path $EXE)) {
    Log "BUILD_FAIL"
    "BUILD_FAIL" | Out-File (Join-Path $RELEASE_DIR "e2e_report.txt")
    exit 1
}
Log "BUILD_OK"

# === GATE 2: AUTOCLOSURE_REAL_RUNTIME ===
Log "=== GATE 2: AUTOCLOSURE_REAL_RUNTIME ==="
$model = if (Test-Path $MODEL_A) { $MODEL_A } else { $MODEL_B }
if (!(Test-Path $model)) {
    Log "MODEL_NOT_FOUND: $model"
    "MODEL_NOT_FOUND" | Out-File (Join-Path $RELEASE_DIR "e2e_report.txt")
    exit 1
}

$env:RAWRXD_AUTOCLOSE_DEBUG = "1"
$env:RAWRXD_AUTOCLOSE_GEN = "1"
$env:RAWRXD_AUTOCLOSE_LAYERS = "26"

$argList = @("--autoclose", "--model", $model, "--workspace", "F:\~dev\rawrxd", "--gate-tokens", "8", "--nonce", "7E91B462", "--receipt", $RECEIPT, "--wall-ms", "300000")
Log "RUN: $EXE $argList"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
# Direct invocation avoids STATUS_STACK_OVERFLOW crash seen with Start-Process
Log "INVOKING: $EXE $argList"
& $EXE @argList
$exitCode = $LASTEXITCODE
$sw.Stop()
Log "EXIT_CODE=$exitCode ELAPSED_MS=$($sw.ElapsedMilliseconds)"

$receiptPathExists = Test-Path $RECEIPT
Log "RECEIPT_PATH=$RECEIPT EXISTS=$receiptPathExists"
$rcpt = @{}
if ($receiptPathExists) {
    Get-Content $RECEIPT | ForEach-Object {
        if ($_ -match "^(.+?)=(.+)$") { $rcpt[$matches[1].Trim()] = $matches[2].Trim() }
    }
}
Log "RECEIPT_KEYS: $($rcpt.Keys -join ',')"
Log "RECEIPT: $($rcpt | ConvertTo-Json -Compress)"

$ok = $true
foreach ($key in @("MODEL_LOADED","TOKENIZER_READY","FORWARD_PASS_OK","LOGITS_FINITE")) {
    if ($rcpt[$key] -ne "PASS") { Log "FAIL: $key=$($rcpt[$key])"; $ok = $false }
}
$gen = 0
if (![int]::TryParse($rcpt["GENERATED_TOKEN_COUNT"], [ref]$gen) -or $gen -le 0) { Log "FAIL: GENERATED_TOKEN_COUNT=$gen"; $ok = $false }
if ($rcpt["REAL_GPU_FORWARD"] -ne "PASS") { Log "FAIL: REAL_GPU_FORWARD=$($rcpt["REAL_GPU_FORWARD"])"; $ok = $false }
if ($rcpt["VERDICT"] -ne "PASS") { Log "FAIL: VERDICT=$($rcpt["VERDICT"])"; $ok = $false }

$report = @{ passed = $ok; time = (Get-Date).ToString("o"); receipt = $rcpt }
$report | ConvertTo-Json | Out-File (Join-Path $RELEASE_DIR "e2e_report.txt")
if ($ok) { Log "WORKER_DONE: PASS"; exit 0 } else { Log "WORKER_DONE: FAIL"; exit 1 }

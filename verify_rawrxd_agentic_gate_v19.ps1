param(
    [string]$BuildRoot = "F:\~dev\rawrxd\win32ide_strict\build_v4",
    [string]$ExpectedNonce = "7E91B462",
    [int]$PollSeconds = 2
)

$ErrorActionPreference = "Stop"

$release = Join-Path $BuildRoot "Release"
$receipt = Join-Path $release "cert_receipt_agentic.txt"
$genDebug = Join-Path $release "gen_debug.txt"

function Show-LatestDiagnostics {
    Write-Host ""
    Write-Host "=== LATEST DIAGNOSTICS ==="

    if (Test-Path $genDebug) {
        Write-Host "--- gen_debug tail ---"
        Get-Content $genDebug -Tail 80
    }

    $latestGate = Get-ChildItem $release -Filter "stderr_gate*.txt" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($latestGate) {
        Write-Host "--- $($latestGate.Name) tail ---"
        Get-Content $latestGate.FullName -Tail 80
    }
}

Write-Host "=== RAWRXD_AGENTIC_GATE_VERIFY_001 ==="
Write-Host "BUILD_ROOT=$BuildRoot"
Write-Host "EXPECTED_NONCE=$ExpectedNonce"

$procs = @(Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue)

if ($procs.Count -gt 0) {
    Write-Host ("ACTIVE_PROCESSES=" + (($procs | ForEach-Object { $_.Id }) -join ","))

    while (@(Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue).Count -gt 0) {
        $p = Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue |
            Sort-Object StartTime |
            Select-Object -First 1

        if ($p) {
            $seq = ""
            if (Test-Path $genDebug) {
                $lastSeq = Select-String -Path $genDebug -Pattern 'seqLen=\d+' |
                    Select-Object -Last 1
                if ($lastSeq -and $lastSeq.Line -match 'seqLen=(\d+)') {
                    $seq = $Matches[1]
                }
            }

            Write-Host ("RUNNING pid={0} cpu_s={1:N1} mem_mb={2:N1} seqLen={3}" -f `
                $p.Id,
                $p.TotalProcessorTime.TotalSeconds,
                ($p.WorkingSet64 / 1MB),
                $seq)
        }

        Start-Sleep -Seconds $PollSeconds
    }
}

Write-Host "PROCESS_ACTIVE=0"

if (!(Test-Path $receipt)) {
    Write-Host "RECEIPT_EXISTS=0"
    Show-LatestDiagnostics
    Write-Host "VERDICT=FAIL"
    exit 2
}

Write-Host "RECEIPT_EXISTS=1"
Write-Host "RECEIPT_PATH=$receipt"

$receiptText = Get-Content $receipt -Raw
Write-Host ""
Write-Host "=== RECEIPT ==="
Write-Host $receiptText.TrimEnd()

$nonceFound = $receiptText -match [regex]::Escape($ExpectedNonce)
Write-Host ("NONCE_MATCH=" + $(if ($nonceFound) { "PASS" } else { "FAIL" }))

# Accept explicit PASS/FAIL conventions without inventing one fixed schema.
$explicitFail = $receiptText -match '(?im)^\s*(VERDICT|RESULT|STATUS)\s*[:=]\s*FAIL\b'
$explicitPass = $receiptText -match '(?im)^\s*(VERDICT|RESULT|STATUS)\s*[:=]\s*PASS\b'

# Search the latest generation debug log for hard runtime faults.
$hardFailurePatterns = @(
    'FATAL_',
    'GPU_FORWARD_FAIL',
    'VSGW_FORWARD_BLOCK_FAIL',
    'RMSNormW: non-finite output',
    'GEN_COMPUTE_LOGITS_EXC',
    'stack buffer overrun',
    'geometry mismatch'
)

$runtimeFailures = @()
if (Test-Path $genDebug) {
    foreach ($pat in $hardFailurePatterns) {
        $m = Select-String -Path $genDebug -Pattern $pat -SimpleMatch -ErrorAction SilentlyContinue |
            Select-Object -Last 1
        if ($m) {
            $runtimeFailures += "$pat :: $($m.Line)"
        }
    }
}

# Receipt is authoritative for final gate status; diagnostics are reported
# independently so old/stale log entries cannot silently overturn a new receipt.
Write-Host ("RECEIPT_EXPLICIT_PASS=" + $(if ($explicitPass) { "1" } else { "0" }))
Write-Host ("RECEIPT_EXPLICIT_FAIL=" + $(if ($explicitFail) { "1" } else { "0" }))
Write-Host ("GEN_DEBUG_HARD_FAILURE_MARKERS=" + $runtimeFailures.Count)

if ($runtimeFailures.Count -gt 0) {
    Write-Host ""
    Write-Host "=== HARD FAILURE MARKERS FOUND IN GEN_DEBUG ==="
    $runtimeFailures | ForEach-Object { Write-Host $_ }
}

# Surface useful generation evidence if present.
if (Test-Path $genDebug) {
    $lastSeq = Select-String -Path $genDebug -Pattern 'seqLen=\d+' |
        Select-Object -Last 1
    if ($lastSeq -and $lastSeq.Line -match 'seqLen=(\d+)') {
        Write-Host "LAST_SEQ_LEN=$($Matches[1])"
    }

    $gpuOkCount = (Select-String -Path $genDebug -Pattern 'FWD_VULKAN_OK|GPU_FORWARD_OK' -AllMatches |
        Measure-Object).Count
    Write-Host "GPU_FORWARD_OK_MARKERS=$gpuOkCount"
}

if (!$nonceFound) {
    Write-Host "VERDICT=FAIL"
    exit 3
}

if ($explicitFail) {
    Write-Host "VERDICT=FAIL"
    exit 4
}

if ($explicitPass) {
    Write-Host "VERDICT=PASS"
    exit 0
}

# If the receipt exists and nonce matches but has no recognized explicit
# verdict field, do not fabricate PASS.
Write-Host "VERDICT=INDETERMINATE"
Write-Host "REASON=receipt exists and nonce matches, but no explicit PASS/FAIL field was recognized"
exit 5

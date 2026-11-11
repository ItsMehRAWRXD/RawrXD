$ErrorActionPreference="Continue"
$ev="F:\rawrxd\evidence\HARNESS_RECOVERY_AND_OS_FORENSICS_001"
$exe="F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe"
$expect="CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB"
$asof=(Get-Date).ToUniversalTime().ToString("o")
$sha=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$bin=Split-Path $exe
$bench=Test-Path (Join-Path $bin "deep2_benchmark.exe")
$cert=Test-Path "F:\rawrxd\tools\certify_e2e.py"
$log=Join-Path $ev "PRODUCT_64_TOKEN_RUNLOG.txt"
@(
"# 64-token product gate probe",
"ASOF_UTC=$asof",
"EXE=$exe",
"SHA256=$sha",
"SHA_MATCH=$($sha -eq $expect)",
"BYTES=$((Get-Item $exe).Length)",
"deep2_benchmark_present=$bench",
"certify_e2e_py_present=$cert"
) | Set-Content $log
# Bounded: if no product 64-token runner for this EXE, do not invent; record exit 0 with NOT_VERIFIED
$verdict="NOT_VERIFIED"
$reason="MISSING_CANDIDATE_64_TOKEN_PRODUCT_PATH"
if(-not ($sha -eq $expect)){ $verdict="FAIL"; $reason="SHA_MISMATCH" }
@"
# PRODUCT_64_TOKEN_RECEIPT — HARNESS_RECOVERY_AND_OS_FORENSICS_001

ASOF_UTC=$asof
GATE=PRODUCT_64_TOKEN_E2E_CANDIDATE
CANDIDATE_EXE=$exe
CANDIDATE_SHA256=$sha
SHA_MATCH_EXPECT=$([int]($sha -eq $expect))
EXPECT_SHA256=$expect
BYTES=$((Get-Item $exe).Length)

## Fresh attempt (this gate)
1. Same-SHA candidate reverify: MATCH=$($sha -eq $expect)
2. deep2_benchmark.exe in candidate bin: PRESENT=$bench (expected absent; benchmarks OFF)
3. certify_e2e.py present=$cert but CORE_DLL-scoped — not transferable to IDE product seal
4. No headless 64-token ProductOpen/SESSION_ENTER runner wired to this candidate EXE was executed here (path missing)

## Verdict
VERDICT=$verdict
STOP_REASON=$reason
GENERATED_TOKENS=NOT_OBSERVED
TOKEN_COMMIT=NOT_OBSERVED
PROCESS_EXIT=N/A_NO_RUNNER
RUNTIME_PASS=0
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
TIP_CLIMB=HOLD
NOT_RUN_NEQ_PASS=1
"@ | Set-Content (Join-Path $ev "PRODUCT_64_TOKEN_RECEIPT.md")
Add-Content $log "VERDICT=$verdict REASON=$reason"
Write-Output "64TOKEN_$verdict"

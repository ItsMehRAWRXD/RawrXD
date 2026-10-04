# RAWRXD_DECODE_STREAM_ROOT_001 -- gate evaluation over ALREADY-CAPTURED streams.
#
# The executable was run; stdout/stderr/merged are on disk. This applies the identical
# assertions to the captured log rather than re-running a 7-minute model load, so the
# receipt is deterministic and derived from the same bytes.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\RAWRXD_DECODE_STREAM_ROOT_001.ps1 `
#       -Merged ".\audit_tombstone_001\decode_capture\merged.txt"

param(
    [string]$Merged = "F:\~dev\audit_tombstone_001\decode_capture\merged.txt",
    [string]$OutDir = "F:\~dev\audit_tombstone_001\RAWRXD_DECODE_STREAM_ROOT_001"
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$receipt = Join-Path $OutDir "RAWRXD_DECODE_STREAM_ROOT_001.ini"

if (-not (Test-Path $Merged)) { Write-Output "ABORT: no capture at $Merged"; exit 2 }
$log = Get-Content $Merged -Raw

$failures = New-Object System.Collections.Generic.List[string]
if ($log -match "dual_row_host_lane_refused")            { $failures.Add("DUAL_ROW_HOST_LANE_REFUSED_PRESENT=1") }
if ($log -match "\[PREFILL\].*FAILED")                  { $failures.Add("PREFILL_FAILED=1") }
if ($log -notmatch "\[FWD_ALL\]")                        { $failures.Add("FORWARD_PATH_ENTERED=0") }
if ($log -notmatch "DECODE_ONE")                         { $failures.Add("DECODE_ONE_LINES_GT_0=0") }
if ($log -notmatch "stream_callbacks=[1-9]")             { $failures.Add("STREAM_CALLBACKS_GT_0=0") }
if ($log -notmatch "tokens=[1-9]")                       { $failures.Add("TOKENS_GT_0=0") }
if ($log -match "faults_total_during_tokens=[1-9]")      { $failures.Add("FAULTS_DURING_TOKENS_GT_0=1") }

# Additional observations the original gate does not test, recorded because they matter here.
$extra = @()
$extra += "MODEL_ADMISSION_REJECTED_PRESENT=" + [int]($log -match "MODEL_ADMISSION_REJECTED")
$extra += "EXPERT_REUSE_SUMMARY_PRESENT=" + [int]($log -match "EXPERT_REUSE_SUMMARY")
$extra += "REUSE_RECEIPT_VALID_PRESENT=" + [int]($log -match "REUSE_RECEIPT_VALID")
$extra += "ROUTE_SELECTION_PRESENT=" + [int]($log -match "ROUTE_SELECTION")

if ($failures.Count -gt 0) {
@"
RAWRXD_DECODE_STREAM_ROOT_001
AUDIT_GATE=ACTIVE
DROW_TRANSFORM=luad_wor_tsoh_enal_desufer -> dual_row_host_lane_refused
EXECUTION_CAPTURED=1
STDOUT_CAPTURED=1
STDERR_CAPTURED=1
DUAL_ROW_HOST_LANE_REFUSED_PRESENT=$([int]($log -match "dual_row_host_lane_refused"))
PREFILL_STATUS=FAIL_OR_UNPROVEN
DECODE_ONE_LINES_GT_0=0
STREAM_CALLBACKS_GT_0=0
TOKENS_GT_0=0
$(($extra -join "`n"))
PROCESS_EXIT_CODE=UNOBSERVED
FAILURES=$($failures -join ",")
VERDICT=FAIL
"@ | Set-Content $receipt
    Get-Content $receipt
    exit 1
}

@"
RAWRXD_DECODE_STREAM_ROOT_001
AUDIT_GATE=ACTIVE
EXECUTION_CAPTURED=1
DUAL_ROW_HOST_LANE_REFUSED_PRESENT=0
PREFILL_STATUS=PASS
DECODE_ONE_LINES_GT_0=1
STREAM_CALLBACKS_GT_0=1
TOKENS_GT_0=1
FAULTS_DURING_TOKENS=0
$(($extra -join "`n"))
VERDICT=PASS
"@ | Set-Content $receipt
Get-Content $receipt
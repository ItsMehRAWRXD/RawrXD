# ============================================================================
# attn_visibility_analyze.ps1
#   RAWRXD_ATTN_VISIBILITY_TRACE_001
#
# Decides the NEWEST_SLOT_KV_NOT_VISIBLE question from the production trace,
# and refuses to pass vacuously.
#
# Usage:
#   powershell -File tools/attn_visibility_analyze.ps1 -Trace <file.txt>
#
# The four invariants are evaluated per position AND in aggregate:
#   INV_WRITE_IS_NEWEST     kv_write_k == kv_pos_before
#   INV_READ_END_GE_WRITE   read_end >= kv_write_k
#   INV_CTX_EQ_WRITE_PLUS1  ctx_len == kv_write_k + 1
#   INV_MASK_END_GE_WRITE   mask_end >= kv_write_k
#
# A run is only meaningful if it actually observed positions. Frames with
# producers=0 are counted separately: they are the case where the instrument
# saw the position but no attention ran, which is a hole in the measurement,
# not a pass.
# ============================================================================
param(
    [Parameter(Mandatory = $true)][string]$Trace
)

if (-not (Test-Path -LiteralPath $Trace)) {
    Write-Output "TRACE_MISSING=1 FILE=$Trace"
    exit 2
}

$pos      = @()
$posLayer = @()

# Field names are case-SENSITIVE and the trace mixes cases on purpose:
# measurement fields (kv_write_k, ctx_len) are lower, invariants (INV_*) are
# upper, enums (phase, route, mask_impl) are lower. An earlier version of this
# parser matched only [A-Z0-9_]+ and therefore silently read producers=0 for
# every frame -- reporting an invariant violation for a run in which all four
# invariants held. The parser must see the same vocabulary the emitter wrote.
$fieldRx = '([A-Za-z0-9_]+)=([^\s]+)'

foreach ($line in [System.IO.File]::ReadAllLines($Trace)) {
    if ($line.StartsWith('POSLAYER step=')) {
        $h = @{}
        foreach ($m in [regex]::Matches($line, $fieldRx)) { $h[$m.Groups[1].Value] = $m.Groups[2].Value }
        $posLayer += [pscustomobject]$h
    } elseif ($line.StartsWith('POS step=')) {
        $h = @{}
        foreach ($m in [regex]::Matches($line, $fieldRx)) { $h[$m.Groups[1].Value] = $m.Groups[2].Value }
        $pos += [pscustomobject]$h
    }
}

# A field the parser failed to see must be an error, not a zero. Without this
# check a broken parser reports a clean-looking run full of zeros.
$missing = 0
foreach ($p in $pos) {
    foreach ($k in @('producers','kv_write_k','ctx_len','read_end','mask_end','kv_len_after','INV_CTX_EQ_WRITE_PLUS1')) {
        if (-not $p.PSObject.Properties.Name.Contains($k)) { $missing++ }
    }
}
if ($missing -gt 0) {
    Write-Output "PARSER_MISSING_FIELDS=$missing"
    Write-Output "VERDICT=ANALYZER_DEFECT_NOT_A_MEASUREMENT"
    exit 4
}

$frames   = $pos.Count
$observed = @($pos | Where-Object { [int]$_.producers -gt 0 }).Count
$empty    = @($pos | Where-Object { [int]$_.producers -eq 0 }).Count

Write-Output "TRACE_FILE=$Trace"
Write-Output "FRAMES=$frames"
Write-Output "FRAMES_WITH_ATTENTION=$observed"
Write-Output "FRAMES_WITHOUT_ATTENTION=$empty"
Write-Output "POSLAYER_RECORDS=$($posLayer.Count)"

if ($frames -eq 0) {
    Write-Output "VERDICT=NO_FRAMES_MEASURED"
    Write-Output "NOTE=an instrument that observed nothing cannot certify anything"
    exit 3
}

$failWrite = @($pos | Where-Object { [int]$_.producers -gt 0 -and [int]$_.INV_WRITE_IS_NEWEST -ne 1 })
$failRead  = @($pos | Where-Object { [int]$_.producers -gt 0 -and [int]$_.INV_READ_END_GE_WRITE -ne 1 })
$failCtx   = @($pos | Where-Object { [int]$_.producers -gt 0 -and [int]$_.INV_CTX_EQ_WRITE_PLUS1 -ne 1 })
$failMask  = @($pos | Where-Object { [int]$_.producers -gt 0 -and [int]$_.INV_MASK_END_GE_WRITE -ne 1 })
$failLayer = @($pos | Where-Object { [int]$_.producers -gt 0 -and [int]$_.ALL_LAYERS_AGREE -ne 1 })
$failPos   = @($pos | Where-Object { [int]$_.producers -gt 0 -and [int]$_.INV_POS_MATCHES_FRAME -ne 1 })

Write-Output "INV_WRITE_IS_NEWEST_VIOLATIONS=$($failWrite.Count)"
Write-Output "INV_READ_END_GE_WRITE_VIOLATIONS=$($failRead.Count)"
Write-Output "INV_CTX_EQ_WRITE_PLUS1_VIOLATIONS=$($failCtx.Count)"
Write-Output "INV_MASK_END_GE_WRITE_VIOLATIONS=$($failMask.Count)"
Write-Output "ALL_LAYERS_AGREE_VIOLATIONS=$($failLayer.Count)"
Write-Output "INV_POS_MATCHES_FRAME_VIOLATIONS=$($failPos.Count)"

Write-Output ""
Write-Output "--- per position (newest-slot visibility) ---"
Write-Output ("{0,-5} {1,-9} {2,-6} {3,-6} {4,-6} {5,-6} {6,-6} {7,-8} {8,-8} {9,-9} {10}" -f `
    'STEP','PHASE','WRITE','CTX','READEND','MASKEND','PAST','KVLEN_B','KVLEN_A','TOP1','HASH')
foreach ($p in $pos) {
    Write-Output ("{0,-5} {1,-9} {2,-6} {3,-6} {4,-6} {5,-6} {6,-6} {7,-8} {8,-8} {9,-9} {10}" -f `
        $p.step, $p.phase, $p.kv_write_k, $p.ctx_len, $p.read_end, $p.mask_end, $p.past,
        $p.kv_len_before, $p.kv_len_after, $p.top1, $p.logits_hash)
}

# The position that produced the FIRST generated token is the last prefill
# position: in generate() the first sampled token's logits come from the final
# prefill forward, not from a decode step. That is the position where a
# one-slot-lag defect would first be visible, so it is called out separately.
$lastPrefill = $pos | Where-Object { $_.phase -eq 'prefill' -and [int]$_.producers -gt 0 } | Select-Object -Last 1
if ($lastPrefill) {
    Write-Output ""
    Write-Output "--- first generated token position (last prefill) ---"
    Write-Output "STEP=$($lastPrefill.step)"
    Write-Output "KV_POS_BEFORE=$($lastPrefill.kv_pos_before)"
    Write-Output "KV_WRITE_INDEX_K=$($lastPrefill.kv_write_k)"
    Write-Output "KV_WRITE_INDEX_V=$($lastPrefill.kv_write_v)"
    Write-Output "KV_HIGHEST_VALID_INDEX=$($lastPrefill.kv_highest_valid)"
    Write-Output "ATTENTION_READ_BEGIN=$($lastPrefill.read_begin)"
    Write-Output "ATTENTION_READ_END=$($lastPrefill.read_end)"
    Write-Output "ATTENTION_CONTEXT_LENGTH=$($lastPrefill.ctx_len)"
    Write-Output "MASK_VISIBLE_BEGIN=$($lastPrefill.mask_begin)"
    Write-Output "MASK_VISIBLE_END=$($lastPrefill.mask_end)"
    Write-Output "PAST_TOKEN_COUNT=$($lastPrefill.past)"
    Write-Output "CURRENT_TOKEN_ID=$($lastPrefill.token)"
    Write-Output "TOP1_TOKEN_ID=$($lastPrefill.top1)"
    Write-Output "LOGITS_HASH=$($lastPrefill.logits_hash)"
    $newestVisible = ([int]$lastPrefill.read_end -ge [int]$lastPrefill.kv_write_k) -and `
                     ([int]$lastPrefill.ctx_len -eq [int]$lastPrefill.kv_write_k + 1)
    Write-Output "NEWEST_SLOT_VISIBLE=$([int]$newestVisible)"
}

# KV length bookkeeping: after N prefill positions currentLength() must be N.
# A one-slot lag here is what the earlier DecodeCursor harness reported; on the
# production path it must NOT appear, because the write happens at
# currentLength() and advance() then increments past it.
$prefillFrames = @($pos | Where-Object { $_.phase -eq 'prefill' -and [int]$_.producers -gt 0 })
if ($prefillFrames.Count -gt 0) {
    $lastPf = $prefillFrames | Select-Object -Last 1
    $expect = [int]$lastPf.kv_write_k + 1
    $actual = [int]$lastPf.kv_len_after
    Write-Output ""
    Write-Output "PREFILL_FRAMES=$($prefillFrames.Count)"
    Write-Output "KV_LEN_AFTER_FINAL_PREFILL=$actual"
    Write-Output "KV_LEN_EXPECTED_AFTER_FINAL_PREFILL=$expect"
    Write-Output "PREFILL_KV_LEN_CORRECT=$([int]($actual -eq $expect))"
}

$clean = ($failWrite.Count -eq 0) -and ($failRead.Count -eq 0) -and
         ($failCtx.Count -eq 0)  -and ($failMask.Count -eq 0) -and
         ($failLayer.Count -eq 0) -and ($failPos.Count -eq 0) -and
         ($empty -eq 0) -and ($observed -gt 0)

Write-Output ""
if ($clean) {
    Write-Output "VERDICT=NEWEST_SLOT_VISIBLE_AT_EVERY_MEASURED_POSITION"
    Write-Output "CONSEQUENCE=the NEWEST_SLOT_KV_NOT_VISIBLE hypothesis is FALSIFIED for this route;"
    Write-Output "            a near-frozen argmax with an advancing, fully visible KV cache is not a"
    Write-Output "            state-visibility defect and must be explained further upstream or downstream."
} else {
    Write-Output "VERDICT=INVARIANT_VIOLATION"
}
exit 0

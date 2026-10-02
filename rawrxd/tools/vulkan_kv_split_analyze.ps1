# ============================================================================
# vulkan_kv_split_analyze.ps1
#   RAWRXD_VULKAN_KV_SPLIT_001
#
# Joins the GPU K/V split capture against the CPU parity probe and applies the
# discriminator:
#
#   PROJECTED cpu~=gpu  AND  CACHE_WRITTEN == PROJECTED  AND  READBACK == WRITTEN
#       -> the Vulkan KV write, storage and read-back are all exonerated.
#          The defect is NOT in the K/V cache and must be looked for after it.
#
#   PROJECTED match, CACHE_WRITTEN differ -> Vulkan KV write/storage defect
#   CACHE_WRITTEN match, READBACK differ  -> cache addressing / layout / read
#   K/V correct, FINAL_NORM differ        -> post-transformer norm defect
#   FINAL_NORM match, LOGITS differ       -> lm_head / quant GEMV / layout
#
# Both sides are FNV-1a over the full kvDim span, so the two kinds of
# comparison are distinguished deliberately:
#
#   HASH equality  is the STRONG claim (bit-identical). It is expected to hold
#                  for GPU-internal transitions (PROJECTED -> CACHE_WRITTEN ->
#                  READBACK), which must be copies, and is NOT expected to hold
#                  against the CPU, where a different summation order in the
#                  quantised GEMV changes the last bits.
#   L2 relative    is the WEAK claim and is only used to say "agrees to float32
#                  rounding" when the hash differs. A small L2 gap with a
#                  different hash is NOT reported as a match.
#
# Usage:
#   powershell -File tools/vulkan_kv_split_analyze.ps1 -CpuFile <probe.txt> -GpuFile <kvsplit.txt>
# ============================================================================
param(
    [Parameter(Mandatory = $true)][string]$CpuFile,
    [Parameter(Mandatory = $true)][string]$GpuFile,
    [int]$MaxLayer = 4096
)

# NOTE ON NAMING: the parse is inlined rather than factored into a helper
# function. An earlier version took the GPU path as a parameter called `-Gpu`
# and stored the parsed records in `$gpu`; PowerShell variable names are
# case-insensitive, so the two were the SAME variable and the run reported
# GPU_SPLIT_RECORDS=1 for a 278-record file and then printed an empty table and
# a confident VERDICT. A helper that shares a name with one of its arguments is
# not a style question when it can silently replace the argument.
$fieldRx = '([A-Za-z0-9_]+)=([^\s]+)'

function Read-Fields([string]$path) {
    $rows = @()
    foreach ($line in [System.IO.File]::ReadAllLines($path)) {
        if (-not $line.StartsWith('STEP=')) { continue }
        $h = @{}
        foreach ($m in [regex]::Matches($line, $fieldRx)) {
            $h[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        $rows += [pscustomobject]$h
    }
    return ,$rows
}

$cpuRows = Read-Fields $CpuFile
$gpuRows = Read-Fields $GpuFile

$cpuKv = @($cpuRows | Where-Object { $_.CP -eq 'KV_WRITE' })

Write-Output "CPU_PROBE_RECORDS=$($cpuRows.Count)"
Write-Output "CPU_KV_WRITE_RECORDS=$($cpuKv.Count)"
Write-Output "GPU_SPLIT_RECORDS=$($gpuRows.Count)"

if ($cpuKv.Count -eq 0) { Write-Output "CPU_PROBE_EMPTY=1 FILE=$CpuFile"; exit 3 }
if ($gpuRows.Count -eq 0) { Write-Output "GPU_SPLIT_EMPTY=1 FILE=$GpuFile"; exit 3 }

# A parse that cannot see the fields the emitter wrote is a broken instrument,
# not a finding. Fail loudly rather than compare empty strings.
#
# The required set is per-stage, because the stages genuinely declare different
# fields: K_SLOT0_SURVIVAL carries HASH, WRITTEN_AT_POS, HASH_AT_WRITE and MATCH
# but no L2, and demanding L2 of it produced PARSER_MISSING_FIELDS=38 -- which
# is the guard working, on an assumption I had not checked against the emitter.
$alwaysRequired = @('STAGE','TENSOR','LAYER','POS')
$missing = 0
foreach ($r in $gpuRows) {
    foreach ($k in $alwaysRequired) {
        if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ }
    }
    switch ($r.STAGE) {
        'K_PROJECTED'      { foreach ($k in @('HASH','L2')) { if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ } } }
        'V_PROJECTED'      { foreach ($k in @('HASH','L2')) { if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ } } }
        'K_CACHE_WRITTEN'  { foreach ($k in @('HASH','L2')) { if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ } } }
        'V_CACHE_WRITTEN'  { foreach ($k in @('HASH','L2')) { if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ } } }
        'K_CACHE_READBACK' { foreach ($k in @('HASH','L2')) { if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ } } }
        'V_CACHE_READBACK' { foreach ($k in @('HASH','L2')) { if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ } } }
        'K_SLOT0_SURVIVAL' { foreach ($k in @('HASH','HASH_AT_WRITE','MATCH')) { if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ } } }
        default            { $missing++ }
    }
}
if ($missing -gt 0) {
    Write-Output "PARSER_MISSING_FIELDS=$missing"
    Write-Output "VERDICT=ANALYZER_DEFECT_NOT_A_MEASUREMENT"
    exit 4
}

$gpuLayerIds = @($gpuRows | ForEach-Object { [int]$_.LAYER } | Sort-Object -Unique |
                 Where-Object { $_ -lt $MaxLayer })
Write-Output "GPU_LAYERS=$($gpuLayerIds -join ',')"
Write-Output "GPU_STAGES=$(($gpuRows | ForEach-Object { $_.STAGE } | Sort-Object -Unique) -join ',')"
Write-Output "GPU_POSITIONS=$(($gpuRows | ForEach-Object { [int]$_.POS } | Sort-Object -Unique) -join ',')"

# ---- GPU-internal transitions: copies, so they must be BIT-IDENTICAL -------
$projByKey = @{}
$writeByKey = @{}
$readByKey = @{}
foreach ($g in $gpuRows) {
    $key = "$($g.POS)|$($g.LAYER)|$($g.TENSOR)"
    switch ($g.STAGE) {
        'K_PROJECTED'        { $projByKey[$key] = $g }
        'V_PROJECTED'        { $projByKey[$key] = $g }
        'K_CACHE_WRITTEN'    { $writeByKey[$key] = $g }
        'V_CACHE_WRITTEN'    { $writeByKey[$key] = $g }
        'K_CACHE_READBACK'   { $readByKey[$key]  = $g }
        'V_CACHE_READBACK'   { $readByKey[$key]  = $g }
    }
}

$writeCompared = 0; $writeMismatch = 0; $writeUnpaired = 0
foreach ($k in $writeByKey.Keys) {
    $p = $projByKey[$k]
    if (-not $p) { $writeUnpaired++; continue }
    if ($p.PROBE -ne 'OK' -or $writeByKey[$k].PROBE -ne 'OK') { $writeUnpaired++; continue }
    $writeCompared++
    if ($p.HASH -ne $writeByKey[$k].HASH) { $writeMismatch++ }
}
$readCompared = 0; $readMismatch = 0; $readUnpaired = 0
foreach ($k in $readByKey.Keys) {
    $w = $writeByKey[$k]
    if (-not $w -or $w.PROBE -ne 'OK' -or $readByKey[$k].PROBE -ne 'OK') { $readUnpaired++; continue }
    $readCompared++
    if ($w.HASH -ne $readByKey[$k].HASH) { $readMismatch++ }
}
Write-Output ""
Write-Output "PROJECTED_VS_CACHE_WRITTEN_COMPARED=$writeCompared HASH_MISMATCH=$writeMismatch UNPAIRED=$writeUnpaired"
Write-Output "CACHE_WRITTEN_VS_READBACK_COMPARED=$readCompared HASH_MISMATCH=$readMismatch UNPAIRED=$readUnpaired"

$surv = @($gpuRows | Where-Object { $_.STAGE -eq 'K_SLOT0_SURVIVAL' })
$survBad = @($surv | Where-Object { $_.MATCH -ne '1' })
Write-Output "SLOT0_SURVIVAL_CHECKS=$($surv.Count) MISMATCH=$($survBad.Count)"

# ---- CPU vs GPU ------------------------------------------------------------
$cpuByKey = @{}
foreach ($c in $cpuKv) {
    $cpuByKey["$($c.STEP)|$($c.LAYER)|K"] = $c
    $cpuByKey["$($c.STEP)|$($c.LAYER)|V"] = $c
}

$rows = @()
foreach ($g in $gpuRows) {
    if ($g.STAGE -ne 'K_CACHE_WRITTEN' -and $g.STAGE -ne 'V_CACHE_WRITTEN') { continue }
    $L = [int]$g.LAYER
    if ($gpuLayerIds -notcontains $L) { continue }
    $c = $cpuByKey["$($g.POS)|$($L)|$($g.TENSOR)"]
    if (-not $c) { continue }
    $cpuL2  = if ($g.TENSOR -eq 'K') { [double]$c.K_L2 } else { [double]$c.V_L2 }
    $cpuHash = if ($g.TENSOR -eq 'K') { $c.K_HASH } else { $c.V_HASH }
    $gpuL2  = [double]$g.L2
    $rel    = if ($cpuL2 -ne 0) { [math]::Abs($gpuL2 - $cpuL2) / $cpuL2 } else { 0.0 }
    $rows += [pscustomobject]@{
        STEP = [int]$g.POS; LAYER = $L; T = $g.TENSOR
        CPU_L2 = $cpuL2; GPU_L2 = $gpuL2; REL = $rel
        HASH_EQ = if ($cpuHash -eq $g.HASH) { 1 } else { 0 }
    }
}

Write-Output ""
Write-Output ("{0,-5} {1,-6} {2,-3} {3,-18} {4,-18} {5,-12} {6}" -f 'STEP','LAYER','T','CPU_L2','GPU_L2','REL_DIFF','HASH_EQ')
foreach ($r in $rows) {
    Write-Output ("{0,-5} {1,-6} {2,-3} {3,-18} {4,-18} {5,-12} {6}" -f `
        $r.STEP, $r.LAYER, $r.T, $r.CPU_L2, $r.GPU_L2, $r.REL, $r.HASH_EQ)
}

$worst = 0.0
if ($rows.Count -gt 0) { $worst = ($rows | Measure-Object -Property REL -Maximum).Maximum }
$bitEq = @($rows | Where-Object { $_.HASH_EQ -eq 1 }).Count
Write-Output ""
Write-Output "CPU_GPU_COMPARISONS=$($rows.Count)"
Write-Output "WORST_REL_L2_DIFF_CPU_VS_GPU_KV=$worst"
Write-Output "BIT_IDENTICAL_TO_CPU=$bitEq"

Write-Output ""
$projBitExact = ($writeCompared -gt 0 -and $writeMismatch -eq 0 -and $writeUnpaired -eq 0)
$survived    = ($readCompared -gt 0 -and $readMismatch -eq 0 -and $readUnpaired -eq 0)

if ($projBitExact -and $survived) {
    Write-Output "VERDICT=KV_WRITE_STORAGE_AND_READBACK_EXONERATED"
    Write-Output "NEXT=the divergence is NOT in the K/V cache; continue at FINAL_NORM then LOGITS."
} elseif (-not $projBitExact) {
    Write-Output "VERDICT=KV_WRITE_OR_STORAGE_DEFECT"
    Write-Output "EVIDENCE=PROJECTED and CACHE_WRITTEN differ on the same slot ($writeMismatch of $writeCompared, $writeUnpaired unpaired)"
} else {
    Write-Output "VERDICT=KV_READBACK_DEFECT"
    Write-Output "EVIDENCE=CACHE_WRITTEN does not survive read-back ($readMismatch of $readCompared, $readUnpaired unpaired)"
}
if ($rows.Count -gt 0 -and $worst -le 1e-5) {
    Write-Output "CPU_VS_GPU_KV=AGREES_TO_FLOAT32_ROUTING (worst relative L2 $worst)"
} else {
    Write-Output "CPU_VS_GPU_KV=DISAGREES_OR_UNMEASURED (worst relative L2 $worst over $($rows.Count) comparisons)"
}
exit 0

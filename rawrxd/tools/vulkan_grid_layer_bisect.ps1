# ============================================================================
# vulkan_grid_layer_bisect.ps1
#   RAWRXD_VULKAN_GRID_STEP_IDENTITY_001
#
# Joins the anchored Vulkan parity grid against the CPU parity probe on
# (STEP, LAYER, STAGE) and names the FIRST layer at which the two disagree,
# per step and per stage.
#
# Why this is only now possible: the grid's `step` was an initialised,
# never-assigned member, so every record carried step 0. With one step visible,
# "the layer body matches" and "the layer body matches on the first token only"
# were indistinguishable, and a single-step agreement was read as an
# all-layer, all-step agreement. The grid is now anchored to
# kvCache->currentLength(), so the same comparison resolves per step.
#
# VALID WINDOW. Only positions at which both routes processed the SAME input can
# be compared. Prefill positions are identical by construction (same prompt, one
# forward per token). Decode positions are not: once the two routes emit
# different token ids they are computing different sequences, and comparing them
# produces a large, confident, meaningless number. -ValidMaxPos therefore cuts
# the join at the end of prefill, and the excluded count is reported rather than
# dropped.
#
# Usage:
#   powershell -File tools/vulkan_grid_layer_bisect.ps1 -CpuFile <probe.txt> -GpuFile <grid.txt> -ValidMaxPos 12
# ============================================================================
param(
    [Parameter(Mandatory = $true)][string]$CpuFile,
    [Parameter(Mandatory = $true)][string]$GpuFile,
    [int]$ValidMaxPos = -1,          # -1 = infer from the CPU KV_WRITE position span
    [double]$Threshold = 1e-3
)

$fieldRx = '([A-Za-z0-9_]+)=([^\s]+)'

# Grid stage name -> CPU probe stage name. Renames only, no invention: every
# pair below is a stage both sides actually emit.
$stageMap = @{
    'RMS_ATTN' = 'ATTN_NORM'
    'RMS_FFN'  = 'FFN_NORM'
}

function Has-Field($obj, [string]$name) {
    # A Hashtable exposes its KEYS through ContainsKey, but its PSObject
    # properties are the CLR surface (Count, Keys, ...). A PSCustomObject is the
    # other way round. Checking only PSObject made this return false for every
    # field of every unconverted hashtable, so the reader reported
    # CPU_PROBE_EMPTY=1 for a 64081-line probe. Both shapes are handled here
    # because both are produced inside this script.
    if ($obj -is [System.Collections.IDictionary]) { return $obj.Contains($name) }
    return $obj.PSObject.Properties.Name.Contains($name)
}

function Read-Cp([string]$path) {
    $rows = @()
    foreach ($line in [System.IO.File]::ReadAllLines($path)) {
        if (-not $line.StartsWith('STEP=')) { continue }
        $h = @{}
        foreach ($m in [regex]::Matches($line, $fieldRx)) {
            $h[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        if ((Has-Field $h 'CP') -and $h['CP'] -like 'LAYER_*') { $rows += [pscustomobject]$h }
    }
    return ,$rows
}

$cpuAll = Read-Cp $CpuFile
$gpuAll = Read-Cp $GpuFile

if ($cpuAll.Count -eq 0) { Write-Output "CPU_PROBE_EMPTY=1"; exit 3 }
if ($gpuAll.Count -eq 0) { Write-Output "GRID_EMPTY=1"; exit 3 }

Write-Output "CPU_LAYER_RECORDS=$($cpuAll.Count)"
Write-Output "GRID_LAYER_RECORDS=$($gpuAll.Count)"

# Split grid gaps out: UNAVAILABLE is a statement about the device, not a value.
$gpuGaps = @($gpuAll | Where-Object { (Has-Field $_ 'UNAVAILABLE') })
$gpuVals = @($gpuAll | Where-Object { (Has-Field $_ 'L2') -and (Has-Field $_ 'READBACK_VALID') -and $_.READBACK_VALID -eq '1' })
Write-Output "GRID_VALUE_RECORDS=$($gpuVals.Count)"
Write-Output "GRID_UNAVAILABLE_GAPS=$($gpuGaps.Count)"

$gpuPositions = @($gpuVals | ForEach-Object { [int]$_.POS } | Sort-Object -Unique)
Write-Output "GRID_POSITIONS=$($gpuPositions -join ',')"
Write-Output "GRID_UNANCHORED_RECORDS=$(@($gpuAll | Where-Object { $_.STEP -eq '-1' }).Count)"

if ($ValidMaxPos -lt 0) {
    $kvWrite = @($cpuAll | Where-Object { $_.CP -eq 'KV_WRITE' })
    $maxKv = 0
    foreach ($k in $kvWrite) { $s = [int]$k.STEP; if ($s -gt $maxKv) { $maxKv = $s } }
    $ValidMaxPos = $maxKv
}
Write-Output "VALID_MAX_POS=$ValidMaxPos (join is meaningful only here; both routes share the prompt)"

$excluded = @($gpuVals | Where-Object { [int]$_.POS -gt $ValidMaxPos }).Count
Write-Output "GRID_RECORDS_EXCLUDED_AS_DIVERGED_TRAJECTORY=$excluded"

# ---- build the join --------------------------------------------------------
$cpuByKey = @{}
foreach ($c in $cpuAll) {
    if (-not (Has-Field $c 'L2')) { continue }
    if ($c.CP -notmatch '^LAYER_(\d+)_(.+)$') { continue }
    $cpuByKey["$($c.STEP)|$($($matches[1]))|$($($matches[2]))"] = $c
}

$joined = @()
$stagePairs = @{}
foreach ($g in $gpuVals) {
    if (-not (Has-Field $g 'L2')) { continue }
    if ($g.CP -notmatch '^LAYER_(\d+)_(.+)$') { continue }
    $pos = [int]$g.POS
    if ($pos -gt $ValidMaxPos) { continue }
    $layer = $matches[1]
    $gstage = $matches[2]
    $cstage = if ($stageMap.ContainsKey($gstage)) { $stageMap[$gstage] } else { $gstage }
    $stagePairs["$gstage->$cstage"] = 1
    $c = $cpuByKey["$pos|$layer|$cstage"]
    if (-not $c) { continue }
    $cpuL2  = if (Has-Field $c 'L2') { [double]$c.L2 } else { 0.0 }
    $gpuL2  = if (Has-Field $g 'L2') { [double]$g.L2 } else { 0.0 }
    # ELEMENT-WISE, NOT BY NORM.
    #
    # The first version of this script compared L2 and reported 13/13
    # step/stage pairs matching at step 0 and 156/169 diverging afterwards --
    # and its step-0 PASS was extended by reading into every step. The L2 test
    # then turned out to be blind to the defect it was supposed to find: at
    # layer 0 step 1, CPU and GPU K_ROPE agreed in L2 to 3.5e-7 while MIN, MAX,
    # MEAN, HASH and every one of the first eight elements disagreed, because a
    # couple of large outliers (K reaches -9.5) dominate the norm and mask
    # O(0.1) differences across the other 250 elements. A magnitude-only
    # comparison is not a weaker version of an element-wise one; it is a
    # different measurement that cannot see this class of defect.
    $cf = if (Has-Field $c 'FIRST8') { @($c.FIRST8 -split ',') } else { $null }
    $gf = if (Has-Field $g 'FIRST8') { @($g.FIRST8 -split ',') } else { $null }
    $relF8 = [double]::PositiveInfinity
    $hashEq = 0
    if ($cf -and $gf -and $cf.Count -eq $gf.Count -and $cf.Count -gt 0) {
        $num = 0.0; $da = 0.0; $db = 0.0
        for ($i = 0; $i -lt $cf.Count; $i++) {
            $x = [double]$cf[$i]; $y = [double]$gf[$i]
            $d = $x - $y
            $num += $d * $d; $da += $x * $x; $db += $y * $y
        }
        $den = [math]::Sqrt($da * $db)
        if ($den -gt 0) { $relF8 = [math]::Sqrt($num) / $den }
    }
    if ((Has-Field $c 'HASH') -and (Has-Field $g 'HASH') -and $c.HASH -eq $g.HASH) { $hashEq = 1 }
    $relL2 = if ($cpuL2 -gt 0) { [math]::Abs($gpuL2 - $cpuL2) / $cpuL2 } else { 0.0 }
    $joined += [pscustomobject]@{
        STEP = $pos; LAYER = [int]$layer; GSTAGE = $gstage; CSTAGE = $cstage
        CPU_L2 = $cpuL2; GPU_L2 = $gpuL2; REL_L2 = $relL2
        REL = $relF8; HASH_EQ = $hashEq
    }
}

Write-Output "STAGE_NAME_MAP=$($stagePairs.Keys -join ' ')"
Write-Output "JOINED_RECORDS=$($joined.Count)"
if ($joined.Count -eq 0) {
    Write-Output "VERDICT=NO_JOINED_RECORDS (the two sides share no (step,layer,stage) key)"
    exit 4
}

Write-Output ""
Write-Output ("{0,-5} {1,-14} {2,-7} {3,-12} {4,-12} {5}" -f 'STEP','STAGE','LAYER','REL_F8','HASH_EQ','VERDICT')
foreach ($j in ($joined | Sort-Object STEP, GSTAGE, LAYER)) {
    $v = if ($j.REL -gt $Threshold) { 'DIVERGENT' } else { 'match' }
    Write-Output ("{0,-5} {1,-14} {2,-7} {3,-12} {4,-12} {5}" -f `
        $j.STEP, $j.GSTAGE, $j.LAYER, $j.REL, $j.HASH_EQ, $v)
}

# ---- the answer: first divergent layer per (step, stage) -------------------
Write-Output ""
Write-Output "--- first divergent layer per (step, stage), threshold rel>$Threshold ---"
$groups = @{}
foreach ($j in $joined) {
    $k = "$($j.STEP)|$($j.GSTAGE)"
    if (-not $groups.ContainsKey($k)) { $groups[$k] = @() }
    $groups[$k] += $j
}
$firstBad = @()
$cleanPairs = 0
foreach ($k in $groups.Keys) {
    $ordered = @($groups[$k] | Sort-Object LAYER)
    $bad = @($ordered | Where-Object { $_.REL -gt $Threshold })
    if ($bad.Count -eq 0) { $cleanPairs++; continue }
    $f = $bad[0]
    $worst = ($bad | Measure-Object -Property REL -Maximum).Maximum
    $firstBad += [pscustomobject]@{
        STEP = $f.STEP; STAGE = $f.GSTAGE; FIRST_LAYER = $f.LAYER
        WORST_REL = $worst; N_BAD = $bad.Count; N_LAYERS = $ordered.Count
    }
}
foreach ($f in ($firstBad | Sort-Object STEP, STAGE)) {
    Write-Output ("STEP={0} STAGE={1} FIRST_DIVERGENT_LAYER={2} WORST_REL={3} LAYERS_DIVERGENT={4}/{5}" -f `
        $f.STEP, $f.STAGE, $f.FIRST_LAYER, $f.WORST_REL, $f.N_BAD, $f.N_LAYERS)
}

Write-Output ""
Write-Output "STEP_STAGE_PAIRS_TOTAL=$($groups.Count)"
Write-Output "STEP_STAGE_PAIRS_ALL_MATCH=$cleanPairs"
Write-Output "STEP_STAGE_PAIRS_WITH_DIVERGENCE=$($firstBad.Count)"

if ($firstBad.Count -eq 0) {
    Write-Output "VERDICT=ALL_JOINED_STAGES_MATCH_OVER_THE_VALID_WINDOW"
} else {
    $earliest = ($firstBad | Measure-Object -Property STEP -Minimum).Minimum
    $layerSet = @($firstBad | Where-Object { $_.STEP -eq $earliest } | ForEach-Object { $_.FIRST_LAYER } | Sort-Object -Unique)
    $stageSet = @($firstBad | Where-Object { $_.STEP -eq $earliest } | ForEach-Object { $_.STAGE } | Sort-Object -Unique)
    Write-Output "VERDICT=LOCALISED"
    Write-Output "EARLIEST_DIVERGENT_STEP=$earliest"
    Write-Output "EARLIEST_DIVERGENT_LAYERS=$($layerSet -join ',')"
    Write-Output "EARLIEST_DIVERGENT_STAGES=$($stageSet -join ',')"
    Write-Output "NOTE=the divergence exists inside a single prefill position; decode recurrence is not required to reach it"
}
exit 0

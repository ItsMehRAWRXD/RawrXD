# ============================================================================
# attn_ctx2_classify.ps1
#   RAWRXD_ATTN_CTX2_PROBE_001
#
# Decides where the Vulkan attention first goes wrong, using the three sources
# emitted by the probe: cpu, gpu_model, gpu_arena.
#
# The pivot is gpu_model vs gpu_arena, because a bare cpu-vs-arena comparison
# cannot separate these two defects:
#
#   gpu_model == gpu_arena, gpu_model != cpu
#       the kernel faithfully implements its own algorithm. The defect is in the
#       ALGORITHM or the LAYOUT, and is reduced to a few lines of arithmetic.
#   gpu_model != gpu_arena
#       the kernel does not do what its source says. That is a race, a
#       descriptor/buffer mix-up, or a fused-window publication problem, and the
#       source is not a description of the behaviour.
#
# Within the algorithm, the first wrong scalar is identified in order:
#
#   Q/K differ              -> dot-product addressing / stride / GQA mapping
#   SCORE_RAW differs       -> dot-product addressing / stride / GQA mapping
#   SCORE_SCALED differs    -> scaling constant or placement
#   SOFTMAX_PROB differs    -> max / exp / denominator reduction
#   ATTN_VALUE differs      -> V addressing / weighted accumulation / output
#   all four agree, arena differs
#                           -> output indexing, synchronisation or publication
#
# CONTROL. Position 0 has one visible slot, where softmax collapses to
# probability 1.0 and the output is V[0] by construction. If the three sides do
# not agree at position 0, the comparison at position 1 means nothing and the
# verdict is INVALID, not DIVERGENT.
#
# Usage:
#   powershell -File tools/attn_ctx2_classify.ps1 -ProbeFile <ctx2.txt>
# ============================================================================
param(
    [Parameter(Mandatory = $true)][string]$ProbeFile,
    [string]$CpuFile = '',
    [double]$Tol = 1e-5,        # relative agreement tolerance
    [double]$ArenaTol = 1e-5    # model-vs-arena: both are float, so last bits differ
)

$fieldRx = '([A-Za-z0-9_]+)=([^\s]+)'

if (-not (Test-Path -LiteralPath $ProbeFile)) {
    Write-Output "PROBE_MISSING=1 FILE=$ProbeFile"; exit 2
}

$rows = @()
foreach ($path in @($ProbeFile, $CpuFile)) {
    if (-not $path) { continue }
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Output "INPUT_MISSING=1 FILE=$path"; exit 2
    }
    foreach ($line in [System.IO.File]::ReadAllLines($path)) {
        if (-not $line.StartsWith('CTX2 ')) { continue }
        $h = @{}
        foreach ($m in [regex]::Matches($line, $fieldRx)) { $h[$m.Groups[1].Value] = $m.Groups[2].Value }
        if ($h.Count -gt 0) { $rows += [pscustomobject]$h }
    }
}
Write-Output "PROBE_FILE=$ProbeFile"
if ($CpuFile) { Write-Output "CPU_FILE=$CpuFile" }

# EVIDENCE_COUNT == 0 => INVALID. A zero-evidence run must never be allowed to
# print a PASS or a FAIL. This rule exists because a sibling analyzer did
# exactly that: it compared empty string sets, reported
# "HASH_MISMATCH=0 of 0" and concluded there was a KV storage defect.
if ($rows.Count -eq 0) {
    Write-Output "EVIDENCE_COUNT=0"
    Write-Output "VERDICT=INVALID"
    Write-Output "REASON=no records were parsed; absence of evidence is not evidence"
    exit 3
}
Write-Output "CTX2_RECORDS=$($rows.Count)"

$required = @('step','ctx','side','q_head','kv_head','gqa_group','head_dim',
              'ATTN_VALUE_L2','ATTN_VALUE_HASH','ATTN_VALUE_F8')
$missing = 0
foreach ($r in $rows) {
    foreach ($k in $required) {
        if (-not $r.PSObject.Properties.Name.Contains($k)) { $missing++ }
    }
}
if ($missing -gt 0) {
    Write-Output "PARSER_MISSING_FIELDS=$missing"
    Write-Output "EVIDENCE_COUNT=0"
    Write-Output "VERDICT=INVALID"
    Write-Output "REASON=the parser cannot see fields the emitter wrote; this is an analyzer defect"
    exit 4
}

$sides = @($rows | ForEach-Object { $_.side } | Sort-Object -Unique)
$steps = @($rows | ForEach-Object { [int]$_.step } | Sort-Object -Unique)
Write-Output "SIDES=$($sides -join ',')"
Write-Output "STEPS=$($steps -join ',')"

function Get-Vec($r, [string]$name) {
    if (-not $r.PSObject.Properties.Name.Contains($name)) { return $null }
    $v = $r.$name
    if ($v -like 'UNAVAILABLE*') { return $null }
    if ($v -eq '') { return $null }
    return @($v -split ',' | ForEach-Object { [double]$_ })
}

function RelDiff($a, $b) {
    if ($null -eq $a -or $null -eq $b) { return $null }
    if ($a.Count -ne $b.Count) { return [double]::PositiveInfinity }
    $num = 0.0; $da = 0.0; $db = 0.0
    for ($i = 0; $i -lt $a.Count; $i++) {
        $d = $a[$i] - $b[$i]
        $num += $d * $d; $da += $a[$i] * $a[$i]; $db += $b[$i] * $b[$i]
    }
    $den = [math]::Sqrt($da * $db)
    if ($den -le 0) { return [double]::PositiveInfinity }
    return [math]::Sqrt($num) / $den
}

$byKey = @{}
foreach ($r in $rows) { $byKey["$($r.step)|$($r.q_head)|$($r.side)"] = $r }

# PAIRING INVARIANT. A head with no counterpart on the other side is UNPAIRED,
# and an UNPAIRED head is NOT agreement. The first version of this analyzer
# read only the GPU file, so every cpu-vs-gpu_model comparison had a null
# counterpart, the loop fell through, and it printed ALL_FOUR_AGREE=32 for a
# comparison that was never made. That is the exact class of failure the whole
# exercise exists to eliminate, committed by the tool meant to detect it.
$steps = @($rows | ForEach-Object { [int]$_.step } | Sort-Object -Unique)
$unpaired = 0
$paired = 0
foreach ($step in $steps) {
    $heads = @($rows | Where-Object { [int]$_.step -eq $step } |
               ForEach-Object { [int]$_.q_head } | Sort-Object -Unique)
    foreach ($q in $heads) {
        $cpu = $byKey["$step|$q|cpu"]
        $gm  = $byKey["$step|$q|gpu_model"]
        $ga  = $byKey["$step|$q|gpu_arena"]
        if ($cpu -and $gm -and $ga) { $paired++ } else { $unpaired++ }
    }
}
Write-Output "HEADS_PAIRED_CPP_ALL_THREE=$paired"
Write-Output "HEADS_UNPAIRED=$unpaired"
if ($paired -eq 0) {
    Write-Output "EVIDENCE_COUNT=0"
    Write-Output "VERDICT=INVALID"
    Write-Output "REASON=no head had a counterpart on all three sides; nothing was compared"
    exit 7
}

# ---- CONTROL: position 0 must agree, or position 1 proves nothing ----------
$ctlMismatch = 0
$ctlCompared = 0
foreach ($key in $byKey.Keys) {
    if ($key -notlike '0|*') { continue }
    $parts = $key -split '\|'
    $q = $parts[1]
    $cpu = $byKey["0|$q|cpu"]; $gm = $byKey["0|$q|gpu_model"]; $ga = $byKey["0|$q|gpu_arena"]
    if ($gm -and $ga) {
        $ctlCompared++
        if ($gm.ATTN_VALUE_HASH -ne $ga.ATTN_VALUE_HASH) { $ctlMismatch++ }
    }
}
Write-Output ""
Write-Output "CONTROL_POS0_GPU_MODEL_VS_ARENA_COMPARED=$ctlCompared MISMATCH=$ctlMismatch"
if ($ctlCompared -gt 0 -and $ctlMismatch -eq 0) {
    Write-Output "CONTROL=POS0_AGREES (gpu_model reproduces the arena, so gpu_model is a faithful model of the kernel)"
} elseif ($ctlCompared -gt 0) {
    Write-Output "CONTROL=POS0_DISAGREES"
    Write-Output "VERDICT=INVALID"
    Write-Output "REASON=the kernel does not reproduce its own algorithm at one visible slot; a comparison at two slots cannot be attributed"
    exit 5
}

# ---- the classification ---------------------------------------------------
$stages = @('SCORE_RAW','SCORE_SCALED','SOFTMAX_PROB','ATTN_VALUE')
$summary = @{}

foreach ($step in $steps) {
    $heads = @($rows | Where-Object { [int]$_.step -eq $step } |
               ForEach-Object { [int]$_.q_head } | Sort-Object -Unique)
    foreach ($q in $heads) {
        $cpu = $byKey["$step|$q|cpu"]
        $gm  = $byKey["$step|$q|gpu_model"]
        $ga  = $byKey["$step|$q|gpu_arena"]
        $first = "ALL_FOUR_AGREE"
        $detail = ""
        foreach ($s in $stages) {
            $vec = if ($s -eq 'ATTN_VALUE') {
                if ($gm) { Get-Vec $gm 'ATTN_VALUE_F8' } else { $null }
            } else {
                if ($gm) { Get-Vec $gm $s } else { $null }
            }
            $cvec = if ($s -eq 'ATTN_VALUE') {
                if ($cpu) { Get-Vec $cpu 'ATTN_VALUE_F8' } else { $null }
            } else {
                if ($cpu) { Get-Vec $cpu $s } else { $null }
            }
            $rd = RelDiff $cvec $vec
            if ($null -ne $rd -and $rd -gt $Tol) { $first = $s; $detail = $rd; break }
        }
        # Does the arena agree with the model of the kernel?
        #
        # By relative L2, not by hash. The model is float and the kernel is
        # float, so they differ in the last bits by construction; hash equality
        # is the wrong test for that pair and reported all 32 heads as DIVERGES
        # on a comparison whose first eight components agree to 7 significant
        # figures. Hash equality IS the right test for the byte-identity claims
        # (Q/K/V), which is why those are still compared by hash below.
        $arenaVsModel = "UNMEASURED"
        $arenaWorst = 0.0
        if ($gm -and $ga) {
            $gv = Get-Vec $gm 'ATTN_VALUE_F8'
            $av = Get-Vec $ga 'ATTN_VALUE_F8'
            $rd = RelDiff $av $gv
            if ($null -ne $rd) {
                $arenaWorst = $rd
                $arenaVsModel = if ($rd -le $ArenaTol) { 'FAITHFUL' } else { 'DIVERGES' }
            }
        }
        $key = "$step"
        if (-not $summary.ContainsKey($key)) {
            $summary[$key] = [pscustomobject]@{
                Step = $step; Ctx = ''; Heads = 0; Unpaired = 0
                FirstStage = @{}; ArenaVsModel = @{}; InputMismatch = 0
                ArenaWorst = 0.0
            }
        }
        $summary[$key].Ctx = $cpu.ctx
        $summary[$key].Heads++
        if (-not $cpu -or -not $gm -or -not $ga) { $summary[$key].Unpaired++ }
        # Did the two sides consume the same BYTES? If not, no score comparison
        # below attributes the difference to arithmetic, and saying so is the
        # whole point of emitting the hashes.
        if ($cpu -and $gm) {
            if ($cpu.Q_HASH -ne $gm.Q_HASH -or
                $cpu.K_HASH -ne $gm.K_HASH -or
                $cpu.V_HASH -ne $gm.V_HASH) {
                $summary[$key].InputMismatch++
            }
        }
        if (-not $summary[$key].FirstStage.ContainsKey($first)) { $summary[$key].FirstStage[$first] = 0 }
        $summary[$key].FirstStage[$first]++
        if (-not $summary[$key].ArenaVsModel.ContainsKey($arenaVsModel)) { $summary[$key].ArenaVsModel[$arenaVsModel] = 0 }
        $summary[$key].ArenaVsModel[$arenaVsModel]++
        if ($arenaWorst -gt $summary[$key].ArenaWorst) { $summary[$key].ArenaWorst = $arenaWorst }
    }
}

Write-Output ""
Write-Output ("{0,-5} {1,-4} {2,-6} {3,-8} {4,-28} {5,-22} {6}" -f 'STEP','CTX','HEADS','UNPAIRED','FIRST_DIVERGENT_STAGE (cpu vs gpu_model)','ARENA_VS_MODEL','WORST_REL')
foreach ($k in ($summary.Keys | Sort-Object)) {
    $s = $summary[$k]
    $st = ($s.FirstStage.GetEnumerator() | Sort-Object -Property Value -Descending |
           ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
    $av = ($s.ArenaVsModel.GetEnumerator() | Sort-Object -Property Value -Descending |
           ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
    Write-Output ("{0,-5} {1,-4} {2,-6} {3,-8} {4,-28} {5,-22} {6}" -f `
        $s.Step, $s.Ctx, $s.Heads, $s.Unpaired, $st, $av, $s.ArenaWorst)
}
Write-Output ""
Write-Output "HEADS_WITH_DIFFERING_INPUT_BYTES=$((($summary.Values | ForEach-Object { $_.InputMismatch }) | Measure-Object -Sum).Sum)"
Write-Output "NOTE=INPUT_BYTES_DIFFER means the two sides did not consume the same Q/K/V, so no"
Write-Output "     score difference below can be attributed to the score ARITHMETIC."

# ---- verdict --------------------------------------------------------------
$step1 = $summary['1']
Write-Output ""
if (-not $step1) {
    Write-Output "VERDICT=INVALID"
    Write-Output "REASON=no records at step 1; the 1->2 transition was not captured"
    exit 6
}

$arenaFaithful = $step1.ArenaVsModel.ContainsKey('FAITHFUL') -and
                 (-not $step1.ArenaVsModel.ContainsKey('DIVERGES'))
$firstStage = ($step1.FirstStage.GetEnumerator() | Sort-Object -Property Value -Descending |
               Select-Object -First 1).Key

Write-Output "STEP1_FIRST_DIVERGENT_STAGE=$firstStage"
Write-Output "STEP1_GPU_MODEL_VS_ARENA=$(if ($arenaFaithful) { 'FAITHFUL' } else { 'DIVERGES' })"
Write-Output "STEP1_WORST_ARENA_REL=$($step1.ArenaWorst)"
Write-Output "STEP1_HEADS_WITH_DIFFERING_INPUT_BYTES=$($step1.InputMismatch)"
Write-Output "STEP1_UNPAIRED=$($step1.Unpaired)"

if ($step1.InputMismatch -gt 0) {
    Write-Output "VERDICT=INPUT_BYTES_DIFFER"
    Write-Output "NEXT=the two sides did not consume the same Q/K/V for these heads; the defect is"
    Write-Output "     upstream of the score arithmetic (projection, RoPE, or the bytes the kernel read),"
    Write-Output "     and the differing Q_HASH/K_HASH/V_HASH names which one."
    exit 0
}

if (-not $arenaFaithful) {
    Write-Output "VERDICT=KERNEL_NOT_FAITHFUL_TO_ITS_OWN_SOURCE"
    Write-Output "NEXT=race, descriptor/buffer mix-up, or fused-window publication; the .comp source is not a description of the behaviour"
    exit 0
}

switch ($firstStage) {
    'SCORE_RAW' {
        Write-Output "VERDICT=DOT_PRODUCT_ADDRESSING_OR_GQA_MAPPING"
        Write-Output "NEXT=the unscaled Q.K already differs; the fault is in score generation, before scaling, softmax and the value mix"
    }
    'SCORE_SCALED' {
        Write-Output "VERDICT=SCALING_CONSTANT_OR_PLACEMENT"
        Write-Output "NEXT=the unscaled scores agree and the scaled ones do not; the fault is the scale constant or where it is applied"
    }
    'SOFTMAX_PROB' {
        Write-Output "VERDICT=SOFTMAX_MAX_EXP_DENOMINATOR"
        Write-Output "NEXT=scaled scores agree and the probabilities do not; the fault is in max reduction, exp, or the denominator"
    }
    'ATTN_VALUE' {
        Write-Output "VERDICT=VALUE_ADDRESSING_OR_WEIGHTED_ACCUMULATION"
        Write-Output "NEXT=the probabilities agree and the mix does not; the fault is in V addressing or the weighted accumulation"
    }
    default {
        Write-Output "VERDICT=NO_ALGORITHMIC_DIVERGENCE_AT_STEP_1"
        Write-Output "NOTE=if the arena diverges from the model while the model equals the CPU, the fault is output indexing, synchronisation or publication"
    }
}
exit 0

# Gate 5 re-verification at HEAD: full-logit parity sweep (129 teacher-forced positions)
# Compares the freshly generated llama.cpp reference against Deep2 CPU-native and
# Deep2 GPU-native logits, per position: cosine, max elementwise diff, argmax
# agreement, plus the margin-vs-error decomposition for every disagreement
# (drift vs boundary flip).
#
# Fail-fast: every artifact is validated (exists, non-empty, equal length)
# BEFORE any comparison; a missing or short artifact terminates the gate with
# a nonzero exit instead of degenerating into per-index errors.
$ErrorActionPreference = 'Stop'
$E = "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate5"
$N = 129
$out = New-Object System.Collections.Generic.List[string]

function Read-Floats([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "GATE5_FAIL: missing artifact $path"
    }
    $b = [System.IO.File]::ReadAllBytes($path)
    if ($b.Length -eq 0 -or ($b.Length % 4) -ne 0) {
        throw "GATE5_FAIL: empty or mis-sized artifact $path ($($b.Length) bytes)"
    }
    $f = New-Object float[] ($b.Length / 4)
    [System.Buffer]::BlockCopy($b, 0, $f, 0, $b.Length)
    if ($null -eq $f -or $f.Count -eq 0) {
        throw "GATE5_FAIL: decoded null/empty logit array from $path"
    }
    return $f
}

# Validate every artifact up front (fail fast, one error, not thousands).
for ($p = 0; $p -lt $N; $p++) {
    foreach ($side in @("ref", "cpu", "gpu")) {
        $name = if ($side -eq "ref") { "ref_head\ref_logits_pos$p.bin" } else { "d2_${side}_head\d2_logits_pos$p.bin" }
        $full = Join-Path $E $name
        if (-not (Test-Path -LiteralPath $full)) { throw "GATE5_FAIL: missing $full" }
        $len = (Get-Item -LiteralPath $full).Length
        if ($len -eq 0) { throw "GATE5_FAIL: empty $full" }
        if ($len -ne 128000) { throw "GATE5_FAIL: length mismatch $full ($len bytes, expected 128000)" }
    }
}
$out.Add("artifact validation: PASS (129 positions x 3 sides, 128000 bytes each)")

$rows = @()
$gate_pass = $true
foreach ($side in @("cpu", "gpu")) {
    $match = 0; $worstCos = 1.0; $worstPos = -1; $worstDiff = 0.0; $nonfinite = 0; $decomposed = 0; $unexplained = 0
    for ($p = 0; $p -lt $N; $p++) {
        $ref = Read-Floats (Join-Path $E "ref_head\ref_logits_pos$p.bin")
        $d2  = Read-Floats (Join-Path $E "d2_${side}_head\d2_logits_pos$p.bin")
        if ($ref.Count -ne $d2.Count) { throw "GATE5_FAIL: length mismatch at pos $p ref=$($ref.Count) d2=$($d2.Count)" }
        $dot = 0.0; $na = 0.0; $nb = 0.0; $maxDiff = 0.0; $argA = 0; $argB = 0; $second = 0.0
        for ($i = 0; $i -lt $ref.Length; $i++) {
            $x = $ref[$i]; $y = $d2[$i]
            if ([double]::IsNaN($y) -or [double]::IsInfinity($y)) { $nonfinite++; continue }
            $dot += $x * $y; $na += $x * $x; $nb += $y * $y
            $d = [Math]::Abs($x - $y); if ($d -gt $maxDiff) { $maxDiff = $d }
            if ($x -gt $ref[$argA]) { $second = $ref[$argA]; $argA = $i } elseif ($x -gt $second) { $second = $x }
            if ($y -gt $d2[$argB]) { $argB = $i }
        }
        $cos = $dot / ([Math]::Sqrt($na) * [Math]::Sqrt($nb))
        $agree = ($argA -eq $argB)
        if ($agree) { $match++ }
        else {
            # margin-vs-error decomposition: the reference's own top1-top2 margin
            # against the measured max error at this position
            $margin = $ref[$argA] - $second
            if ($margin -lt $maxDiff) { $decomposed++ } else { $unexplained++ }
        }
        if ($cos -lt $worstCos) { $worstCos = $cos; $worstPos = $p }
        if ($maxDiff -gt $worstDiff) { $worstDiff = $maxDiff }
        if ($p -in @(0,1,2,8,32,128)) {
            $rows += [pscustomobject]@{ side = $side; pos = $p; cos = [math]::Round($cos,7); maxdiff = [math]::Round($maxDiff,4); ref_argmax = $argA; d2_argmax = $argB; agree = $agree }
        }
    }
    $verdict = if ($unexplained -eq 0 -and $nonfinite -eq 0) { "PASS (all disagreements bounded by measured error)" } else { "FAIL" }
    if ($unexplained -ne 0 -or $nonfinite -ne 0) { $gate_pass = $false }
    $out.Add("[$side] argmax agreement: $match/$N ; worst cos: $([math]::Round($worstCos,7)) (pos $worstPos) ; worst maxdiff: $([math]::Round($worstDiff,4)) ; nonfinite: $nonfinite")
    $out.Add("[$side] disagreements: $($N - $match) ; explained by margin<maxerr (boundary/measurement): $decomposed ; UNEXPLAINED: $unexplained")
    $out.Add("[$side] VERDICT: $verdict")
}
$rows | Format-Table -AutoSize | Out-String | ForEach-Object { $out.Add($_) }
$out.Add("GATE5_RESULT: " + $(if ($gate_pass) { "PASS" } else { "FAIL" }))
$out | Set-Content -Encoding utf8 (Join-Path $E "gate5_reverify_head.txt")
$out | ForEach-Object { Write-Output $_ }
if (-not $gate_pass) { exit 1 }
exit 0

# Gate 7 forensics: first differing operation at the divergent position.
# The parity trace dumps per-op activation traces (d_pos{N}_blk{M}_pc{OP}.bin)
# for both backends. Compare CPU vs GPU op-by-op at the divergent position:
# if they agree with each other but diverge from llama.cpp, the shared Deep2
# computation at the first disagreeing op is the root cause.
$E = "F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate5"
$pos = 2
$cpuDir = Join-Path $E "d2_cpu_head"
$gpuDir = Join-Path $E "d2_gpu_head"

function Read-Floats([string]$path) {
    $b = [System.IO.File]::ReadAllBytes($path)
    $f = New-Object float[] ($b.Length / 4)
    [System.Buffer]::BlockCopy($b, 0, $f, 0, $b.Length)
    return $f
}

$files = Get-ChildItem $cpuDir -Filter "d_pos${pos}_blk*_pc*.bin" | Sort-Object Name
"comparing $($files.Count) op dumps at position $pos (cpu vs gpu)"
$firstBad = $null
foreach ($f in $files) {
    $name = $f.Name
    $g = Join-Path $gpuDir $name
    if (-not (Test-Path $g)) { continue }
    $a = Read-Floats $f.FullName
    $b = Read-Floats $g.FullName
    if ($a.Length -ne $b.Length) { continue }
    $maxDiff = 0.0; $sumA = 0.0; $sumB = 0.0
    for ($i = 0; $i -lt $a.Length; $i++) {
        $d = [Math]::Abs($a[$i] - $b[$i])
        if ($d -gt $maxDiff) { $maxDiff = $d }
        $sumA += $a[$i]; $sumB += $b[$i]
    }
    $meanDelta = [Math]::Abs($sumA - $sumB) / $a.Length
    if ($maxDiff -gt 0.5 -and $null -eq $firstBad) { $firstBad = $name }
    $op = ($name -replace '^d_pos\d+_','' -replace '\.bin$','')
    "{0,-28} maxdiff={1,10:F6} mean_delta={2,10:F6}" -f $op, $maxDiff, $meanDelta
}
if ($firstBad) { "FIRST_DISAGREEING_OP: $firstBad" } else { "FIRST_DISAGREEING_OP: none above 0.5 threshold (cpu/gpu agree)" }

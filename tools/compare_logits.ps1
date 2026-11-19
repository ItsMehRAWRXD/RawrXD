$dc = Join-Path $env:TEMP 'kilo\batch_inv\ref_single'
$dg = Join-Path $env:TEMP 'kilo\batch_inv\ref_batch'
$dc2 = Join-Path $env:TEMP 'kilo\batch_inv\cpu_single'
$dg2 = Join-Path $env:TEMP 'kilo\batch_inv\cpu_batch'
$dg3 = Join-Path $env:TEMP 'kilo\batch_inv\gpu_single'
$dg4 = Join-Path $env:TEMP 'kilo\batch_inv\gpu_batch'

function LoadF($p) {
    $b = [System.IO.File]::ReadAllBytes($p)
    $f = New-Object 'float[]' ($b.Length/4)
    [System.Buffer]::BlockCopy($b, 0, $f, 0, $b.Length)
    return $f
}

function Compare-Logits($a, $b, $name) {
    $n = $a.Length
    $max = 0.0
    $sum = 0.0
    $dif = 0
    for ($i = 0; $i -lt $n; $i++) {
        $d = [Math]::Abs($a[$i] - $b[$i])
        if ($d -gt 0) { $dif++ }
        if ($d -gt $max) { $max = $d }
        $sum += $d * $d
    }
    $rms = [Math]::Sqrt($sum / $n)
    return ("  {0}: diff={1}/{2} max_abs={3} rms={4}" -f $name, $dif, $n, [math]::Round($max,6), [math]::Round([math]::Sqrt($sum/$n),6))
}

$refs1 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\ref_single\ref_logits_pos0.bin')
$refb1 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\ref_batch\ref_logits_pos0.bin')
$cpus1 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\cpu_single\d2_logits_pos0.bin')
$cpub1 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\cpu_batch\d2_logits_pos0.bin')
$gpus1 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\gpu_single\d2_logits_pos0.bin')
$gpub1 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\gpu_batch\d2_logits_pos0.bin')
$refb2 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\ref_batch\ref_logits_pos1.bin')
$cpub2 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\cpu_batch\d2_logits_pos1.bin')
$gpub2 = LoadF (Join-Path $env:TEMP 'kilo\batch_inv\gpu_batch\d2_logits_pos1.bin')

Write-Host "=== POS 0 ==="
Compare-Logits $refs1 $cpus1 "REF_SINGLE_vs_CPU_SINGLE"
Compare-Logits $refb1 $cpub1 "REF_BATCH_vs_CPU_BATCH"
Compare-Logits $refs1 $gpus1 "REF_SINGLE_vs_GPU_SINGLE"
Compare-Logits $refb1 $gpub1 "REF_BATCH_vs_GPU_BATCH"
Compare-Logits $refs1 $refb1 "REF_SINGLE_vs_REF_BATCH"
Compare-Logits $cpus1 $cpub1 "CPU_SINGLE_vs_CPU_BATCH"
Compare-Logits $gpus1 $gpub1 "GPU_SINGLE_vs_GPU_BATCH"
param(
  [string]$RefDir  = "F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_ref_gen",
  [string]$CmpDir  = "F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\ref_repro_f16",
  [int]$Positions  = 19
)

function Read-Floats([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $n = $bytes.Length / 4
  $floats = New-Object float[] $n
  [System.Buffer]::BlockCopy($bytes, 0, $floats, 0, $bytes.Length)
  return $floats
}

$totalMatch = 0
$worstCos = 1.0
$worstDiff = 0.0
$worstPos = -1

for ($p = 0; $p -lt $Positions; $p++) {
  $refPath = Join-Path $RefDir ("ref_logits_pos{0}.bin" -f $p)
  $cmpPath = Join-Path $CmpDir ("ref_logits_pos{0}.bin" -f $p)
  if (-not (Test-Path $refPath) -or -not (Test-Path $cmpPath)) {
    Write-Output ("pos{0}: MISSING" -f $p)
    continue
  }
  $a = Read-Floats $refPath
  $b = Read-Floats $cmpPath
  $n = $a.Length
  $dot = 0.0; $na = 0.0; $nb = 0.0; $maxDiff = 0.0
  $argA = 0; $argB = 0
  for ($i = 0; $i -lt $n; $i++) {
    $x = $a[$i]; $y = $b[$i]
    $dot += $x * $y
    $na += $x * $x
    $nb += $y * $y
    $d = [Math]::Abs($x - $y)
    if ($d -gt $maxDiff) { $maxDiff = $d }
    if ($x -gt $a[$argA]) { $argA = $i }
    if ($y -gt $b[$argB]) { $argB = $i }
  }
  $cos = $dot / ([Math]::Sqrt($na) * [Math]::Sqrt($nb))
  $match = ($argA -eq $argB)
  if ($match) { $totalMatch++ }
  if ($cos -lt $worstCos) { $worstCos = $cos; $worstPos = $p }
  if ($maxDiff -gt $worstDiff) { $worstDiff = $maxDiff }
  Write-Output ("pos{0,2}: cos={1:F9} maxdiff={2:E4} argmax_ref={3} argmax_cmp={4} {5}" -f $p, $cos, $maxDiff, $argA, $argB, $(if ($match) {"MATCH"} else {"MISMATCH"}))
}

Write-Output ("---")
Write-Output ("argmax matches: {0}/{1}" -f $totalMatch, $Positions)
Write-Output ("worst cos: {0:F9} (pos {1})" -f $worstCos, $worstPos)
Write-Output ("worst maxdiff: {0:E4}" -f $worstDiff)

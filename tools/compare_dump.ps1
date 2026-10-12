param(
  [string]$RefDir = "F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\llama_ref_gen",
  [string]$CmpDir = "F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001\ref_repro_f16",
  [string]$Tensor = "kqv",
  [string]$Step = "00",
  [string]$Layer = "00"
)
function Read-Floats([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $n = [Math]::Floor($bytes.Length / 4)
  $floats = New-Object float[] $n
  [System.Buffer]::BlockCopy($bytes, 0, $floats, 0, $n * 4)
  return $floats
}
$ref = Join-Path $RefDir ("probe_step{0}_{1}_l{2}.bin" -f $Step, $Tensor, $Layer)
$cmp = Join-Path $CmpDir ("probe_step{0}_{1}_l{2}.bin" -f $Step, $Tensor, $Layer)
$a = Read-Floats $ref
$b = Read-Floats $cmp
$n = [Math]::Min($a.Length, $b.Length)
$dot = 0.0; $na = 0.0; $nb = 0.0; $maxDiff = 0.0; $nDiff = 0; $firstDiff = -1
for ($i = 0; $i -lt $n; $i++) {
  $x = $a[$i]; $y = $b[$i]
  $dot += $x * $y; $na += $x * $x; $nb += $y * $y
  $d = [Math]::Abs($x - $y)
  if ($d -gt 0.0) { $nDiff++; if ($firstDiff -lt 0) { $firstDiff = $i }; if ($d -gt $maxDiff) { $maxDiff = $d } }
}
$cos = if (($na -gt 0) -and ($nb -gt 0)) { $dot / ([Math]::Sqrt($na) * [Math]::Sqrt($nb)) } else { 0.0 }
Write-Output ("tensor={0} step={1} layer={2} floats={3}" -f $Tensor, $Step, $Layer, $n)
Write-Output ("  differing floats: {0}/{1}  firstDiffIdx={2}" -f $nDiff, $n, $firstDiff)
Write-Output ("  maxAbsDiff={0:E6}  cos={1:F9}" -f $maxDiff, $cos)
# Show first 8 floats of each
$sa = ($a[0..7] | ForEach-Object { "{0:F6}" -f $_ }) -join ", "
$sb = ($b[0..7] | ForEach-Object { "{0:F6}" -f $_ }) -join ", "
Write-Output ("  ref[0..7]: $sa")
Write-Output ("  cmp[0..7]: $sb")

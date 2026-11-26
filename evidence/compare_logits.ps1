# compare_logits.ps1 — A03 independent full-logit comparison.
# Compares two raw logit dumps (8-byte header = uint32 n, uint32 pos; then n float32).
# Usage: pwsh -File compare_logits.ps1 <a.bin> <b.bin>
param([Parameter(Mandatory=$true)][string]$A,[Parameter(Mandatory=$true)][string]$B)
$a=[IO.File]::ReadAllBytes($A); $b=[IO.File]::ReadAllBytes($B)
if($a.Length -ne $b.Length){ Write-Output "SIZE MISMATCH $($a.Length) vs $($b.Length)"; exit 1 }
$n=($a.Length-8)/4
$maxd=0.0;$sumd=0.0;$sumsq=0.0;$dot=0.0;$na=0.0;$nb=0.0;$arga=0;$argb=0;$va=-1e30;$vb=-1e30
for($i=0;$i -lt $n;$i++){ $o=8+$i*4; $x=[BitConverter]::ToSingle($a,$o); $y=[BitConverter]::ToSingle($b,$o)
  $d=[Math]::Abs($x-$y); if($d -gt $maxd){$maxd=$d}; $sumd+=$d; $sumsq+=$d*$d; $dot+=$x*$y; $na+=$x*$x; $nb+=$y*$y
  if($x -gt $va){$va=$x;$arga=$i}; if($y -gt $vb){$vb=$y;$argb=$i} }
$rms=[Math]::Sqrt($sumsq/$n); $mean=$sumd/$n; $cos=$dot/([Math]::Sqrt($na)*[Math]::Sqrt($nb)+1e-30)
Write-Output ("n=$n max_abs_diff=$maxd rms=$rms mean_abs=$mean cosine=$cos argmax_a=$arga argmax_b=$argb")
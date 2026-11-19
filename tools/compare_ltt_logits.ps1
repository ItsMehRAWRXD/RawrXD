param([Parameter(Mandatory=$true)][string]$Deep2File,
      [Parameter(Mandatory=$true)][string]$ReferenceDir)
$d=[IO.BinaryReader]::new([IO.File]::OpenRead($Deep2File))
try {
  for($p=0;;$p++) {
    try {$n=$d.ReadUInt64()} catch { break }
    $g=New-Object float[] $n
    for($i=0;$i -lt $n;$i++){$g[$i]=$d.ReadSingle()}
    $rp=Join-Path $ReferenceDir ("ref_logits_pos{0}.bin" -f $p)
    if(!(Test-Path $rp)){throw "missing $rp"}
    $rbytes=[IO.File]::ReadAllBytes($rp); $r=New-Object float[] ($rbytes.Length/4)
    [Buffer]::BlockCopy($rbytes,0,$r,0,$rbytes.Length)
    if($r.Length -ne $g.Length){throw "vocab mismatch position=$p deep2=$($g.Length) ref=$($r.Length)"}
    [double]$dot=0; [double]$gn=0; [double]$rn=0; [double]$max=0; [double]$sq=0
    $gt=0;$rt=0
    for($i=0;$i -lt $n;$i++) { $x=[double]$g[$i];$y=[double]$r[$i];$dot+=$x*$y;$gn+=$x*$x;$rn+=$y*$y;$e=[math]::Abs($x-$y);if($e -gt $max){$max=$e};$sq+=$e*$e;if($x -gt $g[$gt]){$gt=$i};if($y -gt $r[$rt]){$rt=$i} }
    "pos=$p vocab=$n cosine={0:R} max_abs={1:R} rms={2:R} gpu_top1=$gt ref_top1=$rt" -f ($dot/([math]::Sqrt($gn)*[math]::Sqrt($rn))),$max,[math]::Sqrt($sq/$n)
  }
} finally {$d.Dispose()}

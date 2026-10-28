$ErrorActionPreference = 'Stop'
$evid = 'G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001'
$dirA = Join-Path $evid 'layer_dump_A'
$dirB = Join-Path $evid 'layer_dump_B'
function Cmp-F32([string]$pa, [string]$pb) {
  if (-not (Test-Path $pa) -or -not (Test-Path $pb)) { return $null }
  $ba = [IO.File]::ReadAllBytes($pa); $bb = [IO.File]::ReadAllBytes($pb)
  if ($ba.Length -ne $bb.Length) {
    return [pscustomobject]@{ maxAbs = -1; meanAbs = -1; rms = -1; maxI = -1; n = -1 }
  }
  $n = [int]($ba.Length / 4)
  $fa = New-Object 'System.Single[]' $n
  $fb = New-Object 'System.Single[]' $n
  [Buffer]::BlockCopy($ba, 0, $fa, 0, $ba.Length)
  [Buffer]::BlockCopy($bb, 0, $fb, 0, $bb.Length)
  $maxAbs = 0.0; $sum = 0.0; $maxI = 0; $rss = 0.0
  for ($i = 0; $i -lt $n; $i++) {
    $d = [math]::Abs([double]$fa[$i] - [double]$fb[$i])
    $sum += $d; $rss += $d * $d
    if ($d -gt $maxAbs) { $maxAbs = $d; $maxI = $i }
  }
  return [pscustomobject]@{
    maxAbs = $maxAbs; meanAbs = ($sum / $n); rms = [math]::Sqrt($rss / $n); maxI = $maxI; n = $n
  }
}
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('kind,blk,tag,maxAbs,meanAbs,rms,maxI,n')
$firstResid2 = $null; $firstResid1 = $null; $firstAttn = $null; $firstQkv = $null
$eps = 1.0e-5
for ($b = 0; $b -lt 22; $b++) {
  foreach ($tag in @('resid1', 'resid2')) {
    $name = "h.blk$b.$tag.f32"
    $c = Cmp-F32 (Join-Path $dirA $name) (Join-Path $dirB $name)
    if ($null -eq $c) { continue }
    $lines.Add(("RESID,{0},{1},{2},{3},{4},{5},{6}" -f $b,$tag,$c.maxAbs,$c.meanAbs,$c.rms,$c.maxI,$c.n))
    if ($tag -eq 'resid2' -and $null -eq $firstResid2 -and $c.maxAbs -gt $eps) {
      $firstResid2 = [pscustomobject]@{ blk = $b; maxAbs = $c.maxAbs; meanAbs = $c.meanAbs; rms = $c.rms }
    }
    if ($tag -eq 'resid1' -and $null -eq $firstResid1 -and $c.maxAbs -gt $eps) {
      $firstResid1 = [pscustomobject]@{ blk = $b; maxAbs = $c.maxAbs; meanAbs = $c.meanAbs; rms = $c.rms }
    }
  }
  $ca = Cmp-F32 (Join-Path $dirA "attn.blk$b.attnvalue.f32") (Join-Path $dirB "attn.blk$b.attnvalue.f32")
  if ($ca) {
    $lines.Add(("ATTN,{0},attnvalue,{1},{2},{3},{4},{5}" -f $b,$ca.maxAbs,$ca.meanAbs,$ca.rms,$ca.maxI,$ca.n))
    if ($null -eq $firstAttn -and $ca.maxAbs -gt $eps) {
      $firstAttn = [pscustomobject]@{ blk = $b; maxAbs = $ca.maxAbs; meanAbs = $ca.meanAbs; rms = $ca.rms }
    }
  }
  $cq = Cmp-F32 (Join-Path $dirA "qkv.blk$b.qkv.f32") (Join-Path $dirB "qkv.blk$b.qkv.f32")
  if ($cq) {
    $lines.Add(("QKV,{0},qkv,{1},{2},{3},{4},{5}" -f $b,$cq.maxAbs,$cq.meanAbs,$cq.rms,$cq.maxI,$cq.n))
    if ($null -eq $firstQkv -and $cq.maxAbs -gt $eps) {
      $firstQkv = [pscustomobject]@{ blk = $b; maxAbs = $cq.maxAbs; meanAbs = $cq.meanAbs; rms = $cq.rms }
    }
  }
}
$csv = Join-Path $evid 'LAYER_COMPARE.csv'
$lines | Set-Content -Path $csv -Encoding utf8
Write-Output "WROTE $csv"
Write-Output '==== RESID2 ===='
$lines | Where-Object { $_ -like 'RESID,*,resid2,*' } | ForEach-Object { $_ }
Write-Output ("FIRST_RESID1 eps={0} => {1}" -f $eps, ($(if ($firstResid1) { "blk=$($firstResid1.blk) maxAbs=$($firstResid1.maxAbs) mean=$($firstResid1.meanAbs) rms=$($firstResid1.rms)" } else { 'NONE' })))
Write-Output ("FIRST_RESID2 eps={0} => {1}" -f $eps, ($(if ($firstResid2) { "blk=$($firstResid2.blk) maxAbs=$($firstResid2.maxAbs) mean=$($firstResid2.meanAbs) rms=$($firstResid2.rms)" } else { 'NONE' })))
Write-Output ("FIRST_ATTN eps={0} => {1}" -f $eps, ($(if ($firstAttn) { "blk=$($firstAttn.blk) maxAbs=$($firstAttn.maxAbs) mean=$($firstAttn.meanAbs) rms=$($firstAttn.rms)" } else { 'NONE' })))
Write-Output ("FIRST_QKV eps={0} => {1}" -f $eps, ($(if ($firstQkv) { "blk=$($firstQkv.blk) maxAbs=$($firstQkv.maxAbs) mean=$($firstQkv.meanAbs) rms=$($firstQkv.rms)" } else { 'NONE' })))
# Detail first divergent block
$focus = 0
if ($firstQkv) { $focus = [int]$firstQkv.blk }
elseif ($firstAttn) { $focus = [int]$firstAttn.blk }
elseif ($firstResid1) { $focus = [int]$firstResid1.blk }
Write-Output "==== FOCUS_BLK=$focus ===="
$lines | Where-Object { $_ -match "^[^,]+,$focus," } | ForEach-Object { $_ }

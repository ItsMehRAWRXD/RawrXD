# Compare Deep2 vs CPU-llama STAGE_DIGEST lines; find first pos=0 FNV mismatch.
param(
  [string]$Deep2Log,
  [string]$LlamaLog,
  [int]$Pos = 0
)
$ErrorActionPreference = 'Stop'
function Parse-Digests([string]$path, [string]$side) {
  $map = @{}
  Get-Content $path | ForEach-Object {
    if ($_ -match '\[STAGE_DIGEST\].*side=(\w+)\s+key=(\S+)\s+pos=(\d+)\s+n=(\d+)\s+l2=([0-9.eE+-]+).*max_abs=([0-9.eE+-]+).*fnv=([0-9a-fA-F]+)') {
      $s=$Matches[1]; $k=$Matches[2]; $p=[int]$Matches[3]
      if ($s -ne $side -and $Matches[0] -notmatch "side=$side") { }
      if ($p -ne $Pos) { return }
      $map[$k] = [pscustomobject]@{key=$k; pos=$p; n=[int]$Matches[4]; l2=[double]$Matches[5]; max_abs=[double]$Matches[6]; fnv=$Matches[7].ToLower()}
    } elseif ($_ -match '\[STAGE_DIGEST\]\s+(\S+)\s+pos=(\d+)\s+n=(\d+)\s+l2=([0-9.eE+-]+).*fnv=([0-9a-fA-F]+)') {
      # legacy format without side=
      $k=$Matches[1]; $p=[int]$Matches[2]
      if ($p -ne $Pos) { return }
      $map[$k] = [pscustomobject]@{key=$k; pos=$p; n=[int]$Matches[3]; l2=[double]$Matches[4]; max_abs=-1; fnv=$Matches[5].ToLower()}
    }
  }
  $map
}
$d = Parse-Digests $Deep2Log 'deep2'
$l = Parse-Digests $LlamaLog 'llama'
$order = @(
  'PROMPT_EMBED','ATTN_NORM_0','Q_PRE_ROPE_0','Q_POST_ROPE_0','K_PRE_ROPE_0','K_POST_ROPE_0','V_0',
  'ATTN_OUT_0','FFN_INP_0','FFN_NORM_0','FFN_ACT_0','FFN_DOWN_0','POST_FFN_0','LAYER0_OUT',
  'FINAL_NORM','TIP_FINAL_NORM','TIP_FINAL_HIDDEN','LOGITS','TIP_LOGITS'
)
# Deep2 POST_FFN_N == llama LAYER{N}_OUT (residual out). Alias either side.
if ($d.ContainsKey('POST_FFN_0') -and -not $d.ContainsKey('LAYER0_OUT')) { $d['LAYER0_OUT'] = $d['POST_FFN_0'] }
if ($l.ContainsKey('LAYER0_OUT') -and -not $l.ContainsKey('POST_FFN_0')) { $l['POST_FFN_0'] = $l['LAYER0_OUT'] }
Write-Host "=== BISECT pos=$Pos ==="
$first = $null
foreach ($k in $order) {
  $dk = $d[$k]; $lk = $l[$k]
  if (-not $dk -and -not $lk) { continue }
  if (-not $dk) { Write-Host "MISSING deep2 $k"; if (-not $first) { $first = "missing_deep2:$k" }; continue }
  if (-not $lk) { Write-Host "MISSING llama $k"; if (-not $first) { $first = "missing_llama:$k" }; continue }
  $match = ($dk.fnv -eq $lk.fnv)
  $status = if ($match) { 'MATCH' } else { 'DIFF' }
  Write-Host ("{0,-16} {1} deep2_fnv={2} llama_fnv={3} deep2_l2={4:g6} llama_l2={5:g6}" -f $k,$status,$dk.fnv,$lk.fnv,$dk.l2,$lk.l2)
  if (-not $match -and -not $first) { $first = $k }
}
Write-Host "FIRST_MISMATCH=$first"

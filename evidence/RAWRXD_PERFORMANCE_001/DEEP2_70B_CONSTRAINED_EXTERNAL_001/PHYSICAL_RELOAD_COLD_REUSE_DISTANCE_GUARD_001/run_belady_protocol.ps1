$ErrorActionPreference = "Stop"
$gate = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_70B_CONSTRAINED_EXTERNAL_001\PHYSICAL_RELOAD_COLD_REUSE_DISTANCE_GUARD_001"
$runs = Join-Path $gate "runs"
$seq = Join-Path $gate "expert_seq.bin"
$script = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_70B_CONSTRAINED_EXTERNAL_001\PHYSICAL_RELOAD_ENVELOPE_001\run_l61t8_freeze.ps1"
$receipt = Join-Path $gate "SWEEP_RECEIPT.tsv"
$wantT = "ac263efad52c3033"
$wantE = "828a699d6ec6354a"
$BASE = 1013268480L
New-Item -ItemType Directory -Force -Path $runs | Out-Null

function Get-Meters([string]$runDir) {
  $stderr = Join-Path $runDir "stderr.txt"
  $exitLine = Get-Content (Join-Path $runDir "exit.txt") -ErrorAction SilentlyContinue | Select-Object -First 1
  $exit = if ($exitLine -match 'EXIT=(-?\d+)') { [int]$Matches[1] } else { -999 }
  $wall = if ($exitLine -match 'WALL_MS=(\d+)') { [int]$Matches[1] } else { 0 }
  $text = Get-Content $stderr -Raw -ErrorAction SilentlyContinue
  if (-not $text) { $text = "" }
  $reuse = [regex]::Match($text, 'D2_REUSE_DIST GUARD_D=(\d+) oracle=(\d+) live=(\d+) cursor=(\d+) WASTED_EVICTION_BYTES=(\d+) D1=(\d+) D2=(\d+) D3_4=(\d+) D5_8=(\d+) D9_16=(\d+) D17_32=(\d+) GT32=(\d+) NEVER=(\d+)')
  $attr = [regex]::Match($text, 'MOE_RELOAD_AFTER_EVICTION_BYTES=(\d+).*?moe_hot_victim_evictions=(\d+) moe_cold_victim_evictions=(\d+) MOE_PREMATURE_HOT_RELOAD_BYTES=(\d+)', 'Singleline')
  $acq = [regex]::Match($text, 'acquire_fail=(\d+)')
  $parity = [regex]::Match($text, 'parity=(\d+)')
  $tok = [regex]::Matches($text, 'TOKENS_COMMITTED=(\d+)')
  $gen = 0
  if ($tok.Count -gt 0) { $gen = [int]$tok[$tok.Count - 1].Groups[1].Value }
  [pscustomobject]@{
    RUN = (Split-Path $runDir -Leaf)
    EXIT = $exit; WALL_MS = $wall; GEN = $gen
    TRACE = if ($text -match 'GREEDY_DET TRACE_HASH=([0-9a-fA-F]+)') { $Matches[1].ToLower() } else { "?" }
    ESEQ = if ($text -match 'EXPERT_SEQUENCE_HASH=([0-9a-fA-F]+)') { $Matches[1].ToLower() } else { "?" }
    AFTER = if ($attr.Success) { [int64]$attr.Groups[1].Value } else { -1 }
    HOT_V = if ($attr.Success) { [int64]$attr.Groups[2].Value } else { -1 }
    COLD_V = if ($attr.Success) { [int64]$attr.Groups[3].Value } else { -1 }
    PREMATURE = if ($attr.Success) { [int64]$attr.Groups[4].Value } else { -1 }
    WASTED = if ($reuse.Success) { [int64]$reuse.Groups[5].Value } else { -1 }
    ORACLE = if ($reuse.Success) { [int64]$reuse.Groups[2].Value } else { -1 }
    LIVE = if ($reuse.Success) { [int64]$reuse.Groups[3].Value } else { -1 }
    D1 = if ($reuse.Success) { [int64]$reuse.Groups[6].Value } else { -1 }
    D2 = if ($reuse.Success) { [int64]$reuse.Groups[7].Value } else { -1 }
    D3_4 = if ($reuse.Success) { [int64]$reuse.Groups[8].Value } else { -1 }
    D5_8 = if ($reuse.Success) { [int64]$reuse.Groups[9].Value } else { -1 }
    D9_16 = if ($reuse.Success) { [int64]$reuse.Groups[10].Value } else { -1 }
    D17_32 = if ($reuse.Success) { [int64]$reuse.Groups[11].Value } else { -1 }
    GT32 = if ($reuse.Success) { [int64]$reuse.Groups[12].Value } else { -1 }
    NEVER = if ($reuse.Success) { [int64]$reuse.Groups[13].Value } else { -1 }
    ABORT = if ($text -match 'STREAM_ABORT=1') { 1 } else { 0 }
    PIN_FAIL = if ($text -match 'K2MoEStickPinExpert failed') { 1 } else { 0 }
    ACQ_FAIL = if ($acq.Success) { [int64]$acq.Groups[1].Value } else { -1 }
    PARITY = if ($parity.Success) { [int]$parity.Groups[1].Value } else { -1 }
  }
}

function Test-RecordOk($m) {
  return ($m.EXIT -eq 0 -and $m.GEN -ge 8 -and $m.ABORT -eq 0 -and $m.PIN_FAIL -eq 0 -and
          $m.ACQ_FAIL -eq 0 -and $m.TRACE -eq $wantT -and $m.ESEQ -eq $wantE)
}

function Test-ReplayOk($m) {
  return ((Test-RecordOk $m) -and $m.PARITY -eq 1 -and $m.AFTER -eq $BASE)
}

function Invoke-Freeze([int]$D, [string]$phase) {
  Get-Process rawr -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 12
  $env:DEEP2_REUSE_SEQ_PATH = $seq
  $env:DEEP2_REUSE_GUARD_D = "$D"
  Write-Host "=== $phase D=$D SEQ_EXISTS=$(Test-Path $seq) ==="
  & powershell -NoProfile -ExecutionPolicy Bypass -File $script -OutRoot $runs | Out-Host
  $latest = Get-ChildItem $runs -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  $m = Get-Meters $latest.FullName
  Write-Host ("RESULT {0} EXIT={1} GEN={2} AFTER={3} TRACE={4} ESEQ={5} ABORT={6} PIN={7} ACQ={8} PARITY={9} ORACLE={10} WASTED={11} SEQ={12}" -f `
    $phase,$m.EXIT,$m.GEN,$m.AFTER,$m.TRACE,$m.ESEQ,$m.ABORT,$m.PIN_FAIL,$m.ACQ_FAIL,$m.PARITY,$m.ORACLE,$m.WASTED,(Test-Path $seq))
  return $m
}

function Add-ReceiptRow([string]$Dlabel, $m, [string]$note) {
  $after = $m.AFTER
  $delta = if ($after -ge 0) { $after - $BASE } else { "NA" }
  $traceOk = if ($m.TRACE -eq $wantT -and $m.ESEQ -eq $wantE) { 1 } else { 0 }
  $pin = if ($m.PIN_FAIL -eq 1 -or $m.ACQ_FAIL -gt 0) { 1 } else { 0 }
  $line = "$Dlabel`t$after`t$delta`t$($m.WASTED)`t$pin`t$($m.PARITY)`t$($m.EXIT)`t$($m.GEN)`t$traceOk`t$note"
  Add-Content -LiteralPath $receipt -Value $line -Encoding UTF8
  Write-Host "RECEIPT $line"
}

"D`tAFTER`tDELTA_BASE`tWASTED`tPIN_FAIL`tPARITY`tEXIT`tGEN`tTRACE_OK`tNOTE" | Set-Content -LiteralPath $receipt -Encoding UTF8

Remove-Item -Force -LiteralPath $seq,"$seq.tmp" -ErrorAction SilentlyContinue
$rec = $null
for ($i = 1; $i -le 4; $i++) {
  Write-Host "RECORD_GEN8 attempt $i"
  if (Test-Path $seq) {
    Write-Host "UNEXPECTED_SEQ_BEFORE_SEAL deleting"
    Remove-Item -Force -LiteralPath $seq,"$seq.tmp" -ErrorAction SilentlyContinue
  }
  $rec = Invoke-Freeze 0 "RECORD_GEN8_A$i"
  if (-not (Test-RecordOk $rec)) {
    Add-ReceiptRow "RECORD_FAIL" $rec "INVALID_ABORT_OR_UNLOCK attempt=$i NONAUTH"
    Remove-Item -Force -LiteralPath $seq,"$seq.tmp" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 45
    continue
  }
  if (-not (Test-Path $seq)) {
    Add-ReceiptRow "RECORD_NOSEQ" $rec "LOCKED_OK_BUT_SEQ_NOT_SEALED attempt=$i"
    Start-Sleep -Seconds 45
    continue
  }
  Add-ReceiptRow "RECORD_D0" $rec "RECORD_GEN8_SEALED seq_bytes=$((Get-Item $seq).Length)"
  break
}
if (-not (Test-Path $seq) -or -not (Test-RecordOk $rec)) {
  Write-Host "FATAL RECORD_GEN8 failed - stop before D-sweep"
  exit 2
}

$rep = $null
for ($i = 1; $i -le 3; $i++) {
  Write-Host "D0_ORACLE_REPLAY attempt $i"
  $rep = Invoke-Freeze 0 "D0_ORACLE_REPLAY_A$i"
  if (Test-ReplayOk $rep) {
    Add-ReceiptRow "D0_REPLAY" $rep "ORACLE_READ ok oracle=$($rep.ORACLE)"
    break
  }
  Add-ReceiptRow "D0_REPLAY_FAIL" $rep "replay_not_baseline attempt=$i AFTER=$($rep.AFTER)"
  Start-Sleep -Seconds 40
}
if (-not (Test-ReplayOk $rep)) {
  Write-Host "FATAL D0_ORACLE_REPLAY failed - stop before D-sweep"
  exit 3
}

$results = @()
foreach ($D in @(1, 2, 4, 8, 16, 32)) {
  $m = Invoke-Freeze $D "SWEEP_D$D"
  $note = "buckets D1=$($m.D1) D2=$($m.D2) D3_4=$($m.D3_4) D5_8=$($m.D5_8) D9_16=$($m.D9_16) D17_32=$($m.D17_32) GT32=$($m.GT32) NEVER=$($m.NEVER)"
  if ($m.ABORT -eq 1 -or $m.GEN -lt 8) { $note = "FAIL_MODE abort/gen " + $note }
  Add-ReceiptRow "D$D" $m $note
  if ($m.GEN -ge 8 -and $m.ABORT -eq 0 -and $m.AFTER -ge 0) {
    $results += [pscustomobject]@{ D = $D; AFTER = $m.AFTER; M = $m }
  }
}

if ($results.Count -eq 0) {
  Write-Host "SWEEP_NO_VALID_GEN8"
  exit 4
}

$best = $results | Sort-Object AFTER, D | Select-Object -First 1
Write-Host "BEST_D=$($best.D) AFTER=$($best.AFTER)"
$m2 = Invoke-Freeze $best.D "BEST_D$($best.D)_X2"
$note2 = "2x_best buckets D1=$($m2.D1) D2=$($m2.D2) D3_4=$($m2.D3_4) D5_8=$($m2.D5_8) D9_16=$($m2.D9_16) D17_32=$($m2.D17_32) GT32=$($m2.GT32) NEVER=$($m2.NEVER)"
Add-ReceiptRow "D$($best.D)_X2" $m2 $note2

Write-Host "PROTOCOL_DONE"
exit 0

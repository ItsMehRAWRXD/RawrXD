$ErrorActionPreference='Continue'
$base = 'F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_003'
New-Item -ItemType Directory -Force -Path $base | Out-Null
$exe = 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$sha = '0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E'
$script = 'F:\rawrxd\tools\uia\T05_Cancellation_Recovery.ps1'
$chatLog = 'F:\rawrxd\build_ide\bin\chat_runtime.log'
Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | ForEach-Object { try { Stop-Process -Id $_.Id -Force } catch {} }
Start-Sleep -Seconds 1
$hash = (Get-FileHash -Algorithm SHA256 $exe).Hash
if ($hash -ne $sha) { throw ("SHA mismatch before board: {0}" -f $hash) }
("SHA_PRE_BOARD={0}" -f $hash)
("SIZE={0}" -f (Get-Item $exe).Length)

function Analyze-StaleA {
  param([string[]]$Lines)
  $pairs = @()
  $i = 0
  while ($i -lt $Lines.Count) {
    if ($Lines[$i] -match 'request_started request_id=(\d+)') {
      $rid = [int]$Matches[1]
      $cancelAck = $false
      $lateA = New-Object System.Collections.Generic.List[string]
      $bStarted = $false
      $bComplete = $false
      $bRid = $null
      $j = $i + 1
      while ($j -lt $Lines.Count) {
        $line = $Lines[$j]
        if ($line -match ("cancel_acknowledged request_id={0}\b" -f $rid)) { $cancelAck = $true; $j++; continue }
        if ($cancelAck -and ($line -match ("callback request_id={0}\b" -f $rid) -or $line -match ("ui_update request_id={0}\b" -f $rid))) {
          [void]$lateA.Add($line)
        }
        if ($cancelAck -and $line -match 'request_started request_id=(\d+)') {
          $bRid = [int]$Matches[1]
          $bStarted = $true
          $k = $j + 1
          while ($k -lt $Lines.Count) {
            if ($Lines[$k] -match ("callback request_id={0} complete=1" -f $bRid)) { $bComplete = $true; break }
            if ($Lines[$k] -match 'request_started request_id=') { break }
            if ($Lines[$k] -match ("callback request_id={0}\b" -f $rid) -or $Lines[$k] -match ("ui_update request_id={0}\b" -f $rid)) { [void]$lateA.Add($Lines[$k]) }
            $k++
          }
          break
        }
        if ($line -match 'request_started request_id=' -and -not $cancelAck) { break }
        $j++
      }
      if ($cancelAck) {
        $pairs += [pscustomobject]@{RequestA=$rid; CancelAck=$cancelAck; RequestB=$bRid; RequestBStarted=$bStarted; RequestBComplete=$bComplete; LateACallbackCount=$lateA.Count; LateALines=@($lateA)}
      }
    }
    $i++
  }
  # Always return an array so .Count is element-count (PS unwrap bug).
  return ,@($pairs)
}

$matrix = @()
for ($t = 1; $t -le 5; $t++) {
  $tdir = Join-Path $base ("trial_{0:D2}" -f $t)
  New-Item -ItemType Directory -Force -Path $tdir | Out-Null
  Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | ForEach-Object { try { Stop-Process -Id $_.Id -Force } catch {} }
  Start-Sleep -Seconds 1
  $pre = (Get-FileHash -Algorithm SHA256 $exe).Hash
  if ($pre -ne $sha) { throw ("SHA mismatch before trial {0}: {1}" -f $t, $pre) }
  $chatBeforeLen = 0
  if (Test-Path $chatLog) { $chatBeforeLen = (Get-Item $chatLog).Length }
  ("=== TRIAL {0} START sha={1} chatBeforeLen={2} ===" -f $t, $pre, $chatBeforeLen)
  $outFile = Join-Path $tdir 'console.txt'
  $exitCode = 0
  try {
    $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $script -Exe $exe -Sha256 $sha -EvidenceDir $tdir 2>&1
    $exitCode = $LASTEXITCODE
    $output | Tee-Object -FilePath $outFile | Out-Host
  } catch {
    $exitCode = 1
    ($_ | Out-String) | Tee-Object -FilePath $outFile | Out-Host
  }
  $chatDeltaPath = Join-Path $tdir 'chat_runtime_delta.txt'
  $stalePath = Join-Path $tdir 'stale_a_check.json'
  $staleOk = $false
  $staleDetail = 'NO_CHAT_DELTA'
  if (Test-Path $chatLog) {
    Copy-Item $chatLog (Join-Path $tdir 'chat_runtime_snapshot.log') -Force
    $deltaLines = @()
    if ($chatBeforeLen -gt 0 -and (Get-Item $chatLog).Length -ge $chatBeforeLen) {
      $fs = [System.IO.File]::Open($chatLog, 'Open', 'Read', 'ReadWrite')
      try {
        $null = $fs.Seek($chatBeforeLen, 'Begin')
        $sr = New-Object System.IO.StreamReader($fs)
        $newText = $sr.ReadToEnd()
        $sr.Close()
      } finally { $fs.Close() }
      $deltaLines = @($newText -split "`r?`n" | Where-Object { $_ -ne '' })
    } else {
      $deltaLines = @(Get-Content $chatLog -ErrorAction SilentlyContinue)
    }
    $deltaLines | Set-Content $chatDeltaPath -Encoding UTF8
    $pairs = @(Analyze-StaleA -Lines $deltaLines)
    if ($pairs.Count -eq 1 -and $null -eq $pairs[0]) { $pairs = @() }
    # Normalize: Analyze may return nested array via unary comma.
    if ($pairs.Count -eq 1 -and $pairs[0] -is [System.Array]) { $pairs = @($pairs[0]) }
    @($pairs) | ConvertTo-Json -Depth 6 | Set-Content $stalePath -Encoding UTF8
    if (@($pairs).Count -gt 0 -and $null -ne $pairs[0]) {
      $last = @($pairs)[-1]
      $staleOk = ($last.CancelAck -and $last.RequestBStarted -and ([int]$last.LateACallbackCount -eq 0))
      $staleDetail = ("A={0} cancelAck={1} B={2} BComplete={3} lateA={4}" -f $last.RequestA, $last.CancelAck, $last.RequestB, $last.RequestBComplete, $last.LateACallbackCount)
    } else {
      $staleDetail = 'NO_A_STOP_B_PAIR_IN_DELTA'
      $staleOk = $false
    }
  }
  $receiptPath = Join-Path $tdir 'T05.receipt.json'
  $recv=$false; $cancel=$false; $sent=$false; $alive=$false; $err=$null; $markerExact=$false; $stopFb=$false
  if (Test-Path $receiptPath) {
    $r = Get-Content $receiptPath -Raw | ConvertFrom-Json
    $cancel = [bool]$r.CancelObserved
    $sent = [bool]$r.SecondRequestSent
    $recv = [bool]$r.SecondRequestRecovered
    $alive = [bool]$r.ProcessAlive
    $err = $r.Error
    if ($null -ne $r.PSObject.Properties['MarkerExact']) { $markerExact = [bool]$r.MarkerExact }
    if ($null -ne $r.PSObject.Properties['StopFeedbackObserved']) { $stopFb = [bool]$r.StopFeedbackObserved }
  } else { $err = 'NO_RECEIPT' }
  $t05Pass = ($cancel -and $sent -and $recv -and $alive)
  $row = [ordered]@{
    Trial=$t; ShaPre=$pre
    CancelObserved=$cancel; SecondRequestSent=$sent; SecondRequestRecovered=$recv; ProcessAlive=$alive
    MarkerExact=$markerExact; StopFeedbackObserved=$stopFb
    T05CriteriaPass=$t05Pass
    StaleARejectProven=$staleOk
    StaleADetail=$staleDetail
    Pass=($t05Pass -and $staleOk)
    ScriptExit=$exitCode; Error=$err; EvidenceDir=$tdir
  }
  $matrix += [pscustomobject]$row
  ("=== TRIAL {0} END T05Pass={1} StaleA={2} CombinedPass={3} detail={4} ===" -f $t, $t05Pass, $staleOk, ($t05Pass -and $staleOk), $staleDetail)
  Start-Sleep -Seconds 3
}

$matrix | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $base 'T05_FIVE_TRIAL_MATRIX.json') -Encoding UTF8
$matrix | Format-Table Trial,CancelObserved,SecondRequestSent,SecondRequestRecovered,ProcessAlive,T05CriteriaPass,StaleARejectProven,Pass -AutoSize | Out-String | Write-Host
$t05PassCount = @($matrix | Where-Object { $_.T05CriteriaPass }).Count
$combinedPassCount = @($matrix | Where-Object { $_.Pass }).Count
$failLoci = @($matrix | Where-Object { -not $_.Pass } | ForEach-Object {
  $loci=@()
  if (-not $_.CancelObserved) { $loci += 'CancelObserved' }
  if (-not $_.SecondRequestSent) { $loci += 'SecondRequestSent' }
  if (-not $_.SecondRequestRecovered) { $loci += 'SecondRequestRecovered' }
  if (-not $_.ProcessAlive) { $loci += 'ProcessAlive' }
  if (-not $_.StaleARejectProven) { $loci += ('StaleA=' + $_.StaleADetail) }
  if ($_.Error) { $loci += ('Error=' + $_.Error) }
  ("trial_{0}:{1}" -f $_.Trial, ($loci -join ','))
})
$post = (Get-FileHash -Algorithm SHA256 $exe).Hash
$allFiveT05 = ($t05PassCount -eq 5)
$allFiveCombined = ($combinedPassCount -eq 5)
$disp = if ($allFiveCombined) { 'PASS' } elseif ($allFiveT05 -and -not $allFiveCombined) { 'FAIL_STALE_A_NOT_PROVEN' } else { 'FAIL' }
$agg = [ordered]@{
  Gate='T05'; Board='BUILD_IDE_0F054F01_T05_003'
  CandidateSHA256=$sha; ShaVerifiedPreBoard=$hash; ShaVerifiedPostBoard=$post; ShaMatch=($post -eq $sha)
  Exe=$exe; ExeSizeBytes=(Get-Item $exe).Length
  Trials=5
  T05CriteriaPassCount=$t05PassCount
  CombinedPassCount=$combinedPassCount
  FailCount=(5 - $combinedPassCount)
  FailLoci=$failLoci
  AggregateDisposition=$disp
  MarkerBindSha=$sha
  MarkerNote='F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL_RECOVERY_MARKER_OBSERVED.md'
  DistinctFromDailyDriverSha='9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8'
  HarnessFixes=@('StaleA_array_unwrap','Transcript_1203_marker_poll','Control_reresolve_after_stop','SetText_retry')
  PriorBoards=@('BUILD_IDE_0F054F01_T05_001','BUILD_IDE_0F054F01_T05_002')
  NOT_RUN_NE_PASS=$true; PROMOTE=0; CERTIFIED=0; T25='HELD'
  ASOF_UTC=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$agg | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $base 'T05_AGGREGATE.receipt.json') -Encoding UTF8
$agg | ConvertTo-Json -Depth 8
("AGGREGATE={0} T05PassCount={1} CombinedPassCount={2}" -f $disp, $t05PassCount, $combinedPassCount)

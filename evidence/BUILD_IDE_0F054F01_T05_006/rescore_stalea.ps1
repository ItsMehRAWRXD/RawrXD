$ErrorActionPreference='Stop'
$base='F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006'
$sha='0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E'
$exe='F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
function Analyze-StaleA {
  param([string[]]$Lines)
  $pairs = @()
  $i = 0
  while ($i -lt $Lines.Count) {
    if ($Lines[$i] -match 'request_started request_id=(\d+)') {
      $rid = [int]$Matches[1]
      $cancelAck = $false
      $lateA = New-Object System.Collections.Generic.List[string]
      $rejectProof = New-Object System.Collections.Generic.List[string]
      $bStarted = $false
      $bComplete = $false
      $bRid = $null
      $j = $i + 1
      while ($j -lt $Lines.Count) {
        $line = $Lines[$j]
        if ($line -match ("cancel_acknowledged request_id={0}\b" -f $rid)) { $cancelAck = $true; $j++; continue }
        if ($cancelAck -and $line -match ("^stale_ui_update request_id={0}\b.*rendered=0" -f $rid)) {
          [void]$rejectProof.Add($line)
        }
        if ($cancelAck -and ($line -match ("^callback request_id={0}\b" -f $rid) -or $line -match ("^ui_update request_id={0}\b" -f $rid))) {
          [void]$lateA.Add($line)
        }
        if ($cancelAck -and $line -match 'request_started request_id=(\d+)') {
          $bRid = [int]$Matches[1]
          $bStarted = $true
          $k = $j + 1
          while ($k -lt $Lines.Count) {
            if ($Lines[$k] -match ("callback request_id={0} complete=1" -f $bRid)) { $bComplete = $true; break }
            if ($Lines[$k] -match 'request_started request_id=') { break }
            if ($Lines[$k] -match ("^stale_ui_update request_id={0}\b.*rendered=0" -f $rid)) { [void]$rejectProof.Add($Lines[$k]) }
            if ($Lines[$k] -match ("^callback request_id={0}\b" -f $rid) -or $Lines[$k] -match ("^ui_update request_id={0}\b" -f $rid)) { [void]$lateA.Add($Lines[$k]) }
            $k++
          }
          break
        }
        if ($line -match 'request_started request_id=' -and -not $cancelAck) { break }
        $j++
      }
      if ($cancelAck) {
        $pairs += [pscustomobject]@{
          RequestA=$rid; CancelAck=$cancelAck; RequestB=$bRid; RequestBStarted=$bStarted; RequestBComplete=$bComplete
          LateACallbackCount=$lateA.Count; LateALines=@($lateA)
          StaleRejectProofCount=$rejectProof.Count; StaleRejectProofLines=@($rejectProof)
        }
      }
    }
    $i++
  }
  return ,@($pairs)
}

$prior = Get-Content (Join-Path $base 'T05_FIVE_TRIAL_MATRIX.json') -Raw | ConvertFrom-Json
$matrix = @()
foreach ($row in $prior) {
  $tdir = $row.EvidenceDir
  $deltaPath = Join-Path $tdir 'chat_runtime_delta.txt'
  $stalePath = Join-Path $tdir 'stale_a_check.json'
  $deltaLines = @(Get-Content $deltaPath -ErrorAction SilentlyContinue | Where-Object { $_ -ne '' })
  $pairs = @(Analyze-StaleA -Lines $deltaLines)
  if ($pairs.Count -eq 1 -and $pairs[0] -is [System.Array]) { $pairs = @($pairs[0]) }
  if ($pairs.Count -eq 1 -and $null -eq $pairs[0]) { $pairs = @() }
  @($pairs) | ConvertTo-Json -Depth 6 | Set-Content $stalePath -Encoding UTF8
  $staleOk = $false
  $staleDetail = 'NO_A_STOP_B_PAIR_IN_DELTA'
  if (@($pairs).Count -gt 0 -and $null -ne $pairs[0]) {
    $last = @($pairs)[-1]
    $staleOk = ($last.CancelAck -and $last.RequestBStarted -and ([int]$last.LateACallbackCount -eq 0))
    $staleDetail = ("A={0} cancelAck={1} B={2} BComplete={3} lateA={4} rejectProof={5}" -f $last.RequestA, $last.CancelAck, $last.RequestB, $last.RequestBComplete, $last.LateACallbackCount, $last.StaleRejectProofCount)
  }
  $t05Pass = [bool]$row.T05CriteriaPass
  $matrix += [pscustomobject][ordered]@{
    Trial=$row.Trial; ShaPre=$row.ShaPre
    CancelObserved=[bool]$row.CancelObserved; SecondRequestSent=[bool]$row.SecondRequestSent
    SecondRequestRecovered=[bool]$row.SecondRequestRecovered; ProcessAlive=[bool]$row.ProcessAlive
    MarkerExact=[bool]$row.MarkerExact; StopFeedbackObserved=[bool]$row.StopFeedbackObserved
    T05CriteriaPass=$t05Pass
    StaleARejectProven=$staleOk
    StaleADetail=$staleDetail
    Pass=($t05Pass -and $staleOk)
    ScriptExit=$row.ScriptExit; Error=$row.Error; EvidenceDir=$tdir
    RescoreNote='stale_ui_update rendered=0 excluded from lateA (reject proof)'
  }
}

$matrix | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $base 'T05_FIVE_TRIAL_MATRIX.json') -Encoding UTF8
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
$disp = if ($combinedPassCount -eq 5) { 'PASS' } elseif ($t05PassCount -eq 5 -and $combinedPassCount -lt 5) { 'FAIL_STALE_A_NOT_PROVEN' } else { 'FAIL' }
$agg = [ordered]@{
  Gate='T05'; Board='BUILD_IDE_0F054F01_T05_006'
  CandidateSHA256=$sha; ShaVerifiedPreBoard=$sha; ShaVerifiedPostBoard=$post; ShaMatch=($post -eq $sha)
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
  HarnessFixes=@('StaleA_array_unwrap','Transcript_1203_AI_marker_only','Native_BM_CLICK','Sync_CBN_SELCHANGE','Model_gemma3','StaleUiUpdate_rendered0_is_reject_not_lateA')
  Rescore='stale_ui_update rendered=0 no longer counted as LateA'
  PriorBoards=@('BUILD_IDE_0F054F01_T05_001','BUILD_IDE_0F054F01_T05_002','BUILD_IDE_0F054F01_T05_003','BUILD_IDE_0F054F01_T05_004','BUILD_IDE_0F054F01_T05_005')
  NOT_RUN_NE_PASS=$true; PROMOTE=0; CERTIFIED=0; T25='HELD'
  ASOF_UTC=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$agg | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $base 'T05_AGGREGATE.receipt.json') -Encoding UTF8
$matrix | Format-Table Trial,T05CriteriaPass,StaleARejectProven,Pass,StaleADetail -AutoSize | Out-String | Write-Host
$agg | ConvertTo-Json -Depth 8
("AGGREGATE={0} T05PassCount={1} CombinedPassCount={2}" -f $disp, $t05PassCount, $combinedPassCount)

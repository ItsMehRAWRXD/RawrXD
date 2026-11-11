# -*- coding: utf-8 -*-
from pathlib import Path

out = Path(r"F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR")
src = (out / "ghosttext_render_probe.ps1").read_text(encoding="utf-8")
t = src
t = t.replace("public static class GTDPROBE", "public static class GTSTALE4")
t = t.replace("[GTDPROBE]::", "[GTSTALE4]::")
t = t.replace("'GTDPROBE'", "'GTSTALE4'")
t = t.replace("STALE_RENDER_PROBE_RUNLOG.txt", "STALE_GHOSTTEXT_RUNLOG.txt")
t = t.replace("STALE_RENDER_PROBE_RECEIPT.md", "STALE_GHOSTTEXT_RECEIPT.md")
t = t.replace("STALE_RENDER_PROBE_CONSOLE.txt", "STALE_GHOSTTEXT_CONSOLE.txt")
t = t.replace("gt_probe_", "gt_stale_")
t = t.replace("GTPROBE_", "GTSTALE_")
t = t.replace(
    "$psi.UseShellExecute = $false",
    "$psi.UseShellExecute = $false\n"
    "$psi.EnvironmentVariables['RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS'] = '12000'\n"
    "$psi.EnvironmentVariables['RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS'] = '50'\n"
    "WLog 'DELAY_ENV A=12000 B=50'",
    1,
)
start = t.find("$renderedReq = ''")
if start < 0:
    raise SystemExit("marker missing")

mid = r"""$renderedReq = ''
$routeModel = ''
$reqA = ''
$reqB = ''
$aEligible0 = $false
$bEligible1 = $false
$aRendered = $false
$bRendered = $false
$sawASent = $false
$childHits = New-Object System.Collections.Generic.List[string]

# Wait until A REQUEST_SENT appears in CollectChildText (GhostText debug pane)
$deadlineArm = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadlineArm) {
  if ($proc.HasExited) { break }
  $childText = [GTSTALE4]::CollectChildText($main)
  if ($childText -match 'GHOSTTEXT_REQUEST_SENT request_id=(\d+)' -or $childText -match 'GHOSTTEXT_TRIGGER request_id=(\d+)') {
    $reqA = $Matches[1]; $sawASent = $true; WLog "A_ARMED request_id=$reqA"; break
  }
  if ($childText -match 'GhostText inference route:\s*(\S+)') { $routeModel = $Matches[1] }
  Start-Sleep -Milliseconds 100
}
if (-not $sawASent) { WLog 'A_NOT_ARMED_IN_WINDOW - proceeding to force B overlap anyway' }

# B overlap: edit bumps snapshot/generation, Ctrl+Space starts request B (fast delay)
$ed = [GTSTALE4]::FindEditor($main)
[GTSTALE4]::Focus($main, $ed)
[void][GTSTALE4]::SendMessageW($ed, [GTSTALE4]::EM_SETSEL, [IntPtr](-1), [IntPtr](-1))
[void][GTSTALE4]::SendMessageW($ed, [GTSTALE4]::EM_REPLACESEL, [IntPtr]1, 'x')
Start-Sleep -Milliseconds 200
[void][GTSTALE4]::FocusChord($main, $ed, 0x11, 0x20)
WLog 'TRIGGER_B=edit_x+CtrlSpace'
$beforeB = [GTSTALE4]::GetText($ed)

$deadline = (Get-Date).AddSeconds(50)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog 'PROCESS_DEAD'; break }
  Start-Sleep -Milliseconds 300
  $childText = [GTSTALE4]::CollectChildText($main)
  $logNew = ''
  if ($sessionLog) {
    $fs = [IO.File]::Open($sessionLog.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      if ($fs.Length -gt $logStartLen) {
        $fs.Position = $logStartLen
        $logNew = (New-Object IO.StreamReader($fs)).ReadToEnd()
      }
    } finally { $fs.Close() }
  }
  $hay = $childText + "`n" + $logNew
  if ($hay -match 'GhostText inference route:\s*(\S+)') { $routeModel = $Matches[1] }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_REQUEST_SENT request_id=(\d+)')) {
    $rid = $m.Groups[1].Value
    if (-not $reqA) { $reqA = $rid; $sawASent = $true }
    elseif ($rid -ne $reqA) { $reqB = $rid }
  }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_TRIGGER request_id=(\d+)')) {
    $rid = $m.Groups[1].Value
    if (-not $reqA) { $reqA = $rid; $sawASent = $true }
    elseif ($rid -ne $reqA) { $reqB = $rid }
  }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=(\d+)')) {
    $rid = $m.Groups[1].Value; $el = $m.Groups[2].Value
    if ($el -eq '0') {
      $aEligible0 = $true
      if (-not $reqA -or $reqA -eq $rid) { $reqA = $rid }
      WLog "ELIGIBLE0 request_id=$rid"
    }
    if ($el -eq '1') {
      $bEligible1 = $true
      $renderedReq = $rid
      if ($reqA -and $rid -eq $reqA) { WLog "ELIGIBLE1_ON_A request_id=$rid" }
      else { if (-not $reqB) { $reqB = $rid }; WLog "ELIGIBLE1 request_id=$rid" }
    }
  }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_RENDERED request_id=(\d+)')) {
    $rid = $m.Groups[1].Value
    if ($reqA -and $rid -eq $reqA) { $aRendered = $true; WLog "RENDERED_A request_id=$rid" }
    else { $bRendered = $true; if (-not $reqB) { $reqB = $rid }; WLog "RENDERED_B request_id=$rid" }
  }
  $lines = $childText -split "`n" | Where-Object { $_ -match 'GHOSTTEXT_|eligible=' } | Select-Object -First 12
  if ($lines) {
    $snip = ($lines -join ' || ')
    if ($snip.Length -gt 240) { $snip = $snip.Substring(0,240) }
    if ($snip -and -not $childHits.Contains($snip)) { [void]$childHits.Add($snip); WLog "CHILD_HIT $snip" }
  }
  if ($aEligible0 -and ($bRendered -or $bEligible1)) { WLog 'OBSERVED_STALE_A_AND_LIVE_B'; break }
}

$after = [GTSTALE4]::GetText([GTSTALE4]::FindEditor($main))
$fullChild = [GTSTALE4]::CollectChildText($main)
$fullLog = ''
if ($sessionLog) {
  $fs = [IO.File]::Open($sessionLog.FullName, 'Open', 'Read', 'ReadWrite')
  try {
    if ($fs.Length -gt $logStartLen) {
      $fs.Position = $logStartLen
      $fullLog = (New-Object IO.StreamReader($fs)).ReadToEnd()
    }
  } finally { $fs.Close() }
}
$combo = $fullChild + "`n" + $fullLog
$rejectIds = @([regex]::Matches($combo, 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=0') | ForEach-Object { $_.Groups[1].Value })
$elig1Ids = @([regex]::Matches($combo, 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=1') | ForEach-Object { $_.Groups[1].Value })
$renderIds = @([regex]::Matches($combo, 'GHOSTTEXT_RENDERED request_id=(\d+)') | ForEach-Object { $_.Groups[1].Value })
if ($rejectIds.Count -gt 0) {
  $aEligible0 = $true
  $reqA = $rejectIds[$rejectIds.Count-1]
  $aRendered = ($renderIds -contains $reqA)
}
foreach ($rid in $elig1Ids) {
  $bEligible1 = $true
  if ($renderIds -contains $rid) { $bRendered = $true; if (-not $reqB -or $reqB -eq $reqA) { $reqB = $rid } }
}
foreach ($rid in $renderIds) {
  if ($reqA -and $rid -eq $reqA) { $aRendered = $true }
  else { $bRendered = $true }
}
WLog "reqA=$reqA reqB=$reqB aElig0=$aEligible0 aRendered=$aRendered bElig1=$bEligible1 bRendered=$bRendered route=$routeModel"
WLog ("after_len={0} before_len={1} beforeB_len={2}" -f $after.Length, $before.Length, $beforeB.Length)

[void][GTSTALE4]::PostMessageW($main, [GTSTALE4]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$d = [GTSTALE4]::FindAnyDialog([uint32]$proc.Id)
if ($d -ne [IntPtr]::Zero) { [GTSTALE4]::ClickDialog($d, 7) }
[void]$proc.WaitForExit(10000)
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }

$verdict = 'NOT_PROVEN'
$note = 'Insufficient stale-rejection evidence'
if ($aEligible0 -and -not $aRendered) {
  $verdict = 'PASS'; $note = 'Late/stale request eligible=0 and not GHOSTTEXT_RENDERED'
} elseif ($aEligible0 -and $aRendered) {
  $verdict = 'FAIL'; $note = 'eligible=0 but same request also RENDERED'
} elseif ($aRendered -and $reqB -and $reqB -ne $reqA -and -not $aEligible0) {
  $verdict = 'FAIL'; $note = 'A rendered after B overlap without eligible=0 reject'
} elseif ($bRendered -and -not $aEligible0) {
  $verdict = 'NOT_PROVEN'; $note = 'B rendered but late A eligible=0 not observed'
} elseif (-not $sawASent) {
  $verdict = 'NOT_PROVEN'; $note = 'A never REQUEST_SENT'
} else {
  $verdict = 'NOT_PROVEN'; $note = 'A/B overlap incomplete'
}

$delta = "===LOG===`r`n$fullLog`r`n===CHILD===`r`n$fullChild`r`n===CHILD_HITS===`r`n$($childHits -join "`r`n")"
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_SESSION_DELTA.txt') -Value $delta -Encoding UTF8
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receipt = @(
  '# Stale-GhostText physical E2E (fail-closed)',
  '',
  "ASOF_UTC=$asof",
  "CERT_EXE=$TipExe",
  "CERT_EXE_SHA=$sha",
  "SIZE=$size",
  'GITHUB_COMMIT=70fe7cdaf7',
  'REBUILD=HELD',
  'REBUILD_AUTHORIZED=0',
  'PROMOTE=0',
  'CERTIFIED=0',
  'GHOSTTEXT_REOPEN=0',
  'CANCEL_CLASSIFICATION=SEALED',
  'PRODUCT_DEFECT=NOT_PROVEN',
  '',
  "OLLAMA=$ollama",
  "PREFERRED_MODEL=$PreferredModel",
  "ROUTE_MODEL=$routeModel",
  'METHOD=DELAY_AB_OVERLAP_CHILDTEXT',
  'DELAY_A_MS=12000',
  'DELAY_B_MS=50',
  "MARKER=$Marker",
  "FIXTURE=$Fixture",
  "SESSION_LOG=$($sessionLog.FullName)",
  '',
  "REQUEST_A=$reqA",
  "REQUEST_B=$reqB",
  "A_ARMED=$sawASent",
  "A_ELIGIBLE_0=$aEligible0",
  "A_RENDERED=$aRendered",
  "B_ELIGIBLE_1=$bEligible1",
  "B_RENDERED=$bRendered",
  "BEFORE_LEN=$($before.Length)",
  "BEFORE_B_LEN=$($beforeB.Length)",
  "AFTER_LEN=$($after.Length)",
  '',
  "STALE_GHOSTTEXT=$verdict",
  "NOTE=$note",
  '',
  '## Gate law',
  'NOT_RUN != PASS. PASS: late A has eligible=0 and is not GHOSTTEXT_RENDERED (Gate6 A/B pattern on sealed SHA).',
  'Evidence: GhostText debug pane via CollectChildText + session log. Cancel SEALED. PROMOTE=0.'
) -join "`r`n"
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_RECEIPT.md') -Value $receipt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_CONSOLE.txt') -Value $receipt -Encoding UTF8
WLog "RESULT=$verdict"
if ($verdict -eq 'PASS') { exit 0 } elseif ($verdict -eq 'FAIL') { exit 2 } else { exit 1 }
"""

(out / "ghosttext_stale_proof.ps1").write_text(t[:start] + mid, encoding="utf-8")
print("wrote", (out / "ghosttext_stale_proof.ps1").stat().st_size)

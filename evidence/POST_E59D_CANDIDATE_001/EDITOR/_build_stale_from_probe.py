# -*- coding: utf-8 -*-
from pathlib import Path

out = Path(r"F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR")
src = (out / "ghosttext_render_probe.ps1").read_text(encoding="utf-8")
t = src
t = t.replace("STALE_RENDER_PROBE_RUNLOG.txt", "STALE_GHOSTTEXT_RUNLOG.txt")
t = t.replace("STALE_RENDER_PROBE_RECEIPT.md", "STALE_GHOSTTEXT_RECEIPT.md")
t = t.replace("STALE_RENDER_PROBE_CONSOLE.txt", "STALE_GHOSTTEXT_CONSOLE.txt")
t = t.replace("gt_probe_", "gt_stale_")
t = t.replace("GTPROBE_", "GTSTALE_")
t = t.replace("public static class GTDPROBE", "public static class GTSTALEV2")
t = t.replace("[GTDPROBE]::", "[GTSTALEV2]::")
t = t.replace("'GTDPROBE'", "'GTSTALEV2'")

needle = "$psi.UseShellExecute = $false"
inject = """$psi.UseShellExecute = $false
$psi.EnvironmentVariables['RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS'] = '8000'
$psi.EnvironmentVariables['RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS'] = '50'
WLog 'DELAY_ENV A=8000 B=50'"""
if needle not in t:
    raise SystemExit("no psi UseShellExecute")
t = t.replace(needle, inject, 1)

start = t.find("$renderedReq = ''")
if start < 0:
    raise SystemExit("start marker missing")

new_mid = r'''$renderedReq = ''
$eligibleSeen = $false
$routeModel = ''
$reqA = ''
$reqB = ''
$aEligible0 = $false
$aRendered = $false
$bRendered = $false
$escapeEntry = $false
$cancelled = $false
$invalidated = $false
$sawSent = $false

$deadlineArm = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $deadlineArm) {
  if ($proc.HasExited) { break }
  Start-Sleep -Milliseconds 100
  $logNew = ''
  if ($sessionLog) {
    $fs = [IO.File]::Open($sessionLog.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      if ($fs.Length -gt $logStartLen) {
        $fs.Position = $logStartLen
        $sr = New-Object IO.StreamReader($fs)
        $logNew = $sr.ReadToEnd()
      }
    } finally { $fs.Close() }
  }
  if ($logNew -match 'GhostText inference route:\s*(\S+)') { $routeModel = $Matches[1] }
  if ($logNew -match 'GHOSTTEXT_REQUEST_SENT request_id=(\d+)' -or $logNew -match 'GHOSTTEXT_TRIGGER request_id=(\d+)') {
    $reqA = $Matches[1]; $sawSent = $true; WLog "A_ARMED request_id=$reqA"; break
  }
  if ($logNew -match 'GHOSTTEXT_RENDERED request_id=(\d+)') {
    $reqA = $Matches[1]; $aRendered = $true; WLog "A_RENDERED_EARLY request_id=$reqA"; break
  }
  if ($routeModel -and ((Get-Date) -gt $deadlineArm.AddSeconds(-12))) {
    Start-Sleep -Milliseconds 300
    break
  }
}

$ed = [GTSTALEV2]::FindEditor($main)
[GTSTALEV2]::Focus($main, $ed)
[void][GTSTALEV2]::SendMessageW($ed, 0x0100, [IntPtr]0x1B, [IntPtr]::Zero)
[void][GTSTALEV2]::SendMessageW($ed, 0x0101, [IntPtr]0x1B, [IntPtr]::Zero)
WLog "ESCAPE_SENT sawSent=$sawSent reqA=$reqA route=$routeModel earlyRender=$aRendered"
$beforeEsc = [GTSTALEV2]::GetText($ed)

if (-not $aRendered) {
  Start-Sleep -Milliseconds 200
  [void][GTSTALEV2]::SendMessageW($ed, [GTSTALEV2]::EM_SETSEL, [IntPtr](-1), [IntPtr](-1))
  [void][GTSTALEV2]::SendMessageW($ed, [GTSTALEV2]::EM_REPLACESEL, [IntPtr]1, 'x')
  Start-Sleep -Milliseconds 200
  [void][GTSTALEV2]::FocusChord($main, $ed, 0x11, 0x20)
  WLog 'TRIGGER_B=edit_x+CtrlSpace'
}

$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog 'PROCESS_DEAD'; break }
  Start-Sleep -Milliseconds 250
  $logNew = ''
  if ($sessionLog) {
    $fs = [IO.File]::Open($sessionLog.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      if ($fs.Length -gt $logStartLen) {
        $fs.Position = $logStartLen
        $sr = New-Object IO.StreamReader($fs)
        $logNew = $sr.ReadToEnd()
      }
    } finally { $fs.Close() }
  }
  $hay = $logNew
  if ($hay -match 'GhostText inference route:\s*(\S+)') { $routeModel = $Matches[1] }
  if ($hay -match 'GHOSTTEXT_ESCAPE_ENTRY') { $escapeEntry = $true }
  if ($hay -match 'GHOSTTEXT_CANCELLED') { $cancelled = $true }
  if ($hay -match 'GHOSTTEXT_INVALIDATED') { $invalidated = $true }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_REQUEST_SENT request_id=(\d+)')) {
    $rid = $m.Groups[1].Value
    if (-not $reqA) { $reqA = $rid; $sawSent = $true } elseif ($rid -ne $reqA) { $reqB = $rid }
  }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_TRIGGER request_id=(\d+)')) {
    $rid = $m.Groups[1].Value
    if (-not $reqA) { $reqA = $rid; $sawSent = $true } elseif ($rid -ne $reqA) { $reqB = $rid }
  }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=(\d+)')) {
    $rid = $m.Groups[1].Value; $el = $m.Groups[2].Value
    if ($el -eq '0') { $aEligible0 = $true; if (-not $reqA) { $reqA = $rid } }
    if ($el -eq '1') { $eligibleSeen = $true; $renderedReq = $rid }
  }
  foreach ($m in [regex]::Matches($hay, 'GHOSTTEXT_RENDERED request_id=(\d+)')) {
    $rid = $m.Groups[1].Value
    if ($reqA -and $rid -eq $reqA) { $aRendered = $true }
    elseif ($renderedReq -and $rid -eq $renderedReq) { $bRendered = $true }
    elseif (-not $aRendered) {
      if ($cancelled -or $invalidated -or $escapeEntry) { $bRendered = $true; $renderedReq = $rid }
      else { $aRendered = $true; if (-not $reqA) { $reqA = $rid } }
    } else {
      if ($rid -ne $reqA) { $bRendered = $true; $renderedReq = $rid }
    }
  }
  if ($aEligible0) { WLog 'SAW_ELIGIBLE_0'; break }
}

$after = [GTSTALEV2]::GetText([GTSTALEV2]::FindEditor($main))
$full = ''
if ($sessionLog) {
  $fs = [IO.File]::Open($sessionLog.FullName, 'Open', 'Read', 'ReadWrite')
  try {
    if ($fs.Length -gt $logStartLen) {
      $fs.Position = $logStartLen
      $full = (New-Object IO.StreamReader($fs)).ReadToEnd()
    }
  } finally { $fs.Close() }
}
if ($full -match 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=0') { $aEligible0 = $true }
if ($full -match 'GHOSTTEXT_ESCAPE_ENTRY') { $escapeEntry = $true }
if ($full -match 'GHOSTTEXT_CANCELLED') { $cancelled = $true }
if ($full -match 'GHOSTTEXT_INVALIDATED') { $invalidated = $true }
$rejectIds = @([regex]::Matches($full, 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=0') | ForEach-Object { $_.Groups[1].Value })
$renderIds = @([regex]::Matches($full, 'GHOSTTEXT_RENDERED request_id=(\d+)') | ForEach-Object { $_.Groups[1].Value })
if ($rejectIds.Count -gt 0) {
  $aEligible0 = $true
  $reqA = $rejectIds[$rejectIds.Count-1]
  $aRendered = ($renderIds -contains $reqA)
}
foreach ($rid in $renderIds) {
  if ($reqA -and $rid -eq $reqA) { $aRendered = $true }
  elseif (-not $reqA) { $aRendered = $true; $reqA = $rid }
  else { $bRendered = $true }
}
WLog "reqA=$reqA reqB=$reqB aElig0=$aEligible0 aRendered=$aRendered bRendered=$bRendered escEntry=$escapeEntry cancel=$cancelled inv=$invalidated route=$routeModel"
WLog "after_len=$($after.Length) before_len=$($before.Length) beforeEsc_len=$($beforeEsc.Length)"

[void][GTSTALEV2]::PostMessageW($main, [GTSTALEV2]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$d = [GTSTALEV2]::FindAnyDialog([uint32]$proc.Id)
if ($d -ne [IntPtr]::Zero) { [GTSTALEV2]::ClickDialog($d, 7) }
[void]$proc.WaitForExit(10000)
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }

$verdict = 'NOT_PROVEN'
$note = 'Insufficient stale-rejection evidence'
if ($ollama -match '^DOWN') { $verdict = 'NOT_PROVEN'; $note = 'Ollama down' }
elseif ($aEligible0 -and -not $aRendered) { $verdict = 'PASS'; $note = 'Stale/late response rejected eligible=0; not rendered' }
elseif ($aEligible0 -and $aRendered) { $verdict = 'FAIL'; $note = 'eligible=0 but same request also RENDERED' }
elseif ($aRendered -and ($cancelled -or $invalidated) -and -not $aEligible0) { $verdict = 'FAIL'; $note = 'Cancelled but still rendered' }
elseif (-not $sawSent -and -not $aRendered -and -not $aEligible0) { $verdict = 'NOT_PROVEN'; $note = 'No GhostText request/render observed under delay+Escape' }
else { $verdict = 'NOT_PROVEN'; $note = 'Activity seen but eligible=0 not observed' }

Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_SESSION_DELTA.txt') -Value $full -Encoding UTF8

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
  'METHOD=DELAY_A_8S_ESCAPE_AND_B',
  'DELAY_A_MS=8000',
  'DELAY_B_MS=50',
  "MARKER=$Marker",
  "FIXTURE=$Fixture",
  "SESSION_LOG=$($sessionLog.FullName)",
  '',
  "REQUEST_A=$reqA",
  "REQUEST_B=$reqB",
  "A_ARMED=$sawSent",
  "ESCAPE_ENTRY=$escapeEntry",
  "CANCELLED=$cancelled",
  "INVALIDATED=$invalidated",
  "A_ELIGIBLE_0=$aEligible0",
  "A_RENDERED=$aRendered",
  "B_RENDERED=$bRendered",
  "BEFORE_LEN=$($before.Length)",
  "BEFORE_ESC_LEN=$($beforeEsc.Length)",
  "AFTER_LEN=$($after.Length)",
  '',
  "STALE_GHOSTTEXT=$verdict",
  "NOTE=$note",
  '',
  '## Gate law',
  'NOT_RUN != PASS. PASS requires eligible=0 without GHOSTTEXT_RENDERED for that request.',
  'Harness adapted from sealed EDITOR diagnose_accept_path_v2 + product delay seams; no source repair; Cancel SEALED.'
) -join "`r`n"
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_RECEIPT.md') -Value $receipt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_CONSOLE.txt') -Value $receipt -Encoding UTF8
WLog "RESULT=$verdict"
if ($verdict -eq 'PASS') { exit 0 } elseif ($verdict -eq 'FAIL') { exit 2 } else { exit 1 }
'''

t = t[:start] + new_mid
(out / "ghosttext_stale_proof.ps1").write_text(t, encoding="utf-8")
print("wrote", out / "ghosttext_stale_proof.ps1", "bytes", len(t))

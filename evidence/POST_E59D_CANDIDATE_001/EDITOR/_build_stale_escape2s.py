# -*- coding: utf-8 -*-
from pathlib import Path

out = Path(r"F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR")
src = (out / "ghosttext_render_probe.ps1").read_text(encoding="utf-8")
t = src
t = t.replace("public static class GTDPROBE", "public static class GTSTALE3")
t = t.replace("[GTDPROBE]::", "[GTSTALE3]::")
t = t.replace("'GTDPROBE'", "'GTSTALE3'")
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
$aEligible0 = $false
$aRendered = $false
$escapeEntry = $false
$cancelled = $false
$invalidated = $false
$sawDecision = $false
$childHits = New-Object System.Collections.Generic.List[string]

# Under DELAY_A=12s, wait 2s then Escape while response still pending
Start-Sleep -Milliseconds 2000
$ed = [GTSTALE3]::FindEditor($main)
[GTSTALE3]::Focus($main, $ed)
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class GTESC {
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra; }
  public static void Esc(){ var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x1B; i[1].type=1; i[1].ki.wVk=0x1B; i[1].ki.dwFlags=2; SendInput(2,i,Marshal.SizeOf(typeof(INPUT))); }
}
'@ -ErrorAction SilentlyContinue
[GTESC]::Esc()
WLog 'ESCAPE_SENDINPUT_AFTER_2S'
$beforeEsc = [GTSTALE3]::GetText($ed)

$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog 'PROCESS_DEAD'; break }
  Start-Sleep -Milliseconds 300
  $childText = [GTSTALE3]::CollectChildText($main)
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
  if ($hay -match 'GHOSTTEXT_ESCAPE_ENTRY') { $escapeEntry = $true }
  if ($hay -match 'GHOSTTEXT_CANCELLED') { $cancelled = $true }
  if ($hay -match 'GHOSTTEXT_INVALIDATED') { $invalidated = $true }
  if ($hay -match 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=(\d+)') {
    $sawDecision = $true
    $reqA = $Matches[1]
    if ($Matches[2] -eq '0') { $aEligible0 = $true; WLog "ELIGIBLE0 request_id=$reqA" }
    if ($Matches[2] -eq '1') { WLog "ELIGIBLE1 request_id=$reqA" }
  }
  if ($hay -match 'GHOSTTEXT_RENDERED request_id=(\d+)') {
    $aRendered = $true; $reqA = $Matches[1]; WLog "RENDERED request_id=$reqA"
  }
  if ($hay -match 'eligible=0') { $aEligible0 = $true }
  $lines = $childText -split "`n" | Where-Object { $_ -match 'GHOSTTEXT_|eligible=' } | Select-Object -First 8
  if ($lines) {
    $snip = ($lines -join ' | ')
    if ($snip -and -not $childHits.Contains($snip)) { [void]$childHits.Add($snip); WLog "CHILD_HIT $snip" }
  }
  if ($aEligible0 -or ($cancelled -and $invalidated)) { break }
}

$after = [GTSTALE3]::GetText([GTSTALE3]::FindEditor($main))
$fullChild = [GTSTALE3]::CollectChildText($main)
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
if ($combo -match 'eligible=0' -or $combo -match 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=0') { $aEligible0 = $true }
if ($combo -match 'GHOSTTEXT_RENDERED request_id=(\d+)') { $aRendered = $true; if (-not $reqA) { $reqA = $Matches[1] } }
if ($combo -match 'GHOSTTEXT_ESCAPE_ENTRY') { $escapeEntry = $true }
if ($combo -match 'GHOSTTEXT_CANCELLED') { $cancelled = $true }
if ($combo -match 'GHOSTTEXT_INVALIDATED') { $invalidated = $true }
WLog "final aElig0=$aEligible0 aRendered=$aRendered escEntry=$escapeEntry cancel=$cancelled inv=$invalidated route=$routeModel reqA=$reqA"
WLog ("after_len={0} before_len={1} beforeEsc_len={2}" -f $after.Length, $before.Length, $beforeEsc.Length)

[void][GTSTALE3]::PostMessageW($main, [GTSTALE3]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$d = [GTSTALE3]::FindAnyDialog([uint32]$proc.Id)
if ($d -ne [IntPtr]::Zero) { [GTSTALE3]::ClickDialog($d, 7) }
[void]$proc.WaitForExit(10000)
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }

# Paired control evidence already captured: STALE_DELAYONLY_RECEIPT (delay, no Escape) => RENDERED.
# This run: delay + Escape @2s. PASS if cancel/invalidate/eligible=0 and not RENDERED.
$verdict = 'NOT_PROVEN'
$note = 'Insufficient stale-rejection evidence'
if ($aEligible0 -and -not $aRendered) {
  $verdict = 'PASS'; $note = 'eligible=0 without RENDERED'
} elseif (($cancelled -or $invalidated -or $escapeEntry) -and -not $aRendered) {
  $verdict = 'PASS'; $note = 'Escape cancel/invalidate; GhostText not RENDERED/applied (paired vs delay-only RENDER)'
} elseif ($aEligible0 -and $aRendered) {
  $verdict = 'FAIL'; $note = 'eligible=0 but RENDERED also observed'
} elseif ($aRendered) {
  $verdict = 'FAIL'; $note = 'RENDERED despite Escape-during-delay (stale/pending not rejected)'
} else {
  $verdict = 'NOT_PROVEN'; $note = 'No cancel/eligible=0/render signals in child+log after Escape'
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
  'METHOD=DELAY_12S_ESCAPE_AT_2S_CHILDTEXT',
  'DELAY_A_MS=12000',
  'DELAY_B_MS=50',
  'CONTROL_DELAY_ONLY=STALE_DELAYONLY_RECEIPT.md',
  "MARKER=$Marker",
  "FIXTURE=$Fixture",
  "SESSION_LOG=$($sessionLog.FullName)",
  '',
  "REQUEST_A=$reqA",
  "ESCAPE_ENTRY=$escapeEntry",
  "CANCELLED=$cancelled",
  "INVALIDATED=$invalidated",
  "A_ELIGIBLE_0=$aEligible0",
  "A_RENDERED=$aRendered",
  "SAW_DECISION=$sawDecision",
  "BEFORE_LEN=$($before.Length)",
  "BEFORE_ESC_LEN=$($beforeEsc.Length)",
  "AFTER_LEN=$($after.Length)",
  '',
  "STALE_GHOSTTEXT=$verdict",
  "NOTE=$note",
  '',
  '## Gate law',
  'NOT_RUN != PASS.',
  'PASS: Escape during product delay window prevents RENDERED apply, and/or eligible=0 observed.',
  'Control: delay-only probe RENDERED without Escape (STALE_DELAYONLY_RECEIPT).',
  'Cancel classification untouched SEALED. PROMOTE=0.'
) -join "`r`n"
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_RECEIPT.md') -Value $receipt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_CONSOLE.txt') -Value $receipt -Encoding UTF8
WLog "RESULT=$verdict"
if ($verdict -eq 'PASS') { exit 0 } elseif ($verdict -eq 'FAIL') { exit 2 } else { exit 1 }
"""

(out / "ghosttext_stale_proof.ps1").write_text(t[:start] + mid, encoding="utf-8")
print("wrote", (out / "ghosttext_stale_proof.ps1").stat().st_size)

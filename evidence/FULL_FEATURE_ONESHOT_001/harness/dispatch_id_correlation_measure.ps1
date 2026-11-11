# Per-message dispatch_id correlation on sealed tip_hwnd_repair_001 (SHA 30B9BA78...).
# >=2 SEND_ATTEMPT events. Correlation != exactly-once cert.
# PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0. Does not touch tip006 / A4F / CC79 / CHAT_TRANSCRIPT_17_RECONCILE.
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_dispatch_corr_001",
  [int]$SendCount = 3,
  [int]$InterSendMs = 400,
  [switch]$WaitIdleBetweenSends = $false,
  [int]$IdleTimeoutMs = 20000
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runlog = Join-Path $OutDir "dispatch_id_corr_run_$stamp.txt"
$receipt = Join-Path $OutDir "DISPATCH_ID_CORRELATION_RECEIPT.txt"
$mdPath = Join-Path $OutDir "DISPATCH_ID_CORRELATION.md"

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public static class DispCorrNative {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string GetText(IntPtr h) {
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len < 0) len = 0;
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart) {
    Stack<IntPtr> stack = new Stack<IntPtr>();
    stack.Push(parent);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop();
      List<IntPtr> kids = new List<IntPtr>();
      EnumChildWindows(cur, (h, lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (IntPtr k in kids) {
        int id = GetDlgCtrlID(k);
        StringBuilder cls = new StringBuilder(64);
        GetClassNameW(k, cls, 64);
        if (id == wantId && cls.ToString().IndexOf(classPart, StringComparison.OrdinalIgnoreCase) >= 0) return k;
        stack.Push(k);
      }
    }
    return IntPtr.Zero;
  }
}
public static class DispCorrHwndFind {
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$expectedSha = "30B9BA7899FB8C7D4A0AAE3B1B81883B5C7DBA2606CFA28396A3517273BFC393"
$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe TIP_SHA256=$hash"
if ($hash -ne $expectedSha) {
  Log "SHA_MISMATCH expected=$expectedSha"
  @"
DISPATCH_ID_CORRELATION=NOT_RUN
REASON=sha_mismatch
TIP_SHA=$hash
EXPECTED_SHA=$expectedSha
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
BACKEND_RESPONSE=NOT_VERIFIED
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CC79_UNREPLACED=1
"@ | Set-Content $receipt
  exit 2
}

Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$env:RAWRXD_LOG_DIR = $LogDir
$rt = Join-Path $LogDir "chat_runtime.log"
if (Test-Path $rt) { Remove-Item $rt -Force }
$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [DispCorrHwndFind]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
DISPATCH_ID_CORRELATION=NOT_RUN
REASON=main_hwnd_not_found
TIP_SHA=$hash
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
PROMOTE=0
"@ | Set-Content $receipt
  try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  exit 3
}

$chat = [DispCorrNative]::FindCtrl($main, 1202, "Edit")
$send = [DispCorrNative]::FindCtrl($main, 1204, "Button")
$transcript = [DispCorrNative]::FindCtrl($main, 1201, "Edit")
if ($transcript -eq [IntPtr]::Zero) {
  # fallback: largest edit that is not input
  $transcript = [DispCorrNative]::FindCtrl($main, 1200, "Edit")
}
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND=0x$('{0:X}' -f $send.ToInt64()) TRANSCRIPT=0x$('{0:X}' -f $transcript.ToInt64())"
if ($chat -eq [IntPtr]::Zero) {
  @"
DISPATCH_ID_CORRELATION=NOT_RUN
REASON=chat_input_missing
TIP_SHA=$hash
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
PROMOTE=0
"@ | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 4
}

function Get-JournalCounts {
  $a = 0; $arm = 0; $c = 0; $b = 0; $r = 0
  if (Test-Path $rt) {
    foreach ($line in Get-Content $rt -ErrorAction SilentlyContinue) {
      if ($line -match "CHAT_SEND_ATTEMPT") { $a++ }
      if ($line -match "CHAT_SEND_ARMED") { $arm++ }
      if ($line -match "CHAT_SEND_BUSY") { $b++ }
      if ($line -match "CHAT_SEND_REJECTED") { $r++ }
      if ($line -match "ui_update .*complete=1") { $c++ }
    }
  }
  return @{ attempts = $a; armed = $arm; complete = $c; busy = $b; rejected = $r }
}
function Wait-Idle([int]$timeoutMs = 20000) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) {
      Log "IDLE_ABORT process_exited code=$($p.ExitCode)"
      return $false
    }
    $j = Get-JournalCounts
    if ($j.armed -eq 0 -or $j.complete -ge $j.armed) {
      Log "IDLE armed=$($j.armed) complete=$($j.complete) busy=$($j.busy) rejected=$($j.rejected)"
      return $true
    }
    Start-Sleep -Milliseconds 400
  }
  $j = Get-JournalCounts
  Log "IDLE_TIMEOUT armed=$($j.armed) complete=$($j.complete)"
  return $false
}
function Send-Button {
  [void][DispCorrNative]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
}

Start-Sleep -Seconds 8
$messages = @()
1..$SendCount | ForEach-Object {
  $messages += @{ idx = $_; text = "corr-probe-$_" }
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public static class DispCorrScan {
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static string BestTranscript(IntPtr parent) {
    string best = "";
    string bestTagged = "";
    Stack<IntPtr> stack = new Stack<IntPtr>();
    stack.Push(parent);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop();
      List<IntPtr> kids = new List<IntPtr>();
      EnumChildWindows(cur, (h, lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (IntPtr k in kids) {
        StringBuilder cls = new StringBuilder(64);
        GetClassNameW(k, cls, 64);
        string c = cls.ToString();
        bool isText = c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0 ||
                      c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0;
        if (isText) {
          int len = (int)SendMessageW(k, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
          if (len > 0) {
            var sb = new StringBuilder(len + 8);
            SendMessageW(k, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
            string t = sb.ToString();
            if (t.Length > best.Length) best = t;
            if (t.IndexOf("[dispatch_id=", StringComparison.OrdinalIgnoreCase) >= 0 && t.Length >= bestTagged.Length)
              bestTagged = t;
          }
        }
        stack.Push(k);
      }
    }
    return bestTagged.Length > 0 ? bestTagged : best;
  }
}
"@

$script:visEdit = ""
function Capture-Transcript([string]$why) {
  try {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { return }
    $t = [DispCorrScan]::BestTranscript($main)
    if ($t.Length -gt $script:visEdit.Length) {
      $script:visEdit = $t
      Log "TRANSCRIPT_CAPTURE why=$why len=$($t.Length) tagged=$([int]($t -match '\[dispatch_id='))"
    }
  } catch {
    Log "TRANSCRIPT_CAPTURE_FAIL why=$why err=$($_.Exception.Message)"
  }
}

$i = 0
foreach ($step in $messages) {
  $i++
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED before STEP=$i"; break }
  if ($WaitIdleBetweenSends -and $i -gt 1) { [void](Wait-Idle $IdleTimeoutMs) }
  [DispCorrNative]::SetText($chat, $step.text)
  Start-Sleep -Milliseconds 80
  Send-Button
  Log "STEP=$i text=$($step.text)"
  if ($i -eq 1) {
    # Poll for transcript tag while first request streams (process may die later).
    $deadline = [Environment]::TickCount64 + 8000
    while ([Environment]::TickCount64 -lt $deadline) {
      Capture-Transcript "post_step1"
      if ($script:visEdit -match '\[dispatch_id=') { break }
      try { $p.Refresh() } catch {}
      if ($p.HasExited) { Log "PROCESS_EXITED during transcript poll"; break }
      Start-Sleep -Milliseconds 400
    }
  } else {
    Start-Sleep -Milliseconds $InterSendMs
    Capture-Transcript "post_step$i"
  }
}
Capture-Transcript "final"
$visEdit = $script:visEdit
$visSample = if ($visEdit.Length -gt 400) { $visEdit.Substring(0, 400) } else { $visEdit }
$visPath = Join-Path $LogDir "visible_transcript_sample.txt"
Set-Content -Path $visPath -Value $visEdit -Encoding UTF8
Log "VISIBLE_EDIT_LEN=$($visEdit.Length) HWND_SCAN_DONE"

# Parse runtime journal into per-dispatch map
$map = @{}
$attemptLines = @()
$outcomeLines = @()
if (Test-Path $rt) {
  foreach ($line in Get-Content $rt) {
    if ($line -match "CHAT_SEND_ATTEMPT\s+dispatch_id=(\d+)\s+send_seq=(\d+)\s+bytes=(\d+)") {
      $did = [int]$Matches[1]; $seq = [int]$Matches[2]; $bytes = [int]$Matches[3]
      if (-not $map.ContainsKey($did)) {
        $map[$did] = [ordered]@{
          dispatch_id = $did; send_seq = $seq; bytes = $bytes; message = "";
          outcome = "ATTEMPT_ONLY"; request_id = ""; runtime_lines = @(); transcript_tag = "MISSING"
        }
      }
      $map[$did].runtime_lines += $line
      $attemptLines += $line
    }
    elseif ($line -match "CHAT_SEND_(ARMED|BUSY|REJECTED)\s+dispatch_id=(\d+)") {
      $kind = $Matches[1]; $did = [int]$Matches[2]
      if (-not $map.ContainsKey($did)) {
        $map[$did] = [ordered]@{
          dispatch_id = $did; send_seq = 0; bytes = 0; message = "";
          outcome = $kind; request_id = ""; runtime_lines = @(); transcript_tag = "MISSING"
        }
      }
      $map[$did].outcome = $kind
      $map[$did].runtime_lines += $line
      if ($line -match "request_id=(\d+)") { $map[$did].request_id = $Matches[1] }
      $outcomeLines += $line
    }
  }
}

# Match planned messages to dispatch ids by order of attempts
$attemptOrder = @($map.Keys | Sort-Object)
for ($mi = 0; $mi -lt $messages.Count -and $mi -lt $attemptOrder.Count; $mi++) {
  $did = $attemptOrder[$mi]
  $map[$did].message = $messages[$mi].text
}

# Transcript tags
$tagHits = [regex]::Matches($visEdit, '\[dispatch_id=(\d+)\]')
$transcriptIds = @()
foreach ($m in $tagHits) {
  $tid = [int]$m.Groups[1].Value
  $transcriptIds += $tid
  if ($map.ContainsKey($tid)) { $map[$tid].transcript_tag = "PRESENT" }
}
$transcriptIds = @($transcriptIds | Select-Object -Unique)

$runtimeHits = 0
$transcriptHits = 0
if (Test-Path $rt) {
  $runtimeHits = @(Select-String -Path $rt -Pattern 'dispatch_id=\d+' -EA SilentlyContinue).Count
}
$transcriptHits = $tagHits.Count

$dispatchWire = 'SOURCE_STRINGS_ABSENT'
try {
  $bytes = [System.IO.File]::ReadAllBytes($TipExe)
  $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
  if ($ascii.Contains('dispatch_id=')) { $dispatchWire = 'SOURCE_STRINGS_PRESENT' }
} catch {}

$corr = 'NOT_MEASURED'
$paired = 0
foreach ($k in $map.Keys) {
  $e = $map[$k]
  if ($e.outcome -in @('ARMED','BUSY','REJECTED') -and $e.transcript_tag -eq 'PRESENT') { $paired++ }
  elseif ($e.outcome -in @('ARMED','BUSY','REJECTED')) { }
}
if ($dispatchWire -eq 'SOURCE_STRINGS_PRESENT' -and $map.Count -ge 2 -and $runtimeHits -gt 0 -and $transcriptHits -gt 0 -and $paired -ge 1) {
  $corr = 'RUNTIME_AND_TRANSCRIPT_HIT'
} elseif ($dispatchWire -eq 'SOURCE_STRINGS_PRESENT' -and $map.Count -ge 2 -and $runtimeHits -gt 0) {
  $corr = 'RUNTIME_HIT_MULTI_SEND'
} elseif ($dispatchWire -eq 'SOURCE_STRINGS_PRESENT' -and $runtimeHits -gt 0) {
  $corr = 'RUNTIME_HIT_ONLY'
} elseif ($dispatchWire -eq 'SOURCE_STRINGS_PRESENT') {
  $corr = 'WIRE_ONLY_NO_SEND'
}

$j = Get-JournalCounts
$copyRt = Join-Path $OutDir "dispatch_id_corr_chat_runtime_$stamp.log"
if (Test-Path $rt) { Copy-Item $rt $copyRt -Force }

# Build map table text
$mapRows = @()
foreach ($k in ($map.Keys | Sort-Object)) {
  $e = $map[$k]
  $mapRows += "msg=$($e.message) dispatch_id=$($e.dispatch_id) send_seq=$($e.send_seq) outcome=$($e.outcome) request_id=$($e.request_id) transcript_tag=$($e.transcript_tag)"
}
$mapBlock = ($mapRows -join "`n")

@"
DISPATCH_ID_CORRELATION=$corr
TIP_SHA=$hash
TIP_EXE=$TipExe
SHA_MATCH=1
SEND_ATTEMPT_PLAN=$SendCount
CHAT_SEND_ATTEMPT_COUNT=$($j.attempts)
CHAT_SEND_ARMED_COUNT=$($j.armed)
CHAT_SEND_BUSY_COUNT=$($j.busy)
CHAT_SEND_REJECTED_COUNT=$($j.rejected)
UI_UPDATE_COMPLETE=$($j.complete)
DISPATCH_ID_WIRE=$dispatchWire
DISPATCH_ID_RUNTIME_HITS=$runtimeHits
DISPATCH_ID_TRANSCRIPT_HITS=$transcriptHits
DISPATCH_ID_PAIRED_RUNTIME_TRANSCRIPT=$paired
DISPATCH_ID_UNIQUE=$(@($map.Keys).Count)
TRANSCRIPT_TAG_IDS=$(($transcriptIds -join ','))
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
BACKEND_RESPONSE=NOT_VERIFIED
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
TIP006_SEAL_PRESERVED=5A71CA26FEF42E927A53208A374FEF8BC4FD9D3F4BF6998C596FE2026CE80211
TIP006_EXTERNAL_DRIFT_NOT_SEAL=69FE3D92
A4F_UNTOUCHED=1
CC79_UNREPLACED=1
CHAT_TRANSCRIPT_17_RECONCILE_PRESERVED=1
CHAT_RUNTIME=$rt
CHAT_RUNTIME_COPY=$copyRt
VISIBLE_TRANSCRIPT=$visPath
VISIBLE_EDIT_SAMPLE=$($visSample -replace "`r|`n"," ")
MAP_BEGIN
$mapBlock
MAP_END
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt

$tableRows = New-Object System.Collections.Generic.List[string]
foreach ($k in ($map.Keys | Sort-Object)) {
  $e = $map[$k]
  $tableRows.Add("| ``$($e.message)`` | $($e.dispatch_id) | $($e.send_seq) | $($e.outcome) | $($e.request_id) | $($e.transcript_tag) |")
}
$tableBody = ($tableRows -join "`n")
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$md = @"
# DISPATCH_ID_CORRELATION

ASOF_UTC=$asof
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0

## Scope

Per-message ``dispatch_id`` correlation on sealed HWND tip ``30B9BA78…`` (``tip_hwnd_repair_001`` / ``tip_final_007``).
This is **not** exactly-once certification.

## Preserved seals

| Item | Status |
|------|--------|
| tip006 ``5A71CA26…`` (OUTPUT=FAIL) | PRESERVED — not overwritten |
| external drift ``69FE3D92…`` | NOT the tip006 seal |
| A4F / CC79 / ``CHAT_TRANSCRIPT_17_RECONCILE.md`` | UNTOUCHED |

## Result

``````
DISPATCH_ID_CORRELATION=$corr
DISPATCH_ID_WIRE=$dispatchWire
DISPATCH_ID_RUNTIME_HITS=$runtimeHits
DISPATCH_ID_TRANSCRIPT_HITS=$transcriptHits
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
BACKEND_RESPONSE=NOT_VERIFIED
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
``````

## Message → dispatch_id → outcome

| message | dispatch_id | send_seq | outcome | request_id | transcript ``[dispatch_id=N]`` |
|---------|-------------|----------|---------|------------|--------------------------------|
$tableBody

## Evidence paths

- Runtime: ``$rt``
- Runtime copy: ``$copyRt``
- Visible transcript: ``$visPath``
- Receipt: ``$receipt``
- Runlog: ``$runlog``

## Fail-closed notes

- Correlation measures ATTEMPT→ARMED/BUSY/REJECTED journal lines + optional UI transcript tags.
- ``EXACTLY_ONCE_DELIVERY=NOT_VERIFIED`` (multi-send uniqueness / no-dup cert not claimed).
- ``BACKEND_RESPONSE`` / ``CHAT_FULL_ACCEPTANCE`` remain ``NOT_VERIFIED``.
"@
Set-Content -Path $mdPath -Value $md -Encoding UTF8

Get-Content $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
exit 0

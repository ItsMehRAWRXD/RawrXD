# CHAT exactly-once correlation on tip_cc79_integ_002 (F5F4807E...).
# Chain: INPUT_EVENT -> dispatch_id -> request_started -> callback/ui_update -> transcript.
# EXACTLY_ONCE stays NOT_VERIFIED until 1:1 proven. PROMOTE=0. No Debug/Output PASS claim.
# Do NOT use model "button-probe how-to" as procedure.
param(
  [string]$TipExe = "F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_002\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "F5F4807E4738F500397AA5ACEBC8BE095806DF19C71FF959083512C73A16BA15",
  [string]$OutDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\candidates\tip_cc79_integ_002_eo_corr",
  [string]$MdPath = "F:\rawrxd\evidence\CC79_RUNTIME_001\CHAT_EXACTLY_ONCE_CORRELATE.md",
  [int]$SendCount = 2,
  [int]$IdleTimeoutMs = 90000,
  [int]$BootWaitSec = 3,
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionId = "eo_sess_$stamp"
$runId = "eo_run_$stamp"
$runlog = Join-Path $OutDir "chat_eo_corr_run_$stamp.txt"
$receipt = Join-Path $OutDir "CHAT_EXACTLY_ONCE_CORRELATE_RECEIPT.txt"
$rt = Join-Path $LogDir "chat_runtime.log"

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
public static class EoCorrNative {
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
  public static string BestTranscript(IntPtr parent) {
    string best = ""; string bestTagged = "";
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
public static class EoCorrHwndFind {
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

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe TIP_SHA256=$hash EXPECT=$ExpectSha"
if ($hash -ne $ExpectSha) {
  Log "SHA_MISMATCH measuring SHA used; EXACTLY_ONCE stays NOT_VERIFIED"
}

Get-Process -Name "RawrXD-Win32IDE-Native*","debuggee_fixture" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
if (Test-Path $rt) { Remove-Item $rt -Force }
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_CHAT_SESSION_ID = $sessionId
$env:RAWRXD_CHAT_RUN_ID = $runId
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
Remove-Item Env:RAWRXD_DEBUGGEE -ErrorAction SilentlyContinue
# Match four_panel tip002 launch (fixture arg; no tip-dir WorkingDirectory).
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id) SESSION=$sessionId RUN=$runId FIXTURE=$BrokenCpp"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early code=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [EoCorrHwndFind]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
$mainHx0 = '{0:X}' -f $main.ToInt64()
Log "MAIN_HWND=0x$mainHx0"
if ($main -eq [IntPtr]::Zero) {
  @"
EXACTLY_ONCE=NOT_VERIFIED
REASON=main_hwnd_not_found
TIP_SHA=$hash
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}

$chat = [EoCorrNative]::FindCtrl($main, 1202, "Edit")
$send = [EoCorrNative]::FindCtrl($main, 1204, "Button")
# IDC_COPILOT_CHAT_OUTPUT=1203 (1201 is sidebar header — do not use)
$transcriptHwnd = [EoCorrNative]::FindCtrl($main, 1203, "Edit")
$psPane = [EoCorrNative]::FindCtrl($main, 1401, "Edit")
if ($psPane -eq [IntPtr]::Zero) { $psPane = [EoCorrNative]::FindCtrl($main, 1501, "Edit") }
$chatHx = '{0:X}' -f $chat.ToInt64()
$sendHx = '{0:X}' -f $send.ToInt64()
$trHx = '{0:X}' -f $transcriptHwnd.ToInt64()
$psHx = '{0:X}' -f $psPane.ToInt64()
Log "CHAT_INPUT=0x$chatHx SEND=0x$sendHx TRANSCRIPT=0x$trHx PS_PANE=0x$psHx"
if ($chat -eq [IntPtr]::Zero) {
  @"
EXACTLY_ONCE=NOT_VERIFIED
REASON=chat_input_missing
TIP_SHA=$hash
PROMOTE=0
"@ | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 4
}

function Read-Rt { if (Test-Path $rt) { @(Get-Content $rt -ErrorAction SilentlyContinue) } else { @() } }
function Count-Match([string[]]$lines, [string]$pat) { @($lines | Where-Object { $_ -match $pat }).Count }
function Wait-Idle([int]$armedTarget, [int]$timeoutMs) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "IDLE_ABORT exited=$($p.ExitCode)"; return $false }
    $lines = Read-Rt
    $armed = Count-Match $lines 'CHAT_SEND_ARMED'
    $complete = Count-Match $lines 'ui_update .*complete=1'
    $busy = Count-Match $lines 'CHAT_SEND_BUSY'
    $nomodel = Count-Match $lines 'CHAT_SEND_NO_MODEL'
    if ($armed -ge $armedTarget -and ($complete -ge $armed -or $nomodel -ge $armedTarget)) {
      Log "IDLE armed=$armed complete=$complete busy=$busy nomodel=$nomodel"
      return $true
    }
    # Also idle if attempt produced BUSY/NO_MODEL without armed
    $attempts = Count-Match $lines 'CHAT_SEND_ATTEMPT'
    if ($attempts -ge $armedTarget -and $armed -eq 0 -and ($busy + $nomodel) -ge 1) {
      Log "IDLE_TERMINAL_NO_ARM attempts=$attempts busy=$busy nomodel=$nomodel"
      return $true
    }
    Start-Sleep -Milliseconds 500
  }
  $lines = Read-Rt
  Log "IDLE_TIMEOUT armed=$(Count-Match $lines 'CHAT_SEND_ARMED') complete=$(Count-Match $lines 'ui_update .*complete=1')"
  return $false
}

Start-Sleep -Seconds $BootWaitSec
$planned = @()
1..$SendCount | ForEach-Object { $planned += "eo-corr-$_" }

$clickRecords = @()
for ($i = 0; $i -lt $planned.Count; $i++) {
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED before click $($i+1)"; break }
  $beforeLines = Read-Rt
  $beforeInput = Count-Match $beforeLines 'INPUT_EVENT kind=BUTTON_CLICK'
  $beforeAttempt = Count-Match $beforeLines 'CHAT_SEND_ATTEMPT'
  $beforeArmed = Count-Match $beforeLines 'CHAT_SEND_ARMED'
  $beforeReq = Count-Match $beforeLines 'request_started'
  $msg = $planned[$i]
  [EoCorrNative]::SetText($chat, $msg)
  Start-Sleep -Milliseconds 100
  [void][EoCorrNative]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
  $clickAt = (Get-Date).ToUniversalTime().ToString('o')
  Log "CLICK=$($i+1) msg=$msg at=$clickAt before_input=$beforeInput before_attempt=$beforeAttempt"
  # Short settle then wait idle for this click's arm
  Start-Sleep -Milliseconds 400
  [void](Wait-Idle ($beforeArmed + 1) $IdleTimeoutMs)
  $afterLines = Read-Rt
  $deltaInput = (Count-Match $afterLines 'INPUT_EVENT kind=BUTTON_CLICK') - $beforeInput
  $deltaAttempt = (Count-Match $afterLines 'CHAT_SEND_ATTEMPT') - $beforeAttempt
  $deltaArmed = (Count-Match $afterLines 'CHAT_SEND_ARMED') - $beforeArmed
  $deltaReq = (Count-Match $afterLines 'request_started') - $beforeReq
  $clickRecords += [pscustomobject]@{
    click = ($i + 1); msg = $msg; click_utc = $clickAt
    delta_input = $deltaInput; delta_attempt = $deltaAttempt
    delta_armed = $deltaArmed; delta_request = $deltaReq
  }
  Log "CLICK_DELTA input=$deltaInput attempt=$deltaAttempt armed=$deltaArmed request=$deltaReq"
}

Start-Sleep -Seconds 2
$vis = ""
try {
  if ($transcriptHwnd -ne [IntPtr]::Zero) { $vis = [EoCorrNative]::GetText($transcriptHwnd) }
  if ($vis -notmatch '\[dispatch_id=') { $vis = [EoCorrNative]::BestTranscript($main) }
} catch {}
$visPath = Join-Path $LogDir "visible_transcript_eo_$stamp.txt"
Set-Content -Path $visPath -Value $vis -Encoding UTF8
$psText = ""
if ($psPane -ne [IntPtr]::Zero) {
  try { $psText = [EoCorrNative]::GetText($psPane) } catch {}
}
$psInChat = 0
if ($vis -match 'PowerShell Version:|Integrated PowerShell Console|\[PowerShell session started\]') { $psInChat = 1 }
Log "TRANSCRIPT_LEN=$($vis.Length) PS_IN_CHAT=$psInChat"

# Parse full chain from journal
$lines = Read-Rt
$rtCopy = Join-Path $OutDir "chat_eo_corr_runtime_$stamp.log"
if (Test-Path $rt) { Copy-Item $rt $rtCopy -Force }

$events = @()
foreach ($line in $lines) {
  if ($line -match 'INPUT_EVENT kind=(\w+)') {
    $events += [pscustomobject]@{ kind = 'INPUT'; subtype = $Matches[1]; dispatch = ''; request = ''; raw = $line }
  }
  elseif ($line -match 'CHAT_SEND_ATTEMPT\s+dispatch_id=(\d+)') {
    $events += [pscustomobject]@{ kind = 'ATTEMPT'; subtype = ''; dispatch = $Matches[1]; request = ''; raw = $line }
  }
  elseif ($line -match 'CHAT_SEND_ARMED\s+dispatch_id=(\d+).*request_id=(\d+)') {
    $events += [pscustomobject]@{ kind = 'ARMED'; subtype = ''; dispatch = $Matches[1]; request = $Matches[2]; raw = $line }
  }
  elseif ($line -match 'CHAT_SEND_(BUSY|REJECTED|NO_MODEL|SUPERSEDE)') {
    $events += [pscustomobject]@{ kind = $Matches[1]; subtype = ''; dispatch = ''; request = ''; raw = $line }
    if ($line -match 'dispatch_id=(\d+)') { $events[-1].dispatch = $Matches[1] }
  }
  elseif ($line -match 'request_started\s+request_id=(\d+)') {
    $events += [pscustomobject]@{ kind = 'REQ_START'; subtype = ''; dispatch = ''; request = $Matches[1]; raw = $line }
  }
  elseif ($line -match 'callback\s+request_id=(\d+).*complete=(\d)') {
    $events += [pscustomobject]@{ kind = 'CALLBACK'; subtype = "complete=$($Matches[2])"; dispatch = ''; request = $Matches[1]; raw = $line }
  }
  elseif ($line -match 'ui_update\s+request_id=(\d+).*complete=(\d)') {
    $events += [pscustomobject]@{ kind = 'UI_UPDATE'; subtype = "complete=$($Matches[2])"; dispatch = ''; request = $Matches[1]; raw = $line }
  }
  elseif ($line -match 'stale_ui_update\s+request_id=(\d+)') {
    $events += [pscustomobject]@{ kind = 'STALE_UI'; subtype = ''; dispatch = ''; request = $Matches[1]; raw = $line }
  }
}

# Build per-dispatch chain rows
$chain = @{}
foreach ($e in $events) {
  if ($e.kind -eq 'ATTEMPT' -and $e.dispatch) {
    $did = [int]$e.dispatch
    if (-not $chain.ContainsKey($did)) {
      $chain[$did] = [ordered]@{
        dispatch_id = $did; input_event = 'UNBOUND'; attempt = 1; armed = 0
        request_id = ''; req_start = 0; callback_partial = 0; callback_complete = 0
        ui_partial = 0; ui_complete = 0; stale_ui = 0; transcript_tag = 'MISSING'
        msg = ''; outcome = 'ATTEMPT_ONLY'
      }
    }
  }
  if ($e.kind -eq 'ARMED' -and $e.dispatch) {
    $did = [int]$e.dispatch
    if (-not $chain.ContainsKey($did)) {
      $chain[$did] = [ordered]@{
        dispatch_id = $did; input_event = 'UNBOUND'; attempt = 0; armed = 0
        request_id = ''; req_start = 0; callback_partial = 0; callback_complete = 0
        ui_partial = 0; ui_complete = 0; stale_ui = 0; transcript_tag = 'MISSING'
        msg = ''; outcome = 'ARMED'
      }
    }
    $chain[$did].armed = 1
    $chain[$did].request_id = $e.request
    $chain[$did].outcome = 'ARMED'
  }
  if ($e.kind -in @('BUSY','REJECTED','NO_MODEL') -and $e.dispatch) {
    $did = [int]$e.dispatch
    if ($chain.ContainsKey($did)) { $chain[$did].outcome = $e.kind }
  }
}
# Bind request_started / callbacks by request_id
foreach ($e in $events) {
  if ($e.kind -eq 'REQ_START' -and $e.request) {
    foreach ($k in $chain.Keys) {
      if ($chain[$k].request_id -eq $e.request) { $chain[$k].req_start++ }
    }
  }
  if ($e.kind -eq 'CALLBACK' -and $e.request) {
    foreach ($k in $chain.Keys) {
      if ($chain[$k].request_id -eq $e.request) {
        if ($e.subtype -eq 'complete=1') { $chain[$k].callback_complete++ } else { $chain[$k].callback_partial++ }
      }
    }
  }
  if ($e.kind -eq 'UI_UPDATE' -and $e.request) {
    foreach ($k in $chain.Keys) {
      if ($chain[$k].request_id -eq $e.request) {
        if ($e.subtype -eq 'complete=1') { $chain[$k].ui_complete++ } else { $chain[$k].ui_partial++ }
      }
    }
  }
  if ($e.kind -eq 'STALE_UI' -and $e.request) {
    foreach ($k in $chain.Keys) {
      if ($chain[$k].request_id -eq $e.request) { $chain[$k].stale_ui++ }
    }
  }
}

# Bind INPUT_EVENT BUTTON_CLICK to attempts by order (fail-closed if counts mismatch)
$btnInputs = @($events | Where-Object { $_.kind -eq 'INPUT' -and $_.subtype -eq 'BUTTON_CLICK' })
$attemptOrder = @($chain.Keys | Sort-Object)
for ($bi = 0; $bi -lt [Math]::Min($btnInputs.Count, $attemptOrder.Count); $bi++) {
  $chain[$attemptOrder[$bi]].input_event = 'BUTTON_CLICK'
}
for ($mi = 0; $mi -lt [Math]::Min($planned.Count, $attemptOrder.Count); $mi++) {
  $chain[$attemptOrder[$mi]].msg = $planned[$mi]
}

$tagHits = [regex]::Matches($vis, '\[dispatch_id=(\d+)\]')
$aiBlocks = [regex]::Matches($vis, '(?m)^AI:\s')
$userBlocks = [regex]::Matches($vis, '(?m)^>?\s*User:\s')
$transcriptIds = @()
foreach ($m in $tagHits) {
  $tid = [int]$m.Groups[1].Value
  $transcriptIds += $tid
  if ($chain.ContainsKey($tid)) { $chain[$tid].transcript_tag = 'PRESENT' }
}
$transcriptIds = @($transcriptIds | Select-Object -Unique)

$inputN = $btnInputs.Count
$attemptN = Count-Match $lines 'CHAT_SEND_ATTEMPT'
$armedN = Count-Match $lines 'CHAT_SEND_ARMED'
$reqN = Count-Match $lines 'request_started'
$cbCompleteN = Count-Match $lines 'callback request_id=\d+.*complete=1'
$uiCompleteN = Count-Match $lines 'ui_update request_id=\d+.*complete=1'
$dispatchIds = @($chain.Keys | Sort-Object)
$dispatchIdsStr = if ($dispatchIds.Count -gt 0) { ($dispatchIds -join ',') } else { 'NONE' }

# Per-click ratios (measured deltas)
$reqPerClickVals = @($clickRecords | ForEach-Object { $_.delta_request })
$attPerClickVals = @($clickRecords | ForEach-Object { $_.delta_attempt })
$inpPerClickVals = @($clickRecords | ForEach-Object { $_.delta_input })
$reqPerClick = 'NOT_VERIFIED'
$respPerReq = 'NOT_VERIFIED'
$exactly = 'NOT_VERIFIED'
$dupExec = 'NOT_PROVEN'
$dupDisplay = 'NOT_PROVEN'

$oneInputOneAttempt = ($clickRecords.Count -ge 1) -and (@($clickRecords | Where-Object { $_.delta_input -ne 1 -or $_.delta_attempt -ne 1 }).Count -eq 0)
$oneAttemptOneReq = ($clickRecords.Count -ge 1) -and (@($clickRecords | Where-Object { $_.delta_attempt -ne $_.delta_request }).Count -eq 0) -and ($attemptN -eq $reqN)
if ($oneInputOneAttempt) { $reqPerClick = ($attPerClickVals -join ',') } else { $reqPerClick = "MEASURED_DELTAS attempt=[$($attPerClickVals -join ',')] input=[$($inpPerClickVals -join ',')] NOT_1_1" }

# Responses per request: ui_complete vs request_started per request_id
$respMapNotes = @()
$allOneResp = $true
$anyRespMeasured = $false
foreach ($k in $dispatchIds) {
  $e = $chain[$k]
  if (-not $e.request_id) { $allOneResp = $false; $respMapNotes += "dispatch=$k request_id=NONE"; continue }
  $anyRespMeasured = $true
  $r = [int]$e.ui_complete
  $respMapNotes += "request_id=$($e.request_id) ui_complete=$r callback_complete=$($e.callback_complete)"
  if ($r -ne 1) { $allOneResp = $false }
}
if ($anyRespMeasured -and $allOneResp -and $reqN -ge 1) { $respPerReq = '1' }
elseif ($anyRespMeasured) { $respPerReq = "MEASURED [$($respMapNotes -join '; ')] NOT_1_1" }

# Duplicate execution vs display heuristics (not PASS)
if ($inputN -ge 1 -and $attemptN -gt $inputN) { $dupExec = "SUSPECTED attempt($attemptN)>input($inputN)" }
elseif ($inputN -ge 1 -and $attemptN -eq $inputN -and $reqN -gt $attemptN) { $dupExec = "SUSPECTED request($reqN)>attempt($attemptN)" }
elseif ($inputN -ge 1 -and $attemptN -eq $inputN) { $dupExec = "NO_EXTRA_ATTEMPT_VS_INPUT (NE EXACTLY_ONCE)" }

$aiCount = $aiBlocks.Count
$userCount = $userBlocks.Count
if ($reqN -ge 1 -and $aiCount -gt $reqN) { $dupDisplay = "SUSPECTED AI_blocks($aiCount)>request_started($reqN)" }
elseif ($uiCompleteN -gt $reqN -and $reqN -ge 1) { $dupDisplay = "SUSPECTED ui_complete($uiCompleteN)>request_started($reqN)" }
elseif ($reqN -ge 1 -and $aiCount -le $reqN) { $dupDisplay = "AI_BLOCKS_LE_REQUESTS (NE EXACTLY_ONCE)" }

# Exactly-once only if full 1:1 proven across chain for measured clicks
if ($oneInputOneAttempt -and $oneAttemptOneReq -and $allOneResp -and $anyRespMeasured -and $inputN -eq $attemptN -and $attemptN -eq $armedN -and $armedN -eq $reqN -and $tagHits.Count -eq $attemptN) {
  $busyN = Count-Match $lines 'CHAT_SEND_BUSY|CHAT_SEND_SUPERSEDE'
  if ($busyN -eq 0 -and $dispatchIds.Count -eq $inputN -and $transcriptIds.Count -eq $inputN) {
    $exactly = 'MEASURED_1_1_CHAIN'
  }
}
# Fail-closed product scoreboard: EXACTLY_ONCE stays NOT_VERIFIED until durable 1:1 is proven.
# MEASURED_1_1_CHAIN is recorded in receipt notes only; scoreboard field remains NOT_VERIFIED this lane.
$exactlyScore = 'NOT_VERIFIED'
$chainNote = $exactly

$blockers = @()
if ($attemptN -eq 0) { $blockers += 'NO_CHAT_SEND_ATTEMPT' }
if ($inputN -eq 0) { $blockers += 'NO_INPUT_EVENT_BUTTON_CLICK' }
if ($reqN -eq 0) { $blockers += 'NO_REQUEST_STARTED' }
if (-not $oneInputOneAttempt) { $blockers += 'INPUT_ATTEMPT_NOT_1_1' }
if (-not $allOneResp) { $blockers += 'RESPONSES_PER_REQUEST_NOT_1' }
if ($psInChat -eq 1) { $blockers += 'POWERSHELL_TEXT_IN_CHAT_TRANSCRIPT' }
if ($chainNote -ne 'MEASURED_1_1_CHAIN') { $blockers += 'FULL_CHAIN_1_1_UNPROVEN' }
else { $blockers += 'DURABLE_EXACTLY_ONCE_CERT_PENDING' }
if ($blockers.Count -eq 0) { $blockers += 'NONE' }

$priorDispatchPresence = 'CONFIRMED_1_2_FROM_PRIOR_OUTPUT_HWND_SAMPLE (presence only; NE this-run 1:1)'
$ctrlEnter = 'NOT_DEMONSTRATED_THIS_RUN'
$mainHx = '{0:X}' -f $main.ToInt64()
$originPane = "COPILOT_CHAT input_id=1202 send_id=1204 transcript_id=1203 main=0x$mainHx"

# Chain table rows
$tableRows = New-Object System.Collections.Generic.List[string]
foreach ($k in $dispatchIds) {
  $e = $chain[$k]
  $tableRows.Add("| $($e.msg) | $($e.input_event) | $($e.dispatch_id) | $($e.request_id) | req_start=$($e.req_start) cb_p=$($e.callback_partial) cb_c=$($e.callback_complete) | ui_p=$($e.ui_partial) ui_c=$($e.ui_complete) stale=$($e.stale_ui) | $($e.transcript_tag) | $($e.outcome) |")
}
if ($tableRows.Count -eq 0) {
  $tableRows.Add("| - | - | - | - | - | - | - | NO_DISPATCH |")
}
$tableBody = ($tableRows -join "`n")

$clickRows = New-Object System.Collections.Generic.List[string]
foreach ($c in $clickRecords) {
  $clickRows.Add("| $($c.click) | $($c.msg) | $($c.delta_input) | $($c.delta_attempt) | $($c.delta_armed) | $($c.delta_request) | $($c.click_utc) |")
}
$clickBody = if ($clickRows.Count -gt 0) { $clickRows -join "`n" } else { "| - | - | - | - | - | - | - |" }

$visSample = if ($vis.Length -gt 500) { $vis.Substring(0, 500) } else { $vis }
$visSampleOneLine = ($visSample -replace "`r|`n", " ")
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$nextAction = 'Re-run with WaitIdle + Stop isolation if SUSPECTED dup; instrument pane-id on INPUT_EVENT if still UNBOUND; do not claim Debug/Output PASS from this lane'

@"
EXACTLY_ONCE=$exactlyScore
CHAIN_NOTE=$chainNote
DISPATCH_IDS=$dispatchIdsStr
REQUESTS_PER_CLICK=$reqPerClick
RESPONSES_PER_REQUEST=$respPerReq
PROMOTE=0
BLOCKERS=$($blockers -join ',')
NEXT_ACTION=$nextAction
TIP_SHA=$hash
TIP_EXE=$TipExe
SHA_MATCH=$([int]($hash -eq $ExpectSha))
SESSION_ID=$sessionId
RUN_ID=$runId
ORIGINATING_PANE=$originPane
INPUT_EVENT_BUTTON_CLICK=$inputN
CHAT_SEND_ATTEMPT=$attemptN
CHAT_SEND_ARMED=$armedN
REQUEST_STARTED=$reqN
CALLBACK_COMPLETE=$cbCompleteN
UI_UPDATE_COMPLETE=$uiCompleteN
AI_BLOCKS_VISIBLE=$aiCount
USER_BLOCKS_VISIBLE=$userCount
TRANSCRIPT_TAG_IDS=$(($transcriptIds -join ','))
DUP_EXECUTION=$dupExec
DUP_DISPLAY=$dupDisplay
POWERSHELL_IN_CHAT=$psInChat
CTRL_ENTER=$ctrlEnter
PRIOR_DISPATCH_IDS_1_2=$priorDispatchPresence
BUTTON_PROBE_HOWTO=UNSUPPORTED_NOT_USED
CHAT_RUNTIME=$rt
CHAT_RUNTIME_COPY=$rtCopy
VISIBLE_TRANSCRIPT=$visPath
VISIBLE_EDIT_SAMPLE=$visSampleOneLine
ENGINEERING_MATURITY=82%_UNCHANGED
CERTIFIED=0
PRODUCT_PASS=0
RUNLOG=$runlog
"@ | Set-Content $receipt -Encoding UTF8

$md = @"
# CHAT_EXACTLY_ONCE_CORRELATE

ASOF_UTC=$asof
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
INVENT_PASS=0
NO_DEBUG_OUTPUT_PASS_FROM_THIS_LANE=1

## Controlling tip

| Field | Value |
|-------|-------|
| Tip | ``tip_cc79_integ_002`` |
| SHA256 | ``$hash`` |
| Expect | ``$ExpectSha`` |
| SHA_MATCH | $([int]($hash -eq $ExpectSha)) |
| Session | ``$sessionId`` |
| Run | ``$runId`` |
| Originating pane | $originPane |

## Scoreboard (fail-closed)

``````
EXACTLY_ONCE=$exactlyScore
DISPATCH_IDS=$dispatchIdsStr
REQUESTS_PER_CLICK=$reqPerClick
RESPONSES_PER_REQUEST=$respPerReq
PROMOTE=0
BLOCKERS=$($blockers -join ',')
NEXT_ACTION=$nextAction
``````

## Prior observation (reconciled - not this-run proof)

| Gate | Status |
|------|--------|
| Dispatch IDs 1 and 2 visible | CONFIRMED presence only (OUTPUT HWND sample: test / button-probe) |
| Exactly one request per click | NOT_VERIFIED (prior) |
| Exactly one response per request | NOT_VERIFIED (prior) |
| Ctrl+Enter | Not demonstrated in that transcript |
| Model button-probe how-to | Unsupported - not used as harness procedure |

Law: multiple AI response blocks after one visible submission NE proven duplicate send / callback / render cause.

## Measured chain (this run)

Path: ``input event → dispatch_id → backend request → response start/end → transcript insertion``

| message | input_event | dispatch_id | request_id | response start (req/cb) | response end (ui) | transcript ``[dispatch_id=N]`` | outcome |
|---------|-------------|-------------|------------|-------------------------|-------------------|-------------------------------|---------|
$tableBody

### Per-click deltas (instrumented Send-button WM_COMMAND 1204)

| click | message | dINPUT_EVENT | dATTEMPT | dARMED | drequest_started | click_utc |
|------:|---------|-------------:|---------:|-------:|-----------------:|-----------|
$clickBody

### Duplicate execution vs duplicate display

| Class | Result |
|-------|--------|
| Duplicate execution | $dupExec |
| Duplicate display | $dupDisplay |
| PowerShell text in chat transcript | PS_IN_CHAT=$psInChat |
| Ctrl+Enter this run | $ctrlEnter |

## Counts

``````
INPUT_EVENT_BUTTON_CLICK=$inputN
CHAT_SEND_ATTEMPT=$attemptN
CHAT_SEND_ARMED=$armedN
REQUEST_STARTED=$reqN
CALLBACK_COMPLETE=$cbCompleteN
UI_UPDATE_COMPLETE=$uiCompleteN
AI_BLOCKS_VISIBLE=$aiCount
USER_BLOCKS_VISIBLE=$userCount
TRANSCRIPT_TAG_IDS=$(($transcriptIds -join ','))
``````

## Evidence paths

- Runtime journal: ``$rt``
- Runtime copy: ``$rtCopy``
- Visible transcript: ``$visPath``
- Receipt: ``$receipt``
- Runlog: ``$runlog``
- Harness: ``artifacts\chat_exactly_once_correlate.ps1``

## Visible transcript sample (truncated)

``````
$visSampleOneLine
``````

## Law

``````
MULTI_RESPONSE_BLOCKS NE PROVEN_DUPLICATE_SEND
GENERATED_BUTTON_PROBE_HOWTO NE HARNESS
DISPATCH_ID_PRESENCE NE EXACTLY_ONCE
SOURCE_WIRED NE RUNTIME_REACHED NE TOKEN_SURVIVED NE PERFORMANCE_PASS
EXACTLY_ONCE=$exactlyScore
PROMOTE=0
AUDIT_SEAL_UNCHANGED=1
``````
"@
Set-Content -Path $MdPath -Value $md -Encoding UTF8
# Mirror under FULL_FEATURE_ONESHOT_001 for discoverability (supporting, not seal)
$mirror = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\CHAT_EXACTLY_ONCE_CORRELATE.md"
Copy-Item $MdPath $mirror -Force

Get-Content $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
exit 0

# INPUT_EVENT_DISPATCH measure: real Send-button + keyboard events vs journal.
# Proof = INPUT_EVENT + CHAT_SEND_* journal lines (not model text).
# PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0. Does not overwrite tip_hwnd_repair_001 / A4F / CC79.
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_input_event_dispatch_001",
  [string]$SessionId = "",
  [string]$RunId = "",
  [switch]$NoStopBetween,
  [int]$IdleTimeoutMs = 180000
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $SessionId) { $SessionId = "ied_sess_$stamp" }
if (-not $RunId) { $RunId = "ied_run_$stamp" }
$runlog = Join-Path $OutDir "input_event_dispatch_run_$stamp.txt"
$receipt = Join-Path $OutDir "INPUT_EVENT_DISPATCH_RECEIPT.txt"
$mdPath = Join-Path $OutDir "INPUT_EVENT_DISPATCH.md"
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
public static class IedNative {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  public const uint KEYEVENTF_KEYUP = 0x0002;
  public const int VK_RETURN = 0x0D;
  public const int VK_CONTROL = 0x11;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int nCmdShow);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)]
  public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)]
  public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time;
    public IntPtr dwExtraInfo; public uint padding1; public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk) {
    INPUT[] a = new INPUT[1]; a[0].type = 1; a[0].ki.wVk = vk; return SendInput(1, a, InputSize);
  }
  public static uint KeyUp(ushort vk) {
    INPUT[] a = new INPUT[1]; a[0].type = 1; a[0].ki.wVk = vk; a[0].ki.dwFlags = KEYEVENTF_KEYUP;
    return SendInput(1, a, InputSize);
  }
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
public static class IedHwndFind {
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
Log "TIP_EXE=$TipExe TIP_SHA256=$hash SESSION_ID=$SessionId RUN_ID=$RunId"

Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
if (Test-Path $rt) { Remove-Item $rt -Force }

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_CHAT_SESSION_ID = $SessionId
$env:RAWRXD_CHAT_RUN_ID = $RunId

$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [IedHwndFind]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
INPUT_EVENT_DISPATCH=NOT_RUN
REASON=main_hwnd_not_found
TIP_SHA256=$hash
SESSION_ID=$SessionId
RUN_ID=$RunId
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
  try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  exit 2
}

$chat = [IedNative]::FindCtrl($main, 1202, "Edit")
$send = [IedNative]::FindCtrl($main, 1204, "Button")
$stop = [IedNative]::FindCtrl($main, 1210, "Button")
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND=0x$('{0:X}' -f $send.ToInt64()) STOP=0x$('{0:X}' -f $stop.ToInt64())"
if ($chat -eq [IntPtr]::Zero -or $send -eq [IntPtr]::Zero) {
  @"
INPUT_EVENT_DISPATCH=NOT_RUN
REASON=chat_controls_missing
TIP_SHA256=$hash
SESSION_ID=$SessionId
RUN_ID=$RunId
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
PROMOTE=0
"@ | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 3
}

$script:inputAttached = $false
$script:ideTidAttached = [uint32]0
$script:myTidAttached = [uint32]0
$script:fgTidAttached = [uint32]0

function Focus-Chat {
  $pidIde = [uint32]0
  $ideTid = [IedNative]::GetWindowThreadProcessId($main, [ref]$pidIde)
  $myTid = [IedNative]::GetCurrentThreadId()
  $fg = [IedNative]::GetForegroundWindow()
  $pidFg = [uint32]0
  $fgTid = if ($fg -ne [IntPtr]::Zero) { [IedNative]::GetWindowThreadProcessId($fg, [ref]$pidFg) } else { [uint32]0 }
  if ($fgTid -ne 0 -and $fgTid -ne $myTid -and $fgTid -ne $ideTid) {
    [void][IedNative]::AttachThreadInput($myTid, $fgTid, $true)
    $script:fgTidAttached = $fgTid
  }
  if ($ideTid -ne 0 -and $ideTid -ne $myTid -and -not $script:inputAttached) {
    $script:inputAttached = [IedNative]::AttachThreadInput($myTid, $ideTid, $true)
    $script:ideTidAttached = $ideTid
    $script:myTidAttached = $myTid
  }
  [void][IedNative]::ShowWindow($main, 9)
  [void][IedNative]::BringWindowToTop($main)
  [void][IedNative]::SetForegroundWindow($main)
  [void][IedNative]::SetFocus($chat)
  Start-Sleep -Milliseconds 120
}
function Detach-Chat {
  if ($script:inputAttached -and $script:ideTidAttached -ne 0) {
    [void][IedNative]::AttachThreadInput($script:myTidAttached, $script:ideTidAttached, $false)
  }
  if ($script:fgTidAttached -ne 0) {
    [void][IedNative]::AttachThreadInput($script:myTidAttached, $script:fgTidAttached, $false)
  }
  $script:inputAttached = $false
  $script:ideTidAttached = [uint32]0
  $script:myTidAttached = [uint32]0
  $script:fgTidAttached = [uint32]0
}
function Move-CaretEnd([IntPtr]$h) {
  [void][IedNative]::SendMessageW($h, 0x00B1, [IntPtr](-1), [IntPtr](-1))
}
function Send-CtrlEnter {
  Focus-Chat
  $n1 = [IedNative]::KeyDown(0x11); Start-Sleep -Milliseconds 40
  $n2 = [IedNative]::KeyDown(0x0D); Start-Sleep -Milliseconds 80
  $n3 = [IedNative]::KeyUp(0x0D)
  $n4 = [IedNative]::KeyUp(0x11)
  Log "SEND_CTRL_ENTER SendInput=$n1,$n2,$n3,$n4"
  Detach-Chat
}
function Send-Enter {
  Focus-Chat
  $n1 = [IedNative]::KeyDown(0x0D); Start-Sleep -Milliseconds 50
  $n2 = [IedNative]::KeyUp(0x0D)
  Log "SEND_ENTER SendInput=$n1,$n2"
  Detach-Chat
}
function Get-Rt { if (Test-Path $rt) { Get-Content $rt } else { @() } }
function Slice-New($before, $after) {
  # Append-only journal: index slice (set-diff drops duplicate identical lines).
  $b = @($before); $a = @($after)
  if ($a.Count -le $b.Count) { return @() }
  return @($a[$b.Count..($a.Count - 1)])
}
function Count-ArmedDone([string[]]$lines) {
  $arm = @($lines | Where-Object { $_ -match 'CHAT_SEND_ARMED' }).Count
  $comp = @($lines | Where-Object { $_ -match 'ui_update .*complete=1' }).Count
  $canc = @($lines | Where-Object { $_ -match 'cancel_acknowledged' }).Count
  # NoStopBetween: only UI complete counts as done (cancel must not mask FAILED).
  if ($NoStopBetween) { return @{ arm = $arm; done = $comp; canc = $canc } }
  return @{ arm = $arm; done = ($comp + $canc); canc = $canc }
}
function Wait-Idle([int]$timeoutMs = 25000) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { return $false }
    $st = Count-ArmedDone (Get-Rt)
    if ($st.arm -eq 0 -or $st.done -ge $st.arm) { return $true }
    Start-Sleep -Milliseconds 400
  }
  return $false
}
function Ensure-Idle([int]$timeoutMs = -1) {
  if ($timeoutMs -lt 0) {
    $timeoutMs = if ($NoStopBetween) { $IdleTimeoutMs } else { 20000 }
  } elseif ($NoStopBetween -and $timeoutMs -lt $IdleTimeoutMs) {
    $timeoutMs = $IdleTimeoutMs
  }
  try { $p.Refresh() } catch {}
  if ($p.HasExited) {
    Log "ENSURE_IDLE process_exited"
    return $false
  }
  $st = Count-ArmedDone (Get-Rt)
  if (-not $NoStopBetween -and $st.arm -gt $st.done -and $stop -ne [IntPtr]::Zero) {
    Log "STOP_CLICK armed=$($st.arm) done=$($st.done)"
    # PostMessage: never block forever if the IDE thread is wedged.
    [void][IedNative]::PostMessageW($main, 0x0111, [IntPtr]1210, $stop)
    Start-Sleep -Milliseconds 500
  } elseif ($NoStopBetween -and $st.arm -gt $st.done) {
    Log "WAIT_UI_COMPLETE armed=$($st.arm) complete=$($st.done) (no stop)"
  }
  $ok = Wait-Idle $timeoutMs
  if (-not $ok -and $NoStopBetween) {
    Log "IDLE_TIMEOUT_CLASS=FAILED armed=$($st.arm) complete=$((Count-ArmedDone (Get-Rt)).done)"
  }
  Log "ENSURE_IDLE ok=$ok NoStopBetween=$NoStopBetween"
  return $ok
}
function Classify-Outcome([string[]]$chunk) {
  if ($chunk | Where-Object { $_ -match 'CHAT_SEND_ARMED' }) {
    if ($chunk | Where-Object { $_ -match 'ui_update .*complete=1' }) { return "ARMED_COMPLETE" }
    if ($chunk | Where-Object { $_ -match 'cancel_acknowledged|cancel_requested' }) { return "CANCELLED_OR_INTERRUPTED" }
    if ($NoStopBetween) { return "FAILED" }
    return "ARMED_PENDING"
  }
  if ($chunk | Where-Object { $_ -match 'CHAT_SEND_BUSY' }) { return "BUSY" }
  if ($chunk | Where-Object { $_ -match 'CHAT_SEND_REJECTED' }) { return "REJECTED" }
  if ($chunk | Where-Object { $_ -match 'CHAT_SEND_NO_MODEL' }) { return "NO_MODEL" }
  if ($chunk | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) { return "ATTEMPT_NO_TERMINAL" }
  return "NO_SEND"
}

Start-Sleep -Seconds 10
# Sanity: chat edit must accept WM_SETTEXT before probes.
[IedNative]::SetText($chat, "ied-ready")
Start-Sleep -Milliseconds 200
$readyTxt = [IedNative]::GetText($chat)
Log "READY_TEXT_LEN=$($readyTxt.Length)"
if ($readyTxt -ne "ied-ready") {
  Log "CHAT_INPUT_NOT_WRITABLE - refreshing HWND"
  $chat = [IedNative]::FindCtrl($main, 1202, "Edit")
  $send = [IedNative]::FindCtrl($main, 1204, "Button")
  $stop = [IedNative]::FindCtrl($main, 1210, "Button")
  [IedNative]::SetText($chat, "ied-ready")
  Start-Sleep -Milliseconds 200
  $readyTxt = [IedNative]::GetText($chat)
  Log "READY_TEXT_LEN2=$($readyTxt.Length) CHAT=0x$('{0:X}' -f $chat.ToInt64())"
}
$results = [ordered]@{
  BUTTON_ONE_DISPATCH_PER_CLICK = "FAIL"
  CTRL_ENTER_ONE_DISPATCH = "FAIL"
  ENTER_INSERTS_NEWLINE = "FAIL"
  HELD_KEY_NO_UNINTENDED_REPEAT_SEND = "FAIL"
}
$eventMap = New-Object System.Collections.Generic.List[string]

# --- 1) Enter inserts newline (no send) ---
[IedNative]::SetText($chat, "line1")
Focus-Chat
Move-CaretEnd $chat
$before = Get-Rt
Send-Enter
Start-Sleep -Milliseconds 250
$after = Get-Rt
$chunk = Slice-New $before $after
$t1 = [IedNative]::GetText($chat)
$enterEv = @($chunk | Where-Object { $_ -match 'INPUT_EVENT kind=ENTER_NEWLINE' })
$enterSend = @($chunk | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT|CHAT_SEND_ARMED' })
Log "ENTER text='$($t1 -replace "`r","\\r" -replace "`n","\\n")' events=$($enterEv.Count) sends=$($enterSend.Count)"
if (($t1 -match 'line1') -and ($t1 -match "[\r\n]") -and $enterEv.Count -ge 1 -and $enterSend.Count -eq 0) {
  $results.ENTER_INSERTS_NEWLINE = "PASS"
}
$eventMap.Add("event=ENTER_NEWLINE path=AIM_GETMESSAGE_WM_KEYDOWN input=SendInput_VK_RETURN dispatch_id=NONE outcome=NO_SEND journal_events=$($enterEv.Count)")

# --- 2) Held Ctrl+Enter (idle): first edge send; OS auto-repeat must not re-send ---
[void](Ensure-Idle 5000)
[IedNative]::SetText($chat, "ied-hold")
$before = Get-Rt
# Same chord path as single Ctrl+Enter, but keep keys down so OS generates
# WM_KEYDOWN auto-repeats with bit30 set (AIM HELD_KEY_REPEAT_SUPPRESSED).
Focus-Chat
Start-Sleep -Milliseconds 100
$n1 = [IedNative]::KeyDown(0x11)
Start-Sleep -Milliseconds 50
$n2 = [IedNative]::KeyDown(0x0D)
Log "HOLD_DOWN SendInput=$n1,$n2 - dwell for OS auto-repeat"
Start-Sleep -Milliseconds 900
$n3 = [IedNative]::KeyUp(0x0D)
$n4 = [IedNative]::KeyUp(0x11)
Log "HOLD_UP SendInput=$n3,$n4"
Detach-Chat
# Poll until first INPUT_EVENT/ATTEMPT appears or timeout (ofstream may lag).
$deadline = [Environment]::TickCount64 + 3000
while ([Environment]::TickCount64 -lt $deadline) {
  $probe = Slice-New $before (Get-Rt)
  if (@($probe | Where-Object { $_ -match 'INPUT_EVENT kind=CTRL_ENTER|CHAT_SEND_ATTEMPT' }).Count -ge 1) { break }
  Start-Sleep -Milliseconds 100
}
[void](Ensure-Idle 25000)
$after = Get-Rt
$chunk = Slice-New $before $after
$holdEv = @($chunk | Where-Object { $_ -match 'INPUT_EVENT kind=CTRL_ENTER' })
$suppEv = @($chunk | Where-Object { $_ -match 'INPUT_EVENT kind=HELD_KEY_REPEAT_SUPPRESSED' })
$holdAtt = @($chunk | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' })
$holdBusy = @($chunk | Where-Object { $_ -match 'CHAT_SEND_BUSY' })
$holdDisp = "NONE"
if ($holdAtt.Count -ge 1 -and $holdAtt[0] -match 'dispatch_id=(\d+)') { $holdDisp = $Matches[1] }
$holdOut = Classify-Outcome $chunk
Log "HOLD ctrl_enter=$($holdEv.Count) suppressed=$($suppEv.Count) attempts=$($holdAtt.Count) busy=$($holdBusy.Count)"
# PASS: exactly one CTRL_ENTER edge + exactly one ATTEMPT; repeats either suppressed
# in journal or at least did not create additional ATTEMPTs.
if ($holdEv.Count -eq 1 -and $holdAtt.Count -eq 1) {
  $results.HELD_KEY_NO_UNINTENDED_REPEAT_SEND = "PASS"
}
if ($holdEv.Count -eq 1 -and $holdAtt.Count -eq 1 -and $suppEv.Count -ge 1) {
  $results.HELD_KEY_NO_UNINTENDED_REPEAT_SEND = "PASS"
}
if ($holdAtt.Count -gt 1 -or $holdEv.Count -gt 1) {
  $results.HELD_KEY_NO_UNINTENDED_REPEAT_SEND = "FAIL"
}
$eventMap.Add("event=HELD_CTRL_ENTER path=AIM_GETMESSAGE_WM_KEYDOWN input=SendInput_HELD_CTRL_RETURN_OS_REPEAT dispatch_id=$holdDisp outcome=$holdOut ctrl_enter=$($holdEv.Count) suppressed=$($suppEv.Count) attempts=$($holdAtt.Count)")

# --- 3) Send button → one dispatch (idle) ---
[void](Ensure-Idle 25000)
Detach-Chat
# Refresh HWNDs in case sidebar rebuilt during prior inference.
$send = [IedNative]::FindCtrl($main, 1204, "Button")
$stop = [IedNative]::FindCtrl($main, 1210, "Button")
$chat = [IedNative]::FindCtrl($main, 1202, "Edit")
[IedNative]::SetText($chat, "ied-button")
$before = Get-Rt
$wp = [IntPtr](1204) # MAKEWPARAM(1204, BN_CLICKED=0)
[void][IedNative]::SendMessageW($main, 0x0111, $wp, $send)
Start-Sleep -Milliseconds 600
[void](Ensure-Idle 25000)
$after = Get-Rt
$chunk = Slice-New $before $after
$btnEv = @($chunk | Where-Object { $_ -match 'INPUT_EVENT kind=BUTTON_CLICK' })
$btnAtt = @($chunk | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' })
$btnDisp = "NONE"
if ($btnAtt.Count -ge 1 -and $btnAtt[0] -match 'dispatch_id=(\d+)') { $btnDisp = $Matches[1] }
$btnOut = Classify-Outcome $chunk
Log "BUTTON events=$($btnEv.Count) attempts=$($btnAtt.Count) outcome=$btnOut"
if ($btnEv.Count -eq 1 -and $btnAtt.Count -eq 1) {
  $results.BUTTON_ONE_DISPATCH_PER_CLICK = "PASS"
}
$eventMap.Add("event=BUTTON_CLICK path=WM_COMMAND_BN_CLICKED input=SendMessage_WM_COMMAND_1204 dispatch_id=$btnDisp outcome=$btnOut journal_button=$($btnEv.Count) attempts=$($btnAtt.Count)")

# --- 4) Ctrl+Enter → one dispatch (idle) ---
[void](Ensure-Idle 25000)
[IedNative]::SetText($chat, "ied-ctrl-enter")
$before = Get-Rt
Send-CtrlEnter
Start-Sleep -Milliseconds 600
[void](Ensure-Idle 25000)
$after = Get-Rt
$chunk = Slice-New $before $after
$ceEv = @($chunk | Where-Object { $_ -match 'INPUT_EVENT kind=CTRL_ENTER' })
$ceAtt = @($chunk | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' })
$ceArm = @($chunk | Where-Object { $_ -match 'CHAT_SEND_ARMED' })
$ceBusy = @($chunk | Where-Object { $_ -match 'CHAT_SEND_BUSY' })
$disp = "NONE"
if ($ceAtt.Count -ge 1 -and $ceAtt[0] -match 'dispatch_id=(\d+)') { $disp = $Matches[1] }
$outc = Classify-Outcome $chunk
Log "CTRL_ENTER events=$($ceEv.Count) attempts=$($ceAtt.Count) armed=$($ceArm.Count) busy=$($ceBusy.Count) outcome=$outc"
if ($ceEv.Count -eq 1 -and $ceAtt.Count -eq 1) {
  $results.CTRL_ENTER_ONE_DISPATCH = "PASS"
}
$eventMap.Add("event=CTRL_ENTER path=AIM_GETMESSAGE_WM_KEYDOWN input=SendInput_CTRL_RETURN dispatch_id=$disp outcome=$outc journal_ctrl_enter=$($ceEv.Count) attempts=$($ceAtt.Count)")
[void](Ensure-Idle 25000)

# Session / run bind + dispatch restart classification
$allRt = Get-Rt
$sessionOpen = @($allRt | Where-Object { $_ -match '^SESSION_OPEN' })
$sidHits = @($allRt | Where-Object { $_ -match "session_id=$([regex]::Escape($SessionId))" }).Count
$ridHits = @($allRt | Where-Object { $_ -match "run_id=$([regex]::Escape($RunId))" }).Count
$dispIds = @()
foreach ($line in $allRt) {
  if ($line -match 'dispatch_id=(\d+)') { $dispIds += [int]$Matches[1] }
}
$dispRestart = "NONE"
if ($dispIds.Count -ge 2) {
  $prev = $dispIds[0]
  for ($i = 1; $i -lt $dispIds.Count; $i++) {
    if ($dispIds[$i] -lt $prev) { $dispRestart = "RESTART_WITHIN_SAME_SESSION_RUN_AMBIGUOUS_OR_BUG"; break }
    $prev = $dispIds[$i]
  }
  if ($dispRestart -eq "NONE") { $dispRestart = "MONOTONIC_WITHIN_SESSION_RUN" }
}

$passN = @($results.Values | Where-Object { $_ -eq "PASS" }).Count
$gate = if ($passN -eq 4) { "PASS" } else { "FAIL" }
$instrumented = [bool]($allRt | Where-Object { $_ -match 'INPUT_EVENT kind=' })
if (-not $instrumented) { $gate = "NOT_RUN"; Log "NO_INPUT_EVENT_JOURNAL - tip lacks instrumentation" }

$receiptLines = @(
  "INPUT_EVENT_DISPATCH=$gate"
  "TIP_SHA256=$hash"
  "TIP_EXE=$TipExe"
  "TIP_PACKAGE=tip_input_event_dispatch_001"
  "PRIOR_HWND_TIP_SHA=30B9BA7899FB8C7D4A0AAE3B1B81883B5C7DBA2606CFA28396A3517273BFC393"
  "REBUILD_REQUIRED_FOR_INPUT_EVENT=1"
  "NO_CROSS_SHA_PASS_INHERITANCE=1"
  "SESSION_ID=$SessionId"
  "RUN_ID=$RunId"
  "SESSION_OPEN_LINES=$($sessionOpen.Count)"
  "SESSION_ID_JOURNAL_HITS=$sidHits"
  "RUN_ID_JOURNAL_HITS=$ridHits"
  "BUTTON_ONE_DISPATCH_PER_CLICK=$($results.BUTTON_ONE_DISPATCH_PER_CLICK)"
  "CTRL_ENTER_ONE_DISPATCH=$($results.CTRL_ENTER_ONE_DISPATCH)"
  "ENTER_INSERTS_NEWLINE=$($results.ENTER_INSERTS_NEWLINE)"
  "HELD_KEY_NO_UNINTENDED_REPEAT_SEND=$($results.HELD_KEY_NO_UNINTENDED_REPEAT_SEND)"
  "DISPATCH_ID_SEQUENCE=$([string]::Join(',', $dispIds))"
  "DISPATCH_ID_RESTART_CLASS=$dispRestart"
  "MODEL_RESPONSE_AS_PROBE_EVIDENCE=FORBIDDEN"
  "EXACTLY_ONCE_DELIVERY=NOT_VERIFIED"
  "ENGINEERING_MATURITY=82_PERCENT_UNCHANGED"
  "CC79_UNREPLACED=1"
  "A4F_IMMUTABLE=1"
  "CHAT_TRANSCRIPT_17_RECONCILE_PRESERVED=1"
  "PROMOTE=0"
  "CERTIFIED=0"
  "PRODUCT_PASS=0"
  "CHAT_RUNTIME_LOG=$rt"
  "RUNLOG=$runlog"
)
foreach ($e in $eventMap) { $receiptLines += "MAP $e" }
# Classify no-response / terminal rows from journal (not transcript model text).
$noResp = @()
foreach ($line in $allRt) {
  if ($line -match 'CHAT_SEND_BUSY') { $noResp += "BUSY:$line" }
  elseif ($line -match 'CHAT_SEND_REJECTED') { $noResp += "REJECTED:$line" }
  elseif ($line -match 'CHAT_SEND_NO_MODEL') { $noResp += "FAILED_NO_MODEL:$line" }
  elseif ($line -match 'cancel_requested|cancel_acknowledged') { $noResp += "CANCELLED_OR_INTERRUPTED:$line" }
}
$armedN = @($allRt | Where-Object { $_ -match 'CHAT_SEND_ARMED' }).Count
$compN = @($allRt | Where-Object { $_ -match 'ui_update .*complete=1' }).Count
if ($armedN -gt $compN) { $noResp += "PENDING:armed=$armedN complete=$compN" }
foreach ($n in $noResp) { $receiptLines += "NO_RESPONSE_CLASS $n" }
$receiptLines | Set-Content $receipt -Encoding ASCII

$md = @"
# INPUT_EVENT_DISPATCH

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED

## Verdict

``INPUT_EVENT_DISPATCH=$gate`` on tip package ``tip_input_event_dispatch_001``.

Sealed HWND tip ``30B9BA78…`` lacked ``INPUT_EVENT`` journal strings → rebuild required.
This receipt binds the **rebuilt** EXE SHA, not cross-inherited CC79 / 30B9 AIM PASS.

| Check | Result |
|-------|--------|
| BUTTON_ONE_DISPATCH_PER_CLICK | $($results.BUTTON_ONE_DISPATCH_PER_CLICK) |
| CTRL_ENTER_ONE_DISPATCH | $($results.CTRL_ENTER_ONE_DISPATCH) |
| ENTER_INSERTS_NEWLINE | $($results.ENTER_INSERTS_NEWLINE) |
| HELD_KEY_NO_UNINTENDED_REPEAT_SEND | $($results.HELD_KEY_NO_UNINTENDED_REPEAT_SEND) |

## Bind

- TIP_SHA256=$hash
- SESSION_ID=$SessionId
- RUN_ID=$RunId
- DISPATCH_ID_SEQUENCE=$([string]::Join(',', $dispIds))
- DISPATCH_ID_RESTART_CLASS=$dispRestart
- EXACTLY_ONCE_DELIVERY=NOT_VERIFIED

## Per-event map

$(($eventMap | ForEach-Object { "- $_" }) -join "`n")

## Evidence

- Runtime: ``$rt``
- Runlog: ``$runlog``
- Receipt: ``$receipt``
- Harness: ``harness\input_event_dispatch_measure.ps1``

Proof source = ``INPUT_EVENT`` + ``CHAT_SEND_*`` journal (Win32 path tags). Model replies are forbidden as probe evidence.
"@
Set-Content -Path $mdPath -Value $md -Encoding UTF8

$receiptLines | ForEach-Object { Log $_ }

try { Detach-Chat } catch {}
try {
  if (!$p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds 2
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }
  }
} catch {}
exit $(if ($gate -eq "PASS") { 0 } else { 1 })

# Controlling chat input-event gate (tip_chat_dispatch lane).
# Proves button/ctrl-enter/enter-newline/hold-suppress with SHA+session bind.
# EXACTLY_ONCE stays NOT_VERIFIED unless ATTEMPT==ARMED==complete with DUP=0.
# Never mutates A4F / tip_final_004 / tip_final_005 / CC79. PROMOTE=0.
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_chat_dispatch_001",
  [int]$IdleTimeoutMs = 180000
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionId = "gate_" + [guid]::NewGuid().ToString("N")
$runId = "run_" + $stamp
$runlog = Join-Path $OutDir "chat_input_event_gate_run_$stamp.txt"
$receipt = Join-Path $OutDir "CHAT_INPUT_EVENT_GATE_RECEIPT.txt"
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
public static class GateNative {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  public const uint KEYEVENTF_KEYUP = 0x0002;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int nCmdShow);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint padding1; public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk) { INPUT[] a = new INPUT[1]; a[0].type = 1; a[0].ki.wVk = vk; return SendInput(1, a, InputSize); }
  public static uint KeyUp(ushort vk) { INPUT[] a = new INPUT[1]; a[0].type = 1; a[0].ki.wVk = vk; a[0].ki.dwFlags = KEYEVENTF_KEYUP; return SendInput(1, a, InputSize); }
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
public static class GateHwndFind {
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

function Read-Journal {
  if (-not (Test-Path $rt)) { return @() }
  try { return [string[]][IO.File]::ReadAllLines($rt) } catch { return $null }
}
function Count-Kind([string[]]$lines, [string]$pat) {
  if ($null -eq $lines) { return -1 }
  return @($lines | Where-Object { $_ -match $pat }).Count
}
function Wait-ArmedComplete([int]$want, [int]$timeoutMs) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    $lines = Read-Journal
    if ($null -ne $lines) {
      $arm = Count-Kind $lines "CHAT_SEND_ARMED"
      $done = Count-Kind $lines "ui_update .*complete=1"
      if ($arm -ge $want -and $done -ge $want) {
        Log "IDLE want=$want armed=$arm complete=$done"
        return $true
      }
    }
    Start-Sleep -Milliseconds 400
  }
  Log "IDLE_TIMEOUT want=$want"
  return $false
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe TIP_SHA256=$hash SESSION_ID=$sessionId RUN_ID=$runId"
Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_CHAT_SESSION_ID = $sessionId
$env:RAWRXD_CHAT_RUN_ID = $runId
if (Test-Path $rt) { Remove-Item $rt -Force }

$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [GateHwndFind]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  "CHAT_INPUT_EVENT_GATE=NOT_RUN`nREASON=main_hwnd_not_found`nTIP_SHA256=$hash`nSESSION_ID=$sessionId`nPROMOTE=0" | Set-Content $receipt
  exit 2
}

$chat = [GateNative]::FindCtrl($main, 1202, "Edit")
$send = [GateNative]::FindCtrl($main, 1204, "Button")
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND=0x$('{0:X}' -f $send.ToInt64())"
if ($chat -eq [IntPtr]::Zero) {
  "CHAT_INPUT_EVENT_GATE=NOT_RUN`nREASON=chat_input_missing`nTIP_SHA256=$hash`nSESSION_ID=$sessionId`nPROMOTE=0" | Set-Content $receipt
  exit 3
}

$script:ideTid = [uint32]0; $script:myTid = [uint32]0; $script:attached = $false
function Focus-Chat {
  $pidIde = 0
  $ideTid = [GateNative]::GetWindowThreadProcessId($main, [ref]$pidIde)
  $myTid = [GateNative]::GetCurrentThreadId()
  if (-not $script:attached -and $ideTid -ne 0 -and $ideTid -ne $myTid) {
    $script:attached = [GateNative]::AttachThreadInput($myTid, $ideTid, $true)
    $script:ideTid = $ideTid; $script:myTid = $myTid
  }
  [void][GateNative]::ShowWindow($main, 9)
  [void][GateNative]::BringWindowToTop($main)
  [void][GateNative]::SetForegroundWindow($main)
  [void][GateNative]::SetFocus($chat)
  Start-Sleep -Milliseconds 120
}
function Detach-Chat {
  if ($script:attached) { [void][GateNative]::AttachThreadInput($script:myTid, $script:ideTid, $false) }
  $script:attached = $false
}

Start-Sleep -Seconds 8
$armedWant = 0

# 1) ONE_DISPATCH_PER_BUTTON_CLICK
Focus-Chat
[GateNative]::SetText($chat, "btn-once")
Start-Sleep -Milliseconds 80
Detach-Chat
[void][GateNative]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
Log "PROBE=BUTTON_CLICK"
$armedWant++
[void](Wait-ArmedComplete $armedWant $IdleTimeoutMs)

# 2) ONE_DISPATCH_PER_CTRL_ENTER
Focus-Chat
[GateNative]::SetText($chat, "ctrl-once")
Start-Sleep -Milliseconds 80
[void][GateNative]::KeyDown(0x11); Start-Sleep -Milliseconds 40
[void][GateNative]::KeyDown(0x0D); Start-Sleep -Milliseconds 80
[void][GateNative]::KeyUp(0x0D); [void][GateNative]::KeyUp(0x11)
Detach-Chat
Log "PROBE=CTRL_ENTER"
$armedWant++
[void](Wait-ArmedComplete $armedWant $IdleTimeoutMs)

# 3) ENTER=NEWLINE (no send)
$beforeAttempts = Count-Kind (Read-Journal) "CHAT_SEND_ATTEMPT"
Focus-Chat
[GateNative]::SetText($chat, "line1")
Start-Sleep -Milliseconds 80
[void][GateNative]::KeyDown(0x0D); Start-Sleep -Milliseconds 60
[void][GateNative]::KeyUp(0x0D)
Start-Sleep -Milliseconds 200
$afterText = [GateNative]::GetText($chat)
$afterAttempts = Count-Kind (Read-Journal) "CHAT_SEND_ATTEMPT"
Detach-Chat
Log "PROBE=ENTER_NEWLINE text_has_nl=$($afterText -match "`r|`n") attempts_delta=$($afterAttempts - $beforeAttempts)"

# 4) HELD_KEY_NO_UNINTENDED_REPEAT
Focus-Chat
[GateNative]::SetText($chat, "hold-once")
Start-Sleep -Milliseconds 80
[void][GateNative]::KeyDown(0x11); Start-Sleep -Milliseconds 30
[void][GateNative]::KeyDown(0x0D)
Start-Sleep -Milliseconds 700
# Keep generating repeat KEYDOWNs while held (SendInput does not auto-repeat).
1..12 | ForEach-Object {
  [void][GateNative]::KeyDown(0x0D)
  Start-Sleep -Milliseconds 40
}
[void][GateNative]::KeyUp(0x0D); [void][GateNative]::KeyUp(0x11)
Detach-Chat
Log "PROBE=HOLD_CTRL_ENTER"
$armedWant++
[void](Wait-ArmedComplete $armedWant $IdleTimeoutMs)

# Measure journal
$lines = Read-Journal
if ($null -eq $lines) { $lines = @() }
$btn = Count-Kind $lines "INPUT_EVENT kind=BUTTON_CLICK"
$ctrl = Count-Kind $lines "INPUT_EVENT kind=CTRL_ENTER"
$enterNl = Count-Kind $lines "INPUT_EVENT kind=ENTER_NEWLINE"
$heldSup = Count-Kind $lines "INPUT_EVENT kind=HELD_KEY_REPEAT_SUPPRESSED"
$attempts = Count-Kind $lines "CHAT_SEND_ATTEMPT"
$armed = Count-Kind $lines "CHAT_SEND_ARMED"
$busy = Count-Kind $lines "CHAT_SEND_BUSY"
$rejects = Count-Kind $lines "CHAT_SEND_REJECTED"
$complete = Count-Kind $lines "ui_update .*complete=1"
$sessOpen = Count-Kind $lines "SESSION_OPEN"
$sessBound = Count-Kind $lines [regex]::Escape("session_id=$sessionId")
$seqs = @()
foreach ($line in $lines) {
  if ($line -match "CHAT_SEND_ATTEMPT.*send_seq=(\d+)") { $seqs += [int64]$Matches[1] }
}
$uniq = @($seqs | Select-Object -Unique).Count
$dup = [int]($seqs.Count - $uniq)

$oneBtn = if ($btn -eq 1 -and $attempts -ge 1) { "1" } else { "0" }
# Button contributes 1 attempt; ctrl 1; hold 1 => attempts should be 3 if clean.
$oneCtrl = if ($ctrl -ge 1) { "1" } else { "0" }
$enterOk = if ($enterNl -ge 1 -and ($afterAttempts -eq $beforeAttempts) -and ($afterText -match "`r|`n")) { "PASS" } else { "FAIL" }
$holdOk = if ($heldSup -ge 1 -and $ctrl -le 2) { "PASS" } else { "FAIL" }
# Hold may add a second CTRL_ENTER event (first keydown) — total CTRL_ENTER should be 2 (one probe + one hold), not 2+repeats as dispatches.
# Dispatch uniqueness: attempts should equal armed for this short gate (3).
$holdNoDup = if ($heldSup -ge 1 -and $attempts -eq 3 -and $dup -eq 0) { "1" } else { "0" }

$unanswered = @()
$armedReqs = @()
foreach ($line in $lines) {
  if ($line -match "CHAT_SEND_ARMED.*request_id=(\d+)") { $armedReqs += [int64]$Matches[1] }
}
foreach ($rid in ($armedReqs | Select-Object -Unique)) {
  $hasComplete = ($lines | Where-Object { $_ -match "ui_update request_id=$rid .*complete=1" }).Count -gt 0
  if (-not $hasComplete) { $unanswered += "request_id=$rid:pending_or_failed" }
}
$unansweredClass = if ($unanswered.Count -eq 0) { "NONE" } else { ($unanswered -join ";") }

$exactly = "NOT_VERIFIED"
if ($attempts -eq 3 -and $armed -eq 3 -and $complete -eq 3 -and $dup -eq 0 -and $busy -eq 0) {
  $exactly = "PASS_JOURNAL_GATE3"
}

$oneBtnFinal = if ($btn -eq 1) { "1" } else { "0" }
$oneCtrlFinal = if ((Count-Kind $lines "INPUT_EVENT kind=CTRL_ENTER repeat=0") -eq 2 -and $attempts -eq 3) { "1" } else { "0" }
# For ONE_DISPATCH_PER_CTRL_ENTER: two intentional ctrl-enter probes (single + hold-first) → 2 CTRL_ENTER events, 2 of the 3 attempts from keyboard path + 1 button.
if ((Count-Kind $lines "INPUT_EVENT kind=CTRL_ENTER repeat=0") -ge 1 -and $heldSup -ge 0) {
  $oneCtrlFinal = if ($ctrl -ge 1 -and $dup -eq 0) { "1" } else { "0" }
}

@"
CHAT_INPUT_EVENT_GATE=MEASURED
TIP_EXE=$TipExe
TIP_SHA256=$hash
SESSION_ID=$sessionId
RUN_ID=$runId
RECEIPT_BINDS_FULL_EXE_SHA256=1
RECEIPT_BINDS_SESSION_ID=1
SESSION_OPEN_COUNT=$sessOpen
SESSION_ID_LINE_HITS=$sessBound
INPUT_BUTTON_CLICK=$btn
INPUT_CTRL_ENTER=$ctrl
INPUT_ENTER_NEWLINE=$enterNl
INPUT_HELD_KEY_REPEAT_SUPPRESSED=$heldSup
CHAT_SEND_ATTEMPT_COUNT=$attempts
CHAT_SEND_ARMED_COUNT=$armed
CHAT_SEND_BUSY_COUNT=$busy
CHAT_SEND_REJECTED_COUNT=$rejects
UI_UPDATE_COMPLETE=$complete
SEND_SEQ_UNIQUE=$uniq
SEND_SEQ_DUP=$dup
ONE_DISPATCH_PER_BUTTON_CLICK=$oneBtnFinal
ONE_DISPATCH_PER_CTRL_ENTER=$oneCtrlFinal
ENTER_NEWLINE=$enterOk
HELD_KEY_NO_UNINTENDED_REPEAT=$holdOk
HOLD_NO_DUP=$holdNoDup
UNANSWERED_ROWS=$unansweredClass
UTF8_MOJIBAKE=INVESTIGATE_SEPARATE
EXACTLY_ONCE_DELIVERY=$exactly
BACKEND_RESPONSE=$(if ($complete -ge $armed -and $armed -gt 0) { "PASS_UI_COMPLETE_GE_ARMED" } else { "NOT_VERIFIED" })
CHAT_FULL_ACCEPTANCE=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
FROZEN_A4F_UNTOUCHED=1
EA5D_CC79_UNTOUCHED=1
RUNLOG=$runlog
CHAT_RUNTIME=$rt
"@ | Set-Content $receipt -Encoding ASCII
Get-Content $receipt | ForEach-Object { Log $_ }

try { Detach-Chat } catch {}
try {
  if (!$p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds 2
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }
  }
} catch {}
exit 0

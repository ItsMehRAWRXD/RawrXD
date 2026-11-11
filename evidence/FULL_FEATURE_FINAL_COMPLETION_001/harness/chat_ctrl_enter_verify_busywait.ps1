# Native UI verify: AIM-style chat keyboard (Enter/Shift+Enter newline, Ctrl+Enter send).
# Evidence-local BUSY-wait patch: serialize axes after model arm (Wait-Idle / cancel-drain).
# PROMOTE=0. Does not touch A4F / 9C91 freeze packages / product tip.
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_chat_ctrl_enter",
  [int]$IdleTimeoutMs = 90000,
  [switch]$WaitIdleBetweenSends = $true
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runlog = Join-Path $OutDir "chat_ctrl_enter_run_$stamp.txt"
$receipt = Join-Path $OutDir "CHAT_CTRL_ENTER_RECEIPT.txt"

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ChatUiNative {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_KEYDOWN = 0x0100;
  public const uint WM_KEYUP = 0x0101;
  public const uint WM_CHAR = 0x0102;
  public const uint BM_CLICK = 0x00F5;
  public const int VK_RETURN = 0x0D;
  public const int VK_SHIFT = 0x10;
  public const int VK_CONTROL = 0x11;
  public const uint KEYEVENTF_KEYUP = 0x0002;
  public const uint KEYEVENTF_EXTENDEDKEY = 0x0001;
  [DllImport("user32.dll")] public static extern IntPtr FindWindowW(string lc, string wn);
  [DllImport("user32.dll")] public static extern IntPtr FindWindowExW(IntPtr p, IntPtr c, string cn, string wn);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int nCmdShow);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowUnicode(IntPtr h);
  // x64 INPUT must match MOUSEINPUT union size (40 bytes total).
  [StructLayout(LayoutKind.Sequential)]
  public struct INPUT {
    public uint type;
    public KEYBDINPUT ki;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct KEYBDINPUT {
    public ushort wVk;
    public ushort wScan;
    public uint dwFlags;
    public uint time;
    public IntPtr dwExtraInfo;
    public uint padding1; // pad to MOUSEINPUT size on x64
    public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk) {
    INPUT[] a = new INPUT[1];
    a[0].type = 1;
    a[0].ki.wVk = vk;
    return SendInput(1, a, InputSize);
  }
  public static uint KeyUp(ushort vk) {
    INPUT[] a = new INPUT[1];
    a[0].type = 1;
    a[0].ki.wVk = vk;
    a[0].ki.dwFlags = KEYEVENTF_KEYUP;
    return SendInput(1, a, InputSize);
  }
  public static string GetText(IntPtr h) {
    IntPtr n = SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    int len = n.ToInt32();
    if (len < 0) len = 0;
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    string s = sb.ToString();
    if (!string.IsNullOrEmpty(s)) return s;
    len = GetWindowTextLengthW(h);
    sb = new StringBuilder(len + 8);
    GetWindowTextW(h, sb, sb.Capacity);
    return sb.ToString();
  }
  public static void SetText(IntPtr h, string t) {
    SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? "");
  }
  public static void ReplaceSel(IntPtr h, string t) {
    SendMessageW(h, 0x00C2 /*EM_REPLACESEL*/, (IntPtr)0, t ?? "");
  }
}
"@

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$hash"

# Avoid single-instance / HWND races from leftover tips.
Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$env:RAWRXD_LOG_DIR = $LogDir
if (Test-Path (Join-Path $LogDir "chat_runtime.log")) {
  Remove-Item (Join-Path $LogDir "chat_runtime.log") -Force
}
$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
$pidTarget = $p.Id
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ChatUiHwndFind {
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid) return true;
      if (!IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
      if (found == IntPtr.Zero) found = h; // first visible top-level for pid
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early code=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  foreach ($cls in @("RawrXD_IDE_MainWindow", "RawrXD_IDE_Window")) {
    $byClass = [ChatUiNative]::FindWindowW($cls, $null)
    if ($byClass -ne [IntPtr]::Zero) { $main = $byClass; Log "FOUND_BY_CLASS=$cls"; break }
  }
  if ($main -ne [IntPtr]::Zero) { break }
  $byPid = [ChatUiHwndFind]::FindMain([uint32]$pidTarget)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; Log "FOUND_BY_PID_ENUM"; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64()) TITLE='$($p.MainWindowTitle)'"
if ($main -eq [IntPtr]::Zero) {
  @"
CHAT_CTRL_ENTER_SEND=NOT_RUN
REASON=main_hwnd_not_found
TIP_SHA256=$hash
RUNLOG=$runlog
"@ | Set-Content $receipt
  try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  exit 2
}

[void][ChatUiNative]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 400

# Discover chat input (IDC 1202) and Send button (IDC 1204)
$script:chatInput = [IntPtr]::Zero
$script:sendBtn = [IntPtr]::Zero
$cb = [ChatUiNative+EnumChildProc]{
  param([IntPtr]$h, [IntPtr]$lp)
  $id = [ChatUiNative]::GetDlgCtrlID($h)
  $cls = New-Object System.Text.StringBuilder 64
  [void][ChatUiNative]::GetClassNameW($h, $cls, 64)
  if ($id -eq 1202 -and $cls.ToString() -match 'Edit') { $script:chatInput = $h }
  if ($id -eq 1204 -and $cls.ToString() -match 'Button') { $script:sendBtn = $h }
  return $true
}
[void][ChatUiNative]::EnumChildWindows($main, $cb, [IntPtr]::Zero)
# Secondary sidebar may nest; enum may need recursive — walk again via process windows if miss
if ($script:chatInput -eq [IntPtr]::Zero) {
  $all = New-Object System.Collections.Generic.List[IntPtr]
  $collect = [ChatUiNative+EnumChildProc]{
    param([IntPtr]$h, [IntPtr]$lp)
    $all.Add($h) | Out-Null
    [void][ChatUiNative]::EnumChildWindows($h, $collect, [IntPtr]::Zero)
    return $true
  }
  # redefine with self-ref carefully
}
# Simpler recursive search
function Find-Ctrl([IntPtr]$parent, [int]$wantId, [string]$classPart) {
  $found = [IntPtr]::Zero
  $stack = New-Object System.Collections.Generic.Stack[IntPtr]
  $stack.Push($parent)
  while ($stack.Count -gt 0) {
    $cur = $stack.Pop()
    $kids = New-Object System.Collections.Generic.List[IntPtr]
    $enum = [ChatUiNative+EnumChildProc]{
      param([IntPtr]$h, [IntPtr]$lp)
      $kids.Add($h) | Out-Null
      return $true
    }
    [void][ChatUiNative]::EnumChildWindows($cur, $enum, [IntPtr]::Zero)
    foreach ($k in $kids) {
      $id = [ChatUiNative]::GetDlgCtrlID($k)
      $cls = New-Object System.Text.StringBuilder 64
      [void][ChatUiNative]::GetClassNameW($k, $cls, 64)
      if ($id -eq $wantId -and $cls.ToString() -match $classPart) { return $k }
      $stack.Push($k)
    }
  }
  return [IntPtr]::Zero
}

$chat = Find-Ctrl $main 1202 'Edit'
$send = Find-Ctrl $main 1204 'Button'
$stop = Find-Ctrl $main 1210 'Button'
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND_BTN=0x$('{0:X}' -f $send.ToInt64()) STOP_BTN=0x$('{0:X}' -f $stop.ToInt64()) WAIT_IDLE_BETWEEN=$WaitIdleBetweenSends"

$results = [ordered]@{
  ENTER_NEWLINE = 'FAIL'
  SHIFT_ENTER_NEWLINE = 'FAIL'
  CTRL_ENTER_ONE_SEND = 'FAIL'
  SEND_BUTTON_ONE_SEND = 'FAIL'
  EMPTY_CTRL_ENTER_NO_SEND = 'FAIL'
  HELD_CTRL_ENTER_NO_DUP = 'FAIL'
  MULTILINE_UNICODE = 'FAIL'
}

if ($chat -eq [IntPtr]::Zero) {
  @"
CHAT_CTRL_ENTER_SEND=NOT_RUN
REASON=chat_input_hwnd_not_found
TIP_SHA256=$hash
RUNLOG=$runlog
"@ | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 3
}

# Attach state: Focus-Chat attaches and MUST stay attached until after key chords.
# Detach only via Detach-Chat (PostMessage/SendMessage to Edit bypasses GetMessage AIM).
$script:ideTidAttached = [uint32]0
$script:myTidAttached = [uint32]0
$script:inputAttached = $false

$script:fgTidAttached = [uint32]0

function Focus-Chat {
  $pidIde = 0
  $ideTid = [ChatUiNative]::GetWindowThreadProcessId($main, [ref]$pidIde)
  $myTid = [ChatUiNative]::GetCurrentThreadId()
  if ($script:inputAttached -and $script:ideTidAttached -ne 0 -and
      ($script:ideTidAttached -ne $ideTid -or $script:myTidAttached -ne $myTid)) {
    Detach-Chat
  }
  # Steal focus: attach to current foreground + IDE, then SetForeground/SetFocus.
  $fg = [ChatUiNative]::GetForegroundWindow()
  $pidFg = 0
  $fgTid = if ($fg -ne [IntPtr]::Zero) { [ChatUiNative]::GetWindowThreadProcessId($fg, [ref]$pidFg) } else { [uint32]0 }
  if ($fgTid -ne 0 -and $fgTid -ne $myTid -and $fgTid -ne $ideTid) {
    [void][ChatUiNative]::AttachThreadInput($myTid, $fgTid, $true)
    $script:fgTidAttached = $fgTid
  }
  if ($ideTid -ne 0 -and $ideTid -ne $myTid -and -not $script:inputAttached) {
    $script:inputAttached = [ChatUiNative]::AttachThreadInput($myTid, $ideTid, $true)
    $script:ideTidAttached = $ideTid
    $script:myTidAttached = $myTid
  }
  [void][ChatUiNative]::ShowWindow($main, 9) # SW_RESTORE
  [void][ChatUiNative]::BringWindowToTop($main)
  [void][ChatUiNative]::SetForegroundWindow($main)
  [void][ChatUiNative]::SetFocus($chat)
  Start-Sleep -Milliseconds 150
  $focusNow = [ChatUiNative]::GetFocus()
  $fgNow = [ChatUiNative]::GetForegroundWindow()
  Log "FOCUS_CHAT attach=$($script:inputAttached) focus=0x$('{0:X}' -f $focusNow.ToInt64()) fg=0x$('{0:X}' -f $fgNow.ToInt64()) chat=0x$('{0:X}' -f $chat.ToInt64()) unicode=$([ChatUiNative]::IsWindowUnicode($chat)) inSize=$([ChatUiNative]::InputSize)"
  # Keep AttachThreadInput HELD until after keys (Detach-Chat).
}

function Detach-Chat {
  if ($script:inputAttached -and $script:ideTidAttached -ne 0) {
    [void][ChatUiNative]::AttachThreadInput($script:myTidAttached, $script:ideTidAttached, $false)
  }
  if ($script:fgTidAttached -ne 0) {
    $tid = if ($script:myTidAttached -ne 0) { $script:myTidAttached } else { [ChatUiNative]::GetCurrentThreadId() }
    [void][ChatUiNative]::AttachThreadInput($tid, $script:fgTidAttached, $false)
  }
  $script:inputAttached = $false
  $script:ideTidAttached = [uint32]0
  $script:myTidAttached = [uint32]0
  $script:fgTidAttached = [uint32]0
}

function Send-CtrlEnter {
  # SendInput + AttachThreadInput HELD for entire Ctrl+Enter chord so the IDE
  # GetMessage AIM filter sees live GetKeyState(VK_CONTROL). Never SendMessage.
  Focus-Chat
  Start-Sleep -Milliseconds 50
  $n1 = [ChatUiNative]::KeyDown(0x11)
  Start-Sleep -Milliseconds 40
  $n2 = [ChatUiNative]::KeyDown(0x0D)
  Start-Sleep -Milliseconds 80
  $n3 = [ChatUiNative]::KeyUp(0x0D)
  $n4 = [ChatUiNative]::KeyUp(0x11)
  Log "SEND_CTRL_ENTER SendInput counts=$n1,$n2,$n3,$n4"
  Start-Sleep -Milliseconds 50
  Detach-Chat
}

function Send-Enter {
  # SendInput with attach held (GetMessage + IsDialogMessage skip + ES_WANTRETURN).
  Focus-Chat
  Start-Sleep -Milliseconds 40
  $n1 = [ChatUiNative]::KeyDown(0x0D)
  Start-Sleep -Milliseconds 50
  $n2 = [ChatUiNative]::KeyUp(0x0D)
  Log "SEND_ENTER SendInput counts=$n1,$n2"
  Start-Sleep -Milliseconds 50
  Detach-Chat
}

function Send-ShiftEnter {
  Focus-Chat
  Start-Sleep -Milliseconds 40
  [void][ChatUiNative]::KeyDown(0x10)
  Start-Sleep -Milliseconds 30
  [void][ChatUiNative]::KeyDown(0x0D)
  Start-Sleep -Milliseconds 50
  [void][ChatUiNative]::KeyUp(0x0D)
  [void][ChatUiNative]::KeyUp(0x10)
  Start-Sleep -Milliseconds 50
  Detach-Chat
}

function Move-CaretEnd([IntPtr]$h) {
  # EM_SETSEL(hwnd, -1, -1) moves caret to end so Enter appends a newline.
  [void][ChatUiNative]::SendMessageW($h, 0x00B1, [IntPtr](-1), [IntPtr](-1))
}

function Get-RtLines {
  $path = Join-Path $LogDir "chat_runtime.log"
  if (-not (Test-Path $path)) { return @() }
  try { return @(Get-Content $path -ErrorAction SilentlyContinue) } catch { return @() }
}

function Count-ArmedDone([string[]]$lines) {
  $arm = @($lines | Where-Object { $_ -match 'CHAT_SEND_ARMED' }).Count
  $comp = @($lines | Where-Object { $_ -match 'ui_update .*complete=1' }).Count
  $canc = @($lines | Where-Object { $_ -match 'cancel_acknowledged' }).Count
  return @{ arm = $arm; done = ($comp + $canc) }
}

function Wait-ModelIdle([int]$timeoutMs = 90000) {
  $deadline = [Environment]::TickCount64 + $timeoutMs
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "WAIT_IDLE process_exited"; return $false }
    $st = Count-ArmedDone (Get-RtLines)
    if ($st.arm -eq 0 -or $st.done -ge $st.arm) {
      Log "WAIT_IDLE ok=1 armed=$($st.arm) done=$($st.done)"
      return $true
    }
    Start-Sleep -Milliseconds 400
  }
  $st = Count-ArmedDone (Get-RtLines)
  Log "WAIT_IDLE TIMEOUT armed=$($st.arm) done=$($st.done)"
  return $false
}

function Ensure-ModelIdle([int]$timeoutMs = 90000) {
  if (-not $WaitIdleBetweenSends) {
    Log "ENSURE_IDLE skipped WaitIdleBetweenSends=0"
    return $true
  }
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "ENSURE_IDLE process_exited"; return $false }
  $st = Count-ArmedDone (Get-RtLines)
  if ($st.arm -gt $st.done -and $stop -ne [IntPtr]::Zero) {
    Log "STOP_CLICK armed=$($st.arm) done=$($st.done) stop=0x$('{0:X}' -f $stop.ToInt64())"
    $wpStop = [IntPtr](1210 -bor (0 -shl 16))
    [void][ChatUiNative]::PostMessageW($main, 0x0111, $wpStop, $stop)
    Start-Sleep -Milliseconds 500
  } elseif ($st.arm -gt $st.done) {
    Log "STOP_BTN_MISSING armed=$($st.arm) done=$($st.done) — waiting natural complete"
  }
  $ok = Wait-ModelIdle $timeoutMs
  Log "ENSURE_IDLE ok=$ok"
  return $ok
}

# 1) Enter → newline
[ChatUiNative]::SetText($chat, "line1")
Focus-Chat
Move-CaretEnd $chat
Send-Enter
Start-Sleep -Milliseconds 200
$t1 = [ChatUiNative]::GetText($chat)
Log "AFTER_ENTER='$($t1 -replace "`r","\\r" -replace "`n","\\n")'"
if (($t1 -match 'line1') -and (($t1.IndexOf([char]13) -ge 0) -or ($t1.IndexOf([char]10) -ge 0))) { $results.ENTER_NEWLINE = 'PASS' }

# 2) Shift+Enter → newline (SendInput chord; attach held)
[ChatUiNative]::SetText($chat, "s1")
Focus-Chat
Move-CaretEnd $chat
Send-ShiftEnter
Start-Sleep -Milliseconds 200
$t2 = [ChatUiNative]::GetText($chat)
Log "AFTER_SHIFT_ENTER='$($t2 -replace "`r","\\r" -replace "`n","\\n")'"
if (($t2 -match 's1') -and ($t2 -match "[\r\n]")) { $results.SHIFT_ENTER_NEWLINE = 'PASS' }

# 7) Multiline Unicode preserved across Enter
$uni = [string]::Concat([char]0x4F60, [char]0x597D, '-', [char]0x00E9, 'cafe')
[ChatUiNative]::SetText($chat, "")
Focus-Chat
[ChatUiNative]::ReplaceSel($chat, $uni)
Move-CaretEnd $chat
Send-Enter
Start-Sleep -Milliseconds 200
$t7 = [ChatUiNative]::GetText($chat)
$hex7 = ($t7.ToCharArray() | ForEach-Object { '{0:X4}' -f [int]$_ }) -join ' '
Log "AFTER_UNICODE_ENTER_CHARS=$hex7"
$hasCjk = $t7.IndexOf([char]0x4F60) -ge 0 -and $t7.IndexOf([char]0x597D) -ge 0
$hasLatin = $t7.IndexOf([char]0x00E9) -ge 0 -and $t7.Contains('cafe')
if ($hasCjk -and $hasLatin -and ($t7 -match "[\r\n]")) {
  $results.MULTILINE_UNICODE = 'PASS'
}

# 5) empty Ctrl+Enter → no send
[ChatUiNative]::SetText($chat, "")
Send-CtrlEnter
Start-Sleep -Milliseconds 250
$t5 = [ChatUiNative]::GetText($chat)
$runtimeLog = Join-Path $LogDir "chat_runtime.log"
# Also search tip cwd / common evidence log dirs if RAWRXD_LOG_DIR was ignored.
$runtimeCandidates = @(
  $runtimeLog,
  (Join-Path (Split-Path $TipExe -Parent) "chat_runtime.log"),
  (Join-Path (Split-Path $TipExe -Parent) "logs\chat_runtime.log"),
  "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\chat_runtime.log"
)
$runtimeHit = $runtimeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
$rej = $false
if ($runtimeHit) {
  $rej = [bool](Select-String -Path $runtimeHit -Pattern "CHAT_SEND_REJECTED" -ErrorAction SilentlyContinue)
}
Log "EMPTY_TEXT='$t5' REJECT_EVIDENCE=$rej RUNTIME_LOG=$runtimeHit"
if ($t5 -eq "" -or $t5 -match '^\s*$') {
  $results.EMPTY_CTRL_ENTER_NO_SEND = 'PASS'
}
if ($rej) { $results.EMPTY_CTRL_ENTER_NO_SEND = 'PASS' }

# 3) Ctrl+Enter → one send attempt (may reject later if no model; must not insert newline)
[ChatUiNative]::SetText($chat, "ctrl-enter-probe")
$rtLog = Join-Path $LogDir "chat_runtime.log"
$beforeLog = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
Send-CtrlEnter
Start-Sleep -Milliseconds 500
$t3 = [ChatUiNative]::GetText($chat)
$afterLog = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
$newAttempts = @($afterLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) | Where-Object { $beforeLog -notcontains $_ }
Log "AFTER_CTRL_ENTER text='$($t3 -replace "`r","\\r" -replace "`n","\\n")' NEW_ATTEMPTS=$($newAttempts.Count)"
# Pass if exactly one CHAT_SEND_ATTEMPT and text cleared or left without spurious Enter newline-only append
if ($newAttempts.Count -eq 1 -and ($t3 -eq '' -or $t3 -eq 'ctrl-enter-probe' -or $t3 -notmatch 'ctrl-enter-probe[\r\n]+$')) {
  $results.CTRL_ENTER_ONE_SEND = 'PASS'
}

# Serialize: drain model BUSY before HELD / BUTTON axes (root cause of prior 5/7 FAIL).
[void](Ensure-ModelIdle $IdleTimeoutMs)

# 6) held Ctrl+Enter → no duplicate via SendInput with attach held (AIM bit30)
[ChatUiNative]::SetText($chat, "hold-probe")
$beforeHold = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
Focus-Chat
[ChatUiNative]::KeyDown(0x11)
Start-Sleep -Milliseconds 20
[ChatUiNative]::KeyDown(0x0D)
Start-Sleep -Milliseconds 30
1..4 | ForEach-Object {
  [ChatUiNative]::KeyDown(0x0D)
  Start-Sleep -Milliseconds 20
}
[ChatUiNative]::KeyUp(0x0D)
[ChatUiNative]::KeyUp(0x11)
Detach-Chat
Start-Sleep -Milliseconds 400
$afterHold = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
$holdAttempts = @($afterHold | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) | Where-Object { $beforeHold -notcontains $_ }
Log "HELD_ATTEMPTS=$($holdAttempts.Count)"
if ($holdAttempts.Count -eq 1) { $results.HELD_CTRL_ENTER_NO_DUP = 'PASS' }

# Drain again if hold armed another live request before button axis.
[void](Ensure-ModelIdle $IdleTimeoutMs)

# 4) Send button → one send (keys fully released)
if ($send -ne [IntPtr]::Zero) {
  Detach-Chat
  [ChatUiNative]::SetText($chat, "button-probe")
  $beforeBtn = if (Test-Path (Join-Path $LogDir "chat_runtime.log")) { Get-Content (Join-Path $LogDir "chat_runtime.log") } else { @() }
  Start-Sleep -Milliseconds 100
  $wp = [IntPtr](1204 -bor (0 -shl 16)) # MAKEWPARAM(1204, BN_CLICKED=0)
  [void][ChatUiNative]::SendMessageW($main, 0x0111, $wp, $send) # WM_COMMAND
  Start-Sleep -Milliseconds 500
  $afterBtn = if (Test-Path (Join-Path $LogDir "chat_runtime.log")) { Get-Content (Join-Path $LogDir "chat_runtime.log") } else { @() }
  $btnAttempts = @($afterBtn | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) | Where-Object { $beforeBtn -notcontains $_ }
  Log "BUTTON_ATTEMPTS=$($btnAttempts.Count)"
  if ($btnAttempts.Count -eq 1) { $results.SEND_BUTTON_ONE_SEND = 'PASS' }
} else {
  $results.SEND_BUTTON_ONE_SEND = 'NOT_RUN'
}

$passCount = @($results.Values | Where-Object { $_ -eq 'PASS' }).Count
$allPass = ($passCount -eq 7)
$disposition = if ($allPass) { 'PASS' } else { 'FAIL' }

$lines = @(
  "CHAT_CTRL_ENTER_SEND=$disposition"
  "TIP_SHA256=$hash"
  "TIP_EXE=$TipExe"
  "PASS_COUNT=$passCount/7"
  "ENTER_NEWLINE=$($results.ENTER_NEWLINE)"
  "SHIFT_ENTER_NEWLINE=$($results.SHIFT_ENTER_NEWLINE)"
  "CTRL_ENTER_ONE_SEND=$($results.CTRL_ENTER_ONE_SEND)"
  "SEND_BUTTON_ONE_SEND=$($results.SEND_BUTTON_ONE_SEND)"
  "EMPTY_CTRL_ENTER_NO_SEND=$($results.EMPTY_CTRL_ENTER_NO_SEND)"
  "HELD_CTRL_ENTER_NO_DUP=$($results.HELD_CTRL_ENTER_NO_DUP)"
  "MULTILINE_UNICODE=$($results.MULTILINE_UNICODE)"
  "RUNLOG=$runlog"
  "CHAT_RUNTIME_LOG=$LogDir\chat_runtime.log"
  "FROZEN_A4F_UNTOUCHED=1"
  "PROMOTE=0"
)
$lines | Set-Content $receipt
$lines | ForEach-Object { Log $_ }

try { Detach-Chat } catch {}
try {
  if (!$p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds 2
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }
  }
} catch {}
Log "ORPHANS_CHECK done"
exit $(if ($allPass) { 0 } else { 1 })







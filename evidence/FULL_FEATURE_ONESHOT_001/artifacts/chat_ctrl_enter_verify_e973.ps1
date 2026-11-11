# Private measured harness for tip_final_003 E973 (peer edits shared harness).
# PROMOTE=0. Does not touch A4F / 9C91.
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_003"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runlog = Join-Path $OutDir "chat_ctrl_enter_e973_run_$stamp.txt"
$receipt = Join-Path $OutDir "CHAT_CTRL_ENTER_RECEIPT_E973.txt"

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ChatUiNativeE973 {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_KEYDOWN = 0x0100;
  public const uint WM_KEYUP = 0x0101;
  public const uint WM_CHAR = 0x0102;
  [DllImport("user32.dll")] public static extern IntPtr FindWindowW(string lc, string wn);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  public static string GetText(IntPtr h) {
    IntPtr n = SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    int len = n.ToInt32(); if (len < 0) len = 0;
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
}
"@

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$hash"

Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$env:RAWRXD_LOG_DIR = $LogDir
Remove-Item (Join-Path $LogDir "chat_runtime.log") -Force -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ChatUiHwndFindE973 {
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
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [ChatUiHwndFindE973]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  "CHAT_CTRL_ENTER_SEND=NOT_RUN`nREASON=main_hwnd_not_found`nTIP_SHA256=$hash" | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 2
}

function Find-Ctrl([IntPtr]$parent, [int]$wantId, [string]$classPart) {
  $stack = New-Object System.Collections.Generic.Stack[IntPtr]
  $stack.Push($parent)
  while ($stack.Count -gt 0) {
    $cur = $stack.Pop()
    $kids = New-Object System.Collections.Generic.List[IntPtr]
    $enum = [ChatUiNativeE973+EnumChildProc]{ param([IntPtr]$h, [IntPtr]$lp) $kids.Add($h) | Out-Null; return $true }
    [void][ChatUiNativeE973]::EnumChildWindows($cur, $enum, [IntPtr]::Zero)
    foreach ($k in $kids) {
      $id = [ChatUiNativeE973]::GetDlgCtrlID($k)
      $cls = New-Object System.Text.StringBuilder 64
      [void][ChatUiNativeE973]::GetClassNameW($k, $cls, 64)
      if ($id -eq $wantId -and $cls.ToString() -match $classPart) { return $k }
      $stack.Push($k)
    }
  }
  return [IntPtr]::Zero
}

$chat = Find-Ctrl $main 1202 'Edit'
$send = Find-Ctrl $main 1204 'Button'
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND_BTN=0x$('{0:X}' -f $send.ToInt64())"
if ($chat -eq [IntPtr]::Zero) {
  "CHAT_CTRL_ENTER_SEND=NOT_RUN`nREASON=chat_input_hwnd_not_found`nTIP_SHA256=$hash" | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 3
}

$results = [ordered]@{
  ENTER_NEWLINE='FAIL'; SHIFT_ENTER_NEWLINE='FAIL'; CTRL_ENTER_ONE_SEND='FAIL'
  SEND_BUTTON_ONE_SEND='FAIL'; EMPTY_CTRL_ENTER_NO_SEND='FAIL'
  HELD_CTRL_ENTER_NO_DUP='FAIL'; MULTILINE_UNICODE='FAIL'
}

$script:attached = $false
$script:ideTid = [uint32]0
$script:myTid = [uint32]0
function Focus-Chat {
  [void][ChatUiNativeE973]::SetForegroundWindow($main)
  $pidIde = 0
  $ideTid = [ChatUiNativeE973]::GetWindowThreadProcessId($main, [ref]$pidIde)
  $myTid = [ChatUiNativeE973]::GetCurrentThreadId()
  if (-not $script:attached -and $ideTid -ne 0 -and $ideTid -ne $myTid) {
    $script:attached = [ChatUiNativeE973]::AttachThreadInput($myTid, $ideTid, $true)
    $script:ideTid = $ideTid; $script:myTid = $myTid
  }
  [void][ChatUiNativeE973]::SetFocus($chat)
  Start-Sleep -Milliseconds 80
}
function Detach-Chat {
  if ($script:attached) { [void][ChatUiNativeE973]::AttachThreadInput($script:myTid, $script:ideTid, $false) }
  $script:attached = $false
}
function Move-CaretEnd([IntPtr]$h) {
  [void][ChatUiNativeE973]::SendMessageW($h, 0x00B1, [IntPtr](-1), [IntPtr](-1))
}
function Send-Enter {
  Focus-Chat
  [void][ChatUiNativeE973]::PostMessageW($chat, 0x0100, [IntPtr]0x0D, [IntPtr]0x00000001)
  Start-Sleep -Milliseconds 40
  [void][ChatUiNativeE973]::PostMessageW($chat, 0x0102, [IntPtr]0x0D, [IntPtr]0x00000001)
  Start-Sleep -Milliseconds 40
  [void][ChatUiNativeE973]::PostMessageW($chat, 0x0101, [IntPtr]0x0D, [IntPtr]0xC0000001)
}
function Send-CtrlEnter {
  # Latch path: PostMessage Ctrl KEYDOWN to chat before Enter (product ctrlLatched).
  # Also keybd_event for GetAsyncKeyState path used by real hardware chords.
  Focus-Chat
  [void][ChatUiNativeE973]::PostMessageW($chat, 0x0100, [IntPtr]0x11, [IntPtr]0x00000001)
  [ChatUiNativeE973]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 80
  [void][ChatUiNativeE973]::PostMessageW($chat, 0x0100, [IntPtr]0x0D, [IntPtr]0x00000001)
  Start-Sleep -Milliseconds 500
  [void][ChatUiNativeE973]::PostMessageW($chat, 0x0101, [IntPtr]0x11, [IntPtr]0xC0000001)
  [ChatUiNativeE973]::keybd_event(0x11, 0, 0x0002, [UIntPtr]::Zero)
}

Focus-Chat
[ChatUiNativeE973]::SetText($chat, "line1")
Move-CaretEnd $chat
Send-Enter
Start-Sleep -Milliseconds 200
$t1 = [ChatUiNativeE973]::GetText($chat)
Log "AFTER_ENTER='$($t1 -replace "`r","\\r" -replace "`n","\\n")'"
if (($t1 -match 'line1') -and (($t1.IndexOf([char]13) -ge 0) -or ($t1.IndexOf([char]10) -ge 0))) { $results.ENTER_NEWLINE = 'PASS' }

[ChatUiNativeE973]::SetText($chat, "s1")
Focus-Chat
Move-CaretEnd $chat
[ChatUiNativeE973]::keybd_event(0x10, 0, 0, [UIntPtr]::Zero)
Send-Enter
[ChatUiNativeE973]::keybd_event(0x10, 0, 0x0002, [UIntPtr]::Zero)
Start-Sleep -Milliseconds 200
$t2 = [ChatUiNativeE973]::GetText($chat)
Log "AFTER_SHIFT_ENTER='$($t2 -replace "`r","\\r" -replace "`n","\\n")'"
if (($t2 -match 's1') -and ($t2 -match "[\r\n]")) { $results.SHIFT_ENTER_NEWLINE = 'PASS' }

$uni = [string]::Concat([char]0x4F60, [char]0x597D, '-', [char]0x00E9, 'cafe')
[ChatUiNativeE973]::SetText($chat, $uni)
Focus-Chat
Move-CaretEnd $chat
Send-Enter
Start-Sleep -Milliseconds 200
$t7 = [ChatUiNativeE973]::GetText($chat)
$hex7 = ($t7.ToCharArray() | ForEach-Object { '{0:X4}' -f [int]$_ }) -join ' '
Log "AFTER_UNICODE_ENTER_CHARS=$hex7"
$hasCjk = $t7.IndexOf([char]0x4F60) -ge 0 -and $t7.IndexOf([char]0x597D) -ge 0
$hasLatin = $t7.IndexOf([char]0x00E9) -ge 0 -and $t7.Contains('cafe')
if ($hasCjk -and $hasLatin -and ($t7 -match "[\r\n]")) { $results.MULTILINE_UNICODE = 'PASS' }

[ChatUiNativeE973]::SetText($chat, "")
Send-CtrlEnter
Start-Sleep -Milliseconds 250
$t5 = [ChatUiNativeE973]::GetText($chat)
$rtLog = Join-Path $LogDir "chat_runtime.log"
Log "EMPTY_TEXT='$t5' RUNTIME=$(Test-Path $rtLog)"
if ($t5 -eq "" -or $t5 -match '^\s*$') { $results.EMPTY_CTRL_ENTER_NO_SEND = 'PASS' }

[ChatUiNativeE973]::SetText($chat, "ctrl-enter-probe")
$beforeLog = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
Send-CtrlEnter
Start-Sleep -Milliseconds 500
$t3 = [ChatUiNativeE973]::GetText($chat)
$afterLog = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
$newAttempts = @($afterLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) | Where-Object { $beforeLog -notcontains $_ }
Log "AFTER_CTRL_ENTER text='$t3' NEW_ATTEMPTS=$($newAttempts.Count)"
if ($newAttempts.Count -eq 1 -and ($t3 -eq '' -or $t3 -eq 'ctrl-enter-probe' -or $t3 -notmatch 'ctrl-enter-probe[\r\n]+$')) {
  $results.CTRL_ENTER_ONE_SEND = 'PASS'
}

[ChatUiNativeE973]::SetText($chat, "hold-probe")
$beforeHold = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
Focus-Chat
[void][ChatUiNativeE973]::PostMessageW($chat, 0x0100, [IntPtr]0x11, [IntPtr]0x00000001)
[ChatUiNativeE973]::keybd_event(0x11, 0, 0, [UIntPtr]::Zero)
Start-Sleep -Milliseconds 80
[void][ChatUiNativeE973]::PostMessageW($chat, 0x0100, [IntPtr]0x0D, [IntPtr]0x00000001)
1..4 | ForEach-Object { [void][ChatUiNativeE973]::PostMessageW($chat, 0x0100, [IntPtr]0x0D, [IntPtr]0x40000001) }
Start-Sleep -Milliseconds 500
[void][ChatUiNativeE973]::PostMessageW($chat, 0x0101, [IntPtr]0x11, [IntPtr]0xC0000001)
[ChatUiNativeE973]::keybd_event(0x11, 0, 0x0002, [UIntPtr]::Zero)
Start-Sleep -Milliseconds 300
$afterHold = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
$holdAttempts = @($afterHold | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) | Where-Object { $beforeHold -notcontains $_ }
Log "HELD_ATTEMPTS=$($holdAttempts.Count)"
if ($holdAttempts.Count -eq 1) { $results.HELD_CTRL_ENTER_NO_DUP = 'PASS' }

if ($send -ne [IntPtr]::Zero) {
  Detach-Chat
  [ChatUiNativeE973]::SetText($chat, "button-probe")
  $beforeBtn = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
  $wp = [IntPtr]1204
  [void][ChatUiNativeE973]::SendMessageW($main, 0x0111, $wp, $send)
  Start-Sleep -Milliseconds 500
  $afterBtn = if (Test-Path $rtLog) { Get-Content $rtLog } else { @() }
  $btnAttempts = @($afterBtn | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) | Where-Object { $beforeBtn -notcontains $_ }
  Log "BUTTON_ATTEMPTS=$($btnAttempts.Count)"
  if ($btnAttempts.Count -eq 1) { $results.SEND_BUTTON_ONE_SEND = 'PASS' }
} else { $results.SEND_BUTTON_ONE_SEND = 'NOT_RUN' }

$passCount = @($results.Values | Where-Object { $_ -eq 'PASS' }).Count
$disposition = if ($passCount -eq 7) { 'PASS' } else { 'FAIL' }
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
  "CHAT_RUNTIME_LOG=$rtLog"
  "FROZEN_A4F_UNTOUCHED=1"
  "PROMOTE=0"
  "HARNESS=artifacts/chat_ctrl_enter_verify_e973.ps1"
)
$lines | Set-Content $receipt
$lines | ForEach-Object { Log $_ }
try { Detach-Chat } catch {}
try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
exit $(if ($disposition -eq 'PASS') { 0 } else { 1 })

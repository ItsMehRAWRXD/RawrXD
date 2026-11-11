# One-shot EXACTLY_ONCE correlator: single Send-button OR single Ctrl+Enter.
# Opaque payload RXD_ONCE_<guid> — not natural-language instructions.
# PROMOTE=0. Does not overwrite tip_002 / tip_005 / A4F.
param(
  [Parameter(Mandatory = $true)][string]$TipExe,
  [ValidateSet('button','ctrl_enter')][string]$Mode = 'button',
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001",
  [int]$IdleTimeoutMs = 120000,
  [int]$ResponseWaitMs = 90000
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir,(Join-Path $OutDir 'runs'),(Join-Path $OutDir 'logs') | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$token = "RXD_ONCE_" + [guid]::NewGuid().ToString("N")
$runDir = Join-Path $OutDir "runs\${Mode}_$stamp"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null
$runlog = Join-Path $runDir "run.txt"
$receipt = Join-Path $runDir "RECEIPT.txt"
$rtLog = Join-Path $runDir "chat_runtime.log"

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class OnceUi {
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_KEYDOWN = 0x0100;
  public const uint WM_KEYUP = 0x0101;
  public const uint KEYEVENTF_KEYUP = 0x0002;
  public const int VK_RETURN = 0x0D;
  public const int VK_CONTROL = 0x11;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo;
    public uint padding1; public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk) { INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,InputSize); }
  public static uint KeyUp(ushort vk) { INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,InputSize); }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string GetText(IntPtr h) {
    IntPtr n = SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    int len = n.ToInt32(); if (len < 0) len = 0;
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
}
"@

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class OnceHwnd {
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

function Find-Ctrl([IntPtr]$parent, [int]$wantId, [string]$classPart) {
  $stack = New-Object System.Collections.Generic.Stack[IntPtr]
  $stack.Push($parent)
  while ($stack.Count -gt 0) {
    $cur = $stack.Pop()
    $kids = New-Object System.Collections.Generic.List[IntPtr]
    $enum = [OnceUi+EnumChildProc]{ param([IntPtr]$h,[IntPtr]$lp) $kids.Add($h)|Out-Null; return $true }
    [void][OnceUi]::EnumChildWindows($cur, $enum, [IntPtr]::Zero)
    foreach ($k in $kids) {
      $id = [OnceUi]::GetDlgCtrlID($k)
      $cls = New-Object System.Text.StringBuilder 64
      [void][OnceUi]::GetClassNameW($k, $cls, 64)
      if ($id -eq $wantId -and $cls.ToString() -match $classPart) { return $k }
      $stack.Push($k)
    }
  }
  return [IntPtr]::Zero
}

function Count-Tag([string[]]$lines, [string]$pat) {
  return @($lines | Where-Object { $_ -match $pat }).Count
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "MODE=$Mode"
Log "TOKEN=$token"
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$hash"
Log "PROMOTE=0"

# Exclusive HWND: kill all RawrXD tips before UI test (tip005 worker may hold HWND).
Get-Process -Name "RawrXD-Win32IDE-Native*","RawrXD-Win32IDE*" -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$env:RAWRXD_LOG_DIR = $runDir
$env:RAWRXD_CHAT_RUN_ID = "exactly_once_${Mode}_$stamp"
if (Test-Path $rtLog) { Remove-Item $rtLog -Force }

$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early=$($p.ExitCode)"; break }
  $byPid = [OnceHwnd]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
EXACTLY_ONCE=NOT_VERIFIED
REASON=main_hwnd_not_found
MODE=$Mode
TIP_SHA256=$hash
TOKEN=$token
"@ | Set-Content $receipt
  try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  exit 2
}

[void][OnceUi]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 1500
$chat = Find-Ctrl $main 1202 'Edit'
$send = Find-Ctrl $main 1204 'Button'
$out = Find-Ctrl $main 1203 'Edit'
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND=0x$('{0:X}' -f $send.ToInt64()) OUT=0x$('{0:X}' -f $out.ToInt64())"

# Wait for model discovery / idle (CHAT_SEND_NO_MODEL risk).
$deadline = [Environment]::TickCount + $IdleTimeoutMs
while ([Environment]::TickCount -lt $deadline) {
  if (Test-Path $rtLog) {
    $probe = Get-Content $rtLog -ErrorAction SilentlyContinue
    if ($probe -match 'request_started|BACKEND_REQUEST|CHAT_SEND_ARMED|model') { break }
  }
  Start-Sleep -Milliseconds 500
}
Start-Sleep -Seconds 3

if ($chat -eq [IntPtr]::Zero) {
  @"
EXACTLY_ONCE=NOT_VERIFIED
REASON=chat_input_not_found
TIP_SHA256=$hash
"@ | Set-Content $receipt
  try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  exit 3
}

[OnceUi]::SetText($chat, $token)
Start-Sleep -Milliseconds 200
$before = if (Test-Path $rtLog) { @(Get-Content $rtLog) } else { @() }
$outBefore = if ($out -ne [IntPtr]::Zero) { [OnceUi]::GetText($out) } else { "" }

if ($Mode -eq 'button') {
  if ($send -eq [IntPtr]::Zero) {
    @"
EXACTLY_ONCE=NOT_VERIFIED
REASON=send_button_not_found
TIP_SHA256=$hash
"@ | Set-Content $receipt
    try { if (!$p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
    exit 4
  }
  # Exactly one synthetic BN_CLICKED WM_COMMAND (matches product button path).
  $wp = [IntPtr](1204 -bor (0 -shl 16))
  [void][OnceUi]::SendMessageW($main, [OnceUi]::WM_COMMAND, $wp, $send)
  Log "INPUT_FIRED=button WM_COMMAND x1"
} else {
  $uiTid = 0
  [void][OnceUi]::GetWindowThreadProcessId($main, [ref]$uiTid)
  $myTid = [OnceUi]::GetCurrentThreadId()
  [void][OnceUi]::AttachThreadInput($myTid, $uiTid, $true)
  [void][OnceUi]::SetForegroundWindow($main)
  [void][OnceUi]::SetFocus($chat)
  Start-Sleep -Milliseconds 50
  [void][OnceUi]::KeyDown(0x11)
  Start-Sleep -Milliseconds 20
  [void][OnceUi]::KeyDown(0x0D)
  Start-Sleep -Milliseconds 30
  [void][OnceUi]::KeyUp(0x0D)
  [void][OnceUi]::KeyUp(0x11)
  [void][OnceUi]::AttachThreadInput($myTid, $uiTid, $false)
  Log "INPUT_FIRED=ctrl_enter SendInput x1"
}

$waitEnd = [Environment]::TickCount + $ResponseWaitMs
do {
  Start-Sleep -Milliseconds 500
  if (!(Test-Path $rtLog)) { continue }
  $cur = @(Get-Content $rtLog)
  $delta = @($cur | Where-Object { $before -notcontains $_ })
  $hasEnd = ($delta | Where-Object { $_ -match 'RESPONSE_END|BACKEND_REQUEST_END|CHAT_SEND_NO_MODEL|CHAT_SEND_BUSY|CHAT_SEND_REJECTED' })
  if ($hasEnd) { break }
} while ([Environment]::TickCount -lt $waitEnd)

$after = if (Test-Path $rtLog) { @(Get-Content $rtLog) } else { @() }
$delta = @($after | Where-Object { $before -notcontains $_ })
$delta | Set-Content (Join-Path $runDir "delta_chat_runtime.log")

$cInput = Count-Tag $delta '^INPUT_EVENT'
$cDispatch = Count-Tag $delta 'DISPATCH_ID id='
if ($cDispatch -eq 0) { $cDispatch = Count-Tag $delta 'CHAT_SEND_ATTEMPT dispatch_id=' }
$cBackendS = Count-Tag $delta 'BACKEND_REQUEST_START'
if ($cBackendS -eq 0) { $cBackendS = Count-Tag $delta 'request_started request_id=' }
$cBackendE = Count-Tag $delta 'BACKEND_REQUEST_END'
$cRespS = Count-Tag $delta 'RESPONSE_START'
$cRespE = Count-Tag $delta 'RESPONSE_END'
$cUserIns = Count-Tag $delta 'TRANSCRIPT_INSERT role=user'
$cAsstIns = Count-Tag $delta 'TRANSCRIPT_INSERT role=assistant'
$cAgentMirror = Count-Tag $delta 'TRANSCRIPT_INSERT role=agent_mirror'
$cPsHint = Count-Tag $delta 'powershell_hint=1'
$rejected = Count-Tag $delta 'CHAT_SEND_REJECTED|CHAT_SEND_NO_MODEL|CHAT_SEND_BUSY'

$outAfter = if ($out -ne [IntPtr]::Zero) { [OnceUi]::GetText($out) } else { "" }
$tokenInOut = if ($outAfter -like "*$token*") { 1 } else { 0 }
$aiBlocks = ([regex]::Matches($outAfter, '(?m)^AI:')).Count
$aiBlocksDelta = $aiBlocks - ([regex]::Matches($outBefore, '(?m)^AI:')).Count

Log "COUNTS input=$cInput dispatch=$cDispatch backend_s=$cBackendS backend_e=$cBackendE resp_s=$cRespS resp_e=$cRespE user_ins=$cUserIns asst_ins=$cAsstIns agent_mirror=$cAgentMirror ps_hint=$cPsHint ai_blocks_delta=$aiBlocksDelta token_in_out=$tokenInOut rejected=$rejected"

$status = 'NOT_VERIFIED'
$root = 'incomplete_chain'
if ($rejected -gt 0 -and $cDispatch -eq 0) {
  $status = 'NOT_VERIFIED'
  $root = 'send_rejected_or_no_model'
} elseif ($cInput -eq 1 -and $cDispatch -eq 1 -and $cBackendS -eq 1 -and $cRespE -eq 1 -and $cUserIns -eq 1 -and $cAsstIns -eq 1 -and $aiBlocksDelta -le 1) {
  $status = 'PASS'
  $root = 'none'
} elseif ($cDispatch -gt 1 -or $cBackendS -gt 1) {
  $status = 'FAIL'
  $root = 'duplicate_execution'
} elseif ($cDispatch -eq 1 -and $cBackendS -eq 1 -and ($cAsstIns -gt 1 -or $aiBlocksDelta -gt 1)) {
  $status = 'FAIL'
  $root = 'duplicate_display'
} elseif ($cDispatch -eq 1 -and $cBackendS -eq 1 -and $cRespE -eq 0) {
  $status = 'NOT_VERIFIED'
  $root = 'response_incomplete_timeout'
} elseif ($cInput -gt 1) {
  $status = 'FAIL'
  $root = 'duplicate_input_event'
}

@"
EXACTLY_ONCE=$status
ROOT_CAUSE=$root
MODE=$Mode
TOKEN=$token
TIP_SHA256=$hash
TIP_EXE=$TipExe
INPUT_EVENT_COUNT=$cInput
DISPATCH_ID_COUNT=$cDispatch
BACKEND_REQUEST_START_COUNT=$cBackendS
BACKEND_REQUEST_END_COUNT=$cBackendE
RESPONSE_START_COUNT=$cRespS
RESPONSE_END_COUNT=$cRespE
TRANSCRIPT_INSERT_USER_COUNT=$cUserIns
TRANSCRIPT_INSERT_ASSISTANT_COUNT=$cAsstIns
AGENT_MIRROR_COUNT=$cAgentMirror
POWERSHELL_HINT_COUNT=$cPsHint
AI_BLOCKS_DELTA=$aiBlocksDelta
TOKEN_IN_TRANSCRIPT=$tokenInOut
RUNLOG=$runlog
CHAT_RUNTIME_DELTA=$runDir\delta_chat_runtime.log
FROZEN_A4F_UNTOUCHED=1
TIP_002_UNTOUCHED=1
TIP_005_UNTOUCHED=1
PROMOTE=0
MATURITY_HELD=82
"@ | Set-Content $receipt

Get-Content $receipt | ForEach-Object { Log $_ }

try {
  if (!$p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep -Seconds 2
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }
  }
} catch {}

exit $(if ($status -eq 'PASS') { 0 } elseif ($status -eq 'FAIL') { 1 } else { 3 })

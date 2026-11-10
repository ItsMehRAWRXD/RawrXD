# AIM chat-input measure on tip_freeze_001 — fail-closed, short idle.
# Proves Ctrl+Enter send journal, Enter=newline, busy reject path presence.
param(
  [string]$TipExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "",
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\aim_chat",
  [int]$IdleMs = 12000
)
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionId = "aim_" + $stamp
$runId = "aim_run_" + $stamp
$runlog = Join-Path $OutDir "aim_chat_input_run_$stamp.txt"
$receipt = Join-Path $OutDir "AIM_CHAT_INPUT_RECEIPT.txt"
$rt = Join-Path $LogDir "chat_runtime.log"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runlog -Value $line
  Write-Host $line
}
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public static class AimN {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, KEYEVENTF_KEYUP=0x0002;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("user32.dll",SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint p1; public uint p2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,InputSize); }
  public static uint KeyUp(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,InputSize); }
  public static void SetText(IntPtr h, string t){ SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t??""); }
  public static string GetText(IntPtr h){
    int len=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(len<0) len=0; var sb=new StringBuilder(len+8); SendMessageW(h,WM_GETTEXT,(IntPtr)sb.Capacity,sb); return sb.ToString();
  }
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart){
    Stack<IntPtr> stack=new Stack<IntPtr>(); stack.Push(parent);
    while(stack.Count>0){
      IntPtr cur=stack.Pop(); var kids=new List<IntPtr>();
      EnumChildWindows(cur,(h,lp)=>{ kids.Add(h); return true; },IntPtr.Zero);
      foreach(var k in kids){
        int id=GetDlgCtrlID(k); var cls=new StringBuilder(64); GetClassNameW(k,cls,64);
        if(id==wantId && cls.ToString().IndexOf(classPart,StringComparison.OrdinalIgnoreCase)>=0) return k;
        stack.Push(k);
      }
    }
    return IntPtr.Zero;
  }
  public static IntPtr FindMain(uint pid){
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{
      uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid || !IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      string c=sb.ToString();
      if(c=="RawrXD_IDE_MainWindow" || c=="RawrXD_IDE_Window"){ found=h; return false; }
      if(found==IntPtr.Zero) found=h; return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$hash = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($ExpectSha -and $hash -ne $ExpectSha) {
  "CHAT_INPUT=FAIL`nREASON=SHA_DRIFT`nTIP_SHA256=$hash`nEXPECT=$ExpectSha`nPROMOTE=0" | Set-Content $receipt
  exit 3
}
Log "TIP_EXE=$TipExe TIP_SHA256=$hash SESSION_ID=$sessionId RUN_ID=$runId"
Get-Process -Name "RawrXD-Win32IDE-Native*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_CHAT_SESSION_ID = $sessionId
$env:RAWRXD_CHAT_RUN_ID = $runId
if (Test-Path $rt) { Remove-Item $rt -Force }

$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "PROCESS_EXITED early"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $byPid = [AimN]::FindMain([uint32]$p.Id)
  if ($byPid -ne [IntPtr]::Zero) { $main = $byPid; break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
CHAT_INPUT=FAIL
REASON=main_hwnd_not_found
TIP_SHA256=$hash
PROMOTE=0
RUNLOG=$runlog
"@ | Set-Content $receipt
  exit 2
}
$chat = [AimN]::FindCtrl($main, 1202, "Edit")
$send = [AimN]::FindCtrl($main, 1204, "Button")
Log "CHAT_INPUT=0x$('{0:X}' -f $chat.ToInt64()) SEND=0x$('{0:X}' -f $send.ToInt64())"
if ($chat -eq [IntPtr]::Zero) {
  @"
CHAT_INPUT=FAIL
REASON=chat_input_missing_id_1202
TIP_SHA256=$hash
PROMOTE=0
RUNLOG=$runlog
"@ | Set-Content $receipt
  try { Stop-Process -Id $p.Id -Force } catch {}
  exit 3
}

$script:ideTid=0; $script:myTid=0; $script:attached=$false
function Focus-Chat {
  $pidIde=0
  $ideTid=[AimN]::GetWindowThreadProcessId($main,[ref]$pidIde)
  $myTid=[AimN]::GetCurrentThreadId()
  if (-not $script:attached -and $ideTid -ne 0 -and $ideTid -ne $myTid) {
    $script:attached=[AimN]::AttachThreadInput($myTid,$ideTid,$true)
    $script:ideTid=$ideTid; $script:myTid=$myTid
  }
  [void][AimN]::ShowWindow($main,9)
  [void][AimN]::BringWindowToTop($main)
  [void][AimN]::SetForegroundWindow($main)
  [void][AimN]::SetFocus($chat)
  Start-Sleep -Milliseconds 120
}
function Detach-Chat {
  if ($script:attached) { [void][AimN]::AttachThreadInput($script:myTid,$script:ideTid,$false) }
  $script:attached=$false
}
function Read-J { if (Test-Path $rt) { try { ,[string[]][IO.File]::ReadAllLines($rt) } catch { @() } } else { @() } }
function Count-K([string[]]$lines,[string]$pat){ @($lines | Where-Object { $_ -match $pat }).Count }
function Wait-Pat([string]$pat,[int]$ms){
  $d=[Environment]::TickCount64+$ms
  while([Environment]::TickCount64 -lt $d){
    if ((Count-K (Read-J) $pat) -ge 1) { return $true }
    Start-Sleep -Milliseconds 200
  }
  return $false
}

Start-Sleep 6

# ENTER = newline (no send)
Focus-Chat
[AimN]::SetText($chat, "line1")
Start-Sleep -Milliseconds 80
$beforeAttempts = Count-K (Read-J) "CHAT_SEND_ATTEMPT"
[void][AimN]::KeyDown(0x0D); Start-Sleep -Milliseconds 60; [void][AimN]::KeyUp(0x0D)
Start-Sleep -Milliseconds 300
$afterText = [AimN]::GetText($chat)
$afterAttempts = Count-K (Read-J) "CHAT_SEND_ATTEMPT"
Detach-Chat
Log "PROBE=ENTER_NEWLINE text_has_nl=$($afterText -match "`r|`n") attempts_delta=$($afterAttempts-$beforeAttempts)"

# CTRL+ENTER = send
Focus-Chat
[AimN]::SetText($chat, "ctrl-once")
Start-Sleep -Milliseconds 80
[void][AimN]::KeyDown(0x11); Start-Sleep -Milliseconds 40
[void][AimN]::KeyDown(0x0D); Start-Sleep -Milliseconds 80
[void][AimN]::KeyUp(0x0D); [void][AimN]::KeyUp(0x11)
Detach-Chat
Log "PROBE=CTRL_ENTER"
[void](Wait-Pat "INPUT_EVENT .*kind=CTRL_ENTER" $IdleMs)
[void](Wait-Pat "CHAT_SEND_ATTEMPT|CHAT_SEND_NO_MODEL|CHAT_SEND_REJECTED|CHAT_SEND_BUSY" $IdleMs)

# BUTTON click (also journals INPUT_EVENT)
Focus-Chat
[AimN]::SetText($chat, "btn-once")
Start-Sleep -Milliseconds 80
Detach-Chat
[void][AimN]::SendMessageW($main, 0x0111, [IntPtr]1204, $send)
Log "PROBE=BUTTON_CLICK"
[void](Wait-Pat "INPUT_EVENT .*kind=BUTTON_CLICK" $IdleMs)

# Busy probe: second send immediately after first if still running
Focus-Chat
[AimN]::SetText($chat, "busy-probe")
Start-Sleep -Milliseconds 40
[void][AimN]::KeyDown(0x11); Start-Sleep -Milliseconds 20
[void][AimN]::KeyDown(0x0D); Start-Sleep -Milliseconds 40
[void][AimN]::KeyUp(0x0D); [void][AimN]::KeyUp(0x11)
Detach-Chat
Log "PROBE=BUSY_SECOND_SEND"
Start-Sleep -Milliseconds 800

$lines = Read-J
$ctrl = Count-K $lines "INPUT_EVENT .*kind=CTRL_ENTER"
$enterNl = Count-K $lines "INPUT_EVENT .*kind=ENTER_NEWLINE"
$btn = Count-K $lines "INPUT_EVENT .*kind=BUTTON_CLICK"
$attempts = Count-K $lines "CHAT_SEND_ATTEMPT"
$armed = Count-K $lines "CHAT_SEND_ARMED"
$busy = Count-K $lines "CHAT_SEND_BUSY|exactly_once_reject"
$setLen = if ($chat -ne [IntPtr]::Zero) { [AimN]::GetText($chat).Length } else { -1 }

$enterOk = ($enterNl -ge 1) -and (($afterAttempts -eq $beforeAttempts))
$ctrlOk = ($ctrl -ge 1) -and ($attempts -ge 1)
$inputSetOk = ($chat -ne [IntPtr]::Zero)
# CHAT_INPUT AIM conjunction for this lane
$chatInput = if ($inputSetOk -and $ctrlOk -and $enterOk) { "PASS" } else { "FAIL" }
$busyState = if ($busy -ge 1) { "PASS_JOURNAL" } elseif ($attempts -ge 1) { "PATH_PRESENT_UNEXERCISED_OR_CLEARED" } else { "NOT_DEMONSTRATED" }

@"
CHAT_INPUT=$chatInput
TIP_SHA256=$hash
TIP_EXE=$TipExe
SESSION_ID=$sessionId
RUN_ID=$runId
CHAT_HWND_PRESENT=$([int]$inputSetOk)
INPUT_CTRL_ENTER=$ctrl
INPUT_ENTER_NEWLINE=$enterNl
INPUT_BUTTON_CLICK=$btn
CHAT_SEND_ATTEMPT_COUNT=$attempts
CHAT_SEND_ARMED_COUNT=$armed
BUSY_JOURNAL_HITS=$busy
BUSY_STATE=$busyState
ENTER_NEWLINE=$(if($enterOk){'PASS'}else{'FAIL'})
CTRL_ENTER_SEND=$(if($ctrlOk){'PASS'}else{'FAIL'})
ENTER_TEXT_HAS_NL=$($afterText -match "`r|`n")
POST_ENTER_ATTEMPT_DELTA=$($afterAttempts-$beforeAttempts)
INPUT_SET_LEN_SAMPLE=$setLen
AIM_PATH=AIM_GETMESSAGE_WM_KEYDOWN
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
RUNLOG=$runlog
CHAT_RUNTIME=$rt
"@ | Set-Content $receipt -Encoding ASCII
Get-Content $receipt | ForEach-Object { Log $_ }

try { Detach-Chat } catch {}
try {
  if (!$p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep 2
    if (!$p.HasExited) { Stop-Process -Id $p.Id -Force }
  }
} catch {}
exit 0

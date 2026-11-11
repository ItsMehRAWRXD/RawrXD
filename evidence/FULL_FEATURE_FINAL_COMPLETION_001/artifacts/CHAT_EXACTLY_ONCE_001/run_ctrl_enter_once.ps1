param(
  [string]$TipExe = "F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$OutBase = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001",
  [int]$ResponseWaitMs = 180000
)
$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutBase "runs\ctrl_enter_$stamp"
$logDir = Join-Path $runDir "runtime"
New-Item -ItemType Directory -Force -Path $runDir, $logDir | Out-Null
$token = "RXD_ONCE_" + [guid]::NewGuid().ToString("N")
$hash = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$rtLog = Join-Path $logDir "chat_runtime.log"

# Exclusive HWND: kill all RawrXD (incl tip005 nav worker holders)
Get-Process | Where-Object { $_.ProcessName -match "RawrXD|Win32IDE-Native" } |
  Stop-Process -Force -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and $_.CommandLine -match "powershell_panel_routing|tip_ps_routing|tip_rc_integ|broken_multi|tip_final_integ_005"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 3

Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class OnceCtrl2 {
  public const uint WM_SETTEXT=0x000C;
  public const uint KEYEVENTF_KEYUP=0x0002;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a,uint b,bool f);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,string s);
  [DllImport("user32.dll",SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo;
    public uint p1; public uint p2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,InputSize);} 
  public static uint KeyUp(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,InputSize);} 
  public static void SetText(IntPtr h,string t){ SendMessageW(h,WM_SETTEXT,IntPtr.Zero,t??""); }
  public static IntPtr FindMain(uint pid){
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      string c=sb.ToString();
      if(c=="RawrXD_IDE_MainWindow"||c=="RawrXD_IDE_Window"){ found=h; return false; }
      if(found==IntPtr.Zero) found=h; return true; }, IntPtr.Zero);
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
    $enum = [OnceCtrl2+EnumChildProc]{ param($h,$lp) $kids.Add($h) | Out-Null; return $true }
    [void][OnceCtrl2]::EnumChildWindows($cur, $enum, [IntPtr]::Zero)
    foreach ($k in $kids) {
      $id = [OnceCtrl2]::GetDlgCtrlID($k)
      $cls = New-Object System.Text.StringBuilder 64
      [void][OnceCtrl2]::GetClassNameW($k, $cls, 64)
      if ($id -eq $wantId -and $cls.ToString() -match $classPart) { return $k }
      $stack.Push($k)
    }
  }
  return [IntPtr]::Zero
}
function Count-Tag($lines, $pat) { @($lines | Where-Object { $_ -match $pat }).Count }

$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_CHAT_RUN_ID = "exactly_once_ctrl_$stamp"
$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch { break }
  if ($p.HasExited) { throw "early exit $($p.ExitCode)" }
  $main = [OnceCtrl2]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
if ($main -eq [IntPtr]::Zero) { throw "no main hwnd" }
Get-Process | Where-Object { $_.ProcessName -match "RawrXD|Win32IDE-Native" -and $_.Id -ne $p.Id } |
  Stop-Process -Force -ErrorAction SilentlyContinue
[void][OnceCtrl2]::SetForegroundWindow($main)

$chat = [IntPtr]::Zero
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  $chat = Find-Ctrl $main 1202 "Edit"
  if ($chat -ne [IntPtr]::Zero) { break }
  # keep exclusive during wait
  Get-Process | Where-Object { $_.ProcessName -match "RawrXD|Win32IDE-Native" -and $_.Id -ne $p.Id } |
    Stop-Process -Force -ErrorAction SilentlyContinue
}
"pid=$($p.Id) main=0x$('{0:X}' -f $main.ToInt64()) chat=0x$('{0:X}' -f $chat.ToInt64()) token=$token sha=$hash" |
  Set-Content (Join-Path $runDir "run.txt")
if ($chat -eq [IntPtr]::Zero) { throw "chat missing" }

Start-Sleep -Seconds 10
$before = if (Test-Path $rtLog) { @(Get-Content $rtLog) } else { @() }
[OnceCtrl2]::SetText($chat, $token)
$uiTid = 0
[void][OnceCtrl2]::GetWindowThreadProcessId($main, [ref]$uiTid)
$myTid = [OnceCtrl2]::GetCurrentThreadId()
[void][OnceCtrl2]::AttachThreadInput($myTid, $uiTid, $true)
[void][OnceCtrl2]::SetForegroundWindow($main)
[void][OnceCtrl2]::SetFocus($chat)
Start-Sleep -Milliseconds 60
[void][OnceCtrl2]::KeyDown(0x11); Start-Sleep -Milliseconds 30
[void][OnceCtrl2]::KeyDown(0x0D); Start-Sleep -Milliseconds 50
[void][OnceCtrl2]::KeyUp(0x0D); [void][OnceCtrl2]::KeyUp(0x11)
[void][OnceCtrl2]::AttachThreadInput($myTid, $uiTid, $false)
"INPUT_FIRED=ctrl_enter x1" | Add-Content (Join-Path $runDir "run.txt")

$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.ElapsedMilliseconds -lt $ResponseWaitMs) {
  Start-Sleep -Milliseconds 800
  try { $p.Refresh() } catch { break }
  if ($p.HasExited) { "PROCESS_DIED" | Add-Content (Join-Path $runDir "run.txt"); break }
  Get-Process | Where-Object { $_.ProcessName -match "RawrXD|Win32IDE-Native" -and $_.Id -ne $p.Id } |
    Stop-Process -Force -ErrorAction SilentlyContinue
  if (!(Test-Path $rtLog)) { continue }
  $cur = @(Get-Content $rtLog)
  $delta = @($cur | Where-Object { $before -notcontains $_ })
  if ($delta | Where-Object { $_ -match "RESPONSE_END|BACKEND_REQUEST_END|CHAT_SEND_NO_MODEL|CHAT_SEND_BUSY|CHAT_SEND_REJECTED" }) { break }
}

$after = if (Test-Path $rtLog) { @(Get-Content $rtLog) } else { @() }
$delta = @($after | Where-Object { $before -notcontains $_ })
$delta | Set-Content (Join-Path $runDir "delta_chat_runtime.log")
Copy-Item $rtLog (Join-Path $runDir "chat_runtime_full.log") -ErrorAction SilentlyContinue

$cInput = Count-Tag $delta "INPUT_EVENT source=ctrl_enter"
if ($cInput -eq 0) { $cInput = Count-Tag $delta "kind=CTRL_ENTER" }
$cDispatch = Count-Tag $delta "DISPATCH_ID id="
if ($cDispatch -eq 0) { $cDispatch = Count-Tag $delta "CHAT_SEND_ATTEMPT dispatch_id=" }
$cBackendS = Count-Tag $delta "BACKEND_REQUEST_START"
if ($cBackendS -eq 0) { $cBackendS = Count-Tag $delta "request_started request_id=" }
$cBackendE = Count-Tag $delta "BACKEND_REQUEST_END"
$cRespS = Count-Tag $delta "RESPONSE_START"
$cRespE = Count-Tag $delta "RESPONSE_END"
$cUser = Count-Tag $delta "TRANSCRIPT_INSERT role=user"
$cAsst = Count-Tag $delta "TRANSCRIPT_INSERT role=assistant"
$cMirror = Count-Tag $delta "TRANSCRIPT_INSERT role=agent_mirror"
$cPs = Count-Tag $delta "powershell_hint=1"

$status = "NOT_VERIFIED"; $root = "incomplete_chain"
if ($cInput -eq 0 -and $cDispatch -eq 0) { $root = "ctrl_enter_not_observed" }
elseif ($cDispatch -gt 1 -or $cBackendS -gt 1) { $status = "FAIL"; $root = "duplicate_execution" }
elseif ($cInput -gt 1) { $status = "FAIL"; $root = "duplicate_input_event" }
elseif ($cInput -eq 1 -and $cDispatch -eq 1 -and $cBackendS -eq 1 -and $cRespE -eq 1 -and $cUser -eq 1 -and $cAsst -eq 1) {
  $status = "PASS"; $root = "none"
}
elseif ($cDispatch -eq 1 -and $cBackendS -eq 1 -and $cRespE -eq 0) {
  $status = "NOT_VERIFIED"; $root = "response_incomplete_timeout"
}
elseif ($cInput -eq 1 -and $cDispatch -eq 1 -and $cBackendS -eq 1) {
  $status = "NOT_VERIFIED"; $root = "partial_chain_ok_no_dup"
}

@"
EXACTLY_ONCE=$status
ROOT_CAUSE=$root
MODE=ctrl_enter
TOKEN=$token
TIP_SHA256=$hash
TIP_EXE=$TipExe
INPUT_EVENT_COUNT=$cInput
DISPATCH_ID_COUNT=$cDispatch
BACKEND_REQUEST_START_COUNT=$cBackendS
BACKEND_REQUEST_END_COUNT=$cBackendE
RESPONSE_START_COUNT=$cRespS
RESPONSE_END_COUNT=$cRespE
TRANSCRIPT_INSERT_USER_COUNT=$cUser
TRANSCRIPT_INSERT_ASSISTANT_COUNT=$cAsst
AGENT_MIRROR_COUNT=$cMirror
POWERSHELL_HINT_COUNT=$cPs
WAIT_MS=$ResponseWaitMs
PROMOTE=0
MATURITY_HELD=82
"@ | Tee-Object -FilePath (Join-Path $runDir "RECEIPT.txt")

try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
Write-Host "RUNDIR=$runDir"
exit $(if ($status -eq "PASS") { 0 } elseif ($status -eq "FAIL") { 1 } else { 3 })

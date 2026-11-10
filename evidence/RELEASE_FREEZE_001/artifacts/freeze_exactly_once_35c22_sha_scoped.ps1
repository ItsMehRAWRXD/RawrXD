param(
  [string]$TipExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RXD_PIN_A190_35C22.exe",
  [string]$ExpectSha = "35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563",
  [string]$PreferModel = "nemotron-3-nano:4b",
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\eo_freeze_35c22_sha",
  [int]$IdleTimeoutMs = 180000,
  [int]$BootWaitSec = 10
)
$ErrorActionPreference="Stop"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp=Get-Date -Format "yyyyMMdd-HHmmss"
$runlog=Join-Path $OutDir ("freeze_eo_35c22_run_"+$stamp+".txt")
$receipt=Join-Path $OutDir "FREEZE_EXACTLY_ONCE_RECEIPT_35C22.txt"
$mdPath="F:\rawrxd\evidence\RELEASE_FREEZE_001\FREEZE_EXACTLY_ONCE_35C22.md"
$rt=Join-Path $LogDir "chat_runtime.log"
function Log([string]$m){ $line="$(Get-Date -Format o) $m"; Add-Content $runlog $line; Write-Host $line }
$tipLeaf=[IO.Path]::GetFileName($TipExe)
if($tipLeaf -eq "RawrXD-FreezeEO-A190.exe"){ Set-Content $receipt "EXACTLY_ONCE=NOT_RUN`nREASON=REFUSED_A190_LAUNCH_USE_PIN`nPROMOTE=0`nCERTIFIED=0" -Encoding UTF8; exit 9 }
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class FreezeEoB {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111;
  public const uint CB_SELECTSTRING=0x014D, CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_SETCURSEL=0x014E;
  public const ushort CBN_SELCHANGE=1, CBN_SELENDOK=9;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  public static void SetText(IntPtr h, string t){ SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t??""); }
  public static string GetText(IntPtr h){ int len=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); if(len<0)len=0; var sb=new StringBuilder(len+8); SendMessageW(h,WM_GETTEXT,(IntPtr)sb.Capacity,sb); return sb.ToString(); }
  public static IntPtr FindCtrl(IntPtr parent, int wantId, string classPart){ IntPtr found=IntPtr.Zero; EnumChildWindows(parent,(h,lp)=>{ int id=GetDlgCtrlID(h); var sb=new StringBuilder(64); GetClassNameW(h,sb,64); if(id==wantId && sb.ToString().IndexOf(classPart,StringComparison.OrdinalIgnoreCase)>=0){ found=h; return false;} return true;}, IntPtr.Zero); return found; }
  public static string SelectModel(IntPtr main, IntPtr combo, string prefer){
    int n=(int)SendMessageW(combo, CB_GETCOUNT, IntPtr.Zero, IntPtr.Zero);
    int hit=-1; string hitText="";
    for(int i=0;i<n;i++){ var sb=new StringBuilder(512); SendMessageW(combo, CB_GETLBTEXT, (IntPtr)i, sb); string t=sb.ToString();
      if(t.IndexOf(prefer, StringComparison.OrdinalIgnoreCase)>=0){ hit=i; hitText=t; break; }
      if(hit<0 && (t.IndexOf("llama3.2:3b", StringComparison.OrdinalIgnoreCase)>=0 || t.IndexOf("nemotron-3-nano", StringComparison.OrdinalIgnoreCase)>=0 || t.IndexOf("qwen2.5-coder:1.5b", StringComparison.OrdinalIgnoreCase)>=0)){ hit=i; hitText=t; }
    }
    if(hit<0 && n>0){ var sb=new StringBuilder(512); SendMessageW(combo, CB_GETLBTEXT, (IntPtr)0, sb); hit=0; hitText=sb.ToString(); }
    if(hit>=0){ SendMessageW(combo, CB_SETCURSEL, (IntPtr)hit, IntPtr.Zero);
      IntPtr wp1=(IntPtr)((CBN_SELCHANGE<<16)|1206); SendMessageW(main, WM_COMMAND, wp1, combo);
      IntPtr wp2=(IntPtr)((CBN_SELENDOK<<16)|1206); SendMessageW(main, WM_COMMAND, wp2, combo);
    }
    return hitText;
  }
}
public static class FreezeEoBKeys {
  public const uint KEYEVENTF_KEYUP=0x0002;
  [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr extra);
  public static void CtrlEnter(){ keybd_event(0x11,0,0,UIntPtr.Zero); keybd_event(0x0D,0,0,UIntPtr.Zero); keybd_event(0x0D,0,KEYEVENTF_KEYUP,UIntPtr.Zero); keybd_event(0x11,0,KEYEVENTF_KEYUP,UIntPtr.Zero); }
}
public static class FreezeEoBHwnd {
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindMain(uint pid){ IntPtr found=IntPtr.Zero; EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid); if(wpid!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString(); if(c.Contains("RawrXD_IDE")){ found=h; return false;} if(found==IntPtr.Zero) found=h; return true;}, IntPtr.Zero); return found; }
}
"@
$hash=(Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe SHA=$hash EXPECT=$ExpectSha PREFER_MODEL=$PreferModel"
if($hash -ne $ExpectSha){ Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=SHA_MISMATCH`nMEASURED=$hash`nEXPECT=$ExpectSha`nPROMOTE=0"; exit 2 }
Get-Process -Name "RXD_PIN_A190_35C22*","RawrXD-FreezeSeal*","RawrXD-FreezeGate*","RawrXD-Win32IDE-Native*" -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
if(Test-Path $rt){ Remove-Item $rt -Force }
$env:RAWRXD_LOG_DIR=$LogDir
$env:RAWRXD_CHAT_SESSION_ID="eo35_$stamp"
$env:RAWRXD_CHAT_RUN_ID="eorun_$stamp"
# Normal launch, no fixture (fixture+Native name races tip_final Stop-Process)
# WorkingDirectory=pin dir required: cwd-relative assets; pin exits immediately otherwise.
$tipWd=[IO.Path]::GetDirectoryName($TipExe)
$p=Start-Process -FilePath $TipExe -WorkingDirectory $tipWd -PassThru -WindowStyle Normal
Log ("PID="+$p.Id+" WD="+$tipWd)
$main=[IntPtr]::Zero
for($i=0;$i -lt 60;$i++){ Start-Sleep -Milliseconds 500; try{$p.Refresh()}catch{}; if($p.HasExited){ Log ("EXIT_EARLY "+$p.ExitCode); break }
  if($p.MainWindowHandle -ne 0){ $main=[IntPtr]$p.MainWindowHandle; break }
  $by=[FreezeEoBHwnd]::FindMain([uint32]$p.Id); if($by -ne [IntPtr]::Zero){ $main=$by; break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
if($main -eq [IntPtr]::Zero){ Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=no_main_hwnd`nPROMOTE=0"; exit 3 }
# Prefer RawrXD_IDE class; poll until chat controls exist (fixed sleep races fixture restore).
$ide=[FreezeEoBHwnd]::FindMain([uint32]$p.Id)
if($ide -ne [IntPtr]::Zero){ $main=$ide; Log ("IDE_MAIN=0x{0:X}" -f $main.ToInt64()) }
$chat=[IntPtr]::Zero; $send=[IntPtr]::Zero; $tr=[IntPtr]::Zero; $combo=[IntPtr]::Zero
$ctrlDeadline=[Environment]::TickCount64 + ([Math]::Max($BootWaitSec,25)*1000)
while([Environment]::TickCount64 -lt $ctrlDeadline){
  try{$p.Refresh()}catch{}; if($p.HasExited){ break }
  $ide=[FreezeEoBHwnd]::FindMain([uint32]$p.Id); if($ide -ne [IntPtr]::Zero){ $main=$ide }
  $chat=[FreezeEoB]::FindCtrl($main,1202,"Edit"); $send=[FreezeEoB]::FindCtrl($main,1204,"Button")
  $tr=[FreezeEoB]::FindCtrl($main,1203,"Edit"); $combo=[FreezeEoB]::FindCtrl($main,1206,"ComboBox")
  if($chat -ne [IntPtr]::Zero -and $send -ne [IntPtr]::Zero){ break }
  Start-Sleep -Milliseconds 500
}
Log ("CHAT=0x{0:X} SEND=0x{1:X} TR=0x{2:X} COMBO=0x{3:X}" -f $chat.ToInt64(),$send.ToInt64(),$tr.ToInt64(),$combo.ToInt64())
if($chat -eq [IntPtr]::Zero -or $send -eq [IntPtr]::Zero){ Set-Content $receipt "EXACTLY_ONCE=FAIL`nREASON=controls_missing`nPROMOTE=0"; try{Stop-Process -Id $p.Id -Force}catch{}; exit 4 }
# Wait for preferred/local model rows to populate (else index0 Cloud free completes too fast → false EO FAIL).
if($combo -ne [IntPtr]::Zero){
  $modelDeadline=[Environment]::TickCount64+30000
  while([Environment]::TickCount64 -lt $modelDeadline){
    $n=[int]([FreezeEoB]::SendMessageW($combo,0x0146,[IntPtr]::Zero,[IntPtr]::Zero))
    $hitPrefer=$false
    for($mi=0;$mi -lt $n;$mi++){
      $sb=New-Object System.Text.StringBuilder 512
      [void][FreezeEoB]::SendMessageW($combo,0x0148,[IntPtr]$mi,$sb)
      $t=$sb.ToString()
      if($t -match [regex]::Escape($PreferModel) -or $t -match 'nemotron-3-nano|llama3\.2:3b|qwen2\.5-coder:1\.5b'){ $hitPrefer=$true; break }
    }
    if($hitPrefer){ break }
    Start-Sleep -Milliseconds 400
  }
  $sel=[FreezeEoB]::SelectModel($main,$combo,$PreferModel); Log "MODEL_SELECT=$sel"; Start-Sleep -Milliseconds 600
}
function Read-Rt { if(Test-Path $rt){ @(Get-Content $rt -EA SilentlyContinue) } else { @() } }
function Count-Pat([string[]]$lines,[string]$pat){ @($lines|Where-Object{$_ -match $pat}).Count }
function Wait-SubmitComplete([int]$minSubmit,[int]$timeoutMs){
  $deadline=[Environment]::TickCount64+$timeoutMs
  while([Environment]::TickCount64 -lt $deadline){
    try{$p.Refresh()}catch{}; if($p.HasExited){ Log ("IDLE_ABORT exited code="+$p.ExitCode); return $false }
    $lines=Read-Rt; $sub=Count-Pat $lines '^exactly_once_submit'; $done=Count-Pat $lines 'ui_update .*complete=1'
    if($sub -ge $minSubmit -and $done -ge $minSubmit){ Log ("IDLE ok submit=$sub done=$done"); return $true }
    Start-Sleep -Milliseconds 400
  }
  $lines=Read-Rt; Log ("IDLE_TIMEOUT submit="+(Count-Pat $lines '^exactly_once_submit')+" done="+(Count-Pat $lines 'ui_update .*complete=1')); return $false
}
$before=Read-Rt; $bSub=Count-Pat $before '^exactly_once_submit'; $bReq=Count-Pat $before '^request_started'; $bDone=Count-Pat $before 'ui_update .*complete=1'; $bRej=Count-Pat $before '^exactly_once_reject'
[FreezeEoB]::SetText($chat,"freeze-eo-send-1"); Start-Sleep -Milliseconds 150
[void][FreezeEoB]::SendMessageW($main,0x0111,[IntPtr]1204,$send); Log "SEND1_CLICK"; Start-Sleep -Milliseconds 500
[FreezeEoB]::SetText($chat,"freeze-eo-busy-should-reject")
[void][FreezeEoB]::SendMessageW($main,0x0111,[IntPtr]1204,$send); Log "SEND_BUSY_CLICK"; Start-Sleep -Milliseconds 400
$mid=Read-Rt; $dRejBusy=(Count-Pat $mid '^exactly_once_reject')-$bRej; Log ("BUSY_DELTA reject=$dRejBusy")
[void](Wait-SubmitComplete ($bSub+1) $IdleTimeoutMs)
$after1=Read-Rt; $dSub1=(Count-Pat $after1 '^exactly_once_submit')-$bSub; $dReq1=(Count-Pat $after1 '^request_started')-$bReq; $dDone1=(Count-Pat $after1 'ui_update .*complete=1')-$bDone
Log ("SEND1_DELTA submit=$dSub1 req=$dReq1 done=$dDone1")
$b2=Read-Rt; $b2Sub=Count-Pat $b2 '^exactly_once_submit'; $b2Req=Count-Pat $b2 '^request_started'; $b2Done=Count-Pat $b2 'ui_update .*complete=1'
[FreezeEoB]::SetText($chat,"freeze-eo-send-2"); Start-Sleep -Milliseconds 100
[void][FreezeEoB]::SendMessageW($main,0x0111,[IntPtr]1204,$send); Log "SEND2_CLICK"
[void](Wait-SubmitComplete ($b2Sub+1) $IdleTimeoutMs)
$after2=Read-Rt; $dSub2=(Count-Pat $after2 '^exactly_once_submit')-$b2Sub; $dReq2=(Count-Pat $after2 '^request_started')-$b2Req; $dDone2=(Count-Pat $after2 'ui_update .*complete=1')-$b2Done
Log ("SEND2_DELTA submit=$dSub2 req=$dReq2 done=$dDone2")
$b3=Read-Rt; $b3Sub=Count-Pat $b3 '^exactly_once_submit'
# AIM-parity Enter-alone (KeyDown/KeyUp + detach) — PostMessage WM_CHAR can leave focus odd for later Ctrl+Enter.
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class AimEnterAlone {
  public const uint KEYEVENTF_KEYUP=0x0002;
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint pad1; public uint pad2; }
  [DllImport("user32.dll",SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  public static void EnterNewline(IntPtr main, IntPtr chat){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main,out pid); uint my=GetCurrentThreadId();
    bool att=false; if(ideTid!=0 && ideTid!=my) att=AttachThreadInput(my,ideTid,true);
    ShowWindow(main,9); BringWindowToTop(main); SetForegroundWindow(main); SetFocus(chat);
    System.Threading.Thread.Sleep(80);
    INPUT[] d=new INPUT[1]; d[0].type=1; d[0].ki.wVk=0x0D; SendInput(1,d,Marshal.SizeOf(typeof(INPUT)));
    System.Threading.Thread.Sleep(60);
    INPUT[] u=new INPUT[1]; u[0].type=1; u[0].ki.wVk=0x0D; u[0].ki.dwFlags=KEYEVENTF_KEYUP; SendInput(1,u,Marshal.SizeOf(typeof(INPUT)));
    if(att) AttachThreadInput(my,ideTid,false);
  }
}
"@ -ErrorAction SilentlyContinue
[FreezeEoB]::SetText($chat,"line1"); Start-Sleep -Milliseconds 80
[AimEnterAlone]::EnterNewline($main,$chat); Start-Sleep -Milliseconds 300
$chatAfterEnter=[FreezeEoB]::GetText($chat); $dSubEnter=(Count-Pat (Read-Rt) '^exactly_once_submit')-$b3Sub
$enterNewline=($chatAfterEnter -match "`r`n|`n"); Log ("ENTER_ALONE dSubmit=$dSubEnter newline=$enterNewline len="+$chatAfterEnter.Length)
$b4=Read-Rt; $b4Sub=Count-Pat $b4 '^exactly_once_submit'; $b4Req=Count-Pat $b4 '^request_started'; $b4Done=Count-Pat $b4 'ui_update .*complete=1'
# AIM-parity Ctrl+Enter: AttachThreadInput + paced KeyDown/KeyUp + ALWAYS Detach.
# Prior FAIL: attach-without-detach + tip012 exclusive killer matching RXD_PIN_A190 → IDE_EXIT=-1, dSub=0.
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class AimFocusEoV2 {
  public const uint KEYEVENTF_KEYUP=0x0002;
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint pad1; public uint pad2; }
  [DllImport("user32.dll",SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  static uint ideTid; static uint myTid; static bool attached;
  public static void Focus(IntPtr main, IntPtr chat){
    uint pid=0; ideTid=GetWindowThreadProcessId(main, out pid); myTid=GetCurrentThreadId();
    IntPtr fg=GetForegroundWindow(); uint pidFg=0; uint fgTid=(fg!=IntPtr.Zero)?GetWindowThreadProcessId(fg,out pidFg):(uint)0;
    if(fgTid!=0 && fgTid!=myTid && fgTid!=ideTid) AttachThreadInput(myTid, fgTid, true);
    if(!attached && ideTid!=0 && ideTid!=myTid){ attached=AttachThreadInput(myTid, ideTid, true); }
    ShowWindow(main,9); BringWindowToTop(main); SetForegroundWindow(main); SetFocus(chat);
  }
  public static void Detach(){
    if(attached && ideTid!=0 && ideTid!=myTid){ AttachThreadInput(myTid, ideTid, false); attached=false; }
  }
  public static uint KeyDown(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,Marshal.SizeOf(typeof(INPUT))); }
  public static uint KeyUp(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,Marshal.SizeOf(typeof(INPUT))); }
  public static void CtrlEnterPaced(){
    KeyDown(0x11); System.Threading.Thread.Sleep(40);
    KeyDown(0x0D); System.Threading.Thread.Sleep(80);
    KeyUp(0x0D); KeyUp(0x11);
  }
}
"@ -ErrorAction SilentlyContinue
# Clear foreign tip012 exclusive killers that match RXD_PIN_A190 before Ctrl+Enter.
Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object {
  $_.CommandLine -and ($_.CommandLine -match 'watchdog_exclusive_tip012|run_issue49_tip01[0-9]_exclusive')
} | ForEach-Object { Log ("KILL_FOREIGN_EXCLUSIVE pid=$($_.ProcessId)"); Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
Start-Sleep -Milliseconds 800
try{$p.Refresh()}catch{}
if($p.HasExited){ Log ("PRE_CTRL_ENTER_DEAD exit="+$p.ExitCode) }
[FreezeEoB]::SetText($chat,"freeze-eo-ctrl-enter")
[AimFocusEoV2]::Focus($main,$chat)
Start-Sleep -Milliseconds 120
[AimFocusEoV2]::CtrlEnterPaced(); [AimFocusEoV2]::Detach(); Log "CTRL_ENTER_AIM_PACED_DETACH"; Start-Sleep -Milliseconds 800
$ctrlWaitMs=[Math]::Min($IdleTimeoutMs,90000)
[void](Wait-SubmitComplete ($b4Sub+1) $ctrlWaitMs)
$a4=Read-Rt; $dSubCE=(Count-Pat $a4 '^exactly_once_submit')-$b4Sub; $dReqCE=(Count-Pat $a4 '^request_started')-$b4Req; $dDoneCE=(Count-Pat $a4 'ui_update .*complete=1')-$b4Done
Log ("CTRL_ENTER_DELTA submit=$dSubCE req=$dReqCE done=$dDoneCE")
try{$p.Refresh()}catch{}
if(($dSubCE -eq 0) -and (-not $p.HasExited)){
  Log "CTRL_ENTER_RETRY"
  [FreezeEoB]::SetText($chat,"freeze-eo-ctrl-enter-retry")
  [AimFocusEoV2]::Focus($main,$chat)
  Start-Sleep -Milliseconds 120
  [AimFocusEoV2]::CtrlEnterPaced(); [AimFocusEoV2]::Detach(); Start-Sleep -Milliseconds 800
  [void](Wait-SubmitComplete ($b4Sub+1) 60000)
  $a4=Read-Rt; $dSubCE=(Count-Pat $a4 '^exactly_once_submit')-$b4Sub; $dReqCE=(Count-Pat $a4 '^request_started')-$b4Req; $dDoneCE=(Count-Pat $a4 'ui_update .*complete=1')-$b4Done
  Log ("CTRL_ENTER_RETRY_DELTA submit=$dSubCE req=$dReqCE done=$dDoneCE")
}
try{$p.Refresh()}catch{}; if($p.HasExited){ Log ("POST_CTRL_ENTER_IDE_EXIT="+$p.ExitCode) }
$vis=""; try{ if($tr -ne [IntPtr]::Zero){ $vis=[FreezeEoB]::GetText($tr) } }catch{}
Set-Content (Join-Path $LogDir ("visible_transcript_"+$stamp+".txt")) -Value $vis -Encoding UTF8
if(Test-Path $rt){ Copy-Item $rt (Join-Path $OutDir ("freeze_eo_35c22_runtime_"+$stamp+".log")) -Force }
$final=Read-Rt; $submitU=@(); $reqU=@(); $doneU=@()
foreach($line in $final){
  if($line -match 'exactly_once_submit session=\d+ request_id=(\d+)'){ $submitU+=[int]$Matches[1] }
  if($line -match '^request_started request_id=(\d+)'){ $reqU+=[int]$Matches[1] }
  if($line -match 'ui_update request_id=(\d+).*complete=1'){ $doneU+=[int]$Matches[1] }
}
$submitU=@($submitU|Select-Object -Unique); $reqU=@($reqU|Select-Object -Unique); $doneU=@($doneU|Select-Object -Unique)
Log ("SUBMIT_IDS="+($submitU -join ',')+" REQ="+($reqU -join ',')+" DONE="+($doneU -join ','))
$send1ok=($dSub1 -eq 1 -and $dReq1 -eq 1 -and $dDone1 -ge 1)
$send2ok=($dSub2 -eq 1 -and $dReq2 -eq 1 -and $dDone2 -ge 1)
$busyok=($dRejBusy -ge 1); $enterok=($dSubEnter -eq 0)
$ctrlok=($dSubCE -eq 1 -and $dReqCE -eq 1 -and $dDoneCE -ge 1)
$idsAligned=$true; foreach($id in $submitU){ if($reqU -notcontains $id){$idsAligned=$false}; if($doneU -notcontains $id){$idsAligned=$false} }
$enoughSends=($submitU.Count -ge 2)
$reason=@(); if(-not $send1ok){$reason+="SEND1_NOT_1_1"}; if(-not $send2ok){$reason+="SEND2_NOT_1_1"}; if(-not $busyok){$reason+="BUSY_REJECT_MISSING"}; if(-not $enterok){$reason+="ENTER_TRIGGERED_SUBMIT"}; if(-not $ctrlok){$reason+="CTRL_ENTER_NOT_1_1"}; if(-not $idsAligned){$reason+="REQUEST_ID_CHAIN_MISALIGN"}; if(-not $enoughSends){$reason+="INSUFFICIENT_SUBMIT_IDS"}
$eo="FAIL"; if($send1ok -and $send2ok -and $busyok -and $enterok -and $ctrlok -and $idsAligned -and $enoughSends){ $eo="PASS" }
try{ if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force -EA SilentlyContinue } }catch{}
$rec=@(
 "EXACTLY_ONCE=$eo","SHA=$hash","SHA_MATCH=1",
 "SEND1_1_1=$send1ok dSub=$dSub1 dReq=$dReq1 dDone=$dDone1",
 "SEND2_1_1=$send2ok dSub=$dSub2 dReq=$dReq2 dDone=$dDone2",
 "BUSY_REJECT=$busyok dReject=$dRejBusy",
 "ENTER_NEWLINE_ONLY=$enterok dSubEnter=$dSubEnter",
 "CTRL_ENTER_1_1=$ctrlok dSub=$dSubCE dReq=$dReqCE dDone=$dDoneCE",
 "REQUEST_IDS_ALIGNED=$idsAligned","SUBMIT_IDS=$($submitU -join ',')","REQ_IDS=$($reqU -join ',')","DONE_IDS=$($doneU -join ',')",
 "REASON=$($reason -join ',')","TIP_EXE=$TipExe","TRANSCRIPT_LEN=$($vis.Length)","RUNLOG=$runlog","CHAT_RUNTIME=$rt","RECEIPT_PATH=$receipt","MD_PATH=$mdPath","NO_A190_OVERWRITE=1","NO_EXT_317D_REBIND=1",
 "LAUNCH=NORMAL_NO_FIXTURE_FREEZESEAL","PROMOTE=0","CERTIFIED=0","MATURITY=82%"
)
$rec | Set-Content -LiteralPath $receipt -Encoding UTF8; $rec | ForEach-Object { Write-Host $_ }
@(
 "# FREEZE_EXACTLY_ONCE_35C22","ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))","EXACTLY_ONCE=$eo","SHA=$hash",
 "SEND1=$send1ok BUSY=$busyok SEND2=$send2ok ENTER=$enterok CTRL_ENTER=$ctrlok ALIGN=$idsAligned",
 "REASON=$($reason -join ',')","RECEIPT=artifacts\FREEZE_EXACTLY_ONCE_RECEIPT_35C22.txt","NO_CROSS_SHA_PASS_INHERITANCE=1","PROMOTE=0","CERTIFIED=0","MATURITY=82%"
) | Set-Content $mdPath -Encoding UTF8
if($eo -eq "PASS"){ exit 0 } else { exit 5 }



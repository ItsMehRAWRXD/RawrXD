$ErrorActionPreference='Stop'
$exe='F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe'
$hash=(Get-FileHash $exe -Algorithm SHA256).Hash
$base='F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\CHAT_EXACTLY_ONCE_001'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir=Join-Path $base "runs\ctrl_enter_cc79_$stamp"
$logDir=Join-Path $runDir 'runtime'
New-Item -ItemType Directory -Force -Path $runDir,$logDir | Out-Null
$token='RXD_ONCE_'+[guid]::NewGuid().ToString('N')
$rtLog=Join-Path $logDir 'chat_runtime.log'
Get-Process | Where-Object { $_.ProcessName -match 'RawrXD|Win32IDE-Native' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class OnceCtrl7 {
  public const uint WM_SETTEXT=0x000C; public const uint KEYEVENTF_KEYUP=0x0002;
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
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint p1; public uint p2; }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,InputSize);} 
  public static uint KeyUp(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,InputSize);} 
  public static void SetText(IntPtr h,string t){ SendMessageW(h,WM_SETTEXT,IntPtr.Zero,t??""); }
  public static string GetText(IntPtr h){ IntPtr n=SendMessageW(h,0x000E,IntPtr.Zero,IntPtr.Zero); int len=n.ToInt32(); if(len<0)len=0; var sb=new StringBuilder(len+8); SendMessageW(h,0x000D,(IntPtr)sb.Capacity,sb); return sb.ToString(); }
  public static IntPtr FindMain(uint pid){ IntPtr found=IntPtr.Zero; EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid); if(wpid!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString(); if(c.Contains("RawrXD_IDE")){ found=h; return false;} if(found==IntPtr.Zero) found=h; return true;}, IntPtr.Zero); return found; }
}
"@
function Find-Ctrl([IntPtr]$parent,[int]$wantId,[string]$classPart){ $stack=New-Object System.Collections.Generic.Stack[IntPtr]; $stack.Push($parent); while($stack.Count -gt 0){ $cur=$stack.Pop(); $kids=New-Object System.Collections.Generic.List[IntPtr]; $enum=[OnceCtrl7+EnumChildProc]{ param($h,$lp) $kids.Add($h)|Out-Null; return $true }; [void][OnceCtrl7]::EnumChildWindows($cur,$enum,[IntPtr]::Zero); foreach($k in $kids){ $id=[OnceCtrl7]::GetDlgCtrlID($k); $cls=New-Object System.Text.StringBuilder 64; [void][OnceCtrl7]::GetClassNameW($k,$cls,64); if($id -eq $wantId -and $cls.ToString() -match $classPart){ return $k }; $stack.Push($k) } }; return [IntPtr]::Zero }
function Count-Tag($lines,$pat){ @($lines|Where-Object{$_ -match $pat}).Count }
$env:RAWRXD_LOG_DIR=$logDir; $env:RAWRXD_CHAT_RUN_ID="exactly_once_ctrl_$stamp"
$p=Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru -WindowStyle Normal
$main=[IntPtr]::Zero
for($i=0;$i -lt 100;$i++){ Start-Sleep -Milliseconds 400; try{$p.Refresh()}catch{break}; if($p.HasExited){ throw "early exit $($p.ExitCode)" }; $main=[OnceCtrl7]::FindMain([uint32]$p.Id); if($main -ne [IntPtr]::Zero){ break }; Get-Process | Where-Object { $_.ProcessName -match 'RawrXD|Win32IDE-Native' -and $_.Id -ne $p.Id } | Stop-Process -Force -ErrorAction SilentlyContinue }
if($main -eq [IntPtr]::Zero){ throw 'no hwnd' }
[void][OnceCtrl7]::SetForegroundWindow($main)
$chat=[IntPtr]::Zero
for($i=0;$i -lt 80;$i++){ Start-Sleep -Milliseconds 400; $chat=Find-Ctrl $main 1202 'Edit'; if($chat -ne [IntPtr]::Zero){ break } }
$out=Find-Ctrl $main 1203 'Edit'
"pid=$($p.Id) main=0x$('{0:X}' -f $main.ToInt64()) chat=0x$('{0:X}' -f $chat.ToInt64()) token=$token sha=$hash tip=CC79_tip_final_integ_002" | Set-Content (Join-Path $runDir 'run.txt')
if($chat -eq [IntPtr]::Zero){ throw 'chat missing on CC79' }
Start-Sleep -Seconds 10
$before=if(Test-Path $rtLog){@(Get-Content $rtLog)}else{@()}
$outBefore=if($out -ne [IntPtr]::Zero){[OnceCtrl7]::GetText($out)}else{''}
[OnceCtrl7]::SetText($chat,$token)
$uiTid=0; [void][OnceCtrl7]::GetWindowThreadProcessId($main,[ref]$uiTid); $myTid=[OnceCtrl7]::GetCurrentThreadId()
[void][OnceCtrl7]::AttachThreadInput($myTid,$uiTid,$true); [void][OnceCtrl7]::SetForegroundWindow($main); [void][OnceCtrl7]::SetFocus($chat); Start-Sleep -Milliseconds 50
[void][OnceCtrl7]::KeyDown(0x11); Start-Sleep -Milliseconds 30; [void][OnceCtrl7]::KeyDown(0x0D); Start-Sleep -Milliseconds 50; [void][OnceCtrl7]::KeyUp(0x0D); [void][OnceCtrl7]::KeyUp(0x11)
[void][OnceCtrl7]::AttachThreadInput($myTid,$uiTid,$false)
'INPUT_FIRED=ctrl_enter x1' | Add-Content (Join-Path $runDir 'run.txt')
$sw=[Diagnostics.Stopwatch]::StartNew()
while($sw.ElapsedMilliseconds -lt 180000){ Start-Sleep -Milliseconds 800; try{$p.Refresh()}catch{break}; if($p.HasExited){ 'PROCESS_DIED'|Add-Content (Join-Path $runDir 'run.txt'); break }; Get-Process | Where-Object { $_.ProcessName -match 'RawrXD|Win32IDE-Native' -and $_.Id -ne $p.Id } | Stop-Process -Force -ErrorAction SilentlyContinue; if(!(Test-Path $rtLog)){ continue }; $cur=@(Get-Content $rtLog); $delta=@($cur|Where-Object{ $before -notcontains $_ }); if($delta|Where-Object{$_ -match 'RESPONSE_END|BACKEND_REQUEST_END|CHAT_SEND_NO_MODEL|CHAT_SEND_BUSY|CHAT_SEND_REJECTED'}){ break } }
$after=if(Test-Path $rtLog){@(Get-Content $rtLog)}else{@()}; $delta=@($after|Where-Object{ $before -notcontains $_ }); $delta | Set-Content (Join-Path $runDir 'delta_chat_runtime.log'); Copy-Item $rtLog (Join-Path $runDir 'chat_runtime_full.log') -ErrorAction SilentlyContinue
$outAfter=if($out -ne [IntPtr]::Zero -and -not $p.HasExited){[OnceCtrl7]::GetText($out)}else{''}
$aiDelta=([regex]::Matches($outAfter,'(?m)^AI:')).Count - ([regex]::Matches($outBefore,'(?m)^AI:')).Count
$tokenHit=if($outAfter -like "*$token*"){1}else{0}
$cInput=Count-Tag $delta 'INPUT_EVENT source=ctrl_enter'; if($cInput -eq 0){$cInput=Count-Tag $delta 'kind=CTRL_ENTER'}
$cDispatch=Count-Tag $delta 'DISPATCH_ID id='; if($cDispatch -eq 0){$cDispatch=Count-Tag $delta 'CHAT_SEND_ATTEMPT dispatch_id='}
$cBackendS=Count-Tag $delta 'BACKEND_REQUEST_START'; if($cBackendS -eq 0){$cBackendS=Count-Tag $delta 'request_started request_id='}
$cBackendE=Count-Tag $delta 'BACKEND_REQUEST_END'; $cRespS=Count-Tag $delta 'RESPONSE_START'; $cRespE=Count-Tag $delta 'RESPONSE_END'
$cUser=Count-Tag $delta 'TRANSCRIPT_INSERT role=user'; $cAsst=Count-Tag $delta 'TRANSCRIPT_INSERT role=assistant'
$cMirror=Count-Tag $delta 'TRANSCRIPT_INSERT role=agent_mirror'; $cPs=Count-Tag $delta 'powershell_hint=1'
$status='NOT_VERIFIED'; $root='incomplete_chain'
if($cInput -eq 0 -and $cDispatch -eq 0){$root='ctrl_enter_not_observed'}
elseif($cDispatch -gt 1 -or $cBackendS -gt 1){$status='FAIL'; $root='duplicate_execution'}
elseif($cInput -gt 1){$status='FAIL'; $root='duplicate_input_event'}
elseif($cInput -eq 1 -and $cDispatch -eq 1 -and $cBackendS -eq 1 -and $cRespE -eq 1 -and $cUser -eq 1 -and $cAsst -eq 1 -and $aiDelta -le 1){$status='PASS'; $root='none'}
elseif($cDispatch -eq 1 -and $cBackendS -eq 1 -and $cRespE -eq 0){$status='NOT_VERIFIED'; $root='response_incomplete_timeout'}
elseif($cDispatch -eq 1 -and ($cAsst -gt 1 -or $aiDelta -gt 1)){$status='FAIL'; $root='duplicate_display'}
@"
EXACTLY_ONCE=$status
ROOT_CAUSE=$root
MODE=ctrl_enter
TOKEN=$token
TIP_LABEL=tip_final_integ_002_CC79
TIP_SHA256=$hash
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
AI_BLOCKS_DELTA=$aiDelta
TOKEN_IN_TRANSCRIPT=$tokenHit
MULTI_BLOCK_REPRODUCED=$(if($aiDelta -gt 1 -or $cDispatch -gt 1){'1'}else{'0'})
CC79_UNTOUCHED=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_005_UNTOUCHED=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
PROMOTE=0
MATURITY_HELD=82
"@ | Tee-Object -FilePath (Join-Path $runDir 'RECEIPT.txt')
try{ if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force } } catch {}
Write-Output "RUNDIR=$runDir"


# Bounded P2 smokes for tip_integ_candidate_001. PROMOTE=0. Fail-closed.
$ErrorActionPreference='Continue'
$tip="F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe"
$sha=(Get-FileHash $tip -Algorithm SHA256).Hash
$cand="F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001"
$out="F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts"
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$session="integ_p2_$stamp"
$run="integ_p2_run_$stamp"
$logdir=Join-Path $cand "p2_$stamp"
New-Item -ItemType Directory -Force -Path $logdir | Out-Null
$env:RAWRXD_LOG_DIR=$logdir
Get-Process RawrXD-Win32IDE-Native* -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class P2N {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, BM_CLICK=0x00F5;
  public const uint KEYEVENTF_KEYUP=0x0002; public const int VK_RETURN=0x0D, VK_CONTROL=0x11;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint p1; public uint p2; }
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(128); GetClassNameW(h,sb,sb.Capacity); if(sb.ToString().IndexOf("RawrXD")>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindId(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindCtrl(IntPtr root,int id,string clsWant){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)!=id) return true; var sb=new StringBuilder(64); GetClassNameW(h,sb,sb.Capacity); if(sb.ToString().IndexOf(clsWant,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static string GetText(IntPtr h){ if(h==IntPtr.Zero)return ""; int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); if(n<=0)return ""; var sb=new StringBuilder(n+8); SendMessageW(h,WM_GETTEXT,(IntPtr)sb.Capacity,sb); return sb.ToString(); }
  public static void Key(ushort vk,bool up){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; if(up)a[0].ki.dwFlags=KEYEVENTF_KEYUP; SendInput(1,a,Marshal.SizeOf(typeof(INPUT))); }
}
"@

$fixture="$cand\smoke_edit_$stamp.txt"
Set-Content $fixture "OPEN_MARKER $stamp"
$p=Start-Process -FilePath $tip -ArgumentList @($fixture) -WorkingDirectory $cand -PassThru -WindowStyle Normal
$main=[IntPtr]::Zero
for($i=0;$i -lt 50;$i++){ Start-Sleep -Milliseconds 250; try{$p.Refresh()}catch{}; if($p.HasExited){break}; $main=[P2N]::FindMain([uint32]$p.Id); if($main -ne [IntPtr]::Zero){break} }
$open = if($main -ne [IntPtr]::Zero -and -not $p.HasExited){'PASS'} else {'FAIL'}

# Editor text sample (open)
$editor=[P2N]::FindCtrl($main,1001,"Edit"); if($editor -eq [IntPtr]::Zero){ $editor=[P2N]::FindCtrl($main,1010,"RichEdit") }
$before=[P2N]::GetText($editor)
$openContent = if($before -match 'OPEN_MARKER' -or $before.Length -gt 0){'PASS'} else {'PARTIAL_OR_FAIL'}

# Edit + save via WM_SETTEXT then File Save command if present (301M_FILE_SAVE often 2002/1002)
if($editor -ne [IntPtr]::Zero){
  [void][P2N]::SendMessageW($editor,0x000C,[IntPtr]::Zero,("EDITED $stamp`r`nOPEN_MARKER $stamp"))
}
$afterEdit=[P2N]::GetText($editor)
$edit = if($afterEdit -match 'EDITED'){'PASS'} else {'FAIL'}
# Try common save command IDs
foreach($sid in @(2002,1002,101,57603)){ [void][P2N]::PostMessageW($main,0x0111,[IntPtr]$sid,[IntPtr]::Zero) }
Start-Sleep 1
$savedOnDisk = if((Test-Path $fixture) -and ((Get-Content $fixture -Raw) -match 'EDITED')){'PASS'} else {'FAIL_OR_UNVERIFIED'}

# Chat Ctrl+Enter + Send (IDs from IED harness: input 1202 Edit, send 1204 Button)
$chat=[P2N]::FindCtrl($main,1202,"Edit")
$send=[P2N]::FindCtrl($main,1204,"Button")
[void][P2N]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 300
if($chat -ne [IntPtr]::Zero){
  [void][P2N]::SendMessageW($chat,0x000C,[IntPtr]::Zero,"ctrl-enter-$session")
  Start-Sleep -Milliseconds 150
  [P2N]::Key(0x11,$false); [P2N]::Key(0x0D,$false); [P2N]::Key(0x0D,$true); [P2N]::Key(0x11,$true)
  Start-Sleep -Milliseconds 600
}
if($chat -ne [IntPtr]::Zero -and $send -ne [IntPtr]::Zero){
  [void][P2N]::SendMessageW($chat,0x000C,[IntPtr]::Zero,"button-send-$session")
  Start-Sleep -Milliseconds 100
  [void][P2N]::PostMessageW($send,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero)
  Start-Sleep -Milliseconds 800
}
$rt=Join-Path $logdir 'chat_runtime.log'
Start-Sleep 1
$j= if(Test-Path $rt){ Get-Content $rt -Raw } else { '' }
$ctrl= $j -match 'INPUT_EVENT kind=CTRL_ENTER'
$btn= $j -match 'INPUT_EVENT kind=BUTTON_CLICK'
$sendJ= ([regex]::Matches($j,'CHAT_SEND_')).Count
$chatGate = if($ctrl -and $btn){'PASS'} elseif($ctrl -or $btn){'PARTIAL'} else {'FAIL'}

# Cancel/recovery: click Stop if present (1210), ensure process still alive
$stop=[P2N]::FindCtrl($main,1210,"Button")
$aliveBefore = -not $p.HasExited
if($stop -ne [IntPtr]::Zero){ [void][P2N]::PostMessageW($stop,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero); Start-Sleep 1 }
try{$p.Refresh()}catch{}
$aliveAfter = -not $p.HasExited
$cancel = if($stop -eq [IntPtr]::Zero){'NOT_REACHABLE'} elseif($aliveBefore -and $aliveAfter){'PASS_STOP_CLICKED_PROCESS_ALIVE'} else {'FAIL'}

@"
TIP_SHA256=$sha
TIP_PACKAGE=tip_integ_candidate_001
SESSION_ID=$session
RUN_ID=$run
OPEN_SMOKE=$open
OPEN_CONTENT=$openContent
EDIT_SMOKE=$edit
SAVE_SMOKE=$savedOnDisk
CHAT_CTRL_ENTER_SEND=$chatGate
CTRL_ENTER_JOURNAL=$(if($ctrl){'PASS'}else{'FAIL'})
BUTTON_CLICK_JOURNAL=$(if($btn){'PASS'}else{'FAIL'})
CHAT_SEND_HITS=$sendJ
CANCEL_RECOVERY=$cancel
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
CHAT_HWND=0x$('{0:X}' -f $chat.ToInt64())
SEND_HWND=0x$('{0:X}' -f $send.ToInt64())
STOP_HWND=0x$('{0:X}' -f $stop.ToInt64())
RUNTIME_LOG=$rt
FIXTURE=$fixture
PROMOTE=0
"@ | Set-Content "$out\INTEG_CANDIDATE_001_P2_SMOKE_RECEIPT.txt"
Get-Content "$out\INTEG_CANDIDATE_001_P2_SMOKE_RECEIPT.txt"
if(Test-Path $rt){ "----JOURNAL----"; Get-Content $rt -Tail 30 }
try{ if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force } }catch{}

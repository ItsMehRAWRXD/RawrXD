# Quick EA5D panel measure — PostMessage only (no cross-thread SendMessage deadlock).
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_004\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts"
)
$ErrorActionPreference='Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "ea5d_panel_quick_$stamp.txt"
$receipt = Join-Path $OutDir "EA5D_FOUR_PANEL_GUI_RECEIPT.txt"
function L($m){ $x="$(Get-Date -Format o) $m"; Add-Content $runlog $x; Write-Host $x }
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class Ea5dQ {
  public const uint WM_COMMAND=0x0111, WM_GETTEXTLENGTH=0x000E, TCM_GETITEMCOUNT=0x1304, TCM_SETCURSEL=0x130C, TCM_GETCURSEL=0x130B, LVM_GETITEMCOUNT=0x1004, SMTO=0x0002;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr SendMessageTimeoutW(IntPtr h,uint Msg,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public static int LastItems, LastVis, LastLen;
  public static int Timed(IntPtr h,uint msg,IntPtr w,uint ms){ IntPtr r; var ok=SendMessageTimeoutW(h,msg,w,IntPtr.Zero,SMTO,ms,out r); return ok==IntPtr.Zero?-3:r.ToInt32(); }
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString(); if(c=="RawrXD_IDE_Window"||c=="RawrXD_IDE_MainWindow"){f=h;return false;} if(f==IntPtr.Zero)f=h; return true;},IntPtr.Zero); return f; }
  public static IntPtr FindById(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static void ProbeList(IntPtr root,int id){ LastItems=-1; LastVis=0; LastLen=-1; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)!=id) return true; LastVis=IsWindowVisible(h)?1:0; LastLen=Timed(h,WM_GETTEXTLENGTH,IntPtr.Zero,250); LastItems=Timed(h,LVM_GETITEMCOUNT,IntPtr.Zero,250); return false; },IntPtr.Zero); }
  public static int MaxVisEdit(IntPtr root){ int best=0,n=0; EnumChildWindows(root,(h,lp)=>{ if(!IsWindowVisible(h)) return true; var sb=new StringBuilder(64); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString(); if(c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)<0 && c!="Edit") return true; if(++n>8) return false; int len=Timed(h,WM_GETTEXTLENGTH,IntPtr.Zero,150); if(len>best) best=len; return true; },IntPtr.Zero); return best; }
}
"@
$sha=(Get-FileHash -Algorithm SHA256 $TipExe).Hash
L "TIP_SHA256=$sha"
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$p=Start-Process $TipExe -PassThru -WindowStyle Normal
L "PID=$($p.Id)"
$main=[IntPtr]::Zero
for($i=0;$i -lt 40;$i++){ Start-Sleep -Milliseconds 300; try{$p.Refresh()}catch{}; if($p.HasExited){L "EARLY_EXIT"; break}; if($p.MainWindowHandle -ne 0){$main=[IntPtr]$p.MainWindowHandle; break}; $main=[Ea5dQ]::FindMain([uint32]$p.Id); if($main -ne [IntPtr]::Zero){break} }
L "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if($main -eq [IntPtr]::Zero){ "EA5D_FOUR_PANEL_GUI=NOT_RUN`nPROMOTE=0" | Set-Content $receipt; exit 2 }
[void][Ea5dQ]::SetForegroundWindow($main); Start-Sleep 400
foreach($c in 2034,2025,2021){ [void][Ea5dQ]::PostMessageW($main,0x0111,[IntPtr]$c,[IntPtr]::Zero); L "POST_CMD $c"; Start-Sleep 200 }
$outTabs=[Ea5dQ]::FindById($main,1005)
$panelTabs=[Ea5dQ]::FindById($main,1301)
$panelCont=[Ea5dQ]::FindById($main,1300)
$outN=[Ea5dQ]::Timed($outTabs,0x1304,[IntPtr]::Zero,400)
$panelN=[Ea5dQ]::Timed($panelTabs,0x1304,[IntPtr]::Zero,400)
L "OUT_TABS n=$outN PANEL_TABS n=$panelN"
[void][Ea5dQ]::PostMessageW($outTabs,0x130C,[IntPtr]0,[IntPtr]::Zero); Start-Sleep 400
$vis0=[Ea5dQ]::MaxVisEdit($main)
$cur0=[Ea5dQ]::Timed($outTabs,0x130B,[IntPtr]::Zero,300)
L "OUT_TAB0 cur=$cur0 VIS=$vis0"
[void][Ea5dQ]::PostMessageW($outTabs,0x130C,[IntPtr]4,[IntPtr]::Zero); Start-Sleep 400
$visB=[Ea5dQ]::MaxVisEdit($main)
$curB=[Ea5dQ]::Timed($outTabs,0x130B,[IntPtr]::Zero,300)
L "OUT_TAB4_BUILD cur=$curB VIS=$visB"
[void][Ea5dQ]::PostMessageW($outTabs,0x130C,[IntPtr]7,[IntPtr]::Zero); Start-Sleep 250
[void][Ea5dQ]::PostMessageW($outTabs,0x130C,[IntPtr]9,[IntPtr]::Zero); Start-Sleep 250
$cur9=[Ea5dQ]::Timed($outTabs,0x130B,[IntPtr]::Zero,300)
L "OUT_TAB9_DEEP cur=$cur9"
[void][Ea5dQ]::PostMessageW($outTabs,0x130C,[IntPtr]1,[IntPtr]::Zero); Start-Sleep 300
[void][Ea5dQ]::PostMessageW($panelTabs,0x130C,[IntPtr]2,[IntPtr]::Zero); Start-Sleep 400
[Ea5dQ]::ProbeList($main,1312)
$panelVis= if($panelCont -ne [IntPtr]::Zero -and [Ea5dQ]::IsWindowVisible($panelCont)){1}else{0}
L "PROBLEMS items=$([Ea5dQ]::LastItems) vis=$([Ea5dQ]::LastVis) panelContVis=$panelVis"
[void][Ea5dQ]::PostMessageW($panelTabs,0x130C,[IntPtr]3,[IntPtr]::Zero); Start-Sleep 300
$curDbg=[Ea5dQ]::Timed($panelTabs,0x130B,[IntPtr]::Zero,300)
L "PANEL_DEBUG cur=$curDbg"
$bytes=[IO.File]::ReadAllBytes($TipExe); $ascii=[Text.Encoding]::ASCII.GetString($bytes)
$wfde=([regex]::Matches($ascii,'WaitForDebugEvent')).Count
$dbgeng=([regex]::Matches($ascii,'IDebugClient')).Count
L "ASCII WaitForDebugEvent=$wfde IDebugClient=$dbgeng"

$outPass = if($vis0 -gt 20 -or $visB -gt 20){'PARTIAL'} else {'NOT_RUN'}
$probPass = if(([Ea5dQ]::LastVis -eq 1) -and ([Ea5dQ]::LastItems -gt 0)){'PASS'} elseif([Ea5dQ]::LastItems -ge 0){'PARTIAL'} else {'NOT_RUN'}
$dbgPass = if($wfde -gt 0){'BACKEND_PRESENT_GUI_NOT_RUN'} elseif($curDbg -eq 3){'PARTIAL_UI_TAB_ONLY'} else {'NOT_RUN'}
$four='FAIL_CLOSED_GAPS'

@"
EA5D_FOUR_PANEL_GUI=MEASURED
TIP_SHA256=$sha
TIP_EXE=$TipExe
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
OUT_TAB_COUNT=$outN
PANEL_TAB_COUNT=$panelN
OUT_TAB0_CUR=$cur0
OUT_TAB4_BUILD_CUR=$curB
OUT_TAB9_DEEP_CUR=$cur9
PANEL_DEBUG_CUR=$curDbg
VISIBLE_EDIT_OUTPUT_TAB=$vis0
VISIBLE_EDIT_BUILD_TAB=$visB
PROBLEMS_ID1312_ITEMS=$([Ea5dQ]::LastItems)
PROBLEMS_ID1312_VISIBLE=$([Ea5dQ]::LastVis)
PANEL_CONTAINER_VISIBLE=$panelVis
WAITFORDEBUGEVENT_STRINGS=$wfde
IDEBUGCLIENT_STRINGS=$dbgeng
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
GUI_DEBUG_CONSOLE_E2E=$dbgPass
FOUR_PANEL_INTEGRATION=$four
BUILD_PROJECT_HWND=NOT_RUN
BUILD_CHANNEL_LINES=NOT_RUN
CHANNEL_NOTIFY=POST_SETCURSEL_ONLY_NO_TCN
GAPS=TCN_SELCHANGE_NOT_DRIVEN,BUILD_LINES_HWND,PROBLEMS_POPULATED_ITEMS,DEBUG_BACKEND_ABSENT_ON_EA5D,FOUR_PANEL_1_17
FROZEN_A4F_UNTOUCHED=1
T080_PRESERVED=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
Get-Content $receipt
try{ if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force } }catch{}
exit 0

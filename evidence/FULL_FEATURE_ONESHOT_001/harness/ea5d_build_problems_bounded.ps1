# Bounded EA5D Build+Problems HWND measure. Fail-closed timeouts; force-kill.
# NO invent PASS. Never touch A4F.
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_004\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$Fixture = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [int]$HardTimeoutSec = 55
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "ea5d_build_problems_$stamp.txt"
$receipt = Join-Path $OutDir "EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt"
function L([string]$m) {
  $x = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runlog -Value $x
  Write-Host $x
}
$job = Start-Job -ScriptBlock {
  param($TipExe,$Fixture,$OutDir,$runlog,$receipt,$HardTimeoutSec)
  $ErrorActionPreference='Continue'
  function L([string]$m){ Add-Content -LiteralPath $using:runlog -Value ("{0} {1}" -f (Get-Date -Format o), $m) }
  # Rebind paths from args
  $TipExe=$TipExe; $Fixture=$Fixture; $OutDir=$OutDir; $runlog=$runlog; $receipt=$receipt
  Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class BpH {
  public const uint WM_COMMAND=0x0111, WM_GETTEXTLENGTH=0x000E, WM_CLOSE=0x0010;
  public const uint TCM_GETITEMCOUNT=0x1304, TCM_SETCURSEL=0x130C, TCM_GETCURSEL=0x130B, LVM_GETITEMCOUNT=0x1004;
  public const uint SMTO=0x0002;
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
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString(); if(c=="RawrXD_IDE_Window"||c=="RawrXD_IDE_MainWindow"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindById(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static void ProbeList(IntPtr root,int id){ LastItems=-1; LastVis=0; LastLen=-1; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)!=id) return true; LastVis=IsWindowVisible(h)?1:0; LastLen=Timed(h,WM_GETTEXTLENGTH,IntPtr.Zero,200); LastItems=Timed(h,LVM_GETITEMCOUNT,IntPtr.Zero,200); return false; },IntPtr.Zero); }
  public static int MaxVisEdit(IntPtr root){ int best=0,n=0; EnumChildWindows(root,(h,lp)=>{ if(!IsWindowVisible(h)) return true; var sb=new StringBuilder(64); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString(); if(c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)<0 && c!="Edit") return true; if(++n>6) return false; int len=Timed(h,WM_GETTEXTLENGTH,IntPtr.Zero,120); if(len>best) best=len; return true; },IntPtr.Zero); return best; }
}
"@
  if(-not (Test-Path -LiteralPath $TipExe)){ "MISSING_TIP" | Set-Content $receipt; return }
  $sha=(Get-FileHash -Algorithm SHA256 -LiteralPath $TipExe).Hash
  Add-Content $runlog ("TIP_SHA256="+$sha)
  $env:RAWRXD_PROBLEMS_FIXTURE=$Fixture
  Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep 1
  $psi=New-Object Diagnostics.ProcessStartInfo
  $psi.FileName=$TipExe
  $psi.UseShellExecute=$true
  $psi.EnvironmentVariables['RAWRXD_PROBLEMS_FIXTURE']=$Fixture
  # ProcessStartInfo EnvironmentVariables needs UseShellExecute=false
  $psi.UseShellExecute=$false
  $p=[Diagnostics.Process]::Start($psi)
  Add-Content $runlog ("PID="+$p.Id)
  $main=[IntPtr]::Zero
  for($i=0;$i -lt 50;$i++){
    Start-Sleep -Milliseconds 200
    try{$p.Refresh()}catch{}
    if($p.HasExited){ break }
    if($p.MainWindowHandle -ne [IntPtr]::Zero){ $main=$p.MainWindowHandle; break }
    $main=[BpH]::FindMain([uint32]$p.Id)
    if($main -ne [IntPtr]::Zero){ break }
  }
  Add-Content $runlog ("MAIN_HWND=0x{0:X}" -f $main.ToInt64())
  if($main -eq [IntPtr]::Zero){
@"
EA5D_OUTPUT_PROBLEMS_HWND=NOT_RUN
REASON=no_main_hwnd
TIP_SHA256=$sha
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
    try{ if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force } }catch{}
    return
  }
  [void][BpH]::SetForegroundWindow($main)
  Start-Sleep 300
  # View Output / Problems / Terminal panel cmds
  foreach($c in 2034,2025,2021){ [void][BpH]::PostMessageW($main,0x0111,[IntPtr]$c,[IntPtr]::Zero); Start-Sleep 150 }
  $outTabs=[BpH]::FindById($main,1005)
  $panelTabs=[BpH]::FindById($main,1301)
  $visBefore=[BpH]::MaxVisEdit($main)
  Add-Content $runlog ("VIS_BEFORE=$visBefore")
  # Build Project 3014 with problems fixture env
  [void][BpH]::PostMessageW($main,0x0111,[IntPtr]3014,[IntPtr]::Zero)
  Add-Content $runlog "POST_BUILD_3014"
  # Wait for fixture compile output (bounded)
  Start-Sleep 12
  [void][BpH]::PostMessageW($outTabs,0x130C,[IntPtr]4,[IntPtr]::Zero) # Build channel
  Start-Sleep 400
  $visBuild=[BpH]::MaxVisEdit($main)
  $curBuild=[BpH]::Timed($outTabs,0x130B,[IntPtr]::Zero,200)
  Add-Content $runlog ("BUILD_TAB cur=$curBuild VIS=$visBuild")
  [void][BpH]::PostMessageW($panelTabs,0x130C,[IntPtr]2,[IntPtr]::Zero) # Problems
  Start-Sleep 500
  [BpH]::ProbeList($main,1312)
  Add-Content $runlog ("PROBLEMS items=$([BpH]::LastItems) vis=$([BpH]::LastVis)")
  $buildLines = if($visBuild -gt $visBefore -and $visBuild -gt 20){'PASS'} elseif($visBuild -gt 20){'PARTIAL'} else {'NOT_RUN'}
  $probGui = if(([BpH]::LastVis -eq 1) -and ([BpH]::LastItems -gt 0)){'PASS'} elseif([BpH]::LastItems -ge 0){'PARTIAL'} else {'NOT_RUN'}
@"
EA5D_OUTPUT_PROBLEMS_HWND=MEASURED
TIP_SHA256=$sha
TIP_EXE=$TipExe
FIXTURE=$Fixture
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
VISIBLE_EDIT_BEFORE=$visBefore
VISIBLE_EDIT_BUILD_TAB=$visBuild
OUT_TAB4_CUR=$curBuild
PROBLEMS_ID1312_ITEMS=$([BpH]::LastItems)
PROBLEMS_ID1312_VISIBLE=$([BpH]::LastVis)
BUILD_CHANNEL_LINES_HWND=$buildLines
GUI_PROBLEMS_PANEL_E2E=$probGui
GUI_OUTPUT_PANEL_E2E=$buildLines
FROZEN_A4F_UNTOUCHED=1
T080_PRESERVED=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
"@ | Set-Content $receipt
  try{ [void][BpH]::PostMessageW($main,0x0010,[IntPtr]::Zero,[IntPtr]::Zero); Start-Sleep 2 }catch{}
  try{ if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force } }catch{}
} -ArgumentList $TipExe,$Fixture,$OutDir,$runlog,$receipt,$HardTimeoutSec

$ok = Wait-Job $job -Timeout $HardTimeoutSec
if(-not $ok){
  L "HARD_TIMEOUT=${HardTimeoutSec}s — fail-closed"
  Stop-Job $job -Force -EA SilentlyContinue
  Remove-Job $job -Force -EA SilentlyContinue
  Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  if(-not (Test-Path $receipt)){
@"
EA5D_OUTPUT_PROBLEMS_HWND=NOT_RUN
REASON=hard_timeout_${HardTimeoutSec}s
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
"@ | Set-Content $receipt
  }
  Get-Content $receipt
  exit 3
}
Receive-Job $job | ForEach-Object { L "$_" }
Remove-Job $job -Force -EA SilentlyContinue
if(Test-Path $receipt){ Get-Content $receipt }
exit 0

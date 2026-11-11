# SHA-bound Problems click-to-line: activate diagnostics 0/1/2 → editor lines 3/4/5.
# tip_cc79_integ_002. PROMOTE=0. No invented PASS.
param(
  [string]$TipExe = "F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_002\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "F5F4807E4738F500397AA5ACEBC8BE095806DF19C71FF959083512C73A16BA15",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$Debuggee = "F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_002\debuggee_fixture.exe",
  [string]$OutDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\candidates\tip_cc79_integ_002_click2line"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

$receipt = Join-Path $OutDir 'PROBLEMS_CLICK_TO_LINE_TIP002_RECEIPT.txt'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "problems_click_to_line_tip002_$stamp.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}

if (-not (Test-Path -LiteralPath $TipExe)) {
  "CLICK_TO_LINE=NOT_RUN`nREASON=tip_missing`nPROMOTE=0" | Set-Content $receipt; exit 2
}
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectSha) {
  @"
CLICK_TO_LINE=NOT_RUN
REASON=SHA_DRIFT
TIP_SHA256=$sha
EXPECT=$ExpectSha
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class C2L {
  public const uint WM_COMMAND=0x0111; public const uint WM_NOTIFY=0x004E;
  public const uint WM_GETTEXTLENGTH=0x000E; public const uint WM_LBUTTONDOWN=0x0201;
  public const uint WM_LBUTTONUP=0x0202; public const uint WM_LBUTTONDBLCLK=0x0203;
  public const uint LVM_FIRST=0x1000;
  public const uint LVM_GETITEMCOUNT=0x1004;
  public const uint LVM_ENSUREVISIBLE=LVM_FIRST+19;
  public const uint LVM_SETITEMSTATE=LVM_FIRST+43;
  public const uint LVM_GETITEMRECT=LVM_FIRST+14;
  public const uint EM_GETSEL=0x00B0; public const uint EM_LINEFROMCHAR=0x00C9;
  public const uint TCM_SETCURSEL=0x130C; public const int TCN_SELCHANGE=-551;
  public const uint LVIS_SELECTED=0x0002; public const uint LVIS_FOCUSED=0x0001;
  public const uint LVIF_STATE=0x0008; public const uint SMTO_NORMAL=0;
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int left, top, right, bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct LVITEM {
    public uint mask; public int iItem; public int iSubItem; public uint state; public uint stateMask;
    public IntPtr pszText; public int cchTextMax; public int iImage; public IntPtr lParam;
  }
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMHDR l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref LVITEM l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref RECT l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool SelectTab(IntPtr root, IntPtr tab, int idx, int idFrom){
    if(tab==IntPtr.Zero) return false;
    SendMessageW(tab,TCM_SETCURSEL,(IntPtr)idx,IntPtr.Zero);
    NMHDR nm; nm.hwndFrom=tab; nm.idFrom=(IntPtr)idFrom; nm.code=TCN_SELCHANGE;
    SendMessage(root,WM_NOTIFY,(IntPtr)idFrom,ref nm); return true;
  }
  public static int EditorLine(IntPtr main){
    foreach(int eid in new int[]{1001,1101,1010}){
      IntPtr eh=FindId(main,eid);
      if(eh==IntPtr.Zero) continue;
      IntPtr sel=SendMessageW(eh,EM_GETSEL,IntPtr.Zero,IntPtr.Zero);
      int cp=(int)(sel.ToInt64() & 0xFFFF);
      int ln=(int)SendMessageW(eh,EM_LINEFROMCHAR,(IntPtr)cp,IntPtr.Zero);
      if(ln>=0) return ln+1;
    }
    return -1;
  }
  public static bool ActivateItem(IntPtr main, IntPtr lv, int item){
    if(lv==IntPtr.Zero || item<0) return false;
    SendMessageW(lv,LVM_ENSUREVISIBLE,(IntPtr)item,IntPtr.Zero);
    LVITEM lvi=new LVITEM();
    lvi.mask=LVIF_STATE; lvi.iItem=item; lvi.state=LVIS_SELECTED|LVIS_FOCUSED; lvi.stateMask=LVIS_SELECTED|LVIS_FOCUSED;
    SendMessage(lv,LVM_SETITEMSTATE,(IntPtr)item,ref lvi);
    RECT rc=new RECT();
    // LVIR_BOUNDS=0
    bool gotRect = SendMessage(lv,LVM_GETITEMRECT,(IntPtr)item,ref rc)!=IntPtr.Zero;
    int x = gotRect ? (rc.left+rc.right)/2 : 40;
    int y = gotRect ? (rc.top+rc.bottom)/2 : (20 + item*20);
    if(x<5) x=40; if(y<5) y=20+item*20;
    IntPtr packed=(IntPtr)((y<<16)|(x & 0xFFFF));
    SendMessageW(lv,WM_LBUTTONDOWN,(IntPtr)1,packed);
    SendMessageW(lv,WM_LBUTTONUP,IntPtr.Zero,packed);
    SendMessageW(lv,WM_LBUTTONDBLCLK,(IntPtr)1,packed);
    SendMessageW(lv,WM_LBUTTONUP,IntPtr.Zero,packed);
    return true;
  }
}
"@

$env:RAWRXD_LOG_DIR=$LogDir
$env:RAWRXD_PROBLEMS_FIXTURE=$BrokenCpp
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
Log "TIP_SHA256=$sha"
Log "FIXTURE=$BrokenCpp"

$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main=[IntPtr]::Zero
for($i=0;$i -lt 90;$i++){
  Start-Sleep -Milliseconds 500
  try{$p.Refresh()}catch{}
  if($p.HasExited){ Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
  if($p.MainWindowHandle -ne 0){ $main=[IntPtr]$p.MainWindowHandle; Log "MAIN_VIA_PROC t=$i"; break }
  $main=[C2L]::FindMain([uint32]$p.Id)
  if($main -ne [IntPtr]::Zero){ Log "MAIN_VIA_ENUM t=$i"; break }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if($main -eq [IntPtr]::Zero){
  "CLICK_TO_LINE=NOT_RUN`nREASON=no_main`nTIP_SHA256=$sha`nPROMOTE=0" | Set-Content $receipt; exit 2
}
[void][C2L]::ShowWindow($main,9)
[void][C2L]::SetForegroundWindow($main)
Start-Sleep 2
if([int][C2L]::VisId($main,1300) -eq 0){ [void][C2L]::Cmd($main,2034,2000); Start-Sleep -Milliseconds 500 }

[void][C2L]::Cmd($main,3014,15000)
Start-Sleep 2
$panelTabs=[C2L]::FindId($main,1301)
[void][C2L]::SelectTab($main,$panelTabs,2,1301)
$id1312=-1; $id1604=-1
for($w=0;$w -lt 50;$w++){
  Start-Sleep 1
  if($p.HasExited){ Log "EXIT_BUILD=$($p.ExitCode)"; break }
  $id1312=[C2L]::IdList($main,1312)
  $id1604=[C2L]::IdLen($main,1604)
  if(($w%5)-eq0){ Log "POLL t=$w items=$id1312 out=$id1604 panel=$([int][C2L]::VisId($main,1300))" }
  if($id1312 -ge 3 -and $id1604 -gt 0){ break }
}
Log "POPULATION items=$id1312 out=$id1604"
$problemsVisible = ($id1312 -ge 3)

# Activate each of 3 diagnostics
$expectLines=@(3,4,5)
$nav=@(-1,-1,-1)
$navPass=@($false,$false,$false)
$lv=[C2L]::FindId($main,1312)
for($i=0;$i -lt 3;$i++){
  if($p.HasExited -or $lv -eq [IntPtr]::Zero -or $id1312 -le $i){ Log "SKIP_ITEM i=$i"; break }
  [void][C2L]::SelectTab($main,$panelTabs,2,1301)
  Start-Sleep -Milliseconds 200
  $ok=[C2L]::ActivateItem($main,$lv,$i)
  Start-Sleep -Milliseconds 450
  $ln=[C2L]::EditorLine($main)
  $nav[$i]=$ln
  $navPass[$i]=($ln -eq $expectLines[$i])
  Log "CLICK item=$i ok=$ok editorLine=$ln expect=$($expectLines[$i]) pass=$($navPass[$i])"
}

$clickAll = ($navPass[0] -and $navPass[1] -and $navPass[2])
$clickVerdict = if(-not $problemsVisible){'FAIL_POPULATION_LT3'} elseif($clickAll){'PASS'} else {'FAIL_NAV_MISMATCH'}

# Four-panel brief exercise same SHA
$selTerm=$false;$selOut=$false;$selProb=$false;$selDbg=$false
if(-not $p.HasExited -and $panelTabs -ne [IntPtr]::Zero){
  $selTerm=[C2L]::SelectTab($main,$panelTabs,0,1301); Start-Sleep -Milliseconds 200
  $selOut=[C2L]::SelectTab($main,$panelTabs,1,1301); Start-Sleep -Milliseconds 200
  $selProb=[C2L]::SelectTab($main,$panelTabs,2,1301); Start-Sleep -Milliseconds 200
  $selDbg=[C2L]::SelectTab($main,$panelTabs,3,1301); Start-Sleep -Milliseconds 200
}
$panelVis=[int][C2L]::VisId($main,1300)
$termCmd=[C2L]::Cmd($main,3006,1500)
$outOk=($id1604 -gt 0)

# Debug reconfirm (optional START-only if debuggee present)
$dbgSession=0; $dbgVars=-1; $dbgResult='NEEDS_REVERIFY'
if((Test-Path -LiteralPath $Debuggee) -and -not $p.HasExited){
  $env:RAWRXD_DEBUGGEE=$Debuggee
  foreach($act in @(1104,6004)){ [void][C2L]::Cmd($main,$act,2000); Start-Sleep -Milliseconds 250 }
  [void][C2L]::Cmd($main,5060,15000)
  for($w=0;$w -lt 12;$w++){
    Start-Sleep 1
    if($p.HasExited){ break }
    $dbgVars=[C2L]::IdList($main,6043)
    if($dbgVars -gt 0){ $dbgSession=1; break }
  }
  [void][C2L]::Cmd($main,10501,2000)
  $dbgResult = if($dbgSession -eq 1){'PASS_SESSION_REAL'} else {'BLOCKED_NO_SESSION_REAL'}
  Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
} else {
  $dbgResult='NEEDS_REVERIFY_NO_DEBUGGEE_OR_DEAD'
}

$alive=[int](-not $p.HasExited -and [C2L]::IsWindow($main))
$a4f=(Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe' -Algorithm SHA256).Hash
$cc79=(Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash

$four = 'FAIL_CLOSED'
if($panelVis -eq 1 -and $problemsVisible -and $outOk -and $selTerm -and $selOut -and $selProb -and $selDbg){
  if($dbgSession -eq 1){ $four='PASS' } else { $four='PARTIAL_PANEL_VISIBLE_DEBUG_'+$dbgResult }
}

@"
PROBLEMS_CLICK_TO_LINE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA256=$sha
TIP_EXE=$TipExe
FIXTURE=$BrokenCpp
PROBLEMS_VISIBLE=$([int]$problemsVisible)
PROBLEMS_ID1312_ITEMS=$id1312
OUTPUT_ID1604_LEN=$id1604
EXPECT_LINES=3,4,5
NAV_ITEM0_LINE=$($nav[0])
NAV_ITEM1_LINE=$($nav[1])
NAV_ITEM2_LINE=$($nav[2])
NAV_ITEM0_PASS=$([int]$navPass[0])
NAV_ITEM1_PASS=$([int]$navPass[1])
NAV_ITEM2_PASS=$([int]$navPass[2])
CLICK_TO_LINE=$clickVerdict
SELECT_PANEL_TERMINAL0=$selTerm
SELECT_PANEL_OUTPUT1=$selOut
SELECT_PANEL_PROBLEMS2=$selProb
SELECT_PANEL_DEBUG3=$selDbg
PANEL_CONTAINER_VISIBLE=$panelVis
TERMINAL_CLEAR_CMD=$termCmd
GUI_OUTPUT_OK=$([int]$outOk)
DEBUG_SESSION_RECONFIRM=$dbgResult
DEBUG_VARS_ID6043=$dbgVars
FOUR_PANEL_BRIEF=$four
ALIVE=$alive
SCREENSHOT_ALONE_NOT_AUTHORITY=1
A4F_UNTOUCHED=$([int]($a4f -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))
CC79_UNTOUCHED=$([int]($cc79 -eq 'CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4'))
NO_CROSS_SHA_PASS_INHERITANCE=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
"@ | Set-Content $receipt
Get-Content $receipt
try{if(-not $p.HasExited){Stop-Process -Id $p.Id -Force -EA SilentlyContinue}}catch{}
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
exit $(if($clickVerdict -eq 'PASS'){0}else{4})

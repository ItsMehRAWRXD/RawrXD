#Requires -Version 5.1
param(
  [string]$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_daily_items710_001\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$ExpectSha = '9FDEBF0947AC855619E2CC0A44A40AD6590C4BD680D6FFC4B46D4EF54A266D85',
  [string]$OutRoot = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\p0_createwindow_fix'
)
$ErrorActionPreference = 'Continue'
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectSha) { Write-Host "SHA_DRIFT $sha"; exit 9 }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ud = Join-Path $OutRoot "ud_surv_$stamp"
$receipt = Join-Path $OutRoot "DOCK_SURVIVE_$stamp.txt"
New-Item -ItemType Directory -Force -Path $ud, (Join-Path $ud 'logs') | Out-Null

Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public class DockSurv {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetDC(IntPtr h);
  [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr h, IntPtr hdc);
  [DllImport("gdi32.dll")] public static extern uint GetPixel(IntPtr hdc, int x, int y);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int cx, int cy, bool r);
  [DllImport("user32.dll")] public static extern uint GetSysColor(int i);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  public const int GWL_ID=-12;
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true;
      var cls=new StringBuilder(256); GetClassNameW(h,cls,256);
      if(cls.ToString()=="RawrXD_IDE_Window"){ found=h; return false;} return true; }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr via=GetDlgItem(parent,id); if(via!=IntPtr.Zero) return via;
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,GWL_ID)==id){ found=h; return false;} return true;}, IntPtr.Zero);
    return found;
  }
  public static string SizeOf(IntPtr h){ RECT r; GetClientRect(h,out r); return (r.R-r.L)+"x"+(r.B-r.T); }
  public static uint SamplePoint(IntPtr h,int x,int y){ IntPtr hdc=GetDC(h); uint pix=GetPixel(hdc,x,y); ReleaseDC(h,hdc); return pix; }
}
'@ -Language CSharp

$env:RAWRXD_USER_DATA_DIR=$ud
$env:RAWRXD_LOG_DIR=(Join-Path $ud 'logs')
# Normal (not Minimized): iconic clients previously collapsed dock 1300 to 24px.
$p = Start-Process -FilePath $TipExe -ArgumentList @("--user-data-dir=$ud") -PassThru -WindowStyle Normal
$hwnd=[IntPtr]::Zero
$timeline=@()
for($i=0;$i -lt 60;$i++){
  Start-Sleep -Milliseconds 250
  $p.Refresh()
  $alive = -not $p.HasExited
  if($alive){ $hwnd=[DockSurv]::FindMain([uint32]$p.Id) }
  $timeline += "t=$i alive=$alive exit=$(if($p.HasExited){$p.ExitCode}else{'-'}) hwnd=$hwnd"
  if($p.HasExited){ break }
  if($hwnd -ne [IntPtr]::Zero -and $i -ge 24){ break }
}
try { $p.Refresh() } catch {}
$L=New-Object System.Collections.Generic.List[string]
$L.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))")
$L.Add('GATE=DOCK_SURVIVE_MEASURE')
$L.Add("IDE_SHA256=$sha")
$L.Add("TIP_EXE=$TipExe")
$L.Add("USER_DATA_DIR=$ud")
$L.Add("PID=$($p.Id)")
$L.Add("MAIN_HWND=$hwnd")
$L.Add('PROMOTE=0'); $L.Add('CERTIFIED=0'); $L.Add('INVENT_PASS=0'); $L.Add('NO_CROSS_SHA=1'); $L.Add('PRESENT=1'); $L.Add('ACCEPTED=0')
foreach($t in $timeline){ $L.Add("TL_$t") }

if(-not $p.HasExited -and $hwnd -ne [IntPtr]::Zero){
  [void][DockSurv]::ShowWindow($hwnd,9)
  [void][DockSurv]::SetForegroundWindow($hwnd)
  [void][DockSurv]::MoveWindow($hwnd,50,50,1500,950,$true)
  Start-Sleep 1
  [void][DockSurv]::PostMessageW($hwnd,0x0111,[IntPtr]2034,[IntPtr]::Zero)
  Start-Sleep 1
  [void][DockSurv]::PostMessageW($hwnd,0x0005,[IntPtr]0,[IntPtr]((900 -shl 16) -bor 1480))
  Start-Sleep 2
  $p.Refresh()
  $colorWindow=[DockSurv]::GetSysColor(5)
  $dock=[DockSurv]::FindChildById($hwnd,1300)
  $tabs=[DockSurv]::FindChildById($hwnd,1301)
  $plist=[DockSurv]::FindChildById($hwnd,1312)
  $ps=[DockSurv]::FindChildById($hwnd,5600)
  $dockSz=if($dock -ne [IntPtr]::Zero){[DockSurv]::SizeOf($dock)}else{'0x0'}
  $dockVis=($dock -ne [IntPtr]::Zero) -and [DockSurv]::IsWindowVisible($dock)
  $L.Add(('COLOR_WINDOW_SYS=0x{0:X6}' -f $colorWindow))
  $L.Add("DOCK_PRESENT=$($dock -ne [IntPtr]::Zero)"); $L.Add("DOCK_VISIBLE=$dockVis"); $L.Add("DOCK_SIZE=$dockSz")
  $themePass=$false; $themeNote='NO_DOCK'
  if($dock -ne [IntPtr]::Zero){
    # Sample dock BODY below 24px tab strip (y=12 hits SysTabControl face gray).
    $pix=[DockSurv]::SamplePoint($dock,10,40)
    $r=$pix -band 0xFF; $g=($pix -shr 8)-band 0xFF; $b=($pix -shr 16)-band 0xFF
    $sysR=$colorWindow -band 0xFF; $sysG=($colorWindow -shr 8)-band 0xFF; $sysB=($colorWindow -shr 16)-band 0xFF
    $isSys=($r -eq $sysR -and $g -eq $sysG -and $b -eq $sysB)
    $luma=0.299*$r+0.587*$g+0.114*$b
    $themePass=(-not $isSys) -and ($luma -lt 80)
    $themeNote=('pix=0x{0:X6} rgb={1},{2},{3} luma={4:N1} isSysGray={5}' -f $pix,$r,$g,$b,$luma,$isSys)
  }
  $L.Add("DOCK_PIXEL=$themeNote"); $L.Add("DOCK_THEME_NOT_SYS_GRAY=$themePass")
  $dockH=0; if($dockSz -match 'x(\d+)$'){$dockH=[int]$Matches[1]}
  $L.Add("DOCK_HEIGHT=$dockH"); $L.Add("DOCK_HEIGHT_GE_160=$($dockH -ge 160)")
  $tabOk=$false; $tabNote='NO_TABS'
  if($tabs -ne [IntPtr]::Zero){
    $sels=@(); foreach($sel in @(0,2,1,0)){ [void][DockSurv]::SendMessageW($tabs,0x130C,[IntPtr]$sel,[IntPtr]::Zero); Start-Sleep -Milliseconds 200; $sels+=[DockSurv]::SendMessageW($tabs,0x130B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32() }
    $tabOk=($sels -contains 0) -and ($sels -contains 2) -and ($sels -contains 1); $tabNote='sels='+($sels -join ',')
  }
  $L.Add("TABS_CLICKABLE=$tabOk"); $L.Add("TABS_NOTE=$tabNote")
  if($tabs -ne [IntPtr]::Zero){ [void][DockSurv]::SendMessageW($tabs,0x130C,[IntPtr]2,[IntPtr]::Zero); Start-Sleep -Milliseconds 300 }
  $plist=[DockSurv]::FindChildById($hwnd,1312)
  $L.Add("PROBLEMS_1312_PRESENT=$($plist -ne [IntPtr]::Zero)")
  $L.Add("PROBLEMS_1312_VISIBLE=$(if($plist -ne [IntPtr]::Zero){[DockSurv]::IsWindowVisible($plist)}else{$false})")
  $L.Add("POWERSHELL_5600_PRESENT=$($ps -ne [IntPtr]::Zero)")
  $L.Add("POWERSHELL_5600_VISIBLE=$(if($ps -ne [IntPtr]::Zero){[DockSurv]::IsWindowVisible($ps)}else{$false})")
  $p.Refresh(); $L.Add("PROCESS_ALIVE_AFTER_LAYOUT=$(-not $p.HasExited)")
  $layoutPass=$dockVis -and ($dockH -ge 160)
  $L.Add("THEME_VERDICT=$(if($themePass){'THEME_PASS'}else{'THEME_FAIL'})")
  $L.Add("LAYOUT_VERDICT=$(if($layoutPass){'LAYOUT_PASS'}elseif($dockVis){'LAYOUT_COLLAPSED_LT_160'}else{'LAYOUT_FAIL'})")
  $L.Add("TABS_VERDICT=$(if($tabOk){'TABS_PASS'}else{'TABS_FAIL'})")
  $overall=if($themePass -and $layoutPass -and $tabOk){'DOCK_THEME_LAYOUT_PASS'}elseif($themePass -and $tabOk -and $dockVis){'DOCK_THEME_PASS_LAYOUT_COLLAPSED'}else{'DOCK_PROBE_PARTIAL_OR_FAIL'}
  $L.Add("VERDICT=$overall")
  try{ $p.CloseMainWindow()|Out-Null; $null=$p.WaitForExit(8000)}catch{}
  if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
} else {
  $L.Add("EXIT_CODE=$(if($p.HasExited){$p.ExitCode}else{'ALIVE'})")
  $L.Add('VERDICT=DOCK_PROBE_FAIL')
}
$L | Set-Content $receipt -Encoding UTF8
Write-Host "RECEIPT=$receipt"
Get-Content $receipt

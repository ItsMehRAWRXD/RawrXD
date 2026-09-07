$ErrorActionPreference = "Stop"
Get-Process RawrXD-Win32IDE -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Seconds 1
$bin = "F:\~dev\rawrxd\build-win32ide-fresh\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$want = "366AC1A8CAD29C90B5622B2EAF38EF47A36779013C4B0BC2F76E1F5E11DAE924"
$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
if ($sha -ne $want) { throw "SHA_DRIFT $sha" }
Write-Host "EXE_SHA=$sha PHASE=4"
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
using System.Collections.Generic;
public class P4C {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hh, bool repaint);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool ScreenToClient(IntPtr h, ref POINT pt);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int left, top, right, bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int x, y; }
  const int GWL_STYLE=-16; const int WS_VISIBLE=0x10000000;
  static int s_ds;
  public static IntPtr FindMain(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid)return true;
      var sb=new StringBuilder(256); GetClassName(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_MainWindow"){ found=h; return false;} return true; }, IntPtr.Zero);
    return found;
  }
  public static List<string> List(IntPtr main) {
    var list=new List<string>(); s_ds=0;
    EnumChildWindows(main,(h,l)=>{
      if(GetParent(h)!=main) return true;
      if((GetWindowLong(h,GWL_STYLE)&WS_VISIBLE)==0) return true;
      s_ds++;
      var sb=new StringBuilder(64); GetClassName(h,sb,64);
      var title=new StringBuilder(64); GetWindowText(h,title,64);
      RECT wr; GetWindowRect(h,out wr);
      POINT pt=new POINT{x=wr.left,y=wr.top}; ScreenToClient(main,ref pt);
      list.Add(string.Format("cls={0} title={1} id={2} {3}x{4} rel=({5},{6})",
        sb,title,GetDlgCtrlID(h),wr.right-wr.left,wr.bottom-wr.top,pt.x,pt.y));
      return true;
    },IntPtr.Zero);
    return list;
  }
  public static int DS(){return s_ds;}
  public static void SysCmd(IntPtr h,int cmd){ SendMessage(h,0x0112,(IntPtr)cmd,IntPtr.Zero); }
  public static bool Smoke(IntPtr main, int expectDirect, out string detail) {
    detail="";
    RECT r; GetWindowRect(main,out r);
    MoveWindow(main,r.left,r.top, Math.Max(500,(r.right-r.left)-160), Math.Max(400,(r.bottom-r.top)-80), true);
    System.Threading.Thread.Sleep(1500);
    List(main); if(s_ds!=expectDirect){ detail="RESIZE_DIRECT="+s_ds; return false; }
    SysCmd(main,0xF030); System.Threading.Thread.Sleep(1500);
    List(main); if(s_ds!=expectDirect){ detail="MAX_DIRECT="+s_ds; return false; }
    SysCmd(main,0xF120); System.Threading.Thread.Sleep(1500);
    List(main); if(s_ds!=expectDirect){ detail="RESTORE_DIRECT="+s_ds; return false; }
    SysCmd(main,0xF020); System.Threading.Thread.Sleep(1000);
    SysCmd(main,0xF120); System.Threading.Thread.Sleep(2000);
    if(!IsWindowVisible(main)) ShowWindow(main,5);
    System.Threading.Thread.Sleep(1000);
    List(main); if(s_ds!=expectDirect || !IsWindowVisible(main)){ detail="MINRESTORE_DIRECT="+s_ds; return false; }
    detail="OK"; return true;
  }
}
"@
$env:RAWRXD_SHELL_LAYOUT_REBUILD="1"
$env:RAWRXD_SHELL_LAYOUT_PHASE="4"
$p = Start-Process -FilePath $ide -WorkingDirectory $bin -PassThru
$main=[IntPtr]::Zero
for($i=0;$i -lt 90;$i++){
  Start-Sleep -Seconds 1
  if($p.HasExited){ throw "LAUNCH_EXIT" }
  $main=[P4C]::FindMain([uint32]$p.Id)
  if($main -ne [IntPtr]::Zero -and [P4C]::IsWindowVisible($main)){ break }
}
if($main -eq [IntPtr]::Zero){ throw "NO_MAIN" }
Write-Host "LAUNCH=PASS"
Start-Sleep -Seconds 10
$kids=[P4C]::List($main)
$n=[P4C]::DS()
Write-Host "SETTLED direct=$n"
$kids | ForEach-Object { Write-Host "  $_" }
$hasSt = $false; $hasEd = $false
foreach($k in $kids){
  if($k -match 'msctls_statusbar' -or $k -match 'id=1004'){ $hasSt=$true }
  if($k -match 'id=1001'){ $hasEd=$true }
}
Write-Host "EDITOR=$(if($hasEd){'PASS'}else{'FAIL'}) STATUS=$(if($hasSt){'PASS'}else{'FAIL'})"
$detail=""
$sticky=[P4C]::Smoke($main, $n, [ref]$detail)
Write-Host "STICKY_AT_N=$n $(if($sticky){'PASS'}else{'FAIL'}) detail=$detail"
$strict = ($n -eq 4 -and $hasEd -and $hasSt -and $sticky -and (-not $p.HasExited))
Write-Host "PHASE4_VERDICT=$(if($strict){'PASS'}else{'FAIL'})"
Stop-Process -Id $p.Id -Force -EA SilentlyContinue
if(-not $strict){ exit 1 }

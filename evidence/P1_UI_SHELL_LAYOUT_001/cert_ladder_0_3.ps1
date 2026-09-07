$ErrorActionPreference = 'Stop'
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$bin = "F:\~dev\rawrxd\build-win32ide-fresh\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
Write-Host "CANDIDATE_SHA=$sha"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
using System.Collections.Generic;
public class LadderCertFinal {
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

function Run-Phase([int]$phase, [int]$expect) {
  Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
  $now = (Get-FileHash $ide -Algorithm SHA256).Hash
  if ($now -ne $sha) { return @{ pass = $false; why = "SHA_DRIFT" } }
  $env:RAWRXD_SHELL_LAYOUT_REBUILD = "1"
  $env:RAWRXD_SHELL_LAYOUT_PHASE = "$phase"
  $p = Start-Process -FilePath $ide -WorkingDirectory $bin -PassThru
  $main = [IntPtr]::Zero
  for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 1
    if ($p.HasExited) { return @{ pass = $false; why = "LAUNCH_EXIT" } }
    $main = [LadderCertFinal]::FindMain([uint32]$p.Id)
    if ($main -ne [IntPtr]::Zero -and [LadderCertFinal]::IsWindowVisible($main)) { break }
  }
  if ($main -eq [IntPtr]::Zero -or -not [LadderCertFinal]::IsWindowVisible($main)) {
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
    return @{ pass = $false; why = "NO_MAIN" }
  }
  Start-Sleep -Seconds 10
  $kids = [LadderCertFinal]::List($main)
  $n = [LadderCertFinal]::DS()
  Write-Host "PHASE=$phase SETTLED direct=$n"
  $kids | ForEach-Object { Write-Host "  $_" }
  if ($n -ne $expect) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    return @{ pass = $false; why = "DIRECT=$n expect=$expect" }
  }
  if ($phase -ge 3) {
    $hasEd = $false
    foreach ($k in $kids) {
      if ($k -match 'id=1001' -and $k -match '(\d+)x(\d+)' -and [int]$Matches[1] -ge 200 -and [int]$Matches[2] -ge 200) {
        $hasEd = $true
      }
    }
    if (-not $hasEd) {
      Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
      return @{ pass = $false; why = "NO_EDITOR_1001" }
    }
  }
  $detail = ""
  $sticky = [LadderCertFinal]::Smoke($main, $expect, [ref]$detail)
  $alive = (-not $p.HasExited)
  Write-Host "PHASE=$phase STICKY=$(if($sticky){'PASS'}else{'FAIL'}) ALIVE=$alive detail=$detail"
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  $ok = $sticky -and $alive
  return @{ pass = $ok; why = $(if (-not $sticky) { $detail } elseif (-not $alive) { 'DIED' } else { 'PASS' }) }
}

foreach ($ph in 0, 1, 2, 3) {
  Write-Host "==== PHASE $ph ===="
  $r = Run-Phase $ph $ph
  Write-Host "PHASE${ph}_VERDICT=$(if($r.pass){'PASS'}else{'FAIL'}) WHY=$($r.why)"
  if (-not $r.pass) { exit 1 }
}
Write-Host "LADDER_0_1_2_3=PASS SHA=$sha"
exit 0

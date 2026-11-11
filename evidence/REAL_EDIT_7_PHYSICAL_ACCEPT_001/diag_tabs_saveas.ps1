#Requires -Version 5.1
$ErrorActionPreference = 'Continue'
$TipExe = 'F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe'
$WorkDir = 'F:\rawrxd\evidence\REAL_EDIT_7_PHYSICAL_ACCEPT_001\workdir_07_15'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Diag715 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C;
  public const uint BM_CLICK=0x00F5; public const uint TCM_GETITEMCOUNT=0x132C;
  public const int IDC_EDITOR=1001;
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public static string ClassName(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string Title(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p==pid && ClassName(h)=="RawrXD_IDE_Window"){f=h;return false;} return true;}, IntPtr.Zero); return f; }
  public static void EnumTabs(IntPtr root){
    EnumChildWindows(root,(h,l)=>{
      string cls=ClassName(h);
      if(cls.IndexOf("SysTabControl", StringComparison.OrdinalIgnoreCase)>=0){
        RECT r; GetWindowRect(h,out r);
        int id=GetDlgCtrlID(h);
        int n=SendMessageW(h,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
        Console.WriteLine(string.Format("TAB hwnd=0x{0:X} id={1} class={2} count={3} rect=({4},{5})-({6},{7}) vis={8}",
          h.ToInt64(), id, cls, n, r.L, r.T, r.R, r.B, IsWindowVisible(h)));
      }
      EnumChildWindows(h,(c,q)=>{
        string c2=ClassName(c);
        if(c2.IndexOf("SysTabControl", StringComparison.OrdinalIgnoreCase)>=0){
          RECT r; GetWindowRect(c,out r);
          int id=GetDlgCtrlID(c);
          int n=SendMessageW(c,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
          Console.WriteLine(string.Format("  NESTTAB hwnd=0x{0:X} id={1} class={2} count={3} rect=({4},{5})-({6},{7})",
            c.ToInt64(), id, c2, n, r.L, r.T, r.R, r.B));
        }
        return true;
      }, IntPtr.Zero);
      return true;
    }, IntPtr.Zero);
  }
  public static IntPtr FindEditor(IntPtr root){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,l)=>{ if(GetDlgCtrlID(h)==IDC_EDITOR){ f=h; return false; } return true; },IntPtr.Zero);
    return f;
  }
  public static IntPtr FindDlg(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p==pid && ClassName(h)=="#32770" && IsWindowVisible(h)){ f=h; return false;} return true;},IntPtr.Zero);
    return f;
  }
  public static bool Drive(IntPtr dlg, string path){
    IntPtr edit=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{
      string cls=ClassName(h); int id=GetDlgCtrlID(h);
      if((cls=="Edit"||cls.StartsWith("RichEdit")) && (id==0x47C||id==0x480)){ edit=h; return false; }
      return true;
    },IntPtr.Zero);
    if(edit==IntPtr.Zero){
      EnumChildWindows(dlg,(h,l)=>{
        if(ClassName(h)=="ComboBoxEx32"){
          EnumChildWindows(h,(c,q)=>{ if(ClassName(c)=="Edit"){ edit=c; return false;} return true;},IntPtr.Zero);
          return edit==IntPtr.Zero;
        }
        return true;
      },IntPtr.Zero);
    }
    if(edit==IntPtr.Zero){ Console.WriteLine("NO_EDIT"); return false; }
    SetWindowTextW(edit, path);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, path);
    IntPtr ok=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ if(GetDlgCtrlID(h)==1 && ClassName(h)=="Button"){ ok=h; return false;} return true;},IntPtr.Zero);
    Console.WriteLine(string.Format("edit=0x{0:X} ok=0x{1:X}", edit.ToInt64(), ok.ToInt64()));
    if(ok!=IntPtr.Zero){ SendMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero); return true; }
    PostMessageW(dlg, WM_COMMAND, (IntPtr)1, IntPtr.Zero); return true;
  }
}
'@

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) -PassThru
Write-Host "pid=$($p.Id)"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 40; $i++) {
  $main = [Diag715]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
Write-Host ("main=0x{0:X}" -f $main.ToInt64())
Write-Host '--- TABS AT START ---'
[Diag715]::EnumTabs($main)

$utf8 = [Text.UTF8Encoding]::new($false)
for ($i=0; $i -lt 3; $i++) {
  $fp = Join-Path $WorkDir ("diag_tab_$i.txt")
  [IO.File]::WriteAllText($fp, "diag_$i", $utf8)
  [Diag715]::PostMessageW($main, 0x0111, [IntPtr]2002, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $dlg = [Diag715]::FindDlg([uint32]$p.Id)
  Write-Host ("open i=$i dlg=0x{0:X} title='{1}'" -f $(if($dlg -ne [IntPtr]::Zero){$dlg.ToInt64()}else{0}), $(if($dlg -ne [IntPtr]::Zero){[Diag715]::Title($dlg)}else{''}))
  if ($dlg -ne [IntPtr]::Zero) {
    $t = [Diag715]::Title($dlg)
    if ($t -eq 'Save' -or $t -eq 'Unsaved Changes') {
      [Diag715]::PostMessageW($dlg, 0x0111, [IntPtr]7, [IntPtr]::Zero)
      Start-Sleep -Milliseconds 400
      $dlg = [Diag715]::FindDlg([uint32]$p.Id)
    }
    [void][Diag715]::Drive($dlg, $fp)
    Start-Sleep -Seconds 1
    $still = [Diag715]::FindDlg([uint32]$p.Id)
    if ($still -ne [IntPtr]::Zero) {
      Write-Host ("still dlg title='{0}'" -f [Diag715]::Title($still))
    }
  }
  Write-Host ("title now='{0}'" -f [Diag715]::Title($main))
  Write-Host '--- TABS ---'
  [Diag715]::EnumTabs($main)
}

$ed = [Diag715]::FindEditor($main)
$cjk = Join-Path $WorkDir 'diag_cjk.txt'
Remove-Item $cjk -Force -ErrorAction SilentlyContinue
[Diag715]::SendMessageW($ed, 0x00B1, [IntPtr]::Zero, [IntPtr](-1))
[Diag715]::SendMessageW($ed, 0x00C2, [IntPtr]1, "你好 🎉 emoji-test")
Start-Sleep -Milliseconds 300
[Diag715]::PostMessageW($main, 0x0111, [IntPtr]2004, [IntPtr]::Zero)
Start-Sleep -Milliseconds 600
$dlg = [Diag715]::FindDlg([uint32]$p.Id)
Write-Host ("saveas dlg=0x{0:X} title='{1}'" -f $(if($dlg -ne [IntPtr]::Zero){$dlg.ToInt64()}else{0}), $(if($dlg -ne [IntPtr]::Zero){[Diag715]::Title($dlg)}else{''}))
if ($dlg -ne [IntPtr]::Zero) {
  [void][Diag715]::Drive($dlg, $cjk)
  Start-Sleep -Seconds 2
  $still = [Diag715]::FindDlg([uint32]$p.Id)
  Write-Host ("after saveas still=0x{0:X} exists={1}" -f $(if($still -ne [IntPtr]::Zero){$still.ToInt64()}else{0}), (Test-Path $cjk))
  if ($still -ne [IntPtr]::Zero) { Write-Host ("still title='{0}'" -f [Diag715]::Title($still)) }
  if (Test-Path $cjk) {
    $b = [IO.File]::ReadAllBytes($cjk)
    Write-Host ("cjk bytes: " + (($b | ForEach-Object { $_.ToString('X2') }) -join ' '))
  }
}

Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Write-Host DONE

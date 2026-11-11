#Requires -Version 5.1
$ErrorActionPreference='Continue'
$TipExe='F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe'
$WorkDir='F:\rawrxd\evidence\REAL_EDIT_7_PHYSICAL_ACCEPT_001\workdir'
New-Item -ItemType Directory -Force -Path $WorkDir|Out-Null
$SessionJson=Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
if(Test-Path $SessionJson){Remove-Item $SessionJson -Force}

Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class D2 {
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
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C; public const uint WM_CLOSE=0x0010; public const uint BM_CLICK=0x00F5;
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra; }
  public static string CN(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TT(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr Main(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{uint p;GetWindowThreadProcessId(h,out p); if(p==pid&&CN(h)=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr Dlg(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{uint p;GetWindowThreadProcessId(h,out p); if(p==pid&&CN(h)=="#32770"&&IsWindowVisible(h)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr Editor(IntPtr root){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,l)=>{ if(GetDlgCtrlID(h)==1001){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static void Enter(){ var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x0D; i[1].type=1; i[1].ki.wVk=0x0D; i[1].ki.dwFlags=2; SendInput(2,i,Marshal.SizeOf(typeof(INPUT))); }
  public static bool DriveEnter(IntPtr dlg, string path){
    IntPtr edit=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ string c=CN(h); int id=GetDlgCtrlID(h); if((c=="Edit"||c.StartsWith("RichEdit"))&&(id==0x47C||id==0x480)){edit=h;return false;} return true;},IntPtr.Zero);
    if(edit==IntPtr.Zero){ EnumChildWindows(dlg,(h,l)=>{ if(CN(h)=="ComboBoxEx32"){ EnumChildWindows(h,(c,q)=>{ if(CN(c)=="Edit"){edit=c;return false;} return true;},IntPtr.Zero); return edit==IntPtr.Zero;} return true;},IntPtr.Zero); }
    if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg);
    SetWindowTextW(edit, path);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, path);
    System.Threading.Thread.Sleep(200);
    Enter();
    return true;
  }
}
'@

Get-Process|?{$_.ProcessName -like 'RawrXD-Win32IDE*'}|Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$p=Start-Process $TipExe -WorkingDirectory (Split-Path $TipExe) -PassThru
$main=[IntPtr]::Zero
for($i=0;$i -lt 40;$i++){ $main=[D2]::Main([uint32]$p.Id); if($main -ne [IntPtr]::Zero){break}; Start-Sleep -Milliseconds 250 }
Write-Host "main ok pid=$($p.Id)"
$utf8=[Text.UTF8Encoding]::new($false)
for($i=0;$i -lt 3;$i++){
  $fp=Join-Path $WorkDir "d2_$i.txt"
  [IO.File]::WriteAllText($fp,"seed$i marker_D2_$i",$utf8)
  [D2]::PostMessageW($main,0x0111,[IntPtr]2002,[IntPtr]::Zero)
  Start-Sleep 500
  $d=[D2]::Dlg([uint32]$p.Id)
  if($d -ne [IntPtr]::Zero -and ([D2]::TT($d) -eq 'Save' -or [D2]::TT($d) -eq 'Unsaved Changes')){ [D2]::PostMessageW($d,0x0111,[IntPtr]7,[IntPtr]::Zero); Start-Sleep 400; $d=[D2]::Dlg([uint32]$p.Id) }
  if($d -ne [IntPtr]::Zero){ [void][D2]::DriveEnter($d,$fp); Start-Sleep 1 }
  Write-Host ("opened $i title=" + [D2]::TT($main))
}
# edit markers into current then try switch via notify indices 0..2
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class TabN {
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  public static IntPtr Tabs(IntPtr root){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,l)=>{ if(GetDlgCtrlID(h)==1030){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static void Sel(IntPtr main, IntPtr tabs, int idx){
    SendMessageW(tabs,0x130C,(IntPtr)idx,IntPtr.Zero);
    NMHDR nm; nm.hwndFrom=tabs; nm.idFrom=(IntPtr)1030; nm.code=-551;
    IntPtr p=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NMHDR)));
    Marshal.StructureToPtr(nm,p,false);
    SendMessageW(main,0x004E,(IntPtr)1030,p);
    Marshal.FreeHGlobal(p);
  }
}
'@ -ErrorAction SilentlyContinue

# Save As with Enter
$ed=[D2]::Editor($main)
$cjk=Join-Path $WorkDir 'd2_cjk.txt'
Remove-Item $cjk -Force -EA SilentlyContinue
[D2]::SendMessageW($ed,0x00B1,[IntPtr]::Zero,[IntPtr](-1))
[D2]::SendMessageW($ed,0x00C2,[IntPtr]1,"你好 🎉 emoji-test")
Start-Sleep 300
[D2]::PostMessageW($main,0x0111,[IntPtr]2004,[IntPtr]::Zero)
Start-Sleep 600
$d=[D2]::Dlg([uint32]$p.Id)
Write-Host ("saveas title=" + $(if($d -ne [IntPtr]::Zero){[D2]::TT($d)}else{'none'}))
if($d -ne [IntPtr]::Zero){ [void][D2]::DriveEnter($d,$cjk); Start-Sleep 2 }
Write-Host ("cjk exists=" + (Test-Path $cjk))
if(Test-Path $cjk){ $b=[IO.File]::ReadAllBytes($cjk); Write-Host ("bytes=" + (($b|%{$_.ToString('X2')}) -join ' ')) }

# Graceful close for session
[D2]::PostMessageW($main,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)
Start-Sleep 500
$d=[D2]::Dlg([uint32]$p.Id)
if($d -ne [IntPtr]::Zero){ Write-Host ("close prompt "+[D2]::TT($d)); [D2]::PostMessageW($d,0x0111,[IntPtr]7,[IntPtr]::Zero) }
[void]$p.WaitForExit(10000)
Start-Sleep 1
if(Test-Path $SessionJson){
  $j=Get-Content $SessionJson -Raw -Encoding UTF8 | ConvertFrom-Json
  Write-Host ("session docs=$($j.documents.Count) active=$($j.active)")
  $j.documents | ForEach-Object { Write-Host ("  path=$($_.path) mod=$($_.modified) textlen=$($_.text.Length)") }
} else { Write-Host 'NO_SESSION' }
Write-Host DONE

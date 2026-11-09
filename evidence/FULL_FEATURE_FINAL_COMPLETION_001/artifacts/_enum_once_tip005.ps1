# Single EnumWindows pass by PID. No loops, no WMI.
$ErrorActionPreference = 'Continue'
$Out = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ENUM_ONCE_TIP005.txt'
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class EnumOnce {
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static List<string> ForPid(uint want) {
    var list = new List<string>();
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=want) return true;
      var c=new StringBuilder(256); var t=new StringBuilder(512);
      GetClassNameW(h,c,256); GetWindowTextW(h,t,512);
      list.Add(string.Format("HWND=0x{0:X} CLS={1} TITLE={2} VIS={3}", h.ToInt64(), c, t, IsWindowVisible(h)));
      return true; }, IntPtr.Zero);
    return list;
  }
}
"@
$procs = Get-Process -Name 'RawrXD-Win32IDE-Native-Ext' -EA SilentlyContinue
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("ASOF=$((Get-Date).ToString('o'))")
$lines.Add("PROC_COUNT=$((@($procs)).Count)")
foreach ($p in @($procs)) {
  $lines.Add("PID=$($p.Id) WS=$($p.WorkingSet64) RESPONDING=$($p.Responding) MAINWINDOWHANDLE=0x$('{0:X}' -f $p.MainWindowHandle.ToInt64())")
  try {
    $wins = [EnumOnce]::ForPid([uint32]$p.Id)
    $lines.Add("TOPLEVEL_COUNT=$($wins.Count)")
    foreach ($w in $wins) { $lines.Add($w) }
  } catch {
    $lines.Add("ENUM_ERR=$($_.Exception.Message)")
  }
}
$lines | Set-Content -LiteralPath $Out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }

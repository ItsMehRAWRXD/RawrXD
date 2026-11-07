$ErrorActionPreference='Stop'
$exe='F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$expected='70E6B1700F8EDF7A3770F63A5B89565AB05798CAB4B8DFC784200153B786F9DA'
Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class W { public delegate bool E(IntPtr h,IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumWindows(E e,IntPtr p);
[DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,E e,IntPtr p);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
[DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h,StringBuilder s,int n);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
[DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
[DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out R r);
[DllImport("user32.dll")] public static extern IntPtr GetFocus();
[StructLayout(LayoutKind.Sequential)] public struct R { public int l,t,r,b; }
public static string C(IntPtr h){var s=new StringBuilder(128);GetClassNameW(h,s,s.Capacity);return s.ToString();}
}
'@
if((Get-FileHash $exe -Algorithm SHA256).Hash -ne $expected){throw 'SHA mismatch'}
if(@(Get-Process -Name RawrXD-Win32IDE-Native -ErrorAction SilentlyContinue).Count){throw 'active IDE exists'}
$p=Start-Process $exe -WorkingDirectory (Split-Path $exe) -PassThru
try { $until=(Get-Date).AddSeconds(20); while(!$p.HasExited -and (Get-Date)-lt $until){$p.Refresh();if($p.MainWindowHandle -ne 0){break};Start-Sleep -Milliseconds 100}; if($p.HasExited){throw "exit $($p.ExitCode)"}; $root=$p.MainWindowHandle; $rows=[Collections.Generic.List[object]]::new();
  [W]::EnumChildWindows($root,{param($h,$x);$r=New-Object W+R;[W]::GetWindowRect($h,[ref]$r)|Out-Null;$rows.Add([pscustomobject]@{HWND=('0x{0:X}' -f $h.ToInt64());Class=[W]::C($h);Visible=[W]::IsWindowVisible($h);Enabled=[W]::IsWindowEnabled($h);Rect="$($r.l),$($r.t),$($r.r),$($r.b)";Focus=([W]::GetFocus() -eq $h)});$true},[IntPtr]::Zero)|Out-Null
  [pscustomobject]@{ROOT=('0x{0:X}' -f $root.ToInt64());PID=$p.Id;Children=$rows}|ConvertTo-Json -Depth 5
} finally {if($p -and !$p.HasExited){$p.CloseMainWindow()|Out-Null;if(!$p.WaitForExit(5000)){Stop-Process $p.Id -Force}}}

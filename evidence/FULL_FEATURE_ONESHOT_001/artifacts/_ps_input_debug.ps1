$ErrorActionPreference='Continue'
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class PsFix {
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Ansi)] public static extern bool SetWindowTextA(IntPtr h, string t);
  [DllImport("user32.dll",CharSet=CharSet.Ansi)] public static extern int GetWindowTextA(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity); string c=sb.ToString(); if(c.Contains("RawrXD_IDE")){f=h;return false;} if(f==IntPtr.Zero)f=h; return true;},IntPtr.Zero); return f; }
}
"@
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$exe='F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001\RawrXD-Win32IDE-Native-Ext.exe'
$logdir='F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001'
$env:RAWRXD_LOG_DIR=$logdir
if (Test-Path "$logdir\ps_trace.log") { Remove-Item "$logdir\ps_trace.log" -Force }
$p=Start-Process $exe -WorkingDirectory (Split-Path $exe) -PassThru
$main=[IntPtr]::Zero
for($i=0;$i -lt 40;$i++){ Start-Sleep -Milliseconds 250; try{$p.Refresh()}catch{}; if($p.MainWindowHandle -ne 0){$main=[IntPtr]$p.MainWindowHandle; break}; $main=[PsFix]::FindMain([uint32]$p.Id); if($main -ne [IntPtr]::Zero){break}}
Write-Output "MAIN=0x$('{0:X}' -f $main.ToInt64())"
$inputs=@()
$panel=[IntPtr]::Zero
$exec=[IntPtr]::Zero
[PsFix]::EnumChildWindows($main, {
  param($h,$lp)
  $id=[PsFix]::GetDlgCtrlID($h)
  if ($id -eq 5002) {
    $sb=New-Object System.Text.StringBuilder 64
    [void][PsFix]::GetClassNameW($h,$sb,$sb.Capacity)
    $parent=[PsFix]::GetParent($h)
    Write-Output ("FOUND5002 hwnd=0x{0:X} cls={1} parent=0x{2:X}" -f $h.ToInt64(),$sb.ToString(),$parent.ToInt64())
    $script:inputs += $h
  }
  if ($id -eq 5000) { $script:panel=$h }
  if ($id -eq 5010) { $script:exec=$h }
  return $true
}, [IntPtr]::Zero) | Out-Null
foreach($h in $inputs){
  [void][PsFix]::SetWindowTextA($h, 'Get-ChildItem')
}
Start-Sleep -Milliseconds 300
foreach($h in $inputs){
  $t=New-Object System.Text.StringBuilder 256
  [void][PsFix]::GetWindowTextA($h,$t,$t.Capacity)
  Write-Output ("AFTER_SET hwnd=0x{0:X} txt='{1}'" -f $h.ToInt64(), $t.ToString())
}
Write-Output ("PANEL=0x{0:X} EXEC=0x{1:X}" -f $panel.ToInt64(), $exec.ToInt64())
[void][PsFix]::PostMessageW($panel,0x0111,[IntPtr]5010,$exec)
Start-Sleep 6
$out=[IntPtr]::Zero
[PsFix]::EnumChildWindows($main,{ param($h,$lp) if([PsFix]::GetDlgCtrlID($h)-eq 5001){$script:out=$h; return $false}; return $true },[IntPtr]::Zero)|Out-Null
$ot=New-Object System.Text.StringBuilder 8192
[void][PsFix]::GetWindowTextA($out,$ot,$ot.Capacity)
$s=$ot.ToString()
Write-Output "PS_OUT_LEN=$($s.Length)"
if ($s.Length -gt 600) { Write-Output $s.Substring($s.Length-600) } else { Write-Output $s }
if (Test-Path "$logdir\ps_trace.log") { Write-Output '---TRACE---'; Get-Content "$logdir\ps_trace.log" -Tail 25 }
Stop-Process -Id $p.Id -Force -EA SilentlyContinue

$src = 'G:\~dev\rawrxd-cmake-clean\build-canonical-reference\bin\RawrXD-Win32IDE.exe'
$wd = Join-Path $env:TEMP 'rawrxd-layout-enum'
New-Item -ItemType Directory -Force -Path $wd | Out-Null
$outDir = 'G:\~dev\rawrxd\evidence\RAWRXD_IDE_LAYOUT_REPAIR_001'
$out = Join-Path $outDir 'hwnd_inventory.jsonl'
$p = Start-Process -FilePath $src -WorkingDirectory $wd -PassThru
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class IdeEnum {
  public delegate bool EnumProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  public static List<IntPtr> Tops(uint pid) {
    var xs = new List<IntPtr>();
    EnumWindows((h, lp) => { uint id; GetWindowThreadProcessId(h, out id); if (id == pid) xs.Add(h); return true; }, IntPtr.Zero);
    return xs;
  }
  public static List<IntPtr> Kids(IntPtr h) {
    var xs = new List<IntPtr>();
    EnumChildWindows(h, (c, lp) => { xs.Add(c); return true; }, IntPtr.Zero);
    return xs;
  }
}
'@
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 400
  if ($p.HasExited) { "DIED=$($p.ExitCode) at $i"; break }
  foreach ($h in [IdeEnum]::Tops([uint32]$p.Id)) {
    $sb = New-Object System.Text.StringBuilder 256
    [void][IdeEnum]::GetClassNameW($h, $sb, 256)
    if ($sb.ToString() -eq 'RawrXD_IDE_MainWindow') { $main = $h }
  }
  if ($main -ne [IntPtr]::Zero) { "MAIN=$main tick=$i"; break }
}
if ($main -eq [IntPtr]::Zero) {
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
  'NO_MAIN'
  exit 2
}
Start-Sleep -Milliseconds 1200
$dpi = [IdeEnum]::GetDpiForWindow($main)
"DPI=$dpi"
$kids = [IdeEnum]::Kids($main)
$lines = New-Object System.Collections.Generic.List[string]
foreach ($h in $kids) {
  $sb = New-Object System.Text.StringBuilder 256
  [void][IdeEnum]::GetClassNameW($h, $sb, 256)
  $wr = New-Object IdeEnum+RECT
  $cr = New-Object IdeEnum+RECT
  [void][IdeEnum]::GetWindowRect($h, [ref]$wr)
  [void][IdeEnum]::GetClientRect($h, [ref]$cr)
  $parent = [IdeEnum]::GetParent($h)
  $style = [IdeEnum]::GetWindowLong($h, -16)
  $ex = [IdeEnum]::GetWindowLong($h, -20)
  $w = $wr.R - $wr.L
  $ht = $wr.B - $wr.T
  $obj = [ordered]@{
    hwnd = ('0x{0:X}' -f $h.ToInt64())
    parent = ('0x{0:X}' -f $parent.ToInt64())
    class = $sb.ToString()
    visible = [bool]([IdeEnum]::IsWindowVisible($h))
    enabled = [bool]([IdeEnum]::IsWindowEnabled($h))
    style = ('0x{0:X}' -f $style)
    exStyle = ('0x{0:X}' -f $ex)
    layered = (($ex -band 0x80000) -ne 0)
    l = $wr.L; t = $wr.T; w = $w; h = $ht
    clientW = ($cr.R - $cr.L); clientH = ($cr.B - $cr.T)
  }
  $lines.Add(($obj | ConvertTo-Json -Compress))
}
$lines | Set-Content -Encoding utf8 $out
"COUNT=$($lines.Count)"
$lines | Where-Object { $_ -match '"w":[1-9][0-9]{2,}' } | Select-Object -First 60
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force; 'STOPPED' }

# Minimal HWND probe: FindWindow only. No EnumWindows loop, no WMI.
$ErrorActionPreference = 'Continue'
$Out = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\HWND_PROBE_TIP005.txt'
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class HwndOnce {
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowW(string cls, string title);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
}
"@
$h = [HwndOnce]::FindWindowW('RawrXD_IDE_Window', $null)
$pidOut = 0u
if ($h -ne [IntPtr]::Zero) { [void][HwndOnce]::GetWindowThreadProcessId($h, [ref]$pidOut) }
$sb = New-Object System.Text.StringBuilder 512
if ($h -ne [IntPtr]::Zero) { [void][HwndOnce]::GetWindowTextW($h, $sb, 512) }
$alive = (Get-Process -Name 'RawrXD-Win32IDE-Native-Ext' -EA SilentlyContinue | Measure-Object).Count
$lines = @(
  "ASOF=$((Get-Date).ToString('o'))"
  "PROC_COUNT=$alive"
  "MAIN_HWND=0x$('{0:X}' -f $h.ToInt64())"
  "PID=$pidOut"
  "TITLE=$($sb.ToString())"
  "VISIBLE=$(if($h -ne [IntPtr]::Zero){[HwndOnce]::IsWindowVisible($h)}else{$false})"
)
$lines | Set-Content -LiteralPath $Out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }

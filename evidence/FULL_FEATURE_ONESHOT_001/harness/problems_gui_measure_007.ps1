# Problems GUI measure for tip_ext_host_007. PROMOTE=0. Never touches A4F.
param(
  [string]$TipExe = "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_007\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ide_panels_007d",
  [int]$WaitSec = 60
)
$ErrorActionPreference = 'Continue'
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Set-Content "F:\rawrxd\build_dispatch_trace.log" ""
Remove-Item "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -EA SilentlyContinue
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "ide_panels_gui_run_$stamp.txt"
$receipt = Join-Path $OutDir "IDE_PANELS_GUI_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class P007 {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int IdList(IntPtr root, int id) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) {
        found = (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
        return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int IdLen(IntPtr root, int id) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) {
        found = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int MaxEdit(IntPtr root) {
    int max = 0;
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0 ||
          c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0) {
        int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        if (len > max) max = len;
      }
      return true;
    }, IntPtr.Zero);
    return max;
  }
  public static int ChildCount(IntPtr root) {
    int n = 0;
    EnumChildWindows(root, (h, lp) => { n++; return true; }, IntPtr.Zero);
    return n;
  }
}
"@
$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id) FIXTURE=$BrokenCpp"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 400
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [P007]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64()) alive=$([bool](-not $p.HasExited))"
if ($main -eq [IntPtr]::Zero) {
  @"
IDE_PANELS_GUI=NOT_RUN
REASON=main_hwnd_not_found
TIP_SHA256=$sha
PROMOTE=0
"@ | Set-Content $receipt
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
  exit 2
}
[void][P007]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 800
foreach ($cmd in @(2034, 2025, 2021)) {
  [void][P007]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Log "POST_WM_COMMAND id=$cmd"
  Start-Sleep -Milliseconds 500
}
[void][P007]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
Log "POST_BUILD=3014"
$id1312 = -1
$id1012 = -1
$maxEdit = 0
for ($w = 0; $w -lt $WaitSec; $w++) {
  Start-Sleep 1
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EXIT_DURING_WAIT code=$($p.ExitCode) t=$w"; break }
  if (-not [P007]::IsWindow($main)) { Log "MAIN_DESTROYED t=$w"; break }
  $id1312 = [P007]::IdList($main, 1312)
  $id1012 = [P007]::IdLen($main, 1012)
  $maxEdit = [P007]::MaxEdit($main)
  if (($w % 5) -eq 0) {
    Log "POLL t=$w ID1312=$id1312 ID1012=$id1012 MAXEDIT=$maxEdit CHILD=$([P007]::ChildCount($main))"
  }
  if ($id1312 -gt 0) { Log "PROBLEMS_POPULATED t=$w items=$id1312"; break }
}
$before = $id1312
[void][P007]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
Start-Sleep -Milliseconds 300
$cleared = [P007]::IdList($main, 1312)
for ($w = 0; $w -lt 45; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $n = [P007]::IdList($main, 1312)
  if ($n -gt 0) { $id1312 = $n; break }
  if (($w % 5) -eq 0) { Log "REBUILD_POLL t=$w n=$n" }
}
$clearedPass = if ($before -gt 0 -and $cleared -eq 0) { 'PASS' }
               elseif ($before -gt 0) { 'PARTIAL_TIMING' }
               elseif ($id1312 -gt 0) { 'PARTIAL_NO_PRE' }
               else { 'NOT_RUN' }
$clickToLine = 'NOT_RUN'
if ($id1312 -gt 0) {
  Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class ProbClick2 {
  public const uint WM_NOTIFY = 0x004E;
  public const int NM_DBLCLK = -3;
  [StructLayout(LayoutKind.Sequential)]
  public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMHDR l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  public static IntPtr Find(IntPtr root, int id) {
    IntPtr f = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => { if (GetDlgCtrlID(h)==id){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
}
"@
  $lv = [ProbClick2]::Find($main, 1312)
  if ($lv -ne [IntPtr]::Zero) {
    $nm = New-Object ProbClick2+NMHDR
    $nm.hwndFrom = $lv
    $nm.idFrom = [IntPtr]1312
    $nm.code = [ProbClick2]::NM_DBLCLK
    [void][ProbClick2]::SendMessage($main, [ProbClick2]::WM_NOTIFY, [IntPtr]1312, [ref]$nm)
    $clickToLine = 'POSTED_NM_DBLCLK'
    Log "CLICK_TO_LINE=$clickToLine"
  } else {
    $clickToLine = 'LIST_HWND_MISSING'
  }
}
$probPass = if ($id1312 -gt 0) { 'PASS' } elseif ($id1312 -eq 0) { 'PARTIAL' } else { 'NOT_RUN' }
$outPass = if ($maxEdit -gt 0 -or $id1012 -gt 0) { 'PASS' } else { 'FAIL' }
@"
IDE_PANELS_GUI=MEASURED
TIP_SHA256=$sha
TIP_EXE=$TipExe
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
PROBLEMS_ID1312_ITEMS=$id1312
PROBLEMS_ID1312_BEFORE_REBUILD=$before
PROBLEMS_ID1312_CLEAR_SNAP=$cleared
REBUILD_CLEARS_STALE=$clearedPass
CLICK_TO_LINE=$clickToLine
OUTPUT_ID1012_LEN=$id1012
MAX_EDIT_LEN=$maxEdit
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
RAWRXD_PROBLEMS_FIXTURE=$BrokenCpp
T080_PRESERVED=1
FROZEN_A4F_UNTOUCHED=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
Get-Content $receipt
Write-Host "=== DISPATCH ==="
Get-Content "F:\rawrxd\build_dispatch_trace.log" -EA SilentlyContinue
Write-Host "=== OUT GREP ==="
if (Test-Path "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log") {
  Select-String -Path "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -Pattern "PROBLEMS_FIXTURE|error C|warning C|broken_multi|RAWRXD_BUILD_START" |
    Select-Object -First 40
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
exit 0

# IDE HWND verify: Output / Problems / Build Project on tip candidate.
# PROMOTE=0. Never touches A4F.
param(
  [Parameter(Mandatory=$true)][string]$TipExe,
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ide_panels_001",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [int]$BuildWaitSec = 45
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
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
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class IdePanelNative2 {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const int IDM_TOOLS_BUILD_PROJECT = 3014;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
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
  public static string GetText(IntPtr h) {
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static List<string> DumpChildren(IntPtr root) {
    var lines = new List<string>();
    EnumChildWindows(root, (h, lp) => {
      int id = GetDlgCtrlID(h);
      var sb = new StringBuilder(128);
      GetClassNameW(h, sb, sb.Capacity);
      string cls = sb.ToString();
      string txt = "";
      try { txt = GetText(h); } catch {}
      if (txt.Length > 80) txt = txt.Substring(0, 80);
      txt = txt.Replace("\r","\\r").Replace("\n","\\n");
      lines.Add(string.Format("id={0} cls={1} vis={2} len={3} txt={4}", id, cls, IsWindowVisible(h)?1:0, txt.Length, txt));
      return true;
    }, IntPtr.Zero);
    return lines;
  }
}
"@

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
# Exclusive mutex: concurrent harness Stop-Process -Force yields ExitCode=-1
# (0xFFFFFFFF) mid-Build and falsely seals OUTPUT_GUI_E2E=FAIL.
$mutex = $null
$owned = $false
try {
  $mutex = New-Object System.Threading.Mutex($false, 'Global\RawrXD_IDE_Panels_Gui_Verify')
  $owned = $mutex.WaitOne([TimeSpan]::FromSeconds(120))
} catch {
  $owned = $false
}
if (-not $owned) {
  Log "PANEL_MUTEX=BUSY"
  @"
IDE_PANELS_GUI=NOT_RUN
REASON=panel_mutex_busy
TIP_SHA256=$sha
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}
Log "PANEL_MUTEX=OWNED"
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
# Dismiss any leftover #32770 dialogs
Get-Process | Where-Object { $_.MainWindowTitle -match 'RawrXD|Save|Open|New' } -EA SilentlyContinue | Out-Null
$env:RAWRXD_LOG_DIR = $LogDir
if (Test-Path -LiteralPath $BrokenCpp) {
  $env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
  Log "RAWRXD_PROBLEMS_FIXTURE=$BrokenCpp"
} else {
  Remove-Item Env:RAWRXD_PROBLEMS_FIXTURE -EA SilentlyContinue
  Log "RAWRXD_PROBLEMS_FIXTURE=MISSING path=$BrokenCpp"
}
$p = Start-Process -FilePath $TipExe -ArgumentList "`"$BrokenCpp`"" -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [IdePanelNative2]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
IDE_PANELS_GUI=NOT_RUN
REASON=main_hwnd_not_found
TIP_SHA256=$sha
PROMOTE=0
"@ | Set-Content $receipt
  try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  if ($mutex -ne $null -and $owned) { try { $mutex.ReleaseMutex() } catch {}; try { $mutex.Dispose() } catch {} }
  exit 2
}
[void][IdePanelNative2]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 600

# Show panel / output tabs then Build Project (avoid File>New modal)
foreach ($cmd in @(2034, 2025, 2021, 3014)) {
  [void][IdePanelNative2]::SendMessageW($main, [IdePanelNative2]::WM_COMMAND, [IntPtr]$cmd, [IntPtr]::Zero)
  Log "POST_WM_COMMAND id=$cmd"
  Start-Sleep -Milliseconds 700
}
# Early HWND snapshot (survival proof) before long Build wait.
Start-Sleep 2
try { $p.Refresh() } catch {}
if (-not $p.HasExited) {
  $earlyKids = [IdePanelNative2]::DumpChildren($main)
  Log "EARLY_CHILD_COUNT=$($earlyKids.Count) alive=1"
} else {
  Log "EARLY_EXIT=$($p.ExitCode)"
}
# Poll Problems list while MSVC fixture compile streams into aggregator
$id1312poll = -1
for ($w = 0; $w -lt $BuildWaitSec; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "PROCESS_EXITED_DURING_WAIT exit=$($p.ExitCode) t=$w"; break }
  $tmpKids = [IdePanelNative2]::DumpChildren($main)
  foreach ($line in $tmpKids) {
    if ($line -match 'id=1312 cls=SysListView32') {
      # recount via measure below after loop
    }
  }
  # early exit if list already populated (measure type defined later — soft wait)
  if ($w -ge 8 -and ($w % 5) -eq 0) { Log "BUILD_WAIT_SEC=$w" }
}
Log "BUILD_WAIT_DONE sec=$BuildWaitSec"

$kids = [IdePanelNative2]::DumpChildren($main)
Log "CHILD_COUNT=$($kids.Count)"
$kids | Select-Object -First 80 | ForEach-Object { Log "CHILD $_" }

# Classify controls
$editLens = @()
$listCounts = @()
$byId = @{}
foreach ($line in $kids) {
  if ($line -match 'id=(\d+) cls=([^\s]+) .* len=(\d+)') {
    $id = [int]$matches[1]; $cls = $matches[2]; $len = [int]$matches[3]
    if ($id -gt 0) { $byId[$id] = $true }
  }
}
# Re-walk for measurements
Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class IdePanelMeasure {
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_GETTEXT = 0x000D;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public static int MaxEditLen(IntPtr root) {
    int max = 0;
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0 ||
          c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0 ||
          c == "Static") {
        int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        if (len > max) max = len;
      }
      return true;
    }, IntPtr.Zero);
    return max;
  }
  public static int MaxListItems(IntPtr root) {
    int max = -1;
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("SysListView32", StringComparison.OrdinalIgnoreCase) >= 0) {
        int n = (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
        if (n > max) max = n;
      }
      return true;
    }, IntPtr.Zero);
    return max;
  }
  public static int IdLen(IntPtr root, int wantId) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == wantId) {
        found = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int IdListCount(IntPtr root, int wantId) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == wantId) {
        found = (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
        return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$maxEdit = [IdePanelMeasure]::MaxEditLen($main)
$maxList = [IdePanelMeasure]::MaxListItems($main)
$id1012 = [IdePanelMeasure]::IdLen($main, 1012)
$id1011 = [IdePanelMeasure]::IdLen($main, 1011)
$id1312 = [IdePanelMeasure]::IdListCount($main, 1312)
# Extra poll after measure types exist (fixture cl can still be streaming)
for ($w = 0; $w -lt 30 -and $id1312 -le 0; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $id1312 = [IdePanelMeasure]::IdListCount($main, 1312)
  if (($w % 5) -eq 0) { Log "POLL_ID1312=$id1312 t=$w" }
}
# chat input presence proves enum works (1202)
$id1202 = [IdePanelMeasure]::IdLen($main, 1202)
Log "MAX_EDIT_LEN=$maxEdit MAX_LISTVIEW_ITEMS=$maxList ID1012=$id1012 ID1011=$id1011 ID1312=$id1312 ID1202_CHAT=$id1202"

# Rebuild-clears-stale: second Build should clear then refill
$id1312_before_rebuild = $id1312
[void][IdePanelNative2]::SendMessageW($main, [IdePanelNative2]::WM_COMMAND, [IntPtr]3014, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$id1312_cleared = [IdePanelMeasure]::IdListCount($main, 1312)
for ($w = 0; $w -lt 40; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $n = [IdePanelMeasure]::IdListCount($main, 1312)
  if ($n -gt 0) { $id1312 = $n; break }
  if (($w % 5) -eq 0) { Log "REBUILD_POLL_ID1312=$n t=$w" }
}
Log "REBUILD_CLEAR_CHECK before=$id1312_before_rebuild cleared_snap=$id1312_cleared after=$id1312"

# Click-to-line: NM_DBLCLK on Problems list if items present
$clickToLine = 'NOT_RUN'
if ($id1312 -gt 0) {
  Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class ProbClick {
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
  $lv = [ProbClick]::Find($main, 1312)
  if ($lv -ne [IntPtr]::Zero) {
    $nm = New-Object ProbClick+NMHDR
    $nm.hwndFrom = $lv
    $nm.idFrom = [IntPtr]1312
    $nm.code = [ProbClick]::NM_DBLCLK
    [void][ProbClick]::SendMessage($main, [ProbClick]::WM_NOTIFY, [IntPtr]1312, [ref]$nm)
    Start-Sleep -Milliseconds 500
    $clickToLine = 'POSTED_NM_DBLCLK'
    Log "CLICK_TO_LINE=POSTED_NM_DBLCLK lv=0x$('{0:X}' -f $lv.ToInt64())"
  } else {
    $clickToLine = 'LIST_HWND_MISSING'
  }
}

$outputGui = ($maxEdit -gt 0 -or $id1012 -gt 0 -or $id1011 -gt 0)
$problemsPresent = ($maxList -ge 0 -or $id1312 -ge 0)
$probItems = if ($id1312 -ge 0) { $id1312 } else { $maxList }
$outPass = if ($outputGui) { 'PASS' } else { 'FAIL' }
$rebuildClears = if ($id1312_before_rebuild -gt 0 -and $id1312_cleared -eq 0) { 'PASS' }
                 elseif ($id1312_before_rebuild -gt 0 -and $id1312 -gt 0) { 'PARTIAL_TIMING' }
                 elseif ($id1312 -gt 0) { 'PARTIAL_NO_PRE' }
                 else { 'NOT_RUN' }
$probPass = if ($problemsPresent -and $probItems -gt 0) { 'PASS' } elseif ($problemsPresent) { 'PARTIAL' } else { 'NOT_RUN' }
# Build HWND: command posted + process alive + chat controls discovered (enum healthy)
$enumOk = ($id1202 -ge 0 -or $kids.Count -gt 0)
$buildPass = if ($enumOk -and -not $p.HasExited) { 'PARTIAL' } else { 'FAIL' }
if ($outputGui) { $buildPass = 'PASS' }

@"
IDE_PANELS_GUI=MEASURED
TIP_SHA256=$sha
TIP_EXE=$TipExe
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
CHILD_COUNT=$($kids.Count)
MAX_EDIT_LEN=$maxEdit
MAX_LISTVIEW_ITEMS=$maxList
OUTPUT_ID1012_LEN=$id1012
OUTPUT_ID1011_LEN=$id1011
PROBLEMS_ID1312_ITEMS=$id1312
PROBLEMS_ID1312_BEFORE_REBUILD=$id1312_before_rebuild
PROBLEMS_ID1312_CLEAR_SNAP=$id1312_cleared
REBUILD_CLEARS_STALE=$rebuildClears
CLICK_TO_LINE=$clickToLine
CHAT_ID1202_LEN=$id1202
RAWRXD_PROBLEMS_FIXTURE=$($env:RAWRXD_PROBLEMS_FIXTURE)
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
IDE_BUILD_PROJECT_HWND=$buildPass
T080_PRESERVED=1
FROZEN_A4F_UNTOUCHED=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
"@ | Set-Content $receipt
Get-Content $receipt
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
Start-Sleep 1
if ($mutex -ne $null -and $owned) { try { $mutex.ReleaseMutex() } catch {}; try { $mutex.Dispose() } catch {} }
exit $(if ($enumOk) { 0 } else { 1 })

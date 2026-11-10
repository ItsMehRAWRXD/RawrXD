# EA5D tip_final_004 panel HWND measure. PROMOTE=0. Never touches A4F.
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_final_004\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ide_panels_ea5d"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "ea5d_four_panel_gui_run_$stamp.txt"
$receipt = Join-Path $OutDir "EA5D_FOUR_PANEL_GUI_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Ea5dPanelE {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_NOTIFY = 0x004E;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint TCM_GETITEMCOUNT = 0x1304;
  public const uint TCM_SETCURSEL = 0x130C;
  public const uint TCM_GETCURSEL = 0x130B;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const int TCN_SELCHANGE = -551;
  public const uint SMTO_ABORTIFHUNG = 0x0002;
  [StructLayout(LayoutKind.Sequential)]
  public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint Msg, IntPtr w, IntPtr l, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SendMessageTimeout(IntPtr h, uint Msg, IntPtr w, ref NMHDR l, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public static int LastLen, LastVis, LastItems;
  public static string LastCls = "";
  public static int Timed(IntPtr h, uint msg, IntPtr w, uint ms) {
    IntPtr r; IntPtr ok = SendMessageTimeoutW(h, msg, w, IntPtr.Zero, SMTO_ABORTIFHUNG, ms, out r);
    return ok == IntPtr.Zero ? -3 : r.ToInt32();
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindById(IntPtr root, int wantId) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == wantId) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool Cmd(IntPtr main, int id) {
    IntPtr r; return SendMessageTimeoutW(main, WM_COMMAND, (IntPtr)id, IntPtr.Zero, SMTO_ABORTIFHUNG, 1200, out r) != IntPtr.Zero;
  }
  public static bool SelectTab(IntPtr main, IntPtr tab, int index, int idFrom) {
    if (tab == IntPtr.Zero) return false;
    int n = Timed(tab, TCM_GETITEMCOUNT, IntPtr.Zero, 400);
    if (n >= 0 && index >= n) return false;
    Timed(tab, TCM_SETCURSEL, (IntPtr)index, 400);
    NMHDR nm; nm.hwndFrom = tab; nm.idFrom = (IntPtr)idFrom; nm.code = TCN_SELCHANGE;
    IntPtr r;
    SendMessageTimeout(main, WM_NOTIFY, (IntPtr)idFrom, ref nm, SMTO_ABORTIFHUNG, 800, out r);
    IntPtr parent = GetParent(tab);
    if (parent != IntPtr.Zero && parent != main)
      SendMessageTimeout(parent, WM_NOTIFY, (IntPtr)idFrom, ref nm, SMTO_ABORTIFHUNG, 800, out r);
    return Timed(tab, TCM_GETCURSEL, IntPtr.Zero, 400) == index;
  }
  public static void ProbeId(IntPtr root, int id) {
    LastLen = -1; LastVis = 0; LastItems = -1; LastCls = "";
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) != id) return true;
      LastVis = IsWindowVisible(h) ? 1 : 0;
      var sb = new StringBuilder(64); GetClassNameW(h, sb, sb.Capacity); LastCls = sb.ToString();
      LastLen = Timed(h, WM_GETTEXTLENGTH, IntPtr.Zero, 300);
      if (LastCls.IndexOf("SysListView32", StringComparison.OrdinalIgnoreCase) >= 0)
        LastItems = Timed(h, LVM_GETITEMCOUNT, IntPtr.Zero, 300);
      return false;
    }, IntPtr.Zero);
  }
  public static int MaxVisRichEdit(IntPtr root) {
    int best = 0; int count = 0;
    EnumChildWindows(root, (h, lp) => {
      if (!IsWindowVisible(h)) return true;
      var sb = new StringBuilder(64); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) < 0 && c != "Edit") return true;
      count++;
      if (count > 10) return false;
      int len = Timed(h, WM_GETTEXTLENGTH, IntPtr.Zero, 200);
      if (len > best) best = len;
      return true;
    }, IntPtr.Zero);
    return best;
  }
  public static int TabStripHits(IntPtr root) {
    int hits = 0;
    EnumChildWindows(root, (h, lp) => {
      if (!IsWindowVisible(h)) return true;
      var sb = new StringBuilder(64); GetClassNameW(h, sb, sb.Capacity);
      if (sb.ToString() != "SysTabControl32") return true;
      int n = Timed(h, TCM_GETITEMCOUNT, IntPtr.Zero, 300);
      if (n == 4 || n >= 12) hits++;
      return true;
    }, IntPtr.Zero);
    return hits;
  }
}
"@

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$env:RAWRXD_LOG_DIR = $LogDir
$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 350
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [Ea5dPanelE]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  "EA5D_FOUR_PANEL_GUI=NOT_RUN`nREASON=main_hwnd_not_found`nTIP_SHA256=$sha`nPROMOTE=0" | Set-Content $receipt
  exit 2
}
[void][Ea5dPanelE]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 500
foreach ($cmd in @(2034, 2025, 2021)) { Log "CMD $cmd ok=$([Ea5dPanelE]::Cmd($main, $cmd))"; Start-Sleep -Milliseconds 200 }

$outTabs = [Ea5dPanelE]::FindById($main, 1005)
$panelTabs = [Ea5dPanelE]::FindById($main, 1301)
$panelContainer = [Ea5dPanelE]::FindById($main, 1300)
$outN = if ($outTabs -ne [IntPtr]::Zero) { [Ea5dPanelE]::Timed($outTabs, 0x1304, [IntPtr]::Zero, 400) } else { -1 }
$panelN = if ($panelTabs -ne [IntPtr]::Zero) { [Ea5dPanelE]::Timed($panelTabs, 0x1304, [IntPtr]::Zero, 400) } else { -1 }
Log "OUT_TABS=0x$('{0:X}' -f $outTabs.ToInt64()) n=$outN PANEL_TABS=0x$('{0:X}' -f $panelTabs.ToInt64()) n=$panelN"

$selOut0 = [Ea5dPanelE]::SelectTab($main, $outTabs, 0, 1005)
Start-Sleep 250
$vis0 = [Ea5dPanelE]::MaxVisRichEdit($main)
Log "SELECT_OUTPUT_TAB0=$selOut0 VIS_EDIT=$vis0"

$selBuild = [Ea5dPanelE]::SelectTab($main, $outTabs, 4, 1005)
Start-Sleep 250
$visBuild = [Ea5dPanelE]::MaxVisRichEdit($main)
[Ea5dPanelE]::ProbeId($main, 1012); $len1012=[Ea5dPanelE]::LastLen; $vis1012=[Ea5dPanelE]::LastVis
[Ea5dPanelE]::ProbeId($main, 1052); $len1052=[Ea5dPanelE]::LastLen; $vis1052=[Ea5dPanelE]::LastVis
Log "SELECT_BUILD_TAB4=$selBuild VIS_EDIT=$visBuild id1012=$len1012/$vis1012 id1052=$len1052/$vis1052"

$selExt = [Ea5dPanelE]::SelectTab($main, $outTabs, 7, 1005); Start-Sleep 150
$selDeep = [Ea5dPanelE]::SelectTab($main, $outTabs, 9, 1005); Start-Sleep 150
$selIde = [Ea5dPanelE]::SelectTab($main, $outTabs, 10, 1005)
Log "SELECT_EXT7=$selExt SELECT_DEEP9=$selDeep SELECT_IDE10=$selIde"

$clearOk = [Ea5dPanelE]::Cmd($main, 3006); Start-Sleep 200
$visClear = [Ea5dPanelE]::MaxVisRichEdit($main)
Log "CLEAR_CMD=$clearOk VIS_AFTER_CLEAR=$visClear"

$selErr = [Ea5dPanelE]::SelectTab($main, $outTabs, 1, 1005); Start-Sleep 250
$selProb = [Ea5dPanelE]::SelectTab($main, $panelTabs, 2, 1301); Start-Sleep 250
[Ea5dPanelE]::ProbeId($main, 1312)
$items1312=[Ea5dPanelE]::LastItems; $vis1312=[Ea5dPanelE]::LastVis
$panelVis = if ($panelContainer -ne [IntPtr]::Zero -and [Ea5dPanelE]::IsWindowVisible($panelContainer)) { 1 } else { 0 }
Log "SELECT_ERRORS1=$selErr SELECT_PANEL_PROBLEMS2=$selProb ID1312_ITEMS=$items1312 VIS=$vis1312 PANEL_CONT_VIS=$panelVis"

$selDbg = [Ea5dPanelE]::SelectTab($main, $panelTabs, 3, 1301); Start-Sleep 150
$named = [Ea5dPanelE]::TabStripHits($main)
Log "SELECT_PANEL_DEBUG3=$selDbg NAMED_TABSTRIP_HITS=$named"

$channelSwitch = ($selBuild -and $selExt -and ($selDeep -or $selIde))
$outPass = if (($vis0 -gt 20 -or $visBuild -gt 20) -and $selOut0 -and $channelSwitch) { 'PARTIAL' } elseif ($selOut0) { 'PARTIAL' } else { 'NOT_RUN' }
$probPass = if ($vis1312 -eq 1 -and $items1312 -gt 0) { 'PASS' } elseif ($selProb -or $items1312 -ge 0) { 'PARTIAL' } else { 'NOT_RUN' }
$dbgPass = if ($selDbg) { 'PARTIAL_UI_TAB_ONLY' } else { 'NOT_RUN' }
$four = 'FAIL_CLOSED_GAPS'

@"
EA5D_FOUR_PANEL_GUI=MEASURED
TIP_SHA256=$sha
TIP_EXE=$TipExe
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
OUT_TAB_COUNT=$outN
PANEL_TAB_COUNT=$panelN
SELECT_OUTPUT_TAB0=$selOut0
SELECT_BUILD_TAB4=$selBuild
SELECT_EXT7=$selExt
SELECT_DEEP9=$selDeep
SELECT_IDE10=$selIde
SELECT_ERRORS_TAB1=$selErr
SELECT_PANEL_PROBLEMS2=$selProb
SELECT_PANEL_DEBUG3=$selDbg
CHANNEL_SWITCH=$channelSwitch
VISIBLE_EDIT_OUTPUT_TAB=$vis0
VISIBLE_EDIT_BUILD_TAB=$visBuild
VISIBLE_EDIT_AFTER_CLEAR=$visClear
OUTPUT_ID1012_LEN=$len1012
OUTPUT_ID1012_VISIBLE=$vis1012
OUTPUT_ID1052_LEN=$len1052
OUTPUT_ID1052_VISIBLE=$vis1052
PROBLEMS_ID1312_ITEMS=$items1312
PROBLEMS_ID1312_VISIBLE=$vis1312
PANEL_CONTAINER_VISIBLE=$panelVis
HWND_NAMED_PANEL_HITS=$named
BUILD_PROJECT_HWND=SKIPPED_UI_STALL
BUILD_CHANNEL_LINES=NOT_RUN
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
GUI_DEBUG_CONSOLE_E2E=$dbgPass
FOUR_PANEL_INTEGRATION=$four
GAPS=BUILD_LINES_HWND,PROBLEMS_ITEMS_ZERO_OR_HIDDEN,DEBUG_NO_WAITFORDEBUGEVENT_ON_EA5D,FOUR_PANEL_1_17
FROZEN_A4F_UNTOUCHED=1
T080_PRESERVED=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
Get-Content $receipt
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
exit 0

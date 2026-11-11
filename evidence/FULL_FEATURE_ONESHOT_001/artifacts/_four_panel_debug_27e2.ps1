# CC79 four-panel + IDE debug UI probe. PROMOTE=0. Timeout-safe only.
$ErrorActionPreference = 'Continue'
$tipDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004"
$TipExe = Join-Path $tipDir "RawrXD-Win32IDE-Native-Ext.exe"
$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts"
$LogDir = Join-Path $tipDir "gui_probe_logs"
$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp"
$Debuggee = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\debuggee_fixture.exe"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "four_panel_debug_ui_27e2_run_$stamp.txt"
$receipt = Join-Path $OutDir "FOUR_PANEL_DEBUG_UI_27E2_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runlog -Value $line
  Write-Host $line
}

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class Cc79Safe {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_NOTIFY = 0x004E;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint TCM_FIRST = 0x1300;
  public const uint TCM_GETITEMCOUNT = TCM_FIRST + 4;
  public const uint TCM_SETCURSEL = TCM_FIRST + 12;
  public const uint TCM_GETCURSEL = TCM_FIRST + 11;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const int TCN_FIRST = -550;
  public const int TCN_SELCHANGE = TCN_FIRST - 1;
  public const int NM_DBLCLK = -3;
  public const uint SMTO_ABORTIFHUNG = 0x0002;
  [StructLayout(LayoutKind.Sequential)]
  public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SendMessageTimeoutW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, IntPtr wParam, ref NMHDR lParam, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr SendMessageTimeoutW(IntPtr hWnd, uint Msg, IntPtr wParam, StringBuilder lParam, uint flags, uint timeout, out IntPtr result);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr lp);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool MsgTO(IntPtr h, uint msg, IntPtr w, IntPtr l, uint ms, out IntPtr result) {
    result = IntPtr.Zero;
    if (h == IntPtr.Zero || !IsWindow(h)) return false;
    IntPtr ok = SendMessageTimeoutW(h, msg, w, l, SMTO_ABORTIFHUNG, ms, out result);
    return ok != IntPtr.Zero;
  }
  public static int GetTextLenTO(IntPtr h, uint ms) {
    IntPtr r;
    if (!MsgTO(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero, ms, out r)) return -3;
    return r.ToInt32();
  }
  public static string GetTextTO(IntPtr h, uint ms) {
    int len = GetTextLenTO(h, ms);
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    IntPtr r;
    IntPtr ok = SendMessageTimeoutW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb, SMTO_ABORTIFHUNG, ms, out r);
    if (ok == IntPtr.Zero) return "";
    return sb.ToString();
  }
  public static IntPtr FindById(IntPtr root, int wantId) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == wantId) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int TabCount(IntPtr tab, uint ms) {
    if (tab == IntPtr.Zero) return -1;
    IntPtr r;
    if (!MsgTO(tab, TCM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero, ms, out r)) return -3;
    return r.ToInt32();
  }
  public static bool CmdTimeout(IntPtr main, int cmdId, uint ms) {
    IntPtr r;
    return MsgTO(main, WM_COMMAND, (IntPtr)cmdId, IntPtr.Zero, ms, out r);
  }
  public static bool SelectTabTO(IntPtr main, IntPtr tab, int index, int idFrom, uint ms) {
    if (tab == IntPtr.Zero) return false;
    int n = TabCount(tab, ms);
    if (n >= 0 && index >= n) return false;
    IntPtr r;
    if (!MsgTO(tab, TCM_SETCURSEL, (IntPtr)index, IntPtr.Zero, ms, out r)) return false;
    NMHDR nm;
    nm.hwndFrom = tab;
    nm.idFrom = (IntPtr)idFrom;
    nm.code = TCN_SELCHANGE;
    SendMessageTimeout(main, WM_NOTIFY, (IntPtr)idFrom, ref nm, SMTO_ABORTIFHUNG, ms, out r);
    IntPtr parent = GetParent(tab);
    if (parent != IntPtr.Zero && parent != main) {
      SendMessageTimeout(parent, WM_NOTIFY, (IntPtr)idFrom, ref nm, SMTO_ABORTIFHUNG, ms, out r);
    }
    if (!MsgTO(tab, TCM_GETCURSEL, IntPtr.Zero, IntPtr.Zero, ms, out r)) return false;
    return r.ToInt32() == index;
  }
  public static int MaxVisibleEditLen(IntPtr root, uint ms) {
    int max = 0;
    EnumChildWindows(root, (h, lp) => {
      if (!IsWindowVisible(h)) return true;
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) >= 0 ||
          c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0) {
        int len = GetTextLenTO(h, ms);
        if (len > max) max = len;
      }
      return true;
    }, IntPtr.Zero);
    return max;
  }
  public static int LastListVisible;
  public static int IdListCount(IntPtr root, int wantId, uint ms) {
    int found = -1; LastListVisible = 0;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) != wantId) return true;
      LastListVisible = IsWindowVisible(h) ? 1 : 0;
      IntPtr r;
      if (!MsgTO(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero, ms, out r)) { found = -3; return false; }
      found = r.ToInt32();
      return false;
    }, IntPtr.Zero);
    return found;
  }
  public static int IdLen(IntPtr root, int wantId, bool visibleOnly, uint ms) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) != wantId) return true;
      if (visibleOnly && !IsWindowVisible(h)) { found = -2; return false; }
      found = GetTextLenTO(h, ms);
      return false;
    }, IntPtr.Zero);
    return found;
  }
  public static int NamedPanelHits(IntPtr root, uint ms) {
    int hits = 0;
    EnumChildWindows(root, (h, lp) => {
      string t = "";
      try { t = GetTextTO(h, ms); } catch {}
      if (string.IsNullOrEmpty(t)) return true;
      string u = t.ToUpperInvariant();
      if (u.Contains("OUTPUT") || u.Contains("PROBLEMS") || u.Contains("DEBUG CONSOLE") || u.Contains("TERMINAL")) {
        if (IsWindowVisible(h)) hits++;
      }
      return true;
    }, IntPtr.Zero);
    return hits;
  }
  public static List<string> DumpIds(IntPtr root, uint ms) {
    var lines = new List<string>();
    EnumChildWindows(root, (h, lp) => {
      int id = GetDlgCtrlID(h);
      if (id <= 0) return true;
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      int len = GetTextLenTO(h, ms);
      int items = -1;
      string cls = sb.ToString();
      IntPtr r;
      if (cls.IndexOf("SysListView32", StringComparison.OrdinalIgnoreCase) >= 0) {
        if (MsgTO(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero, ms, out r)) items = r.ToInt32();
      }
      int tabs = -1;
      if (cls.IndexOf("SysTabControl32", StringComparison.OrdinalIgnoreCase) >= 0) {
        if (MsgTO(h, TCM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero, ms, out r)) tabs = r.ToInt32();
      }
      lines.Add(string.Format("id={0} cls={1} vis={2} len={3} items={4} tabs={5}",
        id, cls, IsWindowVisible(h)?1:0, len, items, tabs));
      return true;
    }, IntPtr.Zero);
    return lines;
  }
  public static bool PostDblClk(IntPtr main, IntPtr lv, int id, uint ms) {
    if (lv == IntPtr.Zero) return false;
    NMHDR nm;
    nm.hwndFrom = lv;
    nm.idFrom = (IntPtr)id;
    nm.code = NM_DBLCLK;
    IntPtr r;
    SendMessageTimeout(main, WM_NOTIFY, (IntPtr)id, ref nm, SMTO_ABORTIFHUNG, ms, out r);
    return true;
  }
}
"@

Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' } | ForEach-Object {
  Log "KILL pid=$($_.ProcessId) cmd=$($_.CommandLine)"
  Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
}
Start-Sleep 2
Log "LEFT=$((@(Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' })).Count)"

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
Log "FIXTURE=$BrokenCpp"
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
$env:RAWRXD_DEBUGGEE = $Debuggee

# First empty-cmdline smoke already proved HWND; this run opens fixture for panels.
$p = Start-Process -FilePath $TipExe -ArgumentList "`"$BrokenCpp`"" -WorkingDirectory 'F:\rawrxd' -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
$class = ""; $title = ""
for ($i=0; $i -lt 120; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  $main = [Cc79Safe]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 256
    [void][Cc79Safe]::GetClassNameW($main, $sb, 256)
    $class = $sb.ToString()
    $tb = New-Object System.Text.StringBuilder 512
    [void][Cc79Safe]::GetWindowTextW($main, $tb, 512)
    $title = $tb.ToString()
    break
  }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64()) CLASS=$class TITLE='$title' VIS=$([Cc79Safe]::IsWindowVisible($main))"

if ($main -eq [IntPtr]::Zero) {
  @"
CC79_FOUR_PANEL_DEBUG_UI=FAIL
REASON=main_hwnd_not_found
TIP_SHA256=$sha
EXITED=$($p.HasExited)
EXIT=$($p.ExitCode)
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content -LiteralPath $receipt
  exit 2
}

[void][Cc79Safe]::ShowWindow($main, 9)
[void][Cc79Safe]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 500

foreach ($cmd in @(2034, 2025, 2021, 2029)) {
  $ok = [Cc79Safe]::CmdTimeout($main, $cmd, 1500)
  Log "VIEW_CMD id=$cmd ok=$ok"
}

$TO = [uint32]800
$outTabs = [Cc79Safe]::FindById($main, 1005)
$panelTabs = [Cc79Safe]::FindById($main, 1301)
$panelContainer = [Cc79Safe]::FindById($main, 1300)
$editor = [Cc79Safe]::FindById($main, 1001)
$chat = [Cc79Safe]::FindById($main, 1202)
$outTabCount = [Cc79Safe]::TabCount($outTabs, $TO)
$panelTabCount = [Cc79Safe]::TabCount($panelTabs, $TO)
Log "OUT_TABS count=$outTabCount PANEL_TABS count=$panelTabCount EDITOR=0x$('{0:X}' -f $editor.ToInt64()) CHAT=0x$('{0:X}' -f $chat.ToInt64())"

$selOut0 = [Cc79Safe]::SelectTabTO($main, $outTabs, 0, 1005, $TO)
Log "SELECT_OUTPUT_TAB0=$selOut0"

# Avoid long modal hang: post Build with short timeout, then measure without waiting for compile complete.
$buildOk = [Cc79Safe]::CmdTimeout($main, 3014, 1200)
Log "POST_BUILD_PROJECT ok=$buildOk"
Start-Sleep 2
try { $p.Refresh() } catch {}

$visEdit = [Cc79Safe]::MaxVisibleEditLen($main, $TO)
$id1012 = [Cc79Safe]::IdLen($main, 1012, $false, $TO)
$id1052 = [Cc79Safe]::IdLen($main, 1052, $false, $TO)
$id1012v = [Cc79Safe]::IdLen($main, 1012, $true, $TO)
$id1052v = [Cc79Safe]::IdLen($main, 1052, $true, $TO)
$id1312 = [Cc79Safe]::IdListCount($main, 1312, $TO)
Log "MEASURE1 visEdit=$visEdit id1012=$id1012 id1052=$id1052 id1012v=$id1012v id1052v=$id1052v id1312=$id1312 exited=$($p.HasExited)"

$selBuild = $false; $selErr = $false
if ($outTabCount -gt 4) { $selBuild = [Cc79Safe]::SelectTabTO($main, $outTabs, 4, 1005, $TO) }
if ($outTabCount -gt 1) { $selErr = [Cc79Safe]::SelectTabTO($main, $outTabs, 1, 1005, $TO) }
$selOutPanel = $false; $selProbPanel = $false; $selTermPanel = $false; $selDbg = $false
if ($panelTabCount -gt 1) { $selOutPanel = [Cc79Safe]::SelectTabTO($main, $panelTabs, 1, 1301, $TO) }
if ($panelTabCount -gt 2) { $selProbPanel = [Cc79Safe]::SelectTabTO($main, $panelTabs, 2, 1301, $TO) }
if ($panelTabCount -gt 0) { $selTermPanel = [Cc79Safe]::SelectTabTO($main, $panelTabs, 0, 1301, $TO) }
if ($panelTabCount -gt 3) { $selDbg = [Cc79Safe]::SelectTabTO($main, $panelTabs, 3, 1301, $TO) }
Log "TABS build4=$selBuild err1=$selErr out1=$selOutPanel prob2=$selProbPanel term0=$selTermPanel dbg3=$selDbg"

# Extra short wait for problems populate
for ($w=0; $w -lt 8; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $id1312 = [Cc79Safe]::IdListCount($main, 1312, $TO)
  $visEdit = [Cc79Safe]::MaxVisibleEditLen($main, $TO)
  if ($id1312 -gt 0) { break }
}
$probItems = $id1312
$probVis = [Cc79Safe]::LastListVisible
$panelContVis = if ($panelContainer -ne [IntPtr]::Zero -and [Cc79Safe]::IsWindowVisible($panelContainer)) { 1 } else { 0 }
$namedHits = [Cc79Safe]::NamedPanelHits($main, $TO)
Log "PROBLEMS items=$probItems vis=$probVis panelCont=$panelContVis named=$namedHits visEdit=$visEdit"

$clickToLine = 'NOT_RUN'
if ($probItems -gt 0) {
  $lv = [Cc79Safe]::FindById($main, 1312)
  if ([Cc79Safe]::PostDblClk($main, $lv, 1312, $TO)) { $clickToLine = 'POSTED_NM_DBLCLK' }
  else { $clickToLine = 'LIST_HWND_MISSING' }
}
Log "CLICK_TO_LINE=$clickToLine"

$termClear = [Cc79Safe]::CmdTimeout($main, 3006, 1000)
$termCmd = [Cc79Safe]::CmdTimeout($main, 3002, 1000)
Log "TERMINAL clear=$termClear cmd=$termCmd"

$dbgResults = @()
$dbgCmds = @(
  @{n='TOGGLE_BP'; id=10506},
  @{n='SHOW_VARS'; id=10508},
  @{n='SHOW_WATCH'; id=10509},
  @{n='SHOW_CALLSTACK'; id=10507},
  @{n='DEBUG_START_10500'; id=10500},
  @{n='TOOLS_DEBUG_START_5060'; id=5060},
  @{n='SIDEBAR_DEBUG_START_6041'; id=6041},
  @{n='STEP_OVER'; id=10503},
  @{n='CONTINUE'; id=10502},
  @{n='STOP'; id=10501}
)
foreach ($dc in $dbgCmds) {
  if ($p.HasExited) { $dbgResults += "$($dc.n)=SKIP_EXITED"; break }
  $ok = [Cc79Safe]::CmdTimeout($main, $dc.id, 1200)
  $dbgResults += "$($dc.n)=$ok"
  $varsAfter = [Cc79Safe]::IdListCount($main, 1317, $TO)
  Log "DEBUG $($dc.n)=$ok vars1317=$varsAfter exited=$($p.HasExited)"
  Start-Sleep -Milliseconds 250
}

$dump = [Cc79Safe]::DumpIds($main, $TO)
$dump | Where-Object { $_ -match 'id=(1005|1011|1012|1052|1202|1300|1301|1312|1317) ' } | ForEach-Object { Log "KEY $_" }
$childCount = $dump.Count
$alive = -not $p.HasExited

$outPass = if ($visEdit -gt 20 -or $id1052v -gt 0 -or ($id1012v -gt 20)) { 'PASS' }
          elseif ($id1012 -ge 0 -or $id1052 -ge 0 -or $selOut0 -or $selOutPanel) { 'PARTIAL' }
          else { 'FAIL' }
$probPass = if ($probVis -eq 1 -and $probItems -gt 0) { 'PASS' }
            elseif ($probItems -gt 0) { 'PARTIAL' }
            elseif ($probItems -ge 0 -or $panelContVis -eq 1 -or $selProbPanel) { 'PARTIAL' }
            else { 'FAIL' }
$dbgPosted = @($dbgResults | Where-Object { $_ -match '=True$' }).Count
$dbgPass = 'FAIL'
$missingHook = ''
if ($selDbg -and $dbgPosted -gt 0) {
  $dbgPass = 'PARTIAL_UI_HOOKS_POSTED'
  $missingHook = 'WM_COMMAND 10500/5060/6041 posted but no SESSION_REAL via IDE UI (vars list empty / no BP hit observed)'
} elseif ($dbgPosted -gt 0) {
  $dbgPass = 'PARTIAL_CMDS_POSTED_NO_TAB'
  $missingHook = 'debug menu IDs posted; Debug panel tab select failed or absent'
} elseif ($selDbg) {
  $dbgPass = 'PARTIAL_UI_TAB_ONLY'
  $missingHook = 'Debug panel tab selectable; start/step/var hooks did not confirm live session'
} else {
  $missingHook = 'Debug panel tab not selected; IDE debug UI E2E incomplete'
}
$termPass = if ($selTermPanel -or $termCmd -or $termClear) { 'PARTIAL' } else { 'FAIL' }
$four = 'FAIL'
if ($outPass -eq 'PASS' -and $probPass -eq 'PASS' -and $dbgPass -eq 'PASS') { $four = 'PASS' }
elseif ($outPass -ne 'FAIL' -or $probPass -ne 'FAIL') { $four = 'FAIL_CLOSED_GAPS' }

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@"
CC79_FOUR_PANEL_DEBUG_UI=MEASURED
ASOF_UTC=$asof
TIP_SHA256=$sha
TIP_EXE=$TipExe
TIP_CWD=$tipDir
PID=$($p.Id)
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
CLASS=$class
TITLE=$title
ALIVE=$alive
EXITED=$($p.HasExited)
EXIT=$($p.ExitCode)
CHILD_ID_COUNT=$childCount
FIXTURE=$BrokenCpp
SELECT_OUTPUT_TAB0=$selOut0
SELECT_BUILD_TAB4=$selBuild
SELECT_ERRORS_TAB1=$selErr
SELECT_PANEL_OUTPUT1=$selOutPanel
SELECT_PANEL_PROBLEMS2=$selProbPanel
SELECT_PANEL_TERMINAL0=$selTermPanel
SELECT_PANEL_DEBUG3=$selDbg
MAX_VISIBLE_EDIT_LEN_AFTER_BUILD=$visEdit
OUTPUT_ID1012_LEN=$id1012
OUTPUT_ID1012_VISIBLE_LEN=$id1012v
OUTPUT_ID1052_BUILD_LEN=$id1052
OUTPUT_ID1052_VISIBLE_LEN=$id1052v
PROBLEMS_ID1312_ITEMS=$probItems
PROBLEMS_ID1312_VISIBLE=$probVis
CLICK_TO_LINE=$clickToLine
PANEL_CONTAINER_VISIBLE=$panelContVis
HWND_NAMED_PANEL_HITS=$namedHits
TERMINAL_VIEW_CMD=$termPass
DEBUG_CMDS=$($dbgResults -join ';')
DEBUG_MISSING_HOOK=$missingHook
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
GUI_DEBUG_CONSOLE_E2E=$dbgPass
IDE_DEBUG_UI=$dbgPass
FOUR_PANEL_INTEGRATION=$four
EMPTY_CMDLINE_HWND_PRIOR=0x600EAE
FROZEN_A4F_UNTOUCHED=1
NO_CROSS_SHA_PASS_INHERITANCE=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content -LiteralPath $receipt
Get-Content -LiteralPath $receipt

try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
Start-Sleep 1
Log "POST_KILL_LEFT=$((@(Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' })).Count)"


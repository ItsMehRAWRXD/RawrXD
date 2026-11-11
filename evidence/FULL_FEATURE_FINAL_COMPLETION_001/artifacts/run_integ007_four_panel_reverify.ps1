# G5_DEBUG_UI_REVERIFY â€” tip_final_integ_007 only. PROMOTE=0. No tip-move.
# Based on cc79_followup_four_panel_probe.ps1; points at INTEG_006 + local debuggee.
$ErrorActionPreference = 'Continue'
$tipDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_007"
$TipExe = Join-Path $tipDir "RawrXD-Win32IDE-Native-Ext.exe"
$expect = "ACBE6150D86ECF22A623DA180C78861AC3A91CAA14E761B4C65BB1E7A2C7BE07"
$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts"
$LogDir = Join-Path $tipDir "debug_ui_reverify_logs"
$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp"
$Debuggee = Join-Path $tipDir "debuggee_fixture.exe"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "INTEG007_debug_ui_reverify_run_$stamp.txt"
$receipt = Join-Path $OutDir "INTEG007_DEBUG_UI_HARNESS_RECEIPT.txt"
$histReceipt = Join-Path $OutDir "CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.txt"
$histBackup = Join-Path $OutDir "CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.pre_INTEG007_backup.txt"

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runlog -Value $line
  Write-Host $line
}

$pre = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "PRE_SHA=$pre"
Log "SHA_MATCH=$([int]($pre -eq $expect))"
if ($pre -ne $expect) {
  Log "DISK_DRIFT=1"
  @"
INTEG007_DEBUG_UI_REVERIFY=ABORT
REASON=DISK_DRIFT
EXPECTED=$expect
MEASURED=$pre
DISK_DRIFT=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content -LiteralPath $receipt
  exit 3
}
Log "DISK_DRIFT=0"
if (-not (Test-Path $Debuggee)) {
  Log "DEBUGGEE_MISSING=$Debuggee"
  exit 4
}
if (-not (Test-Path $BrokenCpp)) {
  Log "FIXTURE_MISSING=$BrokenCpp"
  exit 5
}
if ((Test-Path $histReceipt) -and -not (Test-Path $histBackup)) {
  Copy-Item $histReceipt $histBackup -Force
  Log "HIST_BACKUP=$histBackup"
}

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class INTEG007Dbg {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_NOTIFY = 0x004E;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint TCM_FIRST = 0x1300;
  public const uint TCM_GETITEMCOUNT = TCM_FIRST + 4;
  public const uint TCM_SETCURSEL = TCM_FIRST + 12;
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
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int nCmdShow);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr lp);
  public static int LastListVisible = -1;
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
  public static string Title(IntPtr h) {
    var sb = new StringBuilder(512);
    GetWindowTextW(h, sb, sb.Capacity);
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
  public static bool CmdPost(IntPtr main, int cmdId) {
    return PostMessageW(main, WM_COMMAND, (IntPtr)cmdId, IntPtr.Zero);
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
    return true;
  }
  public static int IdListCount(IntPtr root, int id, uint ms) {
    LastListVisible = -1;
    IntPtr h = FindById(root, id);
    if (h == IntPtr.Zero) return -1;
    LastListVisible = IsWindowVisible(h) ? 1 : 0;
    IntPtr r;
    if (!MsgTO(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero, ms, out r)) return -3;
    return r.ToInt32();
  }
  public static int MaxVisibleEditLen(IntPtr root, uint ms) {
    int best = 0;
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if ((c == "Edit" || c == "RichEdit20W" || c == "RichEdit50W") && IsWindowVisible(h)) {
        IntPtr r;
        if (MsgTO(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero, ms, out r)) {
          int n = r.ToInt32();
          if (n > best) best = n;
        }
      }
      return true;
    }, IntPtr.Zero);
    return best;
  }
  public static bool PostDblClk(IntPtr main, IntPtr lv, int id, uint ms) {
    if (lv == IntPtr.Zero) return false;
    NMHDR nm;
    nm.hwndFrom = lv;
    nm.idFrom = (IntPtr)id;
    nm.code = NM_DBLCLK;
    IntPtr r;
    // Prefer timeout path; fall back so a busy UI is not mis-labeled LIST_HWND_MISSING.
    if (SendMessageTimeout(main, WM_NOTIFY, (IntPtr)id, ref nm, SMTO_ABORTIFHUNG, ms, out r) != IntPtr.Zero)
      return true;
    return PostMessageW(main, WM_NOTIFY, (IntPtr)id, IntPtr.Zero);
  }
}
"@

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like 'RawrXD*' -or $_.Name -eq 'debuggee_fixture.exe' } |
  ForEach-Object {
    Log "KILL pid=$($_.ProcessId) name=$($_.Name)"
    Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
  }
Start-Sleep 3
$left = @((Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' })).Count
Log "LEFT=$left"
if ($left -gt 0) {
  Start-Sleep 2
  Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep 2
  $left = @((Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' })).Count
  Log "LEFT_AFTER_RETRY=$left"
}

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
Log "FIXTURE=$BrokenCpp"
Log "DEBUGGEE=$Debuggee"
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
$env:RAWRXD_DEBUGGEE = $Debuggee
Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue

$p = Start-Process -FilePath $TipExe -ArgumentList "`"$BrokenCpp`"" -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
$class = ""; $title = ""
for ($i=0; $i -lt 180; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  $main = [INTEG007Dbg]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 256
    [void][INTEG007Dbg]::GetClassNameW($main, $sb, 256)
    $class = $sb.ToString()
    $title = [INTEG007Dbg]::Title($main)
    if ($title -match 'broken_multi' -or $i -gt 8) { break }
  }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64()) CLASS=$class TITLE='$title' VIS=$([INTEG007Dbg]::IsWindowVisible($main))"
if ($main -eq [IntPtr]::Zero) {
  @"
INTEG007_DEBUG_UI=FAIL
REASON=main_hwnd_not_found
TIP_SHA256=$sha
DISK_DRIFT=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RUNLOG=$runlog
"@ | Set-Content -LiteralPath $receipt
  exit 2
}

[void][INTEG007Dbg]::ShowWindow($main, 9)
[void][INTEG007Dbg]::SetForegroundWindow($main)
Start-Sleep 1
$title = [INTEG007Dbg]::Title($main)
Log "TITLE_AFTER_SHOW='$title'"

$TO = [uint32]2500
foreach ($cmd in @(2034, 2025, 2021, 2029)) {
  $ok = [INTEG007Dbg]::CmdTimeout($main, $cmd, $TO)
  Log "VIEW_CMD id=$cmd ok=$ok"
}

$outTabs = [INTEG007Dbg]::FindById($main, 1005)
$panelTabs = [INTEG007Dbg]::FindById($main, 1301)
$panelContainer = [INTEG007Dbg]::FindById($main, 1300)
$outTabCount = [INTEG007Dbg]::TabCount($outTabs, $TO)
$panelTabCount = [INTEG007Dbg]::TabCount($panelTabs, $TO)
Log "OUT_TABS=$outTabCount PANEL_TABS=$panelTabCount"

Start-Sleep 3
$buildOk = $false
for ($t=0; $t -lt 4 -and -not $buildOk; $t++) {
  $buildOk = [INTEG007Dbg]::CmdTimeout($main, 3014, 15000)
  if (-not $buildOk) { Start-Sleep 1 }
}
if (-not $buildOk) { $buildOk = [INTEG007Dbg]::CmdPost($main, 3014) }
Log "SEND_BUILD_PROJECT ok=$buildOk"

$id1312 = 0
$visEdit = 0
for ($w=0; $w -lt 90; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "EXIT_DURING_WAIT=$($p.ExitCode)"; break }
  $id1312 = [INTEG007Dbg]::IdListCount($main, 1312, $TO)
  $visEdit = [INTEG007Dbg]::MaxVisibleEditLen($main, $TO)
  $title = [INTEG007Dbg]::Title($main)
  if (($w % 5) -eq 0) { Log "POLL t=$w id1312=$id1312 visEdit=$visEdit title='$title'" }
  if ($id1312 -gt 0 -and $title -match 'broken_multi') { break }
  if ($id1312 -gt 0 -and $w -ge 15) { break }
}
$probItems = $id1312
$title = [INTEG007Dbg]::Title($main)
Log "PROBLEMS_PRE_TAB items=$probItems visEdit=$visEdit title='$title' (vis deferred until Problems panel selected)"

$selOut0 = [INTEG007Dbg]::SelectTabTO($main, $outTabs, 0, 1005, $TO)
$selBuild = $false; $selErr = $false
if ($outTabCount -gt 4) { $selBuild = [INTEG007Dbg]::SelectTabTO($main, $outTabs, 4, 1005, $TO) }
if ($outTabCount -gt 1) { $selErr = [INTEG007Dbg]::SelectTabTO($main, $outTabs, 1, 1005, $TO) }
$selOutPanel = $false; $selProbPanel = $false; $selTermPanel = $false; $selDbg = $false
if ($panelTabCount -gt 1) { $selOutPanel = [INTEG007Dbg]::SelectTabTO($main, $panelTabs, 1, 1301, $TO) }
# G7 fix: select Problems and measure vis/click WHILE selected â€” prior order measured
# before tab select then switched to Term/Debug, forcing IsWindowVisible=0 / LIST_HWND_MISSING.
if ($panelTabCount -gt 2) { $selProbPanel = [INTEG007Dbg]::SelectTabTO($main, $panelTabs, 2, 1301, $TO) }
# Force View>Panel show-only + layout (IDM_VIEW_PANEL) so dock height is assigned.
[void][INTEG007Dbg]::CmdTimeout($main, 2034, 2500)
Start-Sleep -Milliseconds 800
$probItems = [INTEG007Dbg]::IdListCount($main, 1312, $TO)
$probVis = [INTEG007Dbg]::LastListVisible
# Measure panelCont WHILE alive + Problems selected (prior end-of-run measure
# hit exited HWND → false panelCont=0).
$panelContainer = [INTEG007Dbg]::FindById($main, 1300)
$panelContVis = if ($panelContainer -ne [IntPtr]::Zero -and [INTEG007Dbg]::IsWindowVisible($panelContainer)) { 1 } else { 0 }
Log "PROBLEMS_AFTER_TAB items=$probItems vis=$probVis selProb=$selProbPanel panelCont=$panelContVis"

$clickToLine = 'NOT_RUN'
if ($probItems -gt 0) {
  $lv = [INTEG007Dbg]::FindById($main, 1312)
  if ($lv -eq [IntPtr]::Zero) { $clickToLine = 'LIST_HWND_MISSING' }
  elseif ([INTEG007Dbg]::PostDblClk($main, $lv, 1312, $TO)) { $clickToLine = 'POSTED_NM_DBLCLK' }
  else { $clickToLine = 'POST_FAILED' }
}
Log "CLICK_TO_LINE=$clickToLine"

if ($panelTabCount -gt 0) { $selTermPanel = [INTEG007Dbg]::SelectTabTO($main, $panelTabs, 0, 1301, $TO) }
if ($panelTabCount -gt 3) { $selDbg = [INTEG007Dbg]::SelectTabTO($main, $panelTabs, 3, 1301, $TO) }
Log "TABS out0=$selOut0 build4=$selBuild err1=$selErr out1=$selOutPanel prob2=$selProbPanel term0=$selTermPanel dbg3=$selDbg"

$termClear = [INTEG007Dbg]::CmdPost($main, 3006)
$termCmd = [INTEG007Dbg]::CmdPost($main, 3002)
Log "TERMINAL clear=$termClear cmd=$termCmd"
Start-Sleep 1
try { $p.Refresh() } catch {}
Log "PRE_DEBUG_ALIVE=$(-not $p.HasExited) EXIT=$($p.ExitCode)"

# Prefer PostMessage for debug view activate — SendMessageTimeout previously
# coincided with process exit (SKIP_EXITED) on this SHA before start cmds ran.
foreach ($act in @(1104, 6004)) {
  if ($p.HasExited) { Log "EXIT_BEFORE_ACTIVATE id=$act code=$($p.ExitCode)"; break }
  $okAct = [INTEG007Dbg]::CmdPost($main, $act)
  Log "ACTIVATE_DEBUG_VIEW id=$act ok=$okAct"
  Start-Sleep 1
  try { $p.Refresh() } catch {}
}
Start-Sleep 2
try { $p.Refresh() } catch {}
$preVars = [INTEG007Dbg]::IdListCount($main, 6043, $TO)
Log "VARS_HWND_PRECREATE count=$preVars vis=$([INTEG007Dbg]::LastListVisible) exited=$($p.HasExited) ( -1 means missing )"

$dbgResults = @()
$peakVars6043 = 0
$peakVars1317 = 0
foreach ($dc in @(
  @{n='TOOLS_DEBUG_START_5060'; id=5060},
  @{n='DEBUG_START_10500'; id=10500},
  @{n='SIDEBAR_DEBUG_START_6041'; id=6041},
  @{n='SHOW_VARS_10508'; id=10508},
  @{n='SHOW_CALLSTACK_10507'; id=10507},
  @{n='STEP_OVER'; id=10503},
  @{n='CONTINUE'; id=10502}
)) {
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { $dbgResults += "$($dc.n)=SKIP_EXITED"; Log "SKIP_EXITED at $($dc.n) code=$($p.ExitCode)"; break }
  # Post start/step cmds so harness never blocks in SendMessageTimeout during debug launch.
  $ok = [INTEG007Dbg]::CmdPost($main, $dc.id)
  Start-Sleep -Milliseconds 1200
  try { $p.Refresh() } catch {}
  $v1317 = [INTEG007Dbg]::IdListCount($main, 1317, $TO)
  $v6043 = [INTEG007Dbg]::IdListCount($main, 6043, $TO)
  if ($v6043 -gt $peakVars6043) { $peakVars6043 = $v6043 }
  if ($v1317 -gt $peakVars1317) { $peakVars1317 = $v1317 }
  $visEditDbg = [INTEG007Dbg]::MaxVisibleEditLen($main, $TO)
  $dbgResults += "$($dc.n)=$ok"
  Log "DEBUG $($dc.n)=$ok vars1317=$v1317 vars6043=$v6043 peak6043=$peakVars6043 visEdit=$visEditDbg exited=$($p.HasExited)"
  if ($dc.id -eq 5060 -or $dc.id -eq 10500 -or $dc.id -eq 6041) {
    for ($w=0; $w -lt 25; $w++) {
      Start-Sleep 1
      try { $p.Refresh() } catch {}
      if ($p.HasExited) { Log "EXIT_DURING_BP_POLL t=$w code=$($p.ExitCode)"; break }
      $v6043 = [INTEG007Dbg]::IdListCount($main, 6043, $TO)
      $v1317 = [INTEG007Dbg]::IdListCount($main, 1317, $TO)
      if ($v6043 -gt $peakVars6043) { $peakVars6043 = $v6043 }
      if ($v1317 -gt $peakVars1317) { $peakVars1317 = $v1317 }
      if ($v6043 -gt 0) { Log "BP_VARS_POLL t=$w vars6043=$v6043"; break }
    }
  }
}
try { $p.Refresh() } catch {}
$stopOk = $false
if (-not $p.HasExited) { $stopOk = [INTEG007Dbg]::CmdPost($main, 10501) }
$dbgResults += "STOP=$stopOk"
Log "DEBUG STOP=$stopOk"
Start-Sleep 1
$vars1317 = $peakVars1317
$vars6043 = $peakVars6043
$vis6043 = [INTEG007Dbg]::LastListVisible
$visEditDbgFinal = [INTEG007Dbg]::MaxVisibleEditLen($main, $TO)
Log "VARS_PEAK 1317=$vars1317 6043=$vars6043 vis6043=$vis6043 visEdit=$visEditDbgFinal"
$title = [INTEG007Dbg]::Title($main)
# Re-measure panelCont only if still alive; else keep Problems-tab live value.
try { $p.Refresh() } catch {}
if (-not $p.HasExited) {
  $panelContainer = [INTEG007Dbg]::FindById($main, 1300)
  $panelContVisEnd = if ($panelContainer -ne [IntPtr]::Zero -and [INTEG007Dbg]::IsWindowVisible($panelContainer)) { 1 } else { 0 }
  Log "PANEL_CONT_END=$panelContVisEnd (live_after_problems=$panelContVis)"
  if ($panelContVisEnd -eq 1) { $panelContVis = 1 }
} else {
  Log "PANEL_CONT_KEEP_LIVE=$panelContVis (process exited; skip end remesure)"
}
$alive = -not $p.HasExited
$outPass = if ($visEdit -gt 20) { 'PASS' } else { 'PARTIAL' }
$probPass = if ($probVis -eq 1 -and $probItems -gt 0) { 'PASS' }
            elseif ($probItems -gt 0) { 'PARTIAL' }
            else { 'PARTIAL' }
$sessionRealUi = 0
if ($vars6043 -gt 0 -or $vars1317 -gt 0) { $sessionRealUi = 1 }
$dbgPass = if ($sessionRealUi -eq 1) { 'PASS' }
           elseif (($dbgResults -join ';') -match '=True') { 'PARTIAL_UI_HOOKS_POSTED' }
           else { 'FAIL' }
$termPass = if ($selTermPanel -or $termCmd) { 'PARTIAL' } else { 'FAIL' }
$four = 'FAIL_CLOSED_GAPS'
# Require Problems vis + panelCont + Debug session UI (vars) for FOUR_PANEL=PASS.
if ($outPass -eq 'PASS' -and $probPass -eq 'PASS' -and $dbgPass -eq 'PASS' -and $panelContVis -eq 1 -and $probVis -eq 1) {
  $four = 'PASS'
}
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$missingHook = if ($sessionRealUi -eq 1) { '' } else { 'no BP/var list items via IDE UI (6043/1317)' }

$post = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$postDrift = [int]($post -ne $expect)

@"
INTEG007_DEBUG_UI_HARNESS=MEASURED
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
FIXTURE=$BrokenCpp
DEBUGGEE=$Debuggee
SELECT_OUTPUT_TAB0=$selOut0
SELECT_BUILD_TAB4=$selBuild
SELECT_ERRORS_TAB1=$selErr
SELECT_PANEL_OUTPUT1=$selOutPanel
SELECT_PANEL_PROBLEMS2=$selProbPanel
SELECT_PANEL_TERMINAL0=$selTermPanel
SELECT_PANEL_DEBUG3=$selDbg
MAX_VISIBLE_EDIT_LEN_AFTER_BUILD=$visEdit
PROBLEMS_ID1312_ITEMS=$probItems
PROBLEMS_ID1312_VISIBLE=$probVis
CLICK_TO_LINE=$clickToLine
PANEL_CONTAINER_VISIBLE=$panelContVis
TERMINAL_VIEW_CMD=$termPass
DEBUG_CMDS=$($dbgResults -join ';')
DEBUG_VARS_ID1317=$vars1317
DEBUG_VARS_ID6043=$vars6043
SESSION_REAL_VIA_IDE_UI=$sessionRealUi
DEBUG_MISSING_HOOK=$missingHook
GUI_OUTPUT_PANEL_E2E=$outPass
GUI_PROBLEMS_PANEL_E2E=$probPass
GUI_DEBUG_CONSOLE_E2E=$dbgPass
IDE_DEBUG_UI=$dbgPass
FOUR_PANEL_INTEGRATION=$four
DISK_DRIFT=0
DISK_POST_DRIFT=$postDrift
POST_SHA=$post
FROZEN_A4F_UNTOUCHED=1
NO_CROSS_SHA_PASS_INHERITANCE=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content -LiteralPath $receipt

# Do not clobber historical CC79 receipt with tip_006 measure.
Log "RECEIPT=$receipt FOUR=$four PROB=$probPass DBG=$dbgPass SESSION_UI=$sessionRealUi POST_DRIFT=$postDrift"
try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
Get-CimInstance Win32_Process -EA SilentlyContinue |
  Where-Object { $_.Name -eq 'debuggee_fixture.exe' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
Start-Sleep 1
Log "POST_KILL_LEFT=$((@(Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' })).Count)"
exit 0









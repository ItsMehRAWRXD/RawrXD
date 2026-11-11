# G5_DEBUG_UI_REVERIFY — tip_final_integ_006 only. PROMOTE=0. No tip-move.
# Based on cc79_followup_four_panel_probe.ps1; points at INTEG_006 + local debuggee.
$ErrorActionPreference = 'Continue'
$tipDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_006"
$TipExe = Join-Path $tipDir "RawrXD-Win32IDE-Native-Ext.exe"
$expect = "B50A2AB10C4261CCC085AB74C02B5979A26FEED714BE3E628DEBFAAF6D041CFC"
$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts"
$LogDir = Join-Path $tipDir "debug_ui_reverify_logs"
$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp"
$Debuggee = Join-Path $tipDir "debuggee_fixture.exe"
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "integ006_debug_ui_reverify_run_$stamp.txt"
$receipt = Join-Path $OutDir "INTEG006_DEBUG_UI_HARNESS_RECEIPT.txt"
$histReceipt = Join-Path $OutDir "CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.txt"
$histBackup = Join-Path $OutDir "CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.pre_integ006_backup.txt"

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
INTEG006_DEBUG_UI_REVERIFY=ABORT
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
public static class Integ006Dbg {
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
    return SendMessageTimeout(main, WM_NOTIFY, (IntPtr)id, ref nm, SMTO_ABORTIFHUNG, ms, out r) != IntPtr.Zero;
  }
}
"@

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like 'RawrXD*' -or $_.Name -eq 'debuggee_fixture.exe' } |
  ForEach-Object {
    Log "KILL pid=$($_.ProcessId) name=$($_.Name)"
    Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
  }
Start-Sleep 2
$left = @((Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'RawrXD*' })).Count
Log "LEFT=$left"

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
  $main = [Integ006Dbg]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 256
    [void][Integ006Dbg]::GetClassNameW($main, $sb, 256)
    $class = $sb.ToString()
    $title = [Integ006Dbg]::Title($main)
    if ($title -match 'broken_multi' -or $i -gt 8) { break }
  }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64()) CLASS=$class TITLE='$title' VIS=$([Integ006Dbg]::IsWindowVisible($main))"
if ($main -eq [IntPtr]::Zero) {
  @"
INTEG006_DEBUG_UI=FAIL
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

[void][Integ006Dbg]::ShowWindow($main, 9)
[void][Integ006Dbg]::SetForegroundWindow($main)
Start-Sleep 1
$title = [Integ006Dbg]::Title($main)
Log "TITLE_AFTER_SHOW='$title'"

$TO = [uint32]2500
# 2034/2025/2021 each toggleOutputPanel(); an odd count leaves
# m_outputPanelVisible=false → onSize SW_HIDE panel container → id1312 vis=0.
# End on an even toggle (panel shown). 2029 only toggles terminal panes.
foreach ($cmd in @(2034, 2025, 2021, 2025, 2029)) {
  $ok = [Integ006Dbg]::CmdTimeout($main, $cmd, $TO)
  Log "VIEW_CMD id=$cmd ok=$ok"
}
# Ensure docked panel surface up before build/Problems measure.
$ensurePanel = [Integ006Dbg]::CmdTimeout($main, 1300, $TO)
Log "ENSURE_PANEL_1300 ok=$ensurePanel"

$outTabs = [Integ006Dbg]::FindById($main, 1005)
$panelTabs = [Integ006Dbg]::FindById($main, 1301)
$panelContainer = [Integ006Dbg]::FindById($main, 1300)
$outTabCount = [Integ006Dbg]::TabCount($outTabs, $TO)
$panelTabCount = [Integ006Dbg]::TabCount($panelTabs, $TO)
Log "OUT_TABS=$outTabCount PANEL_TABS=$panelTabCount"

Start-Sleep 3
$buildOk = $false
for ($t=0; $t -lt 4 -and -not $buildOk; $t++) {
  $buildOk = [Integ006Dbg]::CmdTimeout($main, 3014, 15000)
  if (-not $buildOk) { Start-Sleep 1 }
}
if (-not $buildOk) { $buildOk = [Integ006Dbg]::CmdPost($main, 3014) }
Log "SEND_BUILD_PROJECT ok=$buildOk"

$id1312 = 0
$visEdit = 0
for ($w=0; $w -lt 90; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "EXIT_DURING_WAIT=$($p.ExitCode)"; break }
  $id1312 = [Integ006Dbg]::IdListCount($main, 1312, $TO)
  $visEdit = [Integ006Dbg]::MaxVisibleEditLen($main, $TO)
  $title = [Integ006Dbg]::Title($main)
  if (($w % 5) -eq 0) { Log "POLL t=$w id1312=$id1312 visEdit=$visEdit title='$title'" }
  if ($id1312 -gt 0 -and $title -match 'broken_multi') { break }
  if ($id1312 -gt 0 -and $w -ge 15) { break }
}
$probItems = $id1312
$title = [Integ006Dbg]::Title($main)
Log "PROBLEMS_PRE_TAB items=$probItems visEdit=$visEdit title='$title' (vis deferred until Problems panel selected)"

$selOut0 = [Integ006Dbg]::SelectTabTO($main, $outTabs, 0, 1005, $TO)
$selBuild = $false; $selErr = $false
if ($outTabCount -gt 4) { $selBuild = [Integ006Dbg]::SelectTabTO($main, $outTabs, 4, 1005, $TO) }
if ($outTabCount -gt 1) { $selErr = [Integ006Dbg]::SelectTabTO($main, $outTabs, 1, 1005, $TO) }
$selOutPanel = $false; $selProbPanel = $false; $selTermPanel = $false; $selDbg = $false
if ($panelTabCount -gt 1) { $selOutPanel = [Integ006Dbg]::SelectTabTO($main, $panelTabs, 1, 1301, $TO) }
# G7 fix: select Problems and measure vis/click WHILE selected — prior order measured
# before tab select then switched to Term/Debug, forcing IsWindowVisible=0 / LIST_HWND_MISSING.
# Rely on even VIEW toggles + ENSURE_PANEL_1300 to keep m_outputPanelVisible/panel dock up.
# Do NOT WM_COMMAND 1312 here (goToProblem/refresh can race list HWND during measure).
if ($panelTabCount -gt 2) { $selProbPanel = [Integ006Dbg]::SelectTabTO($main, $panelTabs, 2, 1301, $TO) }
Start-Sleep -Milliseconds 600
$probItems = [Integ006Dbg]::IdListCount($main, 1312, $TO)
$probVis = [Integ006Dbg]::LastListVisible
$pcNow = [Integ006Dbg]::FindById($main, 1300)
$panelContVisNow = if ($pcNow -ne [IntPtr]::Zero -and [Integ006Dbg]::IsWindowVisible($pcNow)) { 1 } else { 0 }
Log "PROBLEMS_AFTER_TAB items=$probItems vis=$probVis selProb=$selProbPanel panelCont=$panelContVisNow"

$clickToLine = 'NOT_RUN'
if ($probItems -gt 0) {
  $lv = [Integ006Dbg]::FindById($main, 1312)
  if ($lv -eq [IntPtr]::Zero) { $clickToLine = 'LIST_HWND_MISSING' }
  elseif ([Integ006Dbg]::PostDblClk($main, $lv, 1312, $TO)) { $clickToLine = 'POSTED_NM_DBLCLK' }
  else { $clickToLine = 'POST_FAILED' }
}
Log "CLICK_TO_LINE=$clickToLine"

if ($panelTabCount -gt 0) { $selTermPanel = [Integ006Dbg]::SelectTabTO($main, $panelTabs, 0, 1301, $TO) }
if ($panelTabCount -gt 3) { $selDbg = [Integ006Dbg]::SelectTabTO($main, $panelTabs, 3, 1301, $TO) }
Log "TABS out0=$selOut0 build4=$selBuild err1=$selErr out1=$selOutPanel prob2=$selProbPanel term0=$selTermPanel dbg3=$selDbg"

$termClear = [Integ006Dbg]::CmdTimeout($main, 3006, 1500)
$termCmd = [Integ006Dbg]::CmdTimeout($main, 3002, 1500)
Log "TERMINAL clear=$termClear cmd=$termCmd"

foreach ($act in @(1104, 6004)) {
  $okAct = [Integ006Dbg]::CmdTimeout($main, $act, 2000)
  Log "ACTIVATE_DEBUG_VIEW id=$act ok=$okAct"
  Start-Sleep -Milliseconds 400
}
$preVars = [Integ006Dbg]::IdListCount($main, 6043, $TO)
Log "VARS_HWND_PRECREATE count=$preVars vis=$([Integ006Dbg]::LastListVisible) ( -1 means missing )"

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
  if ($p.HasExited) { $dbgResults += "$($dc.n)=SKIP_EXITED"; break }
  $ok = [Integ006Dbg]::CmdTimeout($main, $dc.id, 5000)
  Start-Sleep -Milliseconds 900
  $v1317 = [Integ006Dbg]::IdListCount($main, 1317, $TO)
  $v6043 = [Integ006Dbg]::IdListCount($main, 6043, $TO)
  if ($v6043 -gt $peakVars6043) { $peakVars6043 = $v6043 }
  if ($v1317 -gt $peakVars1317) { $peakVars1317 = $v1317 }
  $visEditDbg = [Integ006Dbg]::MaxVisibleEditLen($main, $TO)
  $dbgResults += "$($dc.n)=$ok"
  Log "DEBUG $($dc.n)=$ok vars1317=$v1317 vars6043=$v6043 peak6043=$peakVars6043 visEdit=$visEditDbg exited=$($p.HasExited)"
  if ($dc.id -eq 5060 -or $dc.id -eq 10500 -or $dc.id -eq 6041) {
    for ($w=0; $w -lt 15; $w++) {
      Start-Sleep 1
      $v6043 = [Integ006Dbg]::IdListCount($main, 6043, $TO)
      $v1317 = [Integ006Dbg]::IdListCount($main, 1317, $TO)
      if ($v6043 -gt $peakVars6043) { $peakVars6043 = $v6043 }
      if ($v1317 -gt $peakVars1317) { $peakVars1317 = $v1317 }
      if ($v6043 -gt 0) { Log "BP_VARS_POLL t=$w vars6043=$v6043"; break }
    }
  }
}
$stopOk = [Integ006Dbg]::CmdTimeout($main, 10501, 5000)
$dbgResults += "STOP=$stopOk"
Log "DEBUG STOP=$stopOk"
Start-Sleep 1
$vars1317 = $peakVars1317
$vars6043 = $peakVars6043
$vis6043 = [Integ006Dbg]::LastListVisible
$visEditDbgFinal = [Integ006Dbg]::MaxVisibleEditLen($main, $TO)
Log "VARS_PEAK 1317=$vars1317 6043=$vars6043 vis6043=$vis6043 visEdit=$visEditDbgFinal"
$title = [Integ006Dbg]::Title($main)

$panelContVis = if ($panelContainer -ne [IntPtr]::Zero -and [Integ006Dbg]::IsWindowVisible($panelContainer)) { 1 } else { 0 }
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
if ($outPass -eq 'PASS' -and $probPass -eq 'PASS' -and $dbgPass -eq 'PASS') { $four = 'PASS' }
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$missingHook = if ($sessionRealUi -eq 1) { '' } else { 'no BP/var list items via IDE UI (6043/1317)' }

$post = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$postDrift = [int]($post -ne $expect)

@"
INTEG006_DEBUG_UI_HARNESS=MEASURED
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

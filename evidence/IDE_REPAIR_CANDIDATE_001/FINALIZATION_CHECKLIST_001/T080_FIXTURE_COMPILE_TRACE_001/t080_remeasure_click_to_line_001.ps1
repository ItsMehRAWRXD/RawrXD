# T080 click-to-line remasure (PROMOTE=0; NOT_RUN!=PASS; tip_ext_host lane)
$ErrorActionPreference = 'Continue'
$EvidenceDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\T080_FIXTURE_COMPILE_TRACE_001'
$OutFile = Join-Path $EvidenceDir 'T080_CLICK_TO_LINE_001.txt'
$TipExe = 'F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe'
$TipCwd = 'F:\rawrxd\build_tip_ext_host_001\bin'
$Fixture = 'F:\rawrxd\T080_test_bad.cpp'
$Console = Join-Path $EvidenceDir 't080_click_to_line_console_001.txt'
$PriorSha = '8EE30F97C6137E250237E01F2535935641690E82B1D48427F326E09CA28DE8B9'
'' | Set-Content -Path $Console -Encoding ascii

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class T080CTL {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextLength(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, ref CHARRANGE cr);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, ref RECT r);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [StructLayout(LayoutKind.Sequential)] public struct CHARRANGE { public int cpMin; public int cpMax; }
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  public const uint TCM_SETCURSEL = 0x130C;
  public const uint TCM_GETITEMCOUNT = 0x1304;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint LVM_ENSUREVISIBLE = 0x1013;
  public const uint LVM_GETITEMRECT = 0x100E;
  public const uint EM_GETSEL = 0x00B0;
  public const uint EM_EXGETSEL = 0x0434;
  public static string Title(IntPtr h) {
    int n = GetWindowTextLength(h); if (n <= 0) return "";
    var sb = new StringBuilder(n+2); GetWindowText(h, sb, n+1); return sb.ToString();
  }
  public static string Cls(IntPtr h) {
    var sb = new StringBuilder(256); GetClassName(h, sb, 256); return sb.ToString();
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p == pid) {
        string t = Title(h);
        if (!string.IsNullOrEmpty(t) && t.IndexOf("RawrXD", StringComparison.OrdinalIgnoreCase) >= 0) {
          found = h; return false;
        }
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public class Ctrl {
    public IntPtr Hwnd; public string ClassName; public int Id; public int WmLen; public bool Visible;
  }
  public static List<Ctrl> EnumAll(IntPtr main) {
    var list = new List<Ctrl>();
    EnumChildWindows(main, (h,l) => {
      string c = Cls(h);
      int id = GetDlgCtrlID(h);
      int wm = 0;
      if (c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0
          || c.IndexOf("RICHEDIT", StringComparison.OrdinalIgnoreCase) >= 0
          || c.Equals("Edit", StringComparison.OrdinalIgnoreCase)
          || c.IndexOf("SysListView32", StringComparison.OrdinalIgnoreCase) >= 0
          || c.IndexOf("SysTabControl32", StringComparison.OrdinalIgnoreCase) >= 0) {
        if (c.IndexOf("SysListView32", StringComparison.OrdinalIgnoreCase) >= 0)
          wm = (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
        else if (c.IndexOf("SysTabControl32", StringComparison.OrdinalIgnoreCase) >= 0)
          wm = (int)SendMessageW(h, TCM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
        else
          wm = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        list.Add(new Ctrl{ Hwnd=h, ClassName=c, Id=id, WmLen=wm, Visible=IsWindowVisible(h) });
      }
      return true;
    }, IntPtr.Zero);
    return list;
  }
  public static void ReadSel(IntPtr editor, out int a, out int b) {
    a = 0; b = 0;
    CHARRANGE cr = new CHARRANGE();
    SendMessage(editor, EM_EXGETSEL, IntPtr.Zero, ref cr);
    if (cr.cpMin != 0 || cr.cpMax != 0) { a = cr.cpMin; b = cr.cpMax; return; }
    long packed = SendMessageW(editor, EM_GETSEL, IntPtr.Zero, IntPtr.Zero).ToInt64();
    a = (int)(packed & 0xFFFF);
    b = (int)((packed >> 16) & 0xFFFF);
  }
}
"@

function Log([string]$m) {
  $line = "{0} {1}" -f (Get-Date).ToString('o'), $m
  Write-Host $line
  Add-Content -Path $Console -Value $line -Encoding ascii
}

$sha = (Get-FileHash -Algorithm SHA256 $TipExe).Hash
Set-Content -LiteralPath (Join-Path $EvidenceDir 'tip_sha_post_rebuild.txt') -Value $sha -Encoding ascii
$fixtureBytes = (Get-Item $Fixture).Length
Log "TIP_SHA256=$sha PRIOR_8EE30F97=$PriorSha FIXTURE_BYTES=$fixtureBytes"

$env:RAWRXD_PROBLEMS_FIXTURE = $Fixture
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.Arguments = "`"$Fixture`""
$psi.WorkingDirectory = $TipCwd
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$idePid = $proc.Id
Log "LAUNCHED PID=$idePid"

$title = ''; $titleMatch = $false
$mainHwnd = [IntPtr]::Zero
$editorHwnd = [IntPtr]::Zero
$docLen = -1; $docDetail = ''
$plainEditLen = -1; $richLargest = -1

for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Milliseconds 400
  if ($proc.HasExited) { Log "EXITED_EARLY code=$($proc.ExitCode) iter=$i"; break }
  $mainHwnd = [T080CTL]::FindMain([uint32]$idePid)
  if ($mainHwnd -eq [IntPtr]::Zero) { continue }
  $title = [T080CTL]::Title($mainHwnd)
  $titleMatch = $title -like '*T080_test_bad.cpp*'
  $ctrls = [T080CTL]::EnumAll($mainHwnd)
  $by1001 = $ctrls | Where-Object { $_.Id -eq 1001 } | Select-Object -First 1
  if ($by1001) {
    $editorHwnd = $by1001.Hwnd
    $docLen = $by1001.WmLen
    $docDetail = "id=1001 class=$($by1001.ClassName) hwnd=0x$('{0:X}' -f $by1001.Hwnd.ToInt64()) wm=$($by1001.WmLen) vis=$($by1001.Visible)"
  }
  $plain = $ctrls | Where-Object { $_.ClassName -eq 'Edit' } | Sort-Object WmLen -Descending | Select-Object -First 1
  if ($plain) { $plainEditLen = $plain.WmLen }
  $rich = $ctrls | Where-Object { $_.ClassName -match 'RichEdit|RICHEDIT' } | Sort-Object WmLen -Descending | Select-Object -First 1
  if ($rich) { $richLargest = $rich.WmLen }
  Log "ITER=$i MATCH=$titleMatch DOC1001=$docLen TITLE='$title'"
  if ($titleMatch -and $i -ge 6) { break }
}

$isRichDoc = $docDetail -match 'RichEdit|RICHEDIT'
$bufferPass = ($isRichDoc -and $docLen -ge $fixtureBytes)
Log "BUFFER_PASS=$bufferPass DOC=$docLen DETAIL=$docDetail"

$clSpawned = 'N'; $problemsRows = -1
$problemsHwnd = [IntPtr]::Zero; $problemsDetail = ''
$clickToLine = 'NOT_ATTEMPTED'; $clickMethod = 'NONE'
$ideExitedDuring = $false; $msbuildSeen = 'N'
$clWatchPath = Join-Path $EvidenceDir 'cl_spawn_watch_click_to_line_001.txt'
$clLines = New-Object System.Collections.Generic.List[string]
$captureSnap = ''
$selBeforeA = 0; $selBeforeB = 0; $selAfterA = 0; $selAfterB = 0
$b12Snap = ''

if (-not $proc.HasExited -and $mainHwnd -ne [IntPtr]::Zero) {
  [void][T080CTL]::SetForegroundWindow($mainHwnd)
  $ctrls = [T080CTL]::EnumAll($mainHwnd)
  $tabs = $ctrls | Where-Object { $_.ClassName -match 'SysTabControl32' -and ($_.Id -eq 1301 -or $_.WmLen -ge 3) } | Select-Object -First 1
  if ($tabs) {
    [void][T080CTL]::SendMessageW($tabs.Hwnd, [T080CTL]::TCM_SETCURSEL, [IntPtr]2, [IntPtr]::Zero)
    Log "TAB_SELECT id=$($tabs.Id)"
  }
  $buildRc = [T080CTL]::SendMessageW($mainHwnd, [T080CTL]::WM_COMMAND, [IntPtr]3014, [IntPtr]::Zero)
  Log "BUILD_CMD_3014 rc=$buildRc"

  $deadline = (Get-Date).AddSeconds(25)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { $ideExitedDuring = $true; Log "IDE_EXITED_DURING_WATCH"; break }
    try {
      foreach ($name in @('cl.exe','MSBuild.exe','cmake.exe')) {
        $cls = Get-CimInstance Win32_Process -Filter "Name='$name'" -ErrorAction SilentlyContinue
        foreach ($c in $cls) {
          $walk = $c.ParentProcessId; $ok = $false
          for ($d=0; $d -lt 8 -and $walk -gt 0; $d++) {
            if ($walk -eq $idePid) { $ok = $true; break }
            $par = Get-CimInstance Win32_Process -Filter "ProcessId=$walk" -ErrorAction SilentlyContinue
            if (-not $par) { break }
            $walk = $par.ParentProcessId
          }
          if ($ok) {
            $line = "t=$((Get-Date).ToString('o')) name=$name pid=$($c.ProcessId) ppid=$($c.ParentProcessId)"
            if (-not ($clLines | Where-Object { $_ -eq $line })) {
              $clLines.Add($line)
              if ($name -eq 'cl.exe') { $clSpawned = 'Y'; Log "CL_SPAWNED pid=$($c.ProcessId)" }
              if ($name -eq 'MSBuild.exe' -or $name -eq 'cmake.exe') { $msbuildSeen = 'Y' }
            }
          }
        }
      }
    } catch { Log "CL_WATCH_ERR $($_.Exception.Message)" }

    $ctrls = [T080CTL]::EnumAll($mainHwnd)
    $pref = @($ctrls | Where-Object { $_.ClassName -match 'SysListView32' -and $_.Id -eq 1312 }) | Select-Object -First 1
    if ($pref) {
      $problemsHwnd = $pref.Hwnd
      $problemsRows = $pref.WmLen
      $problemsDetail = "id=$($pref.Id) hwnd=0x$('{0:X}' -f $pref.Hwnd.ToInt64()) rows=$($pref.WmLen) vis=$($pref.Visible)"
      Log "PROBLEMS $problemsDetail"
      if ($problemsRows -gt 0) { break }
    }
    Start-Sleep -Milliseconds 800
  }
  $clLines | Set-Content -Encoding ascii $clWatchPath

  $capPath = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\COMPILER_CAPTURE_RECEIPT.txt'
  if (Test-Path -LiteralPath $capPath) {
    $captureSnap = Get-Content -LiteralPath $capPath -Raw
    Set-Content -LiteralPath (Join-Path $EvidenceDir 'COMPILER_CAPTURE_RECEIPT_snap_click_to_line_001.txt') -Value $captureSnap -Encoding ascii
  }

  # Activate path: WM_COMMAND 1399 (goToProblem idx) then 1312. No LVM_SETITEMSTATE.
  if (-not $proc.HasExited -and $problemsRows -gt 0 -and $editorHwnd -ne [IntPtr]::Zero) {
    [void][T080CTL]::SetForegroundWindow($mainHwnd)
    [T080CTL]::ReadSel($editorHwnd, [ref]$selBeforeA, [ref]$selBeforeB)
    Log "SEL_BEFORE a=$selBeforeA b=$selBeforeB"

    $rc1399 = [T080CTL]::SendMessageW($mainHwnd, [T080CTL]::WM_COMMAND, [IntPtr]1399, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 500
    $proc.Refresh()
    [T080CTL]::ReadSel($editorHwnd, [ref]$selAfterA, [ref]$selAfterB)
    Log "WM_COMMAND_1399 rc=$rc1399 exited=$($proc.HasExited) sel=$selAfterA/$selAfterB"
    if (-not $proc.HasExited -and ($selAfterA -gt 0 -or $selAfterB -gt 0)) {
      $clickToLine = "Y method=WM_COMMAND_1399 selStart=$selAfterA selEnd=$selAfterB"
      $clickMethod = 'WM_COMMAND_1399'
    }

    if ($clickMethod -eq 'NONE' -and -not $proc.HasExited) {
      $rc1312 = [T080CTL]::SendMessageW($mainHwnd, [T080CTL]::WM_COMMAND, [IntPtr]1312, [IntPtr]::Zero)
      Start-Sleep -Milliseconds 500
      $proc.Refresh()
      [T080CTL]::ReadSel($editorHwnd, [ref]$selAfterA, [ref]$selAfterB)
      Log "WM_COMMAND_1312 rc=$rc1312 exited=$($proc.HasExited) sel=$selAfterA/$selAfterB"
      if (-not $proc.HasExited -and ($selAfterA -gt 0 -or $selAfterB -gt 0)) {
        $clickToLine = "Y method=WM_COMMAND_1312 selStart=$selAfterA selEnd=$selAfterB"
        $clickMethod = 'WM_COMMAND_1312'
      }
    }

    if ($clickMethod -eq 'NONE' -and -not $proc.HasExited -and $problemsHwnd -ne [IntPtr]::Zero) {
      [void][T080CTL]::SendMessageW($problemsHwnd, [T080CTL]::LVM_ENSUREVISIBLE, [IntPtr]0, [IntPtr]0)
      $itemRect = New-Object T080CTL+RECT
      $itemRect.L = 0
      [void][T080CTL]::SendMessage($problemsHwnd, [T080CTL]::LVM_GETITEMRECT, [IntPtr]0, [ref]$itemRect)
      $wr = New-Object T080CTL+RECT
      $got = [T080CTL]::GetWindowRect($problemsHwnd, [ref]$wr)
      $cx = [int](($wr.L + $wr.R) / 2)
      $cy = $wr.T + [Math]::Max(12, [int](($itemRect.T + $itemRect.B) / 2))
      Log "CLICK_AT x=$cx y=$cy gotRect=$got"
      if ($got -and $wr.R -gt $wr.L -and $cy -gt 0 -and $cy -lt 20000) {
        [void][T080CTL]::SetCursorPos($cx, $cy)
        Start-Sleep -Milliseconds 60
        [T080CTL]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
        [T080CTL]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 50
        [T080CTL]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
        [T080CTL]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
        Start-Sleep -Milliseconds 700
        $proc.Refresh()
        [T080CTL]::ReadSel($editorHwnd, [ref]$selAfterA, [ref]$selAfterB)
        if (-not $proc.HasExited -and ($selAfterA -gt 0 -or $selAfterB -gt 0)) {
          $clickToLine = "Y method=MOUSE_DBLCLK selStart=$selAfterA selEnd=$selAfterB"
          $clickMethod = 'MOUSE_DBLCLK'
        }
      }
    }

    if ($clickMethod -eq 'NONE') {
      $clickToLine = "ATTEMPTED_NO_SEL_CHANGE selStart=$selAfterA selEnd=$selAfterB"
    }
    Log "CLICK_TO_LINE=$clickToLine METHOD=$clickMethod"
    $b12Path = 'F:\rawrxd\evidence\B12_NAVIGATE_LATEST.log'
    if (Test-Path -LiteralPath $b12Path) {
      $b12Snap = (Get-Content -LiteralPath $b12Path -Raw).Trim()
      Log "B12_NAV=$b12Snap"
    }
  } elseif ($problemsRows -le 0) {
    $clickToLine = 'SKIPPED_PROBLEMS'
  }
} else {
  $clickToLine = 'SKIPPED_IDE_NOT_READY'
}

# SURVIVE: never invent False without process exit.
$proc.Refresh()
$exitedAtSurvive = [bool]$proc.HasExited
$exitCodeAtSurvive = if ($exitedAtSurvive) { $proc.ExitCode } else { '' }
if ($exitedAtSurvive) {
  $survived = $false
  $surviveDetail = "PROCESS_EXITED exitedDuringWatch=$ideExitedDuring exitCode=$exitCodeAtSurvive"
} else {
  $survived = $true
  $surviveDetail = "PROCESS_ALIVE exitedDuringWatch=$ideExitedDuring"
}
Log "SURVIVE survived=$survived detail=$surviveDetail"

$problemsPass = ($problemsRows -gt 0)
$clReceiptOk = ($captureSnap -match 'EXCLUSIVE_FIXTURE_ROUTE=1' -and $captureSnap -match 'PROBLEM_ADDED' -and ($captureSnap -match 'PROCESS_STARTED' -or $captureSnap -match 'DIAGNOSTIC_PARSED'))
$clPass = ($clSpawned -eq 'Y') -or $clReceiptOk
$exclusiveOk = ($captureSnap -match 'EXCLUSIVE_FIXTURE_ROUTE=1')
$cmakeBypassOk = ($msbuildSeen -ne 'Y')
$clickOk = ($clickToLine -like 'Y *')
$t080 = 'FAIL'
if ($titleMatch -and $bufferPass -and $problemsPass -and $clPass -and $survived -and $exclusiveOk -and $cmakeBypassOk -and $clickOk) {
  $t080 = 'PASS'
}

if (-not $proc.HasExited) {
  try { Stop-Process -Id $idePid -Force -ErrorAction Stop; Log "KILLED_PID=$idePid" }
  catch { Log "KILL_ERR $($_.Exception.Message)" }
} else { Log "ALREADY_EXITED pid=$idePid code=$exitCodeAtSurvive" }

$asof = (Get-Date).ToUniversalTime().ToString('o')
@"
T080_CLICK_TO_LINE_001
ASOF_UTC=$asof
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
CONTROLLING=D015
T080=$t080
LAW=NOT_RUN!=PASS
LAW=DO_NOT_INVENT_T080_PASS
LAW=PROMOTE=0
T15=NOT_WIRED

PATCH=F:\rawrxd\src\win32app\Win32IDE_VSCodeUI.cpp;F:\rawrxd\src\win32app\Win32IDE_lifecycle.cpp
PATCH_NOTES=FULLROWSELECT only (no ONECLICKACTIVATE); NM_CLICK/DBLCLK/ITEMACTIVATE PostMessage 1399; goToProblem binds IDC_EDITOR 1001 EM_EXSETSEL

TIP_EXE=$TipExe
TIP_CWD=$TipCwd
TIP_SHA256=$sha
TIP_SHA256_PRIOR_8EE30F97=$PriorSha
NOTE_PRIOR_TIP=8EE30F97 overwritten by tip_ext_host rebuild; remasure on current tip_ext_host binary
LIVE_TIP_LANE=build_tip_ext_host_001
INITIALPATH_ARG=$Fixture
FIXTURE_BYTES=$fixtureBytes
LAUNCH_PID=$idePid
RAWRXD_PROBLEMS_FIXTURE=$Fixture

=== INITIALPATH / BUFFER ===
TITLE_BAR=$title
TITLE_MATCH_T080=$titleMatch
DOCUMENT_EDITOR_ID=1001
DOCUMENT_BUFFER_LEN_WM_GETTEXTLENGTH=$docLen
DOCUMENT_DETAIL=$docDetail
RICHEDIT_LARGEST_ANY=$richLargest
PLAIN_EDIT_LEN=$plainEditLen
BUFFER_PASS=$bufferPass

=== FIXTURE COMPILE / PROBLEMS ===
CL_EXE_SPAWNED=$clSpawned
CL_RECEIPT_PROVED=$clReceiptOk
MSBUILD_OR_CMAKE_SEEN=$msbuildSeen
EXCLUSIVE_FIXTURE_ROUTE_RECEIPT=$exclusiveOk
CMAKE_BYPASS_OK=$cmakeBypassOk
PROBLEMS_ROW_COUNT=$problemsRows
PROBLEMS_DETAIL=$problemsDetail
CLICK_TO_LINE=$clickToLine
CLICK_METHOD=$clickMethod
SEL_BEFORE=$selBeforeA/$selBeforeB
SEL_AFTER=$selAfterA/$selAfterB
B12_NAVIGATE=$b12Snap
IDE_EXITED_DURING_FIXTURE_WATCH=$ideExitedDuring
PROCESS_EXITED_AT_SURVIVE_CHECK=$exitedAtSurvive
SURVIVE_DETAIL=$surviveDetail
SURVIVED=$survived
CL_WATCH=$clWatchPath
CONSOLE=t080_click_to_line_console_001.txt

=== GATE ===
TITLE_OK=$titleMatch
BUFFER_OK=$bufferPass
CL_OK=$clPass
PROBLEMS_OK=$problemsPass
SURVIVE_OK=$survived
CLICK_TO_LINE_OK=$clickOk
EXCLUSIVE_ROUTE_OK=$exclusiveOk
CMAKE_BYPASS_OK=$cmakeBypassOk
T080=$t080
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
CONTROLLING=D015
T15=NOT_WIRED
"@ | Set-Content -Encoding ascii $OutFile
Log "WROTE $OutFile T080=$t080"
Write-Host "RETURN SHA=$sha CLICK=$clickToLine SURVIVE=$survived T080=$t080 PROMOTE=0"

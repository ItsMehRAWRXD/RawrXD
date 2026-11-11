# T080 remasure after exclusive fixture-build route (PROMOTE=0; no invented PASS)
$ErrorActionPreference = 'Continue'
$EvidenceDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\T080_FIXTURE_COMPILE_TRACE_001'
$OutFile = Join-Path $EvidenceDir 'T080_FIXTURE_BUILD_ROUTE_001.txt'
$TipExe = 'F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe'
$TipCwd = 'F:\rawrxd\build_tip_ext_host_001\bin'
$Fixture = 'F:\rawrxd\T080_test_bad.cpp'
$ExpectSha = (Get-Content -LiteralPath (Join-Path $EvidenceDir 'tip_sha_post_rebuild.txt') -Raw).Trim()
$Console = Join-Path $EvidenceDir 't080_fixture_route_console_001.txt'
'' | Set-Content -Path $Console -Encoding ascii

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class T080FR {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextLength(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  public const uint TCM_SETCURSEL = 0x130C;
  public const uint TCM_GETITEMCOUNT = 0x1304;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint LVM_ENSUREVISIBLE = 0x1013;
  public const uint LVM_GETITEMRECT = 0x100E;
  public const uint EM_GETSEL = 0x00B0;
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
}
"@

function Log([string]$m) {
  $line = "{0} {1}" -f (Get-Date).ToString('o'), $m
  Write-Host $line
  Add-Content -Path $Console -Value $line -Encoding ascii
}

$sha = (Get-FileHash -Algorithm SHA256 $TipExe).Hash
$fixtureBytes = (Get-Item $Fixture).Length
Log "TIP_SHA256=$sha EXPECT=$ExpectSha MATCH=$($sha -eq $ExpectSha) FIXTURE_BYTES=$fixtureBytes"
if ($sha -ne $ExpectSha) { throw "SHA mismatch tip=$sha expect=$ExpectSha" }

$env:RAWRXD_PROBLEMS_FIXTURE = $Fixture
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.Arguments = "`"$Fixture`""
$psi.WorkingDirectory = $TipCwd
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$idePid = $proc.Id
Log "LAUNCHED PID=$idePid FIXTURE_ENV=$Fixture"

$title = ''
$titleMatch = $false
$mainHwnd = [IntPtr]::Zero
$editorHwnd = [IntPtr]::Zero
$docLen = -1
$docDetail = ''
$plainEditLen = -1
$richLargest = -1
$editor1001Len = -1

for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Milliseconds 400
  if ($proc.HasExited) { Log "EXITED_EARLY code=$($proc.ExitCode) iter=$i"; break }
  $mainHwnd = [T080FR]::FindMain([uint32]$idePid)
  if ($mainHwnd -eq [IntPtr]::Zero) { continue }
  $title = [T080FR]::Title($mainHwnd)
  $titleMatch = $title -like '*T080_test_bad.cpp*'
  $ctrls = [T080FR]::EnumAll($mainHwnd)
  $by1001 = $ctrls | Where-Object { $_.Id -eq 1001 } | Select-Object -First 1
  if ($by1001) {
    $editorHwnd = $by1001.Hwnd
    $editor1001Len = $by1001.WmLen
    $docLen = $by1001.WmLen
    $docDetail = "id=1001 class=$($by1001.ClassName) hwnd=0x$('{0:X}' -f $by1001.Hwnd.ToInt64()) wm=$($by1001.WmLen) vis=$($by1001.Visible)"
  }
  $by1202 = $ctrls | Where-Object { $_.Id -eq 1202 } | Select-Object -First 1
  $plain = $ctrls | Where-Object { $_.ClassName -eq 'Edit' } | Sort-Object WmLen -Descending | Select-Object -First 1
  if ($plain) { $plainEditLen = $plain.WmLen }
  $rich = $ctrls | Where-Object { $_.ClassName -match 'RichEdit|RICHEDIT' } | Sort-Object WmLen -Descending | Select-Object -First 1
  if ($rich) { $richLargest = $rich.WmLen }
  $lv = ($ctrls | Where-Object { $_.ClassName -match 'SysListView32' } | ForEach-Object { "id=$($_.Id):$($_.WmLen)" }) -join ','
  $d1202 = if ($by1202) { "id=1202:$($by1202.WmLen):$($by1202.ClassName)" } else { 'id=1202:missing' }
  Log "ITER=$i MATCH=$titleMatch DOC1001=$editor1001Len $d1202 RICHMAX=$richLargest EDITMAX=$plainEditLen LV=[$lv] TITLE='$title'"
  if ($titleMatch -and $i -ge 6) { break }
}

$isRichDoc = $docDetail -match 'RichEdit|RICHEDIT'
$bufferPass = ($isRichDoc -and $docLen -ge $fixtureBytes)
Log "BUFFER_PASS=$bufferPass DOC=$docLen DETAIL=$docDetail"

$clSpawned = 'N'
$problemsRows = -1
$problemsHwnd = [IntPtr]::Zero
$problemsDetail = ''
$clickToLine = 'NOT_ATTEMPTED'
$ideExitedDuring = $false
$msbuildSeen = 'N'
$clWatchPath = Join-Path $EvidenceDir 'cl_spawn_watch_fixture_route_001.txt'
$clLines = New-Object System.Collections.Generic.List[string]
$captureSnap = ''

if (-not $proc.HasExited -and $mainHwnd -ne [IntPtr]::Zero) {
  [void][T080FR]::SetForegroundWindow($mainHwnd)
  $ctrls = [T080FR]::EnumAll($mainHwnd)
  $tabs = $ctrls | Where-Object { $_.ClassName -match 'SysTabControl32' -and ($_.Id -eq 1301 -or $_.WmLen -ge 3) } | Select-Object -First 1
  if ($tabs) {
    [void][T080FR]::SendMessageW($tabs.Hwnd, [T080FR]::TCM_SETCURSEL, [IntPtr]2, [IntPtr]::Zero)
    Log "TAB_SELECT id=$($tabs.Id)"
  }
  $buildRc = [T080FR]::SendMessageW($mainHwnd, [T080FR]::WM_COMMAND, [IntPtr]3014, [IntPtr]::Zero)
  Log "BUILD_CMD_3014 rc=$buildRc"

  $deadline = (Get-Date).AddSeconds(25)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { $ideExitedDuring = $true; Log "IDE_EXITED_DURING_WATCH"; break }
    try {
      foreach ($name in @('cl.exe','MSBuild.exe','cmake.exe')) {
        $cls = Get-CimInstance Win32_Process -Filter "Name='$name'" -ErrorAction SilentlyContinue
        foreach ($c in $cls) {
          $walk = $c.ParentProcessId
          $ok = $false
          for ($d=0; $d -lt 8 -and $walk -gt 0; $d++) {
            if ($walk -eq $idePid) { $ok = $true; break }
            $par = Get-CimInstance Win32_Process -Filter "ProcessId=$walk" -ErrorAction SilentlyContinue
            if (-not $par) { break }
            $walk = $par.ParentProcessId
          }
          if ($ok) {
            $line = "t=$((Get-Date).ToString('o')) name=$name pid=$($c.ProcessId) ppid=$($c.ParentProcessId) cmd=$($c.CommandLine)"
            if (-not ($clLines | Where-Object { $_ -eq $line })) {
              $clLines.Add($line)
              if ($name -eq 'cl.exe') { $clSpawned = 'Y'; Log "CL_SPAWNED pid=$($c.ProcessId)" }
              if ($name -eq 'MSBuild.exe' -or $name -eq 'cmake.exe') { $msbuildSeen = 'Y'; Log "CMAKE_OR_MSBUILD_SEEN name=$name" }
            }
          }
        }
      }
    } catch { Log "CL_WATCH_ERR $($_.Exception.Message)" }

    $ctrls = [T080FR]::EnumAll($mainHwnd)
    $candidates = @($ctrls | Where-Object { $_.ClassName -match 'SysListView32' })
    $pref = $candidates | Where-Object { $_.Id -eq 1312 } | Select-Object -First 1
    if (-not $pref) { $pref = $candidates | Sort-Object WmLen -Descending | Select-Object -First 1 }
    if ($pref) {
      $problemsHwnd = $pref.Hwnd
      $problemsRows = $pref.WmLen
      $problemsDetail = "id=$($pref.Id) hwnd=0x$('{0:X}' -f $pref.Hwnd.ToInt64()) rows=$($pref.WmLen) vis=$($pref.Visible)"
      Log "PROBLEMS $problemsDetail"
      if ($problemsRows -gt 0) { break }
    } else {
      Log "PROBLEMS_NONE_FOUND"
    }
    Start-Sleep -Milliseconds 800
  }
  $clLines | Set-Content -Encoding ascii $clWatchPath

  $capPath = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\COMPILER_CAPTURE_RECEIPT.txt'
  if (Test-Path -LiteralPath $capPath) {
    $captureSnap = Get-Content -LiteralPath $capPath -Raw
    Set-Content -LiteralPath (Join-Path $EvidenceDir 'COMPILER_CAPTURE_RECEIPT_snap_fixture_route_001.txt') -Value $captureSnap -Encoding ascii
  }

  if (-not $proc.HasExited -and $problemsRows -gt 0 -and $problemsHwnd -ne [IntPtr]::Zero) {
    [void][T080FR]::SetForegroundWindow($mainHwnd)
    [void][T080FR]::SendMessageW($problemsHwnd, [T080FR]::LVM_ENSUREVISIBLE, [IntPtr]0, [IntPtr]0)
    $rectPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    try {
      [System.Runtime.InteropServices.Marshal]::WriteInt32($rectPtr, 0, 0)
      [void][T080FR]::SendMessageW($problemsHwnd, [T080FR]::LVM_GETITEMRECT, [IntPtr]0, $rectPtr)
      $T = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 4)
      $B = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 12)
      $wr = New-Object T080FR+RECT
      [void][T080FR]::GetWindowRect($problemsHwnd, [ref]$wr)
      $cx = [int](($wr.L + $wr.R) / 2)
      $cy = $wr.T + [Math]::Max(12, [int](($T + $B) / 2))
      Log "CLICK_AT x=$cx y=$cy"
      [void][T080FR]::SetCursorPos($cx, $cy)
      Start-Sleep -Milliseconds 60
      [T080FR]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
      [T080FR]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
      Start-Sleep -Milliseconds 50
      [T080FR]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
      [T080FR]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
      Start-Sleep -Milliseconds 700
      if ($editorHwnd -ne [IntPtr]::Zero) {
        $sel = [int64][T080FR]::SendMessageW($editorHwnd, [T080FR]::EM_GETSEL, [IntPtr]::Zero, [IntPtr]::Zero)
        $selStart = [int]($sel -band 0xFFFF)
        $selEnd = [int](($sel -shr 16) -band 0xFFFF)
        if ($selStart -gt 0 -or $selEnd -gt 0) { $clickToLine = "Y selStart=$selStart selEnd=$selEnd" }
        else { $clickToLine = "ATTEMPTED_NO_SEL_CHANGE selStart=$selStart selEnd=$selEnd" }
      } else {
        $clickToLine = 'ATTEMPTED_NO_EDITOR'
      }
      Log "CLICK_TO_LINE=$clickToLine"
    } finally {
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($rectPtr)
    }
  } elseif ($problemsRows -eq 0) {
    $clickToLine = 'SKIPPED_PROBLEMS_ROWS_0'
  } elseif ($problemsRows -lt 0) {
    $clickToLine = 'SKIPPED_PROBLEMS_HWND_MISSING'
  }
} else {
  $clickToLine = 'SKIPPED_IDE_NOT_READY'
}

$survived = (-not $proc.HasExited) -and (-not $ideExitedDuring)
$problemsPass = ($problemsRows -gt 0)
$clPass = ($clSpawned -eq 'Y')
$exclusiveOk = ($captureSnap -match 'EXCLUSIVE_FIXTURE_ROUTE=1')
$cmakeBypassOk = ($msbuildSeen -ne 'Y')
$t080 = 'FAIL'
# Fail-closed: do not invent PASS. Require title+cl+problems+survive+exclusive; buffer still measured.
if ($titleMatch -and $bufferPass -and $problemsPass -and $clPass -and $survived -and $exclusiveOk -and $cmakeBypassOk) {
  $t080 = 'PASS'
}

if (-not $proc.HasExited) {
  try { Stop-Process -Id $idePid -Force -ErrorAction Stop; Log "KILLED_PID=$idePid" }
  catch { Log "KILL_ERR $($_.Exception.Message)" }
} else { Log "ALREADY_EXITED pid=$idePid" }

$asof = (Get-Date).ToUniversalTime().ToString('o')
@"
T080_FIXTURE_BUILD_ROUTE_001
ASOF_UTC=$asof
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
CONTROLLING=D015
T080=$t080
LAW=NOT_RUN!=PASS
LAW=DO_NOT_INVENT_T080_PASS
LAW=PROMOTE=0

PATCH=F:\rawrxd\src\win32app\Win32IDE_Commands.cpp
PATCH_NOTES=RAWRXD_PROBLEMS_FIXTURE env routes exclusively to fixture cl.exe; clearProblems deferred until after Problems tab visible and immediately before launch; CMake path unreachable when env set

TIP_EXE=$TipExe
TIP_CWD=$TipCwd
TIP_SHA256=$sha
TIP_SHA256_PRIOR_AC9B245A=AC9B245A1E5AC5D5FCD27E4DA4E3CF340F59AD0C732CBFD348D1D4A38DC92123
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
MSBUILD_OR_CMAKE_SEEN=$msbuildSeen
EXCLUSIVE_FIXTURE_ROUTE_RECEIPT=$exclusiveOk
CMAKE_BYPASS_OK=$cmakeBypassOk
PROBLEMS_ROW_COUNT=$problemsRows
PROBLEMS_DETAIL=$problemsDetail
CLICK_TO_LINE=$clickToLine
IDE_EXITED_DURING_FIXTURE_WATCH=$ideExitedDuring
SURVIVED=$survived
CL_WATCH=$clWatchPath
CONSOLE=t080_fixture_route_console_001.txt

=== GATE ===
TITLE_OK=$titleMatch
BUFFER_OK=$bufferPass
CL_OK=$clPass
PROBLEMS_OK=$problemsPass
SURVIVE_OK=$survived
EXCLUSIVE_ROUTE_OK=$exclusiveOk
CMAKE_BYPASS_OK=$cmakeBypassOk
T080=$t080
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
CONTROLLING=D015
"@ | Set-Content -Encoding ascii $OutFile
Log "WROTE $OutFile T080=$t080"
Write-Host "RETURN SHA=$sha DOC_BUF=$docLen PROBLEMS=$problemsRows CL=$clSpawned EXCLUSIVE=$exclusiveOk MSBUILD=$msbuildSeen T080=$t080 PROMOTE=0"

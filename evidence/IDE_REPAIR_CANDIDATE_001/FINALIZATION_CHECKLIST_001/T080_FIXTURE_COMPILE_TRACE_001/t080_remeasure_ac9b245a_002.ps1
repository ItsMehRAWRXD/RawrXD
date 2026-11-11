# T080 remasure pass-2: editor ID 1202 + SysListView32 Problems enum; PID-scoped only
$ErrorActionPreference = 'Continue'
$EvidenceDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\T080_FIXTURE_COMPILE_TRACE_001'
$OutFile = Join-Path $EvidenceDir 'T080_REMEASURE_AC9B245A_001.txt'
$TipExe = 'F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe'
$TipCwd = 'F:\rawrxd\build_tip_ext_host_001\bin'
$Fixture = 'F:\rawrxd\T080_test_bad.cpp'
$ExpectSha = 'AC9B245A1E5AC5D5FCD27E4DA4E3CF340F59AD0C732CBFD348D1D4A38DC92123'
$Console = Join-Path $EvidenceDir 't080_remeasure_console_002.txt'
'' | Set-Content -Path $Console -Encoding ascii

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class T080R2 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextLength(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
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
Log "TIP_SHA256=$sha MATCH=$($sha -eq $ExpectSha) FIXTURE_BYTES=$fixtureBytes"
if ($sha -ne $ExpectSha) { throw "SHA mismatch" }

$env:RAWRXD_PROBLEMS_FIXTURE = $Fixture
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.Arguments = "`"$Fixture`""
$psi.WorkingDirectory = $TipCwd
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$idePid = $proc.Id
Log "LAUNCHED PID=$idePid"

$title = ''
$titleMatch = $false
$mainHwnd = [IntPtr]::Zero
$editorHwnd = [IntPtr]::Zero
$docLen = -1
$docDetail = ''
$plainEditLen = -1
$richLargest = -1
$allSnap = ''

for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Milliseconds 400
  if ($proc.HasExited) { Log "EXITED_EARLY code=$($proc.ExitCode) iter=$i"; break }
  $mainHwnd = [T080R2]::FindMain([uint32]$idePid)
  if ($mainHwnd -eq [IntPtr]::Zero) { continue }
  $title = [T080R2]::Title($mainHwnd)
  $titleMatch = $title -like '*T080_test_bad.cpp*'
  $ctrls = [T080R2]::EnumAll($mainHwnd)
  $byId = $ctrls | Where-Object { $_.Id -eq 1202 } | Select-Object -First 1
  if ($byId) {
    $editorHwnd = $byId.Hwnd
    $docLen = $byId.WmLen
    $docDetail = "id=1202 class=$($byId.ClassName) hwnd=0x$('{0:X}' -f $byId.Hwnd.ToInt64()) wm=$($byId.WmLen) vis=$($byId.Visible)"
  } else {
    # fallback: GetDlgItem
    $h = [T080R2]::GetDlgItem($mainHwnd, 1202)
    if ($h -ne [IntPtr]::Zero) {
      $editorHwnd = $h
      $docLen = [int][T080R2]::SendMessageW($h, [T080R2]::WM_GETTEXTLENGTH, [IntPtr]::Zero, [IntPtr]::Zero)
      $docDetail = "GetDlgItem1202 class=$([T080R2]::Cls($h)) hwnd=0x$('{0:X}' -f $h.ToInt64()) wm=$docLen"
    }
  }
  $plain = $ctrls | Where-Object { $_.ClassName -eq 'Edit' } | Sort-Object WmLen -Descending | Select-Object -First 1
  if ($plain) { $plainEditLen = $plain.WmLen }
  $rich = $ctrls | Where-Object { $_.ClassName -match 'RichEdit|RICHEDIT' } | Sort-Object WmLen -Descending | Select-Object -First 1
  if ($rich) { $richLargest = $rich.WmLen }
  $lv = ($ctrls | Where-Object { $_.ClassName -match 'SysListView32' } | ForEach-Object { "id=$($_.Id):$($_.WmLen)" }) -join ','
  Log "ITER=$i MATCH=$titleMatch DOC=$docLen RICHMAX=$richLargest EDITMAX=$plainEditLen LV=[$lv] TITLE='$title'"
  if ($titleMatch -and $docLen -ge 0 -and $i -ge 6) { break }
  if ($titleMatch -and $docLen -ge $fixtureBytes -and $i -ge 4) { break }
}

# Document buffer gate: prefer id=1202 RichEdit near fixture size; reject plain Edit-only
$isRichDoc = $docDetail -match 'RichEdit|RICHEDIT'
$bufferPass = $false
if ($isRichDoc -and $docLen -ge $fixtureBytes -and $docLen -le 200) {
  $bufferPass = $true
} elseif ($isRichDoc -and $docLen -eq $fixtureBytes) {
  $bufferPass = $true
}
Log "BUFFER_PASS=$bufferPass DOC=$docLen DETAIL=$docDetail"

$clSpawned = 'N'
$problemsRows = -1
$problemsHwnd = [IntPtr]::Zero
$problemsDetail = ''
$clickToLine = 'NOT_ATTEMPTED'
$ideExitedDuring = $false
$clWatchPath = Join-Path $EvidenceDir 'cl_spawn_watch_remeasure_002.txt'
$clLines = New-Object System.Collections.Generic.List[string]

if (-not $proc.HasExited -and $mainHwnd -ne [IntPtr]::Zero) {
  [void][T080R2]::SetForegroundWindow($mainHwnd)
  # Select Problems tab: find SysTabControl32 with id 1301 or any with >=3 tabs
  $ctrls = [T080R2]::EnumAll($mainHwnd)
  $tabs = $ctrls | Where-Object { $_.ClassName -match 'SysTabControl32' -and ($_.Id -eq 1301 -or $_.WmLen -ge 3) } | Select-Object -First 1
  if ($tabs) {
    [void][T080R2]::SendMessageW($tabs.Hwnd, [T080R2]::TCM_SETCURSEL, [IntPtr]2, [IntPtr]::Zero)
    Log "TAB_SELECT id=$($tabs.Id) hwnd=0x$('{0:X}' -f $tabs.Hwnd.ToInt64()) tabs=$($tabs.WmLen)"
  }
  $buildRc = [T080R2]::SendMessageW($mainHwnd, [T080R2]::WM_COMMAND, [IntPtr]3014, [IntPtr]::Zero)
  Log "BUILD_CMD_3014 rc=$buildRc"

  $deadline = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { $ideExitedDuring = $true; Log "IDE_EXITED_DURING_WATCH"; break }
    try {
      $cls = Get-CimInstance Win32_Process -Filter "Name='cl.exe'" -ErrorAction SilentlyContinue
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
          $line = "t=$((Get-Date).ToString('o')) name=cl.exe pid=$($c.ProcessId) ppid=$($c.ParentProcessId) cmd=$($c.CommandLine)"
          if (-not ($clLines | Where-Object { $_ -eq $line })) {
            $clLines.Add($line)
            $clSpawned = 'Y'
            Log "CL_SPAWNED pid=$($c.ProcessId)"
          }
        }
      }
    } catch { Log "CL_WATCH_ERR $($_.Exception.Message)" }

    $ctrls = [T080R2]::EnumAll($mainHwnd)
    $candidates = @($ctrls | Where-Object { $_.ClassName -match 'SysListView32' })
    # Prefer id 1312; else visible list with most items
    $pref = $candidates | Where-Object { $_.Id -eq 1312 } | Select-Object -First 1
    if (-not $pref) { $pref = $candidates | Sort-Object WmLen -Descending | Select-Object -First 1 }
    if ($pref) {
      $problemsHwnd = $pref.Hwnd
      $problemsRows = $pref.WmLen
      $problemsDetail = "id=$($pref.Id) hwnd=0x$('{0:X}' -f $pref.Hwnd.ToInt64()) rows=$($pref.WmLen) vis=$($pref.Visible)"
      $allLv = ($candidates | ForEach-Object { "id=$($_.Id):$($_.WmLen)" }) -join ';'
      Log "PROBLEMS $problemsDetail all=$allLv"
      if ($problemsRows -gt 0) { break }
    } else {
      Log "PROBLEMS_NONE_FOUND"
    }
    Start-Sleep -Milliseconds 800
  }
  $clLines | Set-Content -Encoding ascii $clWatchPath

  if (-not $proc.HasExited -and $problemsRows -gt 0 -and $problemsHwnd -ne [IntPtr]::Zero) {
    [void][T080R2]::SetForegroundWindow($mainHwnd)
    [void][T080R2]::SendMessageW($problemsHwnd, [T080R2]::LVM_ENSUREVISIBLE, [IntPtr]0, [IntPtr]0)
    $rectPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    try {
      [System.Runtime.InteropServices.Marshal]::WriteInt32($rectPtr, 0, 0)
      [void][T080R2]::SendMessageW($problemsHwnd, [T080R2]::LVM_GETITEMRECT, [IntPtr]0, $rectPtr)
      $T = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 4)
      $B = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 12)
      $wr = New-Object T080R2+RECT
      [void][T080R2]::GetWindowRect($problemsHwnd, [ref]$wr)
      $cx = [int](($wr.L + $wr.R) / 2)
      $cy = $wr.T + [Math]::Max(12, [int](($T + $B) / 2))
      Log "CLICK_AT x=$cx y=$cy"
      [void][T080R2]::SetCursorPos($cx, $cy)
      Start-Sleep -Milliseconds 60
      [T080R2]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
      [T080R2]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
      Start-Sleep -Milliseconds 50
      [T080R2]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
      [T080R2]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
      Start-Sleep -Milliseconds 700
      if ($editorHwnd -ne [IntPtr]::Zero) {
        $sel = [int64][T080R2]::SendMessageW($editorHwnd, [T080R2]::EM_GETSEL, [IntPtr]::Zero, [IntPtr]::Zero)
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
$t080 = 'FAIL'
if ($titleMatch -and $bufferPass -and $problemsPass -and $clPass -and $survived) { $t080 = 'PASS' }

if (-not $proc.HasExited) {
  try { Stop-Process -Id $idePid -Force -ErrorAction Stop; Log "KILLED_PID=$idePid" }
  catch { Log "KILL_ERR $($_.Exception.Message)" }
} else { Log "ALREADY_EXITED pid=$idePid" }

$asof = (Get-Date).ToUniversalTime().ToString('o')
@"
T080_REMEASURE_AC9B245A_001
ASOF_UTC=$asof
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
T080=$t080
ISSUE49_D015=UNTOUCHED
A43B5F6A_T080_MEASURE=NOT_INHERITED
89A5F76F_T080_MEASURE=NOT_INHERITED
LAW=NOT_RUN!=PASS
LAW=DO_NOT_INVENT_T080_PASS
PASS2=editor_id_1202_and_SysListView32_enum

TIP_EXE=$TipExe
TIP_CWD=$TipCwd
TIP_SHA256=$sha
SHA_MATCH=$($sha -eq $ExpectSha)
LIVE_TIP_LANE=build_tip_ext_host_001
INITIALPATH_ARG=$Fixture
FIXTURE_BYTES=$fixtureBytes
LAUNCH_PID=$idePid

=== INITIALPATH / BUFFER ===
TITLE_BAR=$title
TITLE_MATCH_T080=$titleMatch
DOCUMENT_EDITOR_ID=1202
DOCUMENT_BUFFER_LEN_WM_GETTEXTLENGTH=$docLen
DOCUMENT_DETAIL=$docDetail
RICHEDIT_LARGEST_ANY=$richLargest
PLAIN_EDIT_LEN=$plainEditLen
BUFFER_PASS=$bufferPass
NOTE=Buffer PASS requires RichEdit id=1202 length near fixture bytes; plain Edit and unrelated RichEdit panes are not sealed

=== FIXTURE COMPILE / PROBLEMS ===
CL_EXE_SPAWNED=$clSpawned
PROBLEMS_ROW_COUNT=$problemsRows
PROBLEMS_DETAIL=$problemsDetail
CLICK_TO_LINE=$clickToLine
IDE_EXITED_DURING_FIXTURE_WATCH=$ideExitedDuring
SURVIVED=$survived
CL_WATCH=$clWatchPath
CONSOLE=t080_remeasure_console_002.txt

=== GATE ===
TITLE_OK=$titleMatch
BUFFER_OK=$bufferPass
CL_OK=$clPass
PROBLEMS_OK=$problemsPass
SURVIVE_OK=$survived
T080=$t080
PROMOTE=0
"@ | Set-Content -Encoding ascii $OutFile
Log "WROTE $OutFile T080=$t080"
Write-Host "RETURN SHA=$sha DOC_BUF=$docLen PROBLEMS=$problemsRows CL=$clSpawned T080=$t080 PROMOTE=0"

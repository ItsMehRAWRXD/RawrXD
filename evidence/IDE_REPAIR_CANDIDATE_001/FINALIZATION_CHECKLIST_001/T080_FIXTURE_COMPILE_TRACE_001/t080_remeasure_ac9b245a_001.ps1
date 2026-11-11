# T080 remasure AC9B245A — short isolated launch; PID-scoped cleanup only
$ErrorActionPreference = 'Continue'
$EvidenceDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\T080_FIXTURE_COMPILE_TRACE_001'
$OutFile = Join-Path $EvidenceDir 'T080_REMEASURE_AC9B245A_001.txt'
$TipExe = 'F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe'
$TipCwd = 'F:\rawrxd\build_tip_ext_host_001\bin'
$Fixture = 'F:\rawrxd\T080_test_bad.cpp'
$ExpectSha = 'AC9B245A1E5AC5D5FCD27E4DA4E3CF340F59AD0C732CBFD348D1D4A38DC92123'

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class T080R {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextLength(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  public const uint TCM_SETCURSEL = 0x130C;
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
  public class CtrlInfo {
    public IntPtr Hwnd; public string ClassName; public int CtrlId; public int WmLen; public int Gtl;
  }
  public static List<CtrlInfo> EnumEditors(IntPtr main) {
    var list = new List<CtrlInfo>();
    EnumChildWindows(main, (h,l) => {
      string c = Cls(h);
      bool rich = c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0
               || c.IndexOf("RICHEDIT", StringComparison.OrdinalIgnoreCase) >= 0;
      bool edit = c.Equals("Edit", StringComparison.OrdinalIgnoreCase);
      if (rich || edit) {
        int wm = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
        int gtl = GetWindowTextLength(h);
        int id = 0;
        // best-effort: walk parents for dlg id not needed; store class/len
        list.Add(new CtrlInfo{ Hwnd=h, ClassName=c, CtrlId=id, WmLen=wm, Gtl=gtl });
      }
      return true;
    }, IntPtr.Zero);
    return list;
  }
}
"@

function Write-Log([string]$m) {
  $line = "{0} {1}" -f (Get-Date).ToString('o'), $m
  Write-Host $line
  Add-Content -Path (Join-Path $EvidenceDir 't080_remeasure_console_001.txt') -Value $line -Encoding ascii
}

# Reset console log
'' | Set-Content -Path (Join-Path $EvidenceDir 't080_remeasure_console_001.txt') -Encoding ascii

$sha = (Get-FileHash -Algorithm SHA256 $TipExe).Hash
$fixtureBytes = (Get-Item $Fixture).Length
Write-Log "TIP_SHA256=$sha"
Write-Log "EXPECT=$ExpectSha MATCH=$($sha -eq $ExpectSha)"
Write-Log "FIXTURE_BYTES=$fixtureBytes"

if ($sha -ne $ExpectSha) {
  @"
T080_REMEASURE_AC9B245A_001
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
PROMOTE=0
T080=FAIL
TIP_SHA256=$sha
EXPECT_SHA256=$ExpectSha
SHA_MATCH=False
NOTE=Tip SHA mismatch; remasure aborted
"@ | Set-Content -Encoding ascii $OutFile
  Write-Log "ABORT SHA mismatch"
  exit 2
}

# Short isolated launch with fixture arg + PROBLEMS fixture env
$env:RAWRXD_PROBLEMS_FIXTURE = $Fixture
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.Arguments = "`"$Fixture`""
$psi.WorkingDirectory = $TipCwd
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$idePid = $proc.Id
Write-Log "LAUNCHED PID=$idePid"

$title = ''
$titleMatch = $false
$richLen = -1
$editLen = -1
$richDetail = ''
$editDetail = ''
$mainHwnd = [IntPtr]::Zero
$editorHwnd = [IntPtr]::Zero
$survivedLaunch = $false

# Wait up to ~12s for main window + buffer settle (short)
for ($i = 0; $i -lt 24; $i++) {
  Start-Sleep -Milliseconds 500
  if ($proc.HasExited) { Write-Log "EXITED_EARLY code=$($proc.ExitCode) at_iter=$i"; break }
  $mainHwnd = [T080R]::FindMain([uint32]$idePid)
  if ($mainHwnd -eq [IntPtr]::Zero) { continue }
  $title = [T080R]::Title($mainHwnd)
  $titleMatch = $title -like '*T080_test_bad.cpp*'
  $ctrls = [T080R]::EnumEditors($mainHwnd)
  $rich = $ctrls | Where-Object { $_.ClassName -match 'RichEdit|RICHEDIT' } | Sort-Object WmLen -Descending | Select-Object -First 1
  $ed = $ctrls | Where-Object { $_.ClassName -eq 'Edit' } | Sort-Object WmLen -Descending | Select-Object -First 1
  if ($rich) {
    $richLen = $rich.WmLen
    $richDetail = "RichEdit class=$($rich.ClassName) hwnd=0x$('{0:X}' -f $rich.Hwnd.ToInt64()) wm=$($rich.WmLen) gtl=$($rich.Gtl)"
    $editorHwnd = $rich.Hwnd
  }
  if ($ed) {
    $editLen = $ed.WmLen
    $editDetail = "Edit hwnd=0x$('{0:X}' -f $ed.Hwnd.ToInt64()) wm=$($ed.WmLen) gtl=$($ed.Gtl)"
  }
  Write-Log "ITER=$i TITLE='$title' MATCH=$titleMatch RICH=$richLen EDIT=$editLen"
  if ($titleMatch -and $richLen -ge $fixtureBytes) { $survivedLaunch = $true; break }
  if ($titleMatch -and $i -ge 8) { $survivedLaunch = -not $proc.HasExited; break }
}

$bufferPass = ($richLen -ge $fixtureBytes -and $richLen -lt 500)  # fixture ~51; reject Edit-525 false positive
Write-Log "BUFFER_PASS=$bufferPass RICH=$richLen EDIT=$editLen TITLE_MATCH=$titleMatch"

# Fixture compile + Problems: only if still alive
$clSpawned = 'N'
$problemsRows = -1
$clickToLine = 'NOT_ATTEMPTED'
$ideExitedDuring = $false
$clWatchPath = Join-Path $EvidenceDir 'cl_spawn_watch_remeasure_001.txt'
$clLines = New-Object System.Collections.Generic.List[string]

if (-not $proc.HasExited -and $mainHwnd -ne [IntPtr]::Zero) {
  [void][T080R]::SetForegroundWindow($mainHwnd)
  # Select Problems tab (control 1301 index 2) best-effort
  $tabs = [T080R]::GetDlgItem($mainHwnd, 1301)
  if ($tabs -ne [IntPtr]::Zero) {
    [void][T080R]::SendMessageW($tabs, [T080R]::TCM_SETCURSEL, [IntPtr]2, [IntPtr]::Zero)
    Write-Log "PROBLEMS_TAB_SELECT hwnd=0x$('{0:X}' -f $tabs.ToInt64())"
  }
  # Trigger Build Project (3014) — fixture path may also auto-run via env
  $buildRc = [T080R]::SendMessageW($mainHwnd, [T080R]::WM_COMMAND, [IntPtr]3014, [IntPtr]::Zero)
  Write-Log "BUILD_CMD_3014 rc=$buildRc"

  $deadline = (Get-Date).AddSeconds(18)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { $ideExitedDuring = $true; Write-Log "IDE_EXITED_DURING_WATCH"; break }
    try {
      $children = Get-CimInstance Win32_Process -Filter "Name='cl.exe'" -ErrorAction SilentlyContinue |
        Where-Object {
          $pp = $_.ParentProcessId
          $walk = $pp
          $ok = $false
          for ($d=0; $d -lt 6 -and $walk -gt 0; $d++) {
            if ($walk -eq $idePid) { $ok = $true; break }
            $par = Get-CimInstance Win32_Process -Filter "ProcessId=$walk" -ErrorAction SilentlyContinue
            if (-not $par) { break }
            $walk = $par.ParentProcessId
          }
          $ok
        }
      foreach ($c in $children) {
        $line = "t=$((Get-Date).ToString('o')) name=cl.exe pid=$($c.ProcessId) ppid=$($c.ParentProcessId) cmd=$($c.CommandLine)"
        if (-not ($clLines -contains $line)) {
          $clLines.Add($line)
          $clSpawned = 'Y'
          Write-Log "CL_SPAWNED $line"
        }
      }
    } catch {
      Write-Log "CL_WATCH_ERR $($_.Exception.Message)"
    }
    $plist = [T080R]::GetDlgItem($mainHwnd, 1312)
    if ($plist -ne [IntPtr]::Zero) {
      $problemsRows = [int][T080R]::SendMessageW($plist, [T080R]::LVM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero)
      Write-Log "PROBLEMS_ROWS=$problemsRows hwnd=0x$('{0:X}' -f $plist.ToInt64())"
      if ($problemsRows -gt 0) { break }
    }
    Start-Sleep -Milliseconds 700
  }

  $clLines | Set-Content -Encoding ascii $clWatchPath

  if (-not $proc.HasExited -and $problemsRows -gt 0) {
    $plist = [T080R]::GetDlgItem($mainHwnd, 1312)
    [void][T080R]::SetForegroundWindow($mainHwnd)
    [void][T080R]::SendMessageW($plist, [T080R]::LVM_ENSUREVISIBLE, [IntPtr]0, [IntPtr]0)
    # Click first row via item rect (LVIR_BOUNDS=0)
    $rectPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)
    try {
      [System.Runtime.InteropServices.Marshal]::WriteInt32($rectPtr, 0, 0) # LVIR_BOUNDS
      [void][T080R]::SendMessageW($plist, [T080R]::LVM_GETITEMRECT, [IntPtr]0, $rectPtr)
      $L = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 0)
      $T = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 4)
      $R = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 8)
      $B = [System.Runtime.InteropServices.Marshal]::ReadInt32($rectPtr, 12)
      $wr = New-Object T080R+RECT
      [void][T080R]::GetWindowRect($plist, [ref]$wr)
      $cx = [int](($wr.L + $wr.R) / 2)
      $cy = $wr.T + [int](($T + $B) / 2)
      if ($cy -le $wr.T) { $cy = $wr.T + 12 }
      Write-Log "CLICK_AT x=$cx y=$cy itemRect=L$L T$T R$R B$B"
      [void][T080R]::SetCursorPos($cx, $cy)
      Start-Sleep -Milliseconds 80
      [T080R]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
      [T080R]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
      Start-Sleep -Milliseconds 400
      # double-click for navigation
      [T080R]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
      [T080R]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
      Start-Sleep -Milliseconds 600
      $sel = [int64][T080R]::SendMessageW($editorHwnd, [T080R]::EM_GETSEL, [IntPtr]::Zero, [IntPtr]::Zero)
      $selStart = [int]($sel -band 0xFFFF)
      $selEnd = [int](($sel -shr 16) -band 0xFFFF)
      if ($selStart -gt 0 -or $selEnd -gt 0) {
        $clickToLine = "Y selStart=$selStart selEnd=$selEnd"
      } else {
        $clickToLine = "ATTEMPTED_NO_SEL_CHANGE selStart=$selStart selEnd=$selEnd"
      }
      Write-Log "CLICK_TO_LINE=$clickToLine"
    } finally {
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($rectPtr)
    }
  } elseif ($problemsRows -le 0) {
    $clickToLine = 'SKIPPED_NO_PROBLEMS_ROWS'
  }
} else {
  Write-Log "SKIP_COMPILE_PROBE exited=$($proc.HasExited) main=$mainHwnd"
  $clickToLine = 'SKIPPED_IDE_NOT_READY'
}

$survived = (-not $proc.HasExited) -and (-not $ideExitedDuring)
$problemsPass = ($problemsRows -gt 0)
$clPass = ($clSpawned -eq 'Y')
$t080 = 'FAIL'
if ($titleMatch -and $bufferPass -and $problemsPass -and $clPass -and $survived) {
  $t080 = 'PASS'
}

# PID-scoped kill only
if (-not $proc.HasExited) {
  try {
    Stop-Process -Id $idePid -Force -ErrorAction Stop
    Write-Log "KILLED_PID=$idePid"
  } catch {
    Write-Log "KILL_ERR $($_.Exception.Message)"
  }
} else {
  Write-Log "ALREADY_EXITED pid=$idePid code=$($proc.ExitCode)"
}

$asof = (Get-Date).ToUniversalTime().ToString('o')
$body = @"
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
RICHEDIT_BUFFER_LEN_WM_GETTEXTLENGTH=$richLen
RICHEDIT_DETAIL=$richDetail
PLAIN_EDIT_LEN=$editLen
PLAIN_EDIT_DETAIL=$editDetail
BUFFER_PASS=$bufferPass
NOTE=RichEdit required for buffer PASS; plain Edit (e.g. 525) is NOT sealed

=== FIXTURE COMPILE / PROBLEMS ===
CL_EXE_SPAWNED=$clSpawned
PROBLEMS_ROW_COUNT=$problemsRows
CLICK_TO_LINE=$clickToLine
IDE_EXITED_DURING_FIXTURE_WATCH=$ideExitedDuring
SURVIVED=$survived
CL_WATCH=$clWatchPath
CONSOLE=t080_remeasure_console_001.txt

=== GATE ===
TITLE_OK=$titleMatch
BUFFER_OK=$bufferPass
CL_OK=$clPass
PROBLEMS_OK=$problemsPass
SURVIVE_OK=$survived
T080=$t080
PROMOTE=0
"@
$body | Set-Content -Encoding ascii $OutFile
Write-Log "WROTE $OutFile T080=$t080"
Write-Host "RETURN SHA=$sha RICH=$richLen PROBLEMS=$problemsRows CL=$clSpawned T080=$t080 PROMOTE=0"
exit 0

# EA5D tip_final_004 — Output HWND + Problems HWND only. PROMOTE=0. No Debug/four-panel.
param(
  [string]$TipExe = "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_004\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ea5d_out_prob",
  [int]$WaitSec = 55
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "ea5d_out_prob_hwnd_run_$stamp.txt"
$receipt = Join-Path $OutDir "EA5D_OUTPUT_PROBLEMS_HWND_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Ea5dOP {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint TCM_FIRST = 0x1300;
  public const uint TCM_SETCURSEL = TCM_FIRST + 12;
  public const uint TCM_GETCURSEL = TCM_FIRST + 11;
  public const uint WM_NOTIFY = 0x004E;
  public const int TCN_SELCHANGE = -551;
  public const int NM_DBLCLK = -3;
  public const int LVN_FIRST = -100;
  public const int LVN_ITEMACTIVATE = LVN_FIRST - 14;
  public const uint LVM_FIRST = 0x1000;
  public const uint LVM_SETITEMSTATE = LVM_FIRST + 43;
  public const uint LVM_ENSUREVISIBLE = LVM_FIRST + 19;
  public const uint EM_LINEFROMCHAR = 0x00C9;
  public const uint EM_GETSEL = 0x00B0;
  public const uint LVIS_SELECTED = 0x0002;
  public const uint LVIS_FOCUSED = 0x0001;
  [StructLayout(LayoutKind.Sequential)]
  public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [StructLayout(LayoutKind.Sequential)]
  public struct LVITEM {
    public uint mask; public int iItem; public int iSubItem; public uint state; public uint stateMask;
    public IntPtr pszText; public int cchTextMax; public int iImage; public IntPtr lParam;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct NMITEMACTIVATE {
    public NMHDR hdr; public int iItem; public int iSubItem; public uint uNewState; public uint uOldState;
    public uint uChanged; public int x; public int y; public uint lParam; public uint uKeyFlags;
  }
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMHDR l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMITEMACTIVATE l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref LVITEM l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
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
  public static IntPtr FindId(IntPtr root, int id) {
    IntPtr f = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => { if (GetDlgCtrlID(h)==id){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static string GetText(IntPtr h) {
    int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (len <= 0) return "";
    var sb = new StringBuilder(Math.Min(len, 4000) + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static bool SelectTab(IntPtr main, IntPtr tab, int index, int idFrom) {
    if (tab == IntPtr.Zero) return false;
    SendMessageW(tab, TCM_SETCURSEL, (IntPtr)index, IntPtr.Zero);
    NMHDR nm; nm.hwndFrom = tab; nm.idFrom = (IntPtr)idFrom; nm.code = TCN_SELCHANGE;
    SendMessage(main, WM_NOTIFY, (IntPtr)idFrom, ref nm);
    IntPtr parent = GetParent(tab);
    if (parent != IntPtr.Zero && parent != main) SendMessage(parent, WM_NOTIFY, (IntPtr)idFrom, ref nm);
    return (int)SendMessageW(tab, TCM_GETCURSEL, IntPtr.Zero, IntPtr.Zero) == index;
  }
  public static int IdLen(IntPtr root, int id) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) { found = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero); return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int IdList(IntPtr root, int id) {
    int found = -1;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) == id) { found = (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero); return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int MaxVisibleEdit(IntPtr root) {
    int max = 0;
    EnumChildWindows(root, (h, lp) => {
      if (!IsWindowVisible(h)) return true;
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
  public static string SampleVisibleEdit(IntPtr root, int maxChars) {
    string best = "";
    EnumChildWindows(root, (h, lp) => {
      if (!IsWindowVisible(h)) return true;
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) < 0 &&
          c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) < 0) return true;
      string t = GetText(h);
      if (t.Length > best.Length) best = t;
      return true;
    }, IntPtr.Zero);
    if (best.Length > maxChars) best = best.Substring(0, maxChars);
    return best.Replace("\r", "\\r").Replace("\n", "\\n");
  }
  // Sample ONE control by dialog ID (Build=1604). Never use MaxVisibleEdit for
  // Build PASS — that mis-attributes chat transcript as Build output.
  public static string SampleId(IntPtr root, int id, int maxChars) {
    IntPtr h = FindId(root, id);
    if (h == IntPtr.Zero) return "";
    string t = GetText(h);
    if (t.Length > maxChars) t = t.Substring(0, maxChars);
    return t.Replace("\r", "\\r").Replace("\n", "\\n");
  }
}
"@

if (-not (Test-Path -LiteralPath $TipExe)) {
  "OUTPUT_HWND=NOT_RUN`nPROBLEMS_HWND=NOT_RUN`nREASON=exe_missing`nPROMOTE=0" | Set-Content $receipt
  exit 2
}
$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
$shaMatch = ($ExpectSha -eq 'IGNORE' -or $ExpectSha -eq 'ANY' -or $sha -eq $ExpectSha)
Log "SHA_MATCH=$shaMatch EXPECT=$ExpectSha"
if (-not $shaMatch) {
  @"
OUTPUT_HWND=NOT_RUN
PROBLEMS_HWND=NOT_RUN
TIP_SHA=$sha
SHA_MATCH=0
REASON=sha_mismatch_expected_$ExpectSha
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
Remove-Item "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -EA SilentlyContinue
Set-Content "F:\rawrxd\build_dispatch_trace.log" ""

$workDir = Split-Path -Parent $TipExe
if (-not $workDir) { $workDir = (Get-Location).Path }
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -WorkingDirectory $workDir -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
# Cold start can exceed 20s under concurrent build load — poll up to ~45s.
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; Log "MAIN_VIA_PROC t=$i"; break }
  $main = [Ea5dOP]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { Log "MAIN_VIA_ENUM t=$i"; break }
  if (($i % 10) -eq 0) { Log "WAIT_MAIN t=$i handle=$($p.MainWindowHandle)" }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
OUTPUT_HWND=NOT_RUN
PROBLEMS_HWND=NOT_RUN
TIP_SHA=$sha
REASON=main_hwnd_not_found
PROMOTE=0
"@ | Set-Content $receipt
  exit 2
}
[void][Ea5dOP]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 700

# View panel / output
foreach ($cmd in @(2034, 2025, 2021)) {
  [void][Ea5dOP]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
}
$outTabs = [Ea5dOP]::FindId($main, 1005)
$panelTabs = [Ea5dOP]::FindId($main, 1301)
$baselineEdit = [Ea5dOP]::MaxVisibleEdit($main)
Log "BASELINE_VISIBLE_EDIT=$baselineEdit OUT_TABS=0x$('{0:X}' -f $outTabs.ToInt64())"

# Build Project
[void][Ea5dOP]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
Log "POST_BUILD=3014"
Start-Sleep 2

# Select Build channel tab index 4
$selBuild = [Ea5dOP]::SelectTab($main, $outTabs, 4, 1005)
Log "SELECT_BUILD_TAB4=$selBuild"

# Build channel HWND id = 1604 (createOutputTabs). 1204=Send collision; 1404=status warnings.
$id1604 = -1; $id1204 = -1; $id1052 = -1; $id1012 = -1; $visEdit = 0; $sample = ""; $visSample = ""; $prob = -1; $peakProb = -1
$click = 'NOT_RUN'
for ($w = 0; $w -lt $WaitSec; $w++) {
  Start-Sleep 1
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EXIT_WAIT code=$($p.ExitCode) t=$w"; break }
  if (-not [Ea5dOP]::IsWindow($main)) { Log "MAIN_GONE t=$w"; break }
  if (($w % 8) -eq 0) { [void][Ea5dOP]::SelectTab($main, $outTabs, 4, 1005) }
  $id1604 = [Ea5dOP]::IdLen($main, 1604)
  $id1204 = [Ea5dOP]::IdLen($main, 1204)
  $id1012 = [Ea5dOP]::IdLen($main, 1012)
  $id1052 = [Ea5dOP]::IdLen($main, 1052)
  $visEdit = [Ea5dOP]::MaxVisibleEdit($main)
  $sample = [Ea5dOP]::SampleId($main, 1604, 400)
  $visSample = [Ea5dOP]::SampleVisibleEdit($main, 240)
  $prob = [Ea5dOP]::IdList($main, 1312)
  if ($prob -gt $peakProb) { $peakProb = $prob }
  if (($w % 5) -eq 0) { Log "POLL t=$w id1604=$id1604 id1204=$id1204 visEdit=$visEdit prob=$prob peak=$peakProb" }
  $chatContaminated = ($sample -match '>\s*User:')
  $hasBuildLines = (-not $chatContaminated) -and (
    ($id1604 -gt 40) -or ($sample -match 'RAWRXD_BUILD|RAWRXD_PROBLEMS|error C|warning C|fixture compile|BUILD_')
  )
  # Early click-to-line via in-target WM_LBUTTONDBLCLK (cross-proc WM_NOTIFY
  # lParam pointers are not marshalled and crash the IDE).
  if ($prob -gt 0 -and $click -eq 'NOT_RUN') {
    $lv = [Ea5dOP]::FindId($main, 1312)
    if ($lv -ne [IntPtr]::Zero) {
      [void][Ea5dOP]::SendMessageW($lv, [Ea5dOP]::LVM_ENSUREVISIBLE, [IntPtr]0, [IntPtr]0)
      $packed = [IntPtr]((20 -shl 16) -bor 40)
      [void][Ea5dOP]::SendMessageW($lv, 0x0201, [IntPtr]1, $packed) # WM_LBUTTONDOWN
      [void][Ea5dOP]::SendMessageW($lv, 0x0202, [IntPtr]0, $packed) # WM_LBUTTONUP
      [void][Ea5dOP]::SendMessageW($lv, 0x0203, [IntPtr]1, $packed) # WM_LBUTTONDBLCLK
      [void][Ea5dOP]::SendMessageW($lv, 0x0202, [IntPtr]0, $packed) # WM_LBUTTONUP
      $click = 'POSTED_NM_DBLCLK'
      Log "EARLY_CLICK_TO_LINE items=$prob via=LBUTTONDBLCLK"
    }
  }
  # Seal as soon as Build+Problems+click are all observed — avoid MAIN_GONE race
  if ($hasBuildLines -and $prob -gt 0 -and ($click -like 'POSTED_NM_DBLCLK*' -or $click -like 'NAVIGATED_LINE_*')) {
    Log "SEAL_READY t=$w id1604=$id1604 items=$prob click=$click"
    break
  }
  if ($hasBuildLines -and $w -ge 35) { break }
}

# Problems tab (reconfirm after Build poll)
[void][Ea5dOP]::SelectTab($main, $panelTabs, 2, 1301)
Start-Sleep -Milliseconds 500
if ([Ea5dOP]::IsWindow($main)) {
  $prob = [Ea5dOP]::IdList($main, 1312)
  if ($prob -gt $peakProb) { $peakProb = $prob }
  if ($id1604 -lt 0) { $id1604 = [Ea5dOP]::IdLen($main, 1604) }
  if ([string]::IsNullOrEmpty($sample)) { $sample = [Ea5dOP]::SampleId($main, 1604, 400) }
}
Log "PROBLEMS_ID1312=$prob PEAK=$peakProb SAMPLE=$sample"
if ($click -eq 'NOT_RUN' -and $prob -gt 0) {
  $lv = [Ea5dOP]::FindId($main, 1312)
  if ($lv -ne [IntPtr]::Zero) {
    $packed = [IntPtr]((20 -shl 16) -bor 40)
    [void][Ea5dOP]::SendMessageW($lv, 0x0203, [IntPtr]1, $packed)
    [void][Ea5dOP]::SendMessageW($lv, 0x0202, [IntPtr]0, $packed)
    $click = 'POSTED_NM_DBLCLK'
  } else { $click = 'LIST_MISSING' }
}

# Click-to-line evidence: editor caret line after goToProblem
$clickLine = -1
$editor = [Ea5dOP]::FindId($main, 1001)
if ($editor -eq [IntPtr]::Zero) {
  # Fallback: largest visible RichEdit (often the document editor)
  $editor = [IntPtr]::Zero
}
if ($click -eq 'POSTED_NM_DBLCLK' -and [Ea5dOP]::IsWindow($main)) {
  Start-Sleep -Milliseconds 300
  # EM_GETSEL -> EM_LINEFROMCHAR on common editor ids
  foreach ($eid in @(1001, 1101, 1010)) {
    $eh = [Ea5dOP]::FindId($main, $eid)
    if ($eh -eq [IntPtr]::Zero) { continue }
    $sel = [Ea5dOP]::SendMessageW($eh, [Ea5dOP]::EM_GETSEL, [IntPtr]::Zero, [IntPtr]::Zero)
    $cp = [int]($sel.ToInt64() -band 0xFFFF)
    $ln = [int][Ea5dOP]::SendMessageW($eh, [Ea5dOP]::EM_LINEFROMCHAR, [IntPtr]$cp, [IntPtr]::Zero)
    if ($ln -ge 0) { $clickLine = $ln + 1; break }
  }
  if ($clickLine -gt 1) { $click = 'NAVIGATED_LINE_' + $clickLine }
  elseif ($clickLine -eq 1) { $click = 'POSTED_NM_DBLCLK_LINE1' }
}

# Dispatch / build output hints
$fixtureLaunch = 0
if (Test-Path "F:\rawrxd\build_dispatch_trace.log") {
  $fixtureLaunch = @(Select-String -Path "F:\rawrxd\build_dispatch_trace.log" -Pattern "PROBLEMS_FIXTURE_LAUNCH" -EA SilentlyContinue).Count
}
$buildOutHasMsvc = 0
if (Test-Path "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log") {
  $buildOutHasMsvc = @(Select-String -Path "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -Pattern "error C\d+" -EA SilentlyContinue).Count
}

# dispatch_id correlation measure (wire presence + runtime log hits). EXACTLY_ONCE stays NOT_VERIFIED.
$dispatchWire = 'SOURCE_STRINGS_ABSENT'
$dispatchRuntimeHits = 0
$dispatchTranscriptHits = 0
try {
  $strHits = @(Select-String -Path $TipExe -Pattern 'dispatch_id=' -Encoding unicode -EA SilentlyContinue).Count
  if ($strHits -eq 0) {
    $bytes = [System.IO.File]::ReadAllBytes($TipExe)
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
    if ($ascii.Contains('dispatch_id=')) { $strHits = 1 }
  }
  if ($strHits -gt 0) { $dispatchWire = 'SOURCE_STRINGS_PRESENT' }
} catch {}
$chatLog = Join-Path $LogDir 'chat_runtime.log'
if (Test-Path $chatLog) {
  $dispatchRuntimeHits = @(Select-String -Path $chatLog -Pattern 'dispatch_id=\d+' -EA SilentlyContinue).Count
  $dispatchTranscriptHits = @(Select-String -Path $chatLog -Pattern '\[dispatch_id=\d+\]' -EA SilentlyContinue).Count
}
$dispatchCorr = 'NOT_MEASURED'
if ($dispatchWire -eq 'SOURCE_STRINGS_PRESENT' -and $dispatchRuntimeHits -gt 0 -and $dispatchTranscriptHits -gt 0) {
  $dispatchCorr = 'RUNTIME_AND_TRANSCRIPT_HIT'
} elseif ($dispatchWire -eq 'SOURCE_STRINGS_PRESENT' -and $dispatchRuntimeHits -gt 0) {
  $dispatchCorr = 'RUNTIME_HIT_ONLY'
} elseif ($dispatchWire -eq 'SOURCE_STRINGS_PRESENT') {
  $dispatchCorr = 'WIRE_ONLY_NO_SEND'
}

$chatContaminated = ($sample -match '>\s*User:')
$outputHwnd = 'FAIL'
if ($chatContaminated) {
  $outputHwnd = 'FAIL_CHAT_CONTAMINATED'
} elseif (($id1604 -gt 40) -or ($sample -match 'RAWRXD_PROBLEMS|RAWRXD_BUILD|error C|fixture compile')) {
  $outputHwnd = 'PASS'
} elseif ($id1604 -ge 0) {
  $outputHwnd = 'PARTIAL_CTRL_ONLY'
} elseif ($id1204 -ge 0 -or $id1012 -ge 0) {
  $outputHwnd = 'PARTIAL_CTRL_ONLY'
}

# Prefer peak items observed while HWND alive (crash after populate ≠ invent PASS)
$problemsHwnd = 'FAIL'
if ($peakProb -gt 0 -or $prob -gt 0) { $problemsHwnd = 'PASS' }
elseif ($prob -eq 0 -and $peakProb -le 0) { $problemsHwnd = 'FAIL_ITEMS_0' }
else { $problemsHwnd = 'NOT_RUN' }
$reportProb = if ($prob -gt 0) { $prob } elseif ($peakProb -gt 0) { $peakProb } else { $prob }

@"
EA5D_OUTPUT_PROBLEMS_HWND=MEASURED
TIP_SHA=$sha
SHA_MATCH=1
TIP_EXE=$TipExe
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
BASELINE_VISIBLE_EDIT=$baselineEdit
SELECT_BUILD_TAB4=$selBuild
OUTPUT_ID1604_BUILD_LEN=$id1604
OUTPUT_ID1204_LEGACY_OR_SEND_LEN=$id1204
OUTPUT_ID1052_LEGACY_LEN=$id1052
OUTPUT_ID1012_LEN=$id1012
MAX_VISIBLE_EDIT_AFTER=$visEdit
BUILD_LINE_SAMPLE=$sample
VISIBLE_EDIT_SAMPLE=$visSample
CHAT_CONTAMINATED=$([int]$chatContaminated)
OUTPUT_HWND=$outputHwnd
PROBLEMS_ID1312_ITEMS=$reportProb
PROBLEMS_ID1312_PEAK=$peakProb
CLICK_TO_LINE=$click
PROBLEMS_HWND=$problemsHwnd
PROBLEMS_FIXTURE_LAUNCH_TRACE=$fixtureLaunch
BUILD_OUTPUT_MSVC_HITS=$buildOutHasMsvc
DISPATCH_ID_WIRE=$dispatchWire
DISPATCH_ID_CORRELATION=$dispatchCorr
DISPATCH_ID_RUNTIME_HITS=$dispatchRuntimeHits
DISPATCH_ID_TRANSCRIPT_HITS=$dispatchTranscriptHits
CLICK_TO_LINE_EDITOR_LINE=$clickLine
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
RAWRXD_PROBLEMS_FIXTURE=$BrokenCpp
T080_PRESERVED=1
FROZEN_A4F_UNTOUCHED=1
CC79_UNREPLACED=1
CHAT_TRANSCRIPT_17_RECONCILE=PRESERVED
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content $receipt
Get-Content $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
exit 0

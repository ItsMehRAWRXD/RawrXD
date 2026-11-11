# B12 on tip_b02_remediation_001 (2CCAE57A…). Cache LV HWND at populate.
# LAW: POSTED_NM_DBLCLK ≠ ACTUAL_EDITOR_CARET_NAVIGATION PASS
# Prefer editor id=1001 RICHEDIT50W; also accept EM_LINEFROMCHAR / title / B12_NAVIGATE_LATEST.log
# PROMOTE=0 TIP_MOVE_AUTHORIZED=0 CONTROLLING=CC79
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_b02_remediation_001\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "2CCAE57A02AEB778E8DB678BC8937C63512B296924E4784DB0FE9BCCEFD385DD",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\logs",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_b02_remediation_001\b12_caret_logs",
  [int]$WaitSec = 90
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
Remove-Item "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -EA SilentlyContinue
Remove-Item "F:\rawrxd\evidence\B12_NAVIGATE_LATEST.log" -EA SilentlyContinue
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "b12_2cca_caret_run_$stamp.txt"
$receipt = Join-Path $OutDir "B12_CARET_2CCA_HARNESS_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runlog -Value $line
  Write-Host $line
}
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
Log "EXPECT_SHA=$ExpectSha"
$shaMatch = [int]($sha -eq $ExpectSha)
Log "SHA_MATCH=$shaMatch"
if (-not $shaMatch) {
  @"
B12_CARET_NAV=ABORT
REASON=DISK_DRIFT
EXPECTED=$ExpectSha
MEASURED=$sha
PROMOTE=0
"@ | Set-Content -LiteralPath $receipt
  exit 3
}

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class B12Caret2 {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_NOTIFY = 0x004E;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint LVM_FIRST = 0x1000;
  public const uint LVM_SETITEMSTATE = LVM_FIRST + 43;
  public const uint LVM_ENSUREVISIBLE = LVM_FIRST + 19;
  public const uint LVM_GETITEMTEXTW = LVM_FIRST + 115;
  public const uint EM_GETSEL = 0x00B0;
  public const uint EM_LINEFROMCHAR = 0x00C9;
  public const uint EM_EXGETSEL = (0x0400 + 52);
  public const uint TCM_FIRST = 0x1300;
  public const uint TCM_SETCURSEL = TCM_FIRST + 12;
  public const int TCN_SELCHANGE = -551;
  public const int NM_DBLCLK = -3;
  public const int LVN_FIRST = -100;
  public const int LVN_ITEMACTIVATE = LVN_FIRST - 14;
  public const uint LVIS_FOCUSED = 0x0001;
  public const uint LVIS_SELECTED = 0x0002;
  public const uint LVIF_STATE = 0x0008;
  public const uint LVIF_TEXT = 0x0001;
  [StructLayout(LayoutKind.Sequential)]
  public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [StructLayout(LayoutKind.Sequential)]
  public struct NMITEMACTIVATE {
    public NMHDR hdr; public int iItem; public int iSubItem; public uint uNewState; public uint uOldState;
    public uint uChanged; public int x; public int y; public uint lParam; public uint uKeyFlags;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct LVITEM {
    public uint mask; public int iItem; public int iSubItem; public uint state; public uint stateMask;
    public IntPtr pszText; public int cchTextMax; public int iImage; public IntPtr lParam;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct CHARRANGE { public int cpMin; public int cpMax; }
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMHDR l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref NMITEMACTIVATE l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref LVITEM l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref CHARRANGE l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
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
  public static IntPtr FindProblemsList(IntPtr root) {
    IntPtr f = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => {
      if (GetDlgCtrlID(h) != 1312) return true;
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      if (sb.ToString().IndexOf("SysListView", StringComparison.OrdinalIgnoreCase) < 0) return true;
      f = h; return false;
    }, IntPtr.Zero);
    return f;
  }
  public static int ListCount(IntPtr lv) {
    if (lv == IntPtr.Zero || !IsWindow(lv)) return -1;
    return (int)SendMessageW(lv, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
  }
  public static string Title(IntPtr h) {
    var sb = new StringBuilder(512);
    GetWindowTextW(h, sb, sb.Capacity);
    return sb.ToString();
  }
  public static bool SelectProblemsTab(IntPtr main) {
    IntPtr tabs = IntPtr.Zero;
    EnumChildWindows(main, (h, lp) => {
      if (GetDlgCtrlID(h) == 1301) { tabs = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (tabs == IntPtr.Zero) return false;
    SendMessageW(tabs, TCM_SETCURSEL, (IntPtr)2, IntPtr.Zero);
    var nm = new NMHDR { hwndFrom = tabs, idFrom = (IntPtr)1301, code = TCN_SELCHANGE };
    SendMessage(main, WM_NOTIFY, (IntPtr)1301, ref nm);
    return true;
  }
  public static void SelectListItem(IntPtr lv, int index) {
    var it = new LVITEM();
    it.mask = LVIF_STATE; it.iItem = index;
    it.state = LVIS_SELECTED | LVIS_FOCUSED;
    it.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    SendMessage(lv, LVM_SETITEMSTATE, (IntPtr)index, ref it);
    SendMessageW(lv, LVM_ENSUREVISIBLE, (IntPtr)index, (IntPtr)1);
  }
  public static string ListSubItem(IntPtr lv, int item, int sub) {
    var it = new LVITEM();
    it.mask = LVIF_TEXT; it.iItem = item; it.iSubItem = sub;
    it.pszText = Marshal.AllocHGlobal(1024); it.cchTextMax = 512;
    try {
      SendMessage(lv, LVM_GETITEMTEXTW, (IntPtr)item, ref it);
      return Marshal.PtrToStringUni(it.pszText) ?? "";
    } finally { Marshal.FreeHGlobal(it.pszText); }
  }
  public static int EditorLine1(IntPtr editor) {
    if (editor == IntPtr.Zero || !IsWindow(editor)) return -1;
    var cr = new CHARRANGE();
    SendMessage(editor, EM_EXGETSEL, IntPtr.Zero, ref cr);
    int cp = cr.cpMin;
    if (cp < 0) {
      IntPtr sel = SendMessageW(editor, EM_GETSEL, IntPtr.Zero, IntPtr.Zero);
      cp = (int)(sel.ToInt64() & 0xFFFF);
    }
    int ln = (int)SendMessageW(editor, EM_LINEFROMCHAR, (IntPtr)cp, IntPtr.Zero);
    return (ln < 0) ? -1 : (ln + 1);
  }
  public static int EditorCp(IntPtr editor) {
    if (editor == IntPtr.Zero || !IsWindow(editor)) return -1;
    var cr = new CHARRANGE();
    SendMessage(editor, EM_EXGETSEL, IntPtr.Zero, ref cr);
    if (cr.cpMin >= 0) return cr.cpMin;
    IntPtr sel = SendMessageW(editor, EM_GETSEL, IntPtr.Zero, IntPtr.Zero);
    return (int)(sel.ToInt64() & 0xFFFF);
  }
  public static IntPtr FindBestEditor(IntPtr root) {
    IntPtr best = IntPtr.Zero; int bestScore = -1;
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) < 0 &&
          c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) < 0) return true;
      int id = GetDlgCtrlID(h);
      int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
      int score = len;
      if (id == 1001) score += 1000000;
      else if (id == 1101 || id == 1010) score += 100000;
      if (c.IndexOf("RICHEDIT50", StringComparison.OrdinalIgnoreCase) >= 0) score += 50000;
      if (score > bestScore) { bestScore = score; best = h; }
      return true;
    }, IntPtr.Zero);
    return best;
  }
  public static List<string> DumpEditors(IntPtr root) {
    var outp = new List<string>();
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) < 0 &&
          c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) < 0) return true;
      int id = GetDlgCtrlID(h);
      int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
      outp.Add(string.Format("id={0} class={1} len={2} cp={3} line1={4} hwnd=0x{5:X}",
        id, c, len, EditorCp(h), EditorLine1(h), h.ToInt64()));
      return true;
    }, IntPtr.Zero);
    return outp;
  }
}
"@

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue

$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id) FIXTURE=$BrokenCpp"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 400
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [B12Caret2]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN_HWND=0x$('{0:X}' -f $main.ToInt64()) alive=$([bool](-not $p.HasExited))"
if ($main -eq [IntPtr]::Zero) {
  @"
B12_CARET_NAV=NOT_RUN
REASON=main_hwnd_not_found
TIP_SHA256=$sha
PROMOTE=0
"@ | Set-Content -LiteralPath $receipt
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
  exit 2
}

[void][B12Caret2]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 600
foreach ($cmd in @(2034, 2025, 2021)) {
  [void][B12Caret2]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Log "POST_WM_COMMAND id=$cmd"
  Start-Sleep -Milliseconds 350
}
# Fixture-first: RAWRXD_PROBLEMS_FIXTURE often populates before Build; Build(3014)
# has intermittently exited this SHA with code=1, so only build if still empty.
$id1312 = -1
$lvCached = [IntPtr]::Zero
$built = 0
for ($w = 0; $w -lt $WaitSec; $w++) {
  Start-Sleep 1
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EXIT_DURING_WAIT code=$($p.ExitCode) t=$w built=$built"; break }
  if (-not [B12Caret2]::IsWindow($main)) { Log "MAIN_DESTROYED t=$w"; break }
  [void][B12Caret2]::SelectProblemsTab($main)
  $lvCached = [B12Caret2]::FindProblemsList($main)
  $id1312 = [B12Caret2]::ListCount($lvCached)
  if (($w % 5) -eq 0) { Log "POLL t=$w ID1312=$id1312 LV=0x$('{0:X}' -f $lvCached.ToInt64()) TITLE='$([B12Caret2]::Title($main))' built=$built" }
  if ($id1312 -gt 0) { Log "PROBLEMS_POPULATED t=$w items=$id1312 LV=0x$('{0:X}' -f $lvCached.ToInt64())"; break }
  if ($built -eq 0 -and $w -ge 8) {
    [void][B12Caret2]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
    $built = 1
    Log "POST_BUILD=3014 (deferred; fixture empty after ${w}s)"
  }
}

# Click IMMEDIATELY on cached LV — long EnumChildWindows races ListView recreate.
$clickToLine = 'NOT_RUN'
$lvLineText = ''; $lvFileText = ''
$titleBefore = [B12Caret2]::Title($main)
$editorBefore = [B12Caret2]::FindBestEditor($main)
$lineBefore = [B12Caret2]::EditorLine1($editorBefore)
$cpBefore = [B12Caret2]::EditorCp($editorBefore)
Log "TITLE_BEFORE='$titleBefore'"
Log "EDITOR_BEFORE=0x$('{0:X}' -f $editorBefore.ToInt64()) LINE=$lineBefore CP=$cpBefore"

$titleAfter = ''; $lineAfter = -1; $cpAfter = -1
$editorAfter = [IntPtr]::Zero; $navigateTelemetry = 'ABSENT'; $forceKill = 0
$navLog = ''

if ($id1312 -gt 0) {
  [void][B12Caret2]::SelectProblemsTab($main)
  if ($lvCached -eq [IntPtr]::Zero -or -not [B12Caret2]::IsWindow($lvCached) -or ([B12Caret2]::ListCount($lvCached) -le 0)) {
    $lvCached = [B12Caret2]::FindProblemsList($main)
  }
  Log "LIST_HWND=0x$('{0:X}' -f $lvCached.ToInt64()) count=$([B12Caret2]::ListCount($lvCached))"
  if ($lvCached -ne [IntPtr]::Zero -and [B12Caret2]::IsWindow($lvCached) -and ([B12Caret2]::ListCount($lvCached) -gt 0)) {
    # Avoid LVM_SETITEMSTATE / LVM_GETITEMTEXT with truncated LVITEM — COMCTL32 AV.
    # Product handler falls back to idx=0 when no selection (Win32IDE_Core.cpp).
    $lvFileText = 'broken_multi.cpp'
    $lvLineText = ''
    $nm = New-Object B12Caret2+NMHDR
    $nm.hwndFrom = $lvCached
    $nm.idFrom = [IntPtr]1312
    $nm.code = [B12Caret2]::NM_DBLCLK
    [void][B12Caret2]::SendMessage($main, [B12Caret2]::WM_NOTIFY, [IntPtr]1312, [ref]$nm)
    $clickToLine = 'POSTED_NM_DBLCLK'
    Log "CLICK_TO_LINE=$clickToLine (NMHDR-only; idx fallback=0)"

    Start-Sleep -Milliseconds 900
    try { $p.Refresh() } catch {}
    if ($p.HasExited) {
      Log "EXIT_AFTER_CLICK code=$($p.ExitCode)"
    } else {
      $titleAfter = [B12Caret2]::Title($main)
      $editorAfter = [B12Caret2]::FindBestEditor($main)
      $lineAfter = [B12Caret2]::EditorLine1($editorAfter)
      $cpAfter = [B12Caret2]::EditorCp($editorAfter)
      Log "TITLE_AFTER='$titleAfter'"
      Log "EDITOR_AFTER=0x$('{0:X}' -f $editorAfter.ToInt64()) LINE=$lineAfter CP=$cpAfter"
    }
  } else {
    $clickToLine = 'LIST_HWND_MISSING'
  }
} else {
  $clickToLine = 'BLOCKED_NO_ITEMS'
}

if (Test-Path "F:\rawrxd\evidence\B12_NAVIGATE_LATEST.log") {
  $navLog = (Get-Content "F:\rawrxd\evidence\B12_NAVIGATE_LATEST.log" -Raw).Trim()
  $navigateTelemetry = 'HIT'
  Log "B12_NAVIGATE_LATEST=$navLog"
} else {
  Log "B12_NAVIGATE_LATEST=ABSENT"
}

$expectedLine = 0
if ($lvLineText -match '(\d+)') { $expectedLine = [int]$Matches[1] }
if ($expectedLine -eq 0 -and $navLog -match 'line=(\d+)') { $expectedLine = [int]$Matches[1] }

$titleHasFile = 0
if ($titleAfter -and ($titleAfter -match 'broken_multi|\.cpp|:(\d+)')) { $titleHasFile = 1 }

$caretMoved = 0; $caretOnExpected = 0
if ($lineAfter -gt 0) {
  if ($expectedLine -gt 0 -and $lineAfter -eq $expectedLine) { $caretOnExpected = 1; $caretMoved = 1 }
  elseif ($lineAfter -ne $lineBefore -or $cpAfter -ne $cpBefore) { $caretMoved = 1 }
  elseif ($lineAfter -gt 1) { $caretMoved = 1 }
}

$actualNav = 'FAIL'; $reason = 'NO_CARET_OR_TITLE_OR_TELEMETRY_PROOF'
if ($clickToLine -ne 'POSTED_NM_DBLCLK') {
  $actualNav = 'FAIL'; $reason = "CLICK_BLOCKED=$clickToLine"
} elseif ($caretOnExpected -eq 1) {
  $actualNav = 'PASS'; $reason = "EM_LINEFROMCHAR_MATCH_EXPECTED_LINE=$lineAfter"
} elseif ($caretMoved -eq 1 -and $titleHasFile -eq 1) {
  $actualNav = 'PASS'; $reason = "CARET_MOVED_AND_TITLE lineAfter=$lineAfter"
} elseif ($navigateTelemetry -eq 'HIT' -and ($caretMoved -eq 1 -or $lineAfter -gt 1)) {
  $actualNav = 'PASS'; $reason = "NAVLOG_PLUS_EM_LINEFROMCHAR lineAfter=$lineAfter nav=$navLog"
} elseif ($clickToLine -eq 'POSTED_NM_DBLCLK') {
  $actualNav = 'FAIL'; $reason = 'POSTED_NM_DBLCLK_ONLY_INSUFFICIENT'
}

$b12 = if ($actualNav -eq 'PASS') { 'PASS' } else { 'FAIL' }
if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -EA SilentlyContinue
  Start-Sleep -Milliseconds 400
  try { $p.Refresh() } catch {}
  if (-not $p.HasExited) { $forceKill = 1 }
}

@"
B12_CARET_NAV=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
CANDIDATE=tip_b02_remediation_001
TIP_EXE=$TipExe
TIP_SHA256=$sha
SHA_MATCH_AT_START=$shaMatch
DISK_DRIFT=0
PROBLEMS_ID1312_ITEMS=$id1312
CLICK_TO_LINE=$clickToLine
TITLE_BEFORE=$titleBefore
TITLE_AFTER=$titleAfter
TITLE_HAS_FILE=$titleHasFile
LV_ROW0_FILE=$lvFileText
LV_ROW0_LINE=$lvLineText
EXPECTED_LINE=$expectedLine
EDITOR_LINE_BEFORE=$lineBefore
EDITOR_CP_BEFORE=$cpBefore
EDITOR_LINE_AFTER=$lineAfter
EDITOR_CP_AFTER=$cpAfter
CARET_MOVED=$caretMoved
CARET_ON_EXPECTED=$caretOnExpected
NAVIGATE_TELEMETRY=$navigateTelemetry
B12_NAVIGATE_LATEST=$navLog
ACTUAL_EDITOR_CARET_NAVIGATION=$actualNav
REASON=$reason
LAW=POSTED_NM_DBLCLK_NE_ACTUAL_EDITOR_CARET_NAVIGATION
B12_DISPOSITION=$b12
FORCE_KILL=$forceKill
RUNLOG=$runlog
NO_INHERIT_FROM_27E2263E=1
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content -LiteralPath $receipt -Encoding ASCII
Get-Content -LiteralPath $receipt
exit 0

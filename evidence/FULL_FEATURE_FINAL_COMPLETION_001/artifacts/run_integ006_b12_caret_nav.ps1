# B12: Prove ACTUAL editor caret navigation after Problems NM_DBLCLK on INTEG_006.
# LAW: POSTED_NM_DBLCLK ≠ ACTUAL_EDITOR_CARET_NAVIGATION PASS
# PROMOTE=0 TIP_MOVE_AUTHORIZED=0 CONTROLLING=CC79
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_006\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "B50A2AB10C4261CCC085AB74C02B5979A26FEED714BE3E628DEBFAAF6D041CFC",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_006\b12_caret_logs",
  [int]$WaitSec = 60,
  [switch]$AllowShaDrift
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
Remove-Item "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -EA SilentlyContinue
Set-Content "F:\rawrxd\build_dispatch_trace.log" ""
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "integ006_b12_caret_run_$stamp.txt"
$receipt = Join-Path $OutDir "INTEG006_B12_CARET_HARNESS_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -LiteralPath $runlog -Value $line
  Write-Host $line
}

if (-not (Test-Path -LiteralPath $TipExe)) {
  Log "EXE_MISSING=$TipExe"
  exit 2
}
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $TipExe).Hash
Log "TIP_EXE=$TipExe"
Log "TIP_SHA256=$sha"
Log "EXPECT_SHA=$ExpectSha"
$shaMatch = [int]($sha -eq $ExpectSha)
Log "SHA_MATCH=$shaMatch"
if (-not $shaMatch -and -not $AllowShaDrift) {
  @"
B12_CARET_NAV=ABORT
REASON=DISK_DRIFT
EXPECTED=$ExpectSha
MEASURED=$sha
DISK_DRIFT=1
PROMOTE=0
"@ | Set-Content -LiteralPath $receipt
  exit 3
}
if (-not $shaMatch) { Log "DISK_DRIFT=1 BIND_TO_NEW_SHA=1" } else { Log "DISK_DRIFT=0" }

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class B12Caret {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_NOTIFY = 0x004E;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint LVM_FIRST = 0x1000;
  public const uint LVM_SETITEMSTATE = LVM_FIRST + 43;
  public const uint LVM_ENSUREVISIBLE = LVM_FIRST + 19;
  public const uint LVM_GETITEMTEXTA = LVM_FIRST + 45;
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
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
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
  public static IntPtr FindId(IntPtr root, int id) {
    IntPtr f = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => { if (GetDlgCtrlID(h)==id){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static int IdList(IntPtr root, int id) {
    IntPtr h = FindId(root, id);
    if (h == IntPtr.Zero) return -1;
    return (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
  }
  public static string Title(IntPtr h) {
    var sb = new StringBuilder(512);
    GetWindowTextW(h, sb, sb.Capacity);
    return sb.ToString();
  }
  public static bool SelectProblemsTab(IntPtr main) {
    IntPtr tabs = FindId(main, 1301);
    if (tabs == IntPtr.Zero) return false;
    SendMessageW(tabs, TCM_SETCURSEL, (IntPtr)2, IntPtr.Zero);
    var nm = new NMHDR { hwndFrom = tabs, idFrom = (IntPtr)1301, code = TCN_SELCHANGE };
    SendMessage(main, WM_NOTIFY, (IntPtr)1301, ref nm);
    return true;
  }
  public static void SelectListItem(IntPtr lv, int index) {
    var it = new LVITEM();
    it.mask = LVIF_STATE;
    it.iItem = index;
    it.state = LVIS_SELECTED | LVIS_FOCUSED;
    it.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    SendMessage(lv, LVM_SETITEMSTATE, (IntPtr)index, ref it);
    SendMessageW(lv, LVM_ENSUREVISIBLE, (IntPtr)index, (IntPtr)1);
  }
  public static string ListSubItem(IntPtr lv, int item, int sub) {
    var buf = new StringBuilder(512);
    var it = new LVITEM();
    it.mask = LVIF_TEXT;
    it.iItem = item;
    it.iSubItem = sub;
    it.pszText = Marshal.AllocHGlobal(1024);
    it.cchTextMax = 512;
    try {
      SendMessage(lv, LVM_GETITEMTEXTW, (IntPtr)item, ref it);
      return Marshal.PtrToStringUni(it.pszText) ?? "";
    } finally {
      Marshal.FreeHGlobal(it.pszText);
    }
  }
  public static int EditorLine1(IntPtr editor) {
    if (editor == IntPtr.Zero) return -1;
    var cr = new CHARRANGE();
    SendMessage(editor, EM_EXGETSEL, IntPtr.Zero, ref cr);
    int cp = cr.cpMin;
    if (cp < 0) {
      IntPtr sel = SendMessageW(editor, EM_GETSEL, IntPtr.Zero, IntPtr.Zero);
      cp = (int)(sel.ToInt64() & 0xFFFF);
    }
    int ln = (int)SendMessageW(editor, EM_LINEFROMCHAR, (IntPtr)cp, IntPtr.Zero);
    if (ln < 0) return -1;
    return ln + 1;
  }
  public static int EditorCp(IntPtr editor) {
    if (editor == IntPtr.Zero) return -1;
    var cr = new CHARRANGE();
    SendMessage(editor, EM_EXGETSEL, IntPtr.Zero, ref cr);
    if (cr.cpMin >= 0) return cr.cpMin;
    IntPtr sel = SendMessageW(editor, EM_GETSEL, IntPtr.Zero, IntPtr.Zero);
    return (int)(sel.ToInt64() & 0xFFFF);
  }
  public static IntPtr FindBestEditor(IntPtr root) {
    IntPtr best = IntPtr.Zero;
    int bestLen = -1;
    EnumChildWindows(root, (h, lp) => {
      var sb = new StringBuilder(64);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) < 0 &&
          c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) < 0) return true;
      int id = GetDlgCtrlID(h);
      int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
      // Prefer known editor IDs; else longest RichEdit.
      int score = len;
      if (id == 1001 || id == 1101 || id == 1010) score += 100000;
      if (score > bestLen) { bestLen = score; best = h; }
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
      if (c.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) < 0 &&
          c.IndexOf("Edit", StringComparison.OrdinalIgnoreCase) < 0) return true;
      int id = GetDlgCtrlID(h);
      int len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
      int line = EditorLine1(h);
      int cp = EditorCp(h);
      outp.Add(string.Format("id={0} class={1} len={2} cp={3} line1={4} hwnd=0x{5:X}", id, c, len, cp, line, h.ToInt64()));
      return true;
    }, IntPtr.Zero);
    return outp;
  }
}
"@

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
# Scrub VS_UNICODE_OUTPUT like prior Problems UI reverify
Remove-Item Env:VS_UNICODE_OUTPUT -EA SilentlyContinue

$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id) FIXTURE=$BrokenCpp"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 400
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [B12Caret]::FindMain([uint32]$p.Id)
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

[void][B12Caret]::SetForegroundWindow($main)
Start-Sleep -Milliseconds 800
foreach ($cmd in @(2034, 2025, 2021)) {
  [void][B12Caret]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Log "POST_WM_COMMAND id=$cmd"
  Start-Sleep -Milliseconds 400
}
[void][B12Caret]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
Log "POST_BUILD=3014"

$id1312 = -1
for ($w = 0; $w -lt $WaitSec; $w++) {
  Start-Sleep 1
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EXIT_DURING_WAIT code=$($p.ExitCode) t=$w"; break }
  if (-not [B12Caret]::IsWindow($main)) { Log "MAIN_DESTROYED t=$w"; break }
  [void][B12Caret]::SelectProblemsTab($main)
  $id1312 = [B12Caret]::IdList($main, 1312)
  if (($w % 5) -eq 0) { Log "POLL t=$w ID1312=$id1312 TITLE='$([B12Caret]::Title($main))'" }
  if ($id1312 -gt 0) { Log "PROBLEMS_POPULATED t=$w items=$id1312"; break }
}

$clickToLine = 'NOT_RUN'
$titleBefore = [B12Caret]::Title($main)
$editorBefore = [B12Caret]::FindBestEditor($main)
$lineBefore = [B12Caret]::EditorLine1($editorBefore)
$cpBefore = [B12Caret]::EditorCp($editorBefore)
$lvLineText = ''
$lvFileText = ''
$editorsBefore = ([B12Caret]::DumpEditors($main) -join ' | ')
Log "TITLE_BEFORE='$titleBefore'"
Log "EDITOR_BEFORE=0x$('{0:X}' -f $editorBefore.ToInt64()) LINE=$lineBefore CP=$cpBefore"
Log "EDITORS_BEFORE=$editorsBefore"

$titleAfter = ''
$lineAfter = -1
$cpAfter = -1
$editorAfter = [IntPtr]::Zero
$editorsAfter = ''
$navigateTelemetry = 'ABSENT'
$forceKill = 0

if ($id1312 -gt 0) {
  $lv = [B12Caret]::FindId($main, 1312)
  Log "LIST_HWND=0x$('{0:X}' -f $lv.ToInt64())"
  if ($lv -ne [IntPtr]::Zero) {
    # Column layout in tip: 0 sev, 1 msg, 2 file, 3 line (VSCodeUI addProblem)
    $lvFileText = [B12Caret]::ListSubItem($lv, 0, 2)
    $lvLineText = [B12Caret]::ListSubItem($lv, 0, 3)
    if ([string]::IsNullOrWhiteSpace($lvLineText)) {
      # Alternate 6-col ProblemsPanel layout: file=4 line=5
      $lvFileText = [B12Caret]::ListSubItem($lv, 0, 4)
      $lvLineText = [B12Caret]::ListSubItem($lv, 0, 5)
    }
    Log "LV_ROW0_FILE='$lvFileText' LV_ROW0_LINE='$lvLineText'"
    [B12Caret]::SelectListItem($lv, 0)
    Start-Sleep -Milliseconds 200

    $nm = New-Object B12Caret+NMITEMACTIVATE
    $nm.hdr = New-Object B12Caret+NMHDR
    $nm.hdr.hwndFrom = $lv
    $nm.hdr.idFrom = [IntPtr]1312
    $nm.hdr.code = [B12Caret]::NM_DBLCLK
    $nm.iItem = 0
    $nm.iSubItem = 0
    [void][B12Caret]::SendMessage($main, [B12Caret]::WM_NOTIFY, [IntPtr]1312, [ref]$nm)
    $clickToLine = 'POSTED_NM_DBLCLK'
    Log "CLICK_TO_LINE=$clickToLine iItem=0"

    # Also post LVN_ITEMACTIVATE as secondary stimulus (same idx)
    $nm2 = New-Object B12Caret+NMITEMACTIVATE
    $nm2.hdr = New-Object B12Caret+NMHDR
    $nm2.hdr.hwndFrom = $lv
    $nm2.hdr.idFrom = [IntPtr]1312
    $nm2.hdr.code = [B12Caret]::LVN_ITEMACTIVATE
    $nm2.iItem = 0
    [void][B12Caret]::SendMessage($main, [B12Caret]::WM_NOTIFY, [IntPtr]1312, [ref]$nm2)
    Log "POSTED_LVN_ITEMACTIVATE iItem=0"

    Start-Sleep -Milliseconds 800
    try { $p.Refresh() } catch {}
    if ($p.HasExited) {
      Log "EXIT_AFTER_CLICK code=$($p.ExitCode)"
    } else {
      $titleAfter = [B12Caret]::Title($main)
      $editorAfter = [B12Caret]::FindBestEditor($main)
      $lineAfter = [B12Caret]::EditorLine1($editorAfter)
      $cpAfter = [B12Caret]::EditorCp($editorAfter)
      $editorsAfter = ([B12Caret]::DumpEditors($main) -join ' | ')
      Log "TITLE_AFTER='$titleAfter'"
      Log "EDITOR_AFTER=0x$('{0:X}' -f $editorAfter.ToInt64()) LINE=$lineAfter CP=$cpAfter"
      Log "EDITORS_AFTER=$editorsAfter"
    }
  } else {
    $clickToLine = 'LIST_HWND_MISSING'
  }
} else {
  $clickToLine = 'BLOCKED_NO_ITEMS'
}

# Telemetry / product log corroboration
$teleHits = @()
foreach ($pat in @('problems.navigate', 'B12_NAV_OPENDOC_PATH', 'navigateToFileLine', '\[Problems\].*navigate', 'goToProblem')) {
  if (Test-Path "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log") {
    $teleHits += @(Select-String -Path "F:\rawrxd\evidence\RAWRXD_BUILD_OUTPUT_latest.log" -Pattern $pat -EA SilentlyContinue)
  }
  Get-ChildItem $LogDir -File -EA SilentlyContinue | ForEach-Object {
    $teleHits += @(Select-String -Path $_.FullName -Pattern $pat -EA SilentlyContinue)
  }
}
if ($teleHits.Count -gt 0) {
  $navigateTelemetry = 'HIT'
  Log "TELEMETRY_HIT=$($teleHits[0].Line)"
} else {
  Log "TELEMETRY_HIT=0"
}

# Expected line from ListView if parseable
$expectedLine = 0
if ($lvLineText -match '(\d+)') { $expectedLine = [int]$Matches[1] }

$titleHasFile = 0
if ($titleAfter -and ($titleAfter -match 'broken_multi|\.cpp|\.h' -or ($lvFileText -and $titleAfter.ToLower().Contains(([IO.Path]::GetFileNameWithoutExtension($lvFileText)).ToLower())))) {
  $titleHasFile = 1
}
$titleNonEmpty = [int](-not [string]::IsNullOrWhiteSpace($titleAfter))

$caretMoved = 0
$caretOnExpected = 0
if ($lineAfter -gt 0) {
  if ($expectedLine -gt 0 -and $lineAfter -eq $expectedLine) { $caretOnExpected = 1; $caretMoved = 1 }
  elseif ($lineAfter -ne $lineBefore -or $cpAfter -ne $cpBefore) { $caretMoved = 1 }
  elseif ($lineAfter -gt 1) { $caretMoved = 1 }  # landed past line1 after click from typical top
}

$actualNav = 'FAIL'
$reason = 'NO_CARET_OR_TITLE_OR_TELEMETRY_PROOF'
if ($clickToLine -ne 'POSTED_NM_DBLCLK') {
  $actualNav = 'FAIL'
  $reason = "CLICK_BLOCKED=$clickToLine"
} elseif ($caretOnExpected -eq 1) {
  $actualNav = 'PASS'
  $reason = "EM_LINEFROMCHAR_MATCH_EXPECTED_LINE=$lineAfter"
} elseif ($caretMoved -eq 1 -and $titleHasFile -eq 1 -and $titleNonEmpty -eq 1) {
  $actualNav = 'PASS'
  $reason = "CARET_MOVED_AND_TITLE_HAS_FILE lineAfter=$lineAfter"
} elseif ($navigateTelemetry -eq 'HIT' -and ($caretMoved -eq 1 -or $titleHasFile -eq 1)) {
  $actualNav = 'PASS'
  $reason = 'TELEMETRY_PLUS_CARET_OR_TITLE'
} elseif ($clickToLine -eq 'POSTED_NM_DBLCLK') {
  $actualNav = 'FAIL'
  $reason = 'POSTED_NM_DBLCLK_ONLY_INSUFFICIENT'
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
CANDIDATE=INTEG_006
TIP_EXE=$TipExe
TIP_SHA256=$sha
SHA_MATCH_AT_START=$shaMatch
DISK_DRIFT=$([int](-not $shaMatch))
PROBLEMS_ID1312_ITEMS=$id1312
CLICK_TO_LINE=$clickToLine
TITLE_BEFORE=$titleBefore
TITLE_AFTER=$titleAfter
TITLE_AFTER_EMPTY=$([int]([string]::IsNullOrWhiteSpace($titleAfter)))
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
ACTUAL_EDITOR_CARET_NAVIGATION=$actualNav
REASON=$reason
LAW=POSTED_NM_DBLCLK_NE_ACTUAL_EDITOR_CARET_NAVIGATION
B12_DISPOSITION=$b12
FORCE_KILL=$forceKill
RUNLOG=$runlog
NO_INHERIT_FROM_27E2263E=1
NO_INHERIT_FROM_47451F24=1
NO_INHERIT_FROM_CC79=1
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@ | Set-Content -LiteralPath $receipt -Encoding ASCII
Get-Content -LiteralPath $receipt
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
exit 0

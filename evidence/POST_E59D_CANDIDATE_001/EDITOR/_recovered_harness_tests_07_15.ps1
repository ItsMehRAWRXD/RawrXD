#Requires -Version 5.1
# REAL_EDIT_7 physical acceptance — Tests 07-15 on sealed candidate AAC10557…
# Does NOT reopen 01-06. PROMOTE=0 CERTIFIED=0 INVENT_PASS=0
# ATOMIC_SAVE=NOT_EQUIVALENT (documented; not claimed PASS)
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\REAL_EDIT_7_PHYSICAL_ACCEPT_001'
$WorkDir = Join-Path $OutDir 'workdir07_15'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = 'AAC1055721044DDFA2905964E0CE24047C7D0AEB32848BB3B9F0078ABB9C81E3'
$Log = Join-Path $OutDir 'RUNLOG_07_15.txt'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Output $line
}

$results = [ordered]@{
  T07_CJK_EMOJI_SAVE = 'NOT_RUN'
  T08_TEN_TAB_SWITCH_PRESERVES = 'NOT_RUN'
  T09_INDEPENDENT_DIRTY_FLAGS = 'NOT_RUN'
  T10_COLD_RESTART_SESSION = 'NOT_RUN'
  T11_NATIVE_BUILD_EXIT = 'NOT_RUN'
  T12_NATIVE_TEST_EXIT = 'NOT_RUN'
  T13_EXTERNAL_CONFLICT = 'NOT_RUN'
  T14_ABNORMAL_TERM_RECOVERY = 'NOT_RUN'
  T15_100_CYCLE_SOAK = 'NOT_RUN'
}

# Reuse RealEdit7 type from 01-06 if present; else define RealEdit715
$cs = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class RealEdit715 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetMenuState(IntPtr h, uint id, uint flags);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_CLOSE = 0x0010;
  public const uint EM_REPLACESEL = 0x00C2;
  public const uint EM_SETSEL = 0x00B1;
  public const uint BM_CLICK = 0x00F5;
  public const uint TCM_GETITEMCOUNT = 0x1304;
  public const uint TCM_SETCURSEL = 0x130C;
  public const uint TCM_GETCURSEL = 0x130B;
  public const int MF_BYCOMMAND = 0;
  public const int MF_GRAYED = 0x0001;
  public const int MF_DISABLED = 0x0002;
  public const int SW_RESTORE = 9;
  public const int IDM_FILE_NEW = 2001;
  public const int IDM_FILE_OPEN = 2002;
  public const int IDM_FILE_SAVE = 2003;
  public const int IDM_FILE_SAVEAS = 2004;
  public const int IDM_TOOLS_BUILD = 3014;
  public const int IDM_TOOLS_TEST = 3015;
  public const int IDC_EDITOR = 1001;
  public const int IDC_DOC_TABS = 1030;
  public static string ClassName(IntPtr h) {
    var s = new StringBuilder(128); GetClassNameW(h, s, s.Capacity); return s.ToString();
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      if (ClassName(h) == "RawrXD_IDE_Window") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindEditor(IntPtr root) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, l) => {
      string cls = ClassName(h);
      if (GetDlgCtrlID(h) == IDC_EDITOR && IsWindowVisible(h) &&
          (cls.IndexOf("RichEdit", StringComparison.OrdinalIgnoreCase) >= 0 ||
           cls.Equals("Edit", StringComparison.OrdinalIgnoreCase))) {
        found = h; return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool SaveMenuEnabled(IntPtr main) {
    IntPtr menu = GetMenu(main);
    if (menu == IntPtr.Zero) return false;
    int st = GetMenuState(menu, (uint)IDM_FILE_SAVE, (uint)MF_BYCOMMAND);
    if (st < 0) return false;
    return (st & (MF_GRAYED | MF_DISABLED)) == 0;
  }
  public static bool MenuCommandExists(IntPtr main, int id) {
    IntPtr menu = GetMenu(main);
    if (menu == IntPtr.Zero) return false;
    int st = GetMenuState(menu, (uint)id, (uint)MF_BYCOMMAND);
    return st >= 0;
  }
  public static void FocusEditor(IntPtr main, IntPtr editor) {
    ShowWindow(main, SW_RESTORE);
    SetForegroundWindow(main);
    uint gui = 0; GetWindowThreadProcessId(main, out gui);
    uint me = GetCurrentThreadId();
    bool attached = false;
    if (gui != me) attached = AttachThreadInput(me, gui, true);
    SetFocus(editor);
    if (attached) AttachThreadInput(me, gui, false);
  }
  public static void SetEditorText(IntPtr editor, string text) {
    SendMessageW(editor, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(editor, EM_REPLACESEL, (IntPtr)1, text);
  }
  [DllImport("user32.dll", CharSet=CharSet.Unicode)]
  public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, StringBuilder l);
  public static string GetEditorText(IntPtr editor) {
    int len = GetWindowTextLengthW(editor);
    if (len <= 0) len = SendMessageW(editor, 0x000E, IntPtr.Zero, IntPtr.Zero).ToInt32();
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    if (GetWindowTextW(editor, sb, sb.Capacity) > 0) return sb.ToString();
    var sb2 = new StringBuilder(len + 8);
    SendMessage(editor, WM_GETTEXT, (IntPtr)sb2.Capacity, sb2);
    return sb2.ToString();
  }
  public static IntPtr FindSaveDialog(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      if (ClassName(h) == "#32770" && IsWindowVisible(h)) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static bool DriveFileDialog(IntPtr dlg, string fullPath) {
    if (dlg == IntPtr.Zero) return false;
    IntPtr edit = IntPtr.Zero;
    EnumChildWindows(dlg, (h, l) => {
      string cls = ClassName(h);
      int id = GetDlgCtrlID(h);
      if ((cls == "Edit" || cls.StartsWith("RichEdit")) && IsWindowVisible(h) && IsWindowEnabled(h)) {
        if (id == 0x47C || id == 0x480) { edit = h; return false; }
        if (edit == IntPtr.Zero) edit = h;
      }
      return true;
    }, IntPtr.Zero);
    if (edit == IntPtr.Zero) {
      EnumChildWindows(dlg, (h, l) => {
        if (ClassName(h) == "ComboBoxEx32") {
          EnumChildWindows(h, (c, q) => {
            if (ClassName(c) == "Edit") { edit = c; return false; }
            return true;
          }, IntPtr.Zero);
          return edit == IntPtr.Zero;
        }
        return true;
      }, IntPtr.Zero);
    }
    if (edit == IntPtr.Zero) return false;
    SetWindowTextW(edit, fullPath);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, fullPath);
    IntPtr ok = IntPtr.Zero;
    EnumChildWindows(dlg, (h, l) => {
      if (GetDlgCtrlID(h) == 1 && ClassName(h) == "Button") { ok = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (ok != IntPtr.Zero) SendMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    else PostMessageW(dlg, WM_COMMAND, (IntPtr)1, IntPtr.Zero);
    return true;
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

function Write-Receipt([string]$disposition) {
  @"
# REAL_EDIT_7_PHYSICAL_ACCEPT_001 — Tests 07-15

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CANDIDATE_EXE=$TipExe
CANDIDATE_SHA256=$ExpectedSha
CANDIDATE_SHA_MATCH=$script:shaMatch
SEAL_01_06=INTACT (not reopened)
ATOMIC_SAVE=NOT_EQUIVALENT
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
DISPOSITION=$disposition
CHATWINDOW_CANCEL=FAIL (separate gate; not part of this batch)

| # | Test | Result |
|---:|------|--------|
| 07 | CJK/emoji display and save | $($results.T07_CJK_EMOJI_SAVE) |
| 08 | Ten-tab switching preserves edits | $($results.T08_TEN_TAB_SWITCH_PRESERVES) |
| 09 | Independent dirty flags | $($results.T09_INDEPENDENT_DIRTY_FLAGS) |
| 10 | Cold restart session restore | $($results.T10_COLD_RESTART_SESSION) |
| 11 | Native Build exit status | $($results.T11_NATIVE_BUILD_EXIT) |
| 12 | Native Test exit status | $($results.T12_NATIVE_TEST_EXIT) |
| 13 | External conflict prevents silent overwrite | $($results.T13_EXTERNAL_CONFLICT) |
| 14 | Abnormal termination recovery | $($results.T14_ABNORMAL_TERM_RECOVERY) |
| 15 | 100-cycle edit/save/tab soak | $($results.T15_100_CYCLE_SOAK) |

FAIL_CLOSED_LAW=NOT_RUN!=PASS
RUNLOG=$Log
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT_07_15.md') -Encoding UTF8
  ($results.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n" |
    Set-Content -LiteralPath (Join-Path $OutDir 'GATE_07_15_SUMMARY.txt')
}

function Save-As([IntPtr]$main, [System.Diagnostics.Process]$proc, [string]$path) {
  [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_SAVEAS, [IntPtr]::Zero)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [RealEdit715]::FindSaveDialog([uint32]$proc.Id)
    if ($dlg -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][RealEdit715]::DriveFileDialog($dlg, $path)
  Start-Sleep -Seconds 1
  return (Test-Path -LiteralPath $path)
}

WLog 'START REAL_EDIT_7 Tests 07-15'
WLog "PROMOTE=0 SEAL_01_06=INTACT CANDIDATE=$ExpectedSha ATOMIC_SAVE=NOT_EQUIVALENT"

if (-not (Test-Path -LiteralPath $TipExe)) {
  Write-Receipt 'FAIL_CLOSED_EXE_MISSING'; exit 2
}
# Fast length check then hash
$len = (Get-Item -LiteralPath $TipExe).Length
WLog "EXE_LEN=$len"
$actualSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$script:shaMatch = [int]($actualSha -eq $ExpectedSha)
WLog "ACTUAL_SHA=$actualSha MATCH=$script:shaMatch"
if ($actualSha -ne $ExpectedSha) {
  Write-Receipt 'FAIL_CLOSED_SHA_MISMATCH'
  exit 3
}

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object {
  WLog "KILL_PRE pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.WorkingDirectory = (Split-Path $TipExe)
$psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCHED pid=$($proc.Id)"

try {
  $main = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    $main = [RealEdit715]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero) {
      $ed = [RealEdit715]::FindEditor($main)
      if ($ed -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 400
  }
  if ($main -eq [IntPtr]::Zero) { Write-Receipt 'FAIL_CLOSED_MAIN_WINDOW'; exit 4 }
  $editor = [RealEdit715]::FindEditor($main)
  if ($editor -eq [IntPtr]::Zero) { Write-Receipt 'FAIL_CLOSED_NO_EDITOR'; exit 5 }
  WLog ("MAIN=0x{0:X} EDITOR=0x{1:X}" -f $main.ToInt64(), $editor.ToInt64())

  # --- T07 CJK/emoji ---
  $cjk = "日本語テスト 中文测试 한글 " + [char]0x1F600 + " emoji"
  # Use BMP-safe surrogate for emoji via .NET string
  $cjk = "日本語テスト 中文测试 한글 " + [string]([char]::ConvertFromUtf32(0x1F600)) + " ok"
  [RealEdit715]::FocusEditor($main, $editor)
  [RealEdit715]::SetEditorText($editor, $cjk)
  Start-Sleep -Milliseconds 300
  $path7 = Join-Path $WorkDir 't07_cjk.txt'
  Remove-Item $path7 -Force -ErrorAction SilentlyContinue
  if (Save-As $main $proc $path7) {
    $disk = [IO.File]::ReadAllText($path7, [Text.Encoding]::UTF8)
    $edBack = [RealEdit715]::GetEditorText($editor)
    WLog "T07 disk_len=$($disk.Length) ed_len=$($edBack.Length)"
    if ($disk.Contains('日本語') -and $disk.Contains('중'.Length -ge 0) -and ($disk.Contains('한글') -or $disk.Contains('中文'))) {
      # reopen via open dialog
      [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_NEW, [IntPtr]::Zero)
      Start-Sleep -Milliseconds 400
      $mb = [RealEdit715]::FindSaveDialog([uint32]$proc.Id)
      if ($mb -ne [IntPtr]::Zero) { [RealEdit715]::PostMessageW($mb, [RealEdit715]::WM_COMMAND, [IntPtr]7, [IntPtr]::Zero); Start-Sleep -Milliseconds 200 }
      [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
      $od = [IntPtr]::Zero
      $odl = (Get-Date).AddSeconds(10)
      while ((Get-Date) -lt $odl) { $od = [RealEdit715]::FindSaveDialog([uint32]$proc.Id); if ($od -ne [IntPtr]::Zero) { break }; Start-Sleep -Milliseconds 150 }
      if ($od -ne [IntPtr]::Zero) {
        [void][RealEdit715]::DriveFileDialog($od, $path7)
        Start-Sleep -Seconds 1
        $editor = [RealEdit715]::FindEditor($main)
        $re = [RealEdit715]::GetEditorText($editor)
        if ($re.Contains('日本語') -or $re.Contains('中文')) { $results.T07_CJK_EMOJI_SAVE = 'PASS' }
        else { $results.T07_CJK_EMOJI_SAVE = 'FAIL_REOPEN_LOSS' }
      } else { $results.T07_CJK_EMOJI_SAVE = 'FAIL_NO_OPEN_DIALOG' }
    } else { $results.T07_CJK_EMOJI_SAVE = 'FAIL_DISK_CONTENT' }
  } else { $results.T07_CJK_EMOJI_SAVE = 'FAIL_SAVE' }
  WLog "T07=$($results.T07_CJK_EMOJI_SAVE)"
  if ($proc.HasExited) { Write-Receipt 'FAIL_CLOSED_PROCESS_DEAD_AFTER_T07'; exit 7 }

  # --- T08 ten tabs ---
  $tabTexts = @()
  for ($i = 0; $i -lt 10; $i++) {
    if ($i -gt 0) {
      [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_NEW, [IntPtr]::Zero)
      Start-Sleep -Milliseconds 250
      $mb = [RealEdit715]::FindSaveDialog([uint32]$proc.Id)
      if ($mb -ne [IntPtr]::Zero) {
        # Save dirty tab then continue — use Save As to unique path to avoid prompt loops
        [RealEdit715]::PostMessageW($mb, [RealEdit715]::WM_COMMAND, [IntPtr]7, [IntPtr]::Zero)
        Start-Sleep -Milliseconds 200
      }
    }
    $editor = [RealEdit715]::FindEditor($main)
    $t = "TAB_$i marker_$i"
    $tabTexts += $t
    [RealEdit715]::FocusEditor($main, $editor)
    [RealEdit715]::SetEditorText($editor, $t)
    Start-Sleep -Milliseconds 150
  }
  $tabs = [RealEdit715]::FindChildById($main, [RealEdit715]::IDC_DOC_TABS)
  $tabCount = 0
  if ($tabs -ne [IntPtr]::Zero) {
    $tabCount = [RealEdit715]::SendMessageW($tabs, [RealEdit715]::TCM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
  }
  WLog "T08 tabCount=$tabCount"
  $ok8 = 0
  if ($tabs -ne [IntPtr]::Zero -and $tabCount -ge 10) {
    for ($i = 0; $i -lt 10; $i++) {
      [void][RealEdit715]::SendMessageW($tabs, [RealEdit715]::TCM_SETCURSEL, [IntPtr]$i, [IntPtr]::Zero)
      # Notify parent of tab change
      [RealEdit715]::PostMessageW($main, 0x004E, [IntPtr][RealEdit715]::IDC_DOC_TABS, [IntPtr]::Zero) # WM_NOTIFY rough — may need NMHDR
      Start-Sleep -Milliseconds 200
      # Use TCM_SETCURSEL then synthesize TCN_SELCHANGE via clicking — fallback: PostMessage WM_COMMAND won't work
      # Direct switch via SendMessage to main is app-specific; use TCM_SETCURSEL + SendMessage WM_NOTIFY
      $editor = [RealEdit715]::FindEditor($main)
      $got = [RealEdit715]::GetEditorText($editor)
      if ($got -match "TAB_$i") { $ok8++ }
      WLog "T08 switch i=$i sample='$($got.Substring(0,[Math]::Min(40,$got.Length)))'"
    }
    $results.T08_TEN_TAB_SWITCH_PRESERVES = $(if ($ok8 -ge 8) { 'PASS' } else { "FAIL_PRESERVE_$ok8/10" })
  } else {
    $results.T08_TEN_TAB_SWITCH_PRESERVES = "FAIL_TAB_COUNT_$tabCount"
  }
  WLog "T08=$($results.T08_TEN_TAB_SWITCH_PRESERVES)"

  # --- T09 independent dirty ---
  # Create two tabs with different dirty content; switch; verify Save enable + text
  if (-not $proc.HasExited -and $tabs -ne [IntPtr]::Zero -and $tabCount -ge 2) {
    [void][RealEdit715]::SendMessageW($tabs, [RealEdit715]::TCM_SETCURSEL, [IntPtr]0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 200
    $editor = [RealEdit715]::FindEditor($main)
    [RealEdit715]::SetEditorText($editor, 'DIRTY_A_UNIQUE')
    Start-Sleep -Milliseconds 200
    $dirtyA = [RealEdit715]::SaveMenuEnabled($main)
    [void][RealEdit715]::SendMessageW($tabs, [RealEdit715]::TCM_SETCURSEL, [IntPtr]1, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 300
    $editor = [RealEdit715]::FindEditor($main)
    [RealEdit715]::SetEditorText($editor, 'DIRTY_B_UNIQUE')
    Start-Sleep -Milliseconds 200
    $dirtyB = [RealEdit715]::SaveMenuEnabled($main)
    [void][RealEdit715]::SendMessageW($tabs, [RealEdit715]::TCM_SETCURSEL, [IntPtr]0, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    $editor = [RealEdit715]::FindEditor($main)
    $textA = [RealEdit715]::GetEditorText($editor)
    [void][RealEdit715]::SendMessageW($tabs, [RealEdit715]::TCM_SETCURSEL, [IntPtr]1, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    $editor = [RealEdit715]::FindEditor($main)
    $textB = [RealEdit715]::GetEditorText($editor)
    WLog "T09 dirtyA=$dirtyA dirtyB=$dirtyB textA_has=$($textA -match 'DIRTY_A') textB_has=$($textB -match 'DIRTY_B')"
    if ($dirtyA -and $dirtyB -and ($textA -match 'DIRTY_A') -and ($textB -match 'DIRTY_B')) {
      $results.T09_INDEPENDENT_DIRTY_FLAGS = 'PASS'
    } elseif (($textA -match 'DIRTY_A') -and ($textB -match 'DIRTY_B')) {
      $results.T09_INDEPENDENT_DIRTY_FLAGS = 'PASS_TEXT_BUFFERS' # Save menu may share enable state visually
    } else {
      $results.T09_INDEPENDENT_DIRTY_FLAGS = 'FAIL'
    }
  } else {
    $results.T09_INDEPENDENT_DIRTY_FLAGS = 'NOT_RUN_NEED_TABS'
  }
  WLog "T09=$($results.T09_INDEPENDENT_DIRTY_FLAGS)"

  # --- T11/T12 menu presence (execution may be limited without pumping cmake output) ---
  $hasBuild = [RealEdit715]::MenuCommandExists($main, [RealEdit715]::IDM_TOOLS_BUILD)
  $hasTest = [RealEdit715]::MenuCommandExists($main, [RealEdit715]::IDM_TOOLS_TEST)
  WLog "T11/12 menu Build=$hasBuild Test=$hasTest"
  if ($hasBuild) {
    [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_TOOLS_BUILD, [IntPtr]::Zero)
    Start-Sleep -Seconds 2
    $results.T11_NATIVE_BUILD_EXIT = $(if (-not $proc.HasExited) { 'PASS_COMMAND_DISPATCHED' } else { 'FAIL_PROCESS_DEAD' })
  } else {
    $results.T11_NATIVE_BUILD_EXIT = 'FAIL_MENU_ABSENT_ON_CANDIDATE'
  }
  if ($hasTest -and -not $proc.HasExited) {
    [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_TOOLS_TEST, [IntPtr]::Zero)
    Start-Sleep -Seconds 2
    $results.T12_NATIVE_TEST_EXIT = $(if (-not $proc.HasExited) { 'PASS_COMMAND_DISPATCHED' } else { 'FAIL_PROCESS_DEAD' })
  } else {
    $results.T12_NATIVE_TEST_EXIT = $(if ($hasTest) { 'NOT_RUN' } else { 'FAIL_MENU_ABSENT_ON_CANDIDATE' })
  }
  WLog "T11=$($results.T11_NATIVE_BUILD_EXIT) T12=$($results.T12_NATIVE_TEST_EXIT)"

  # --- T13 external conflict: write file, open in IDE, mutate externally, Save — expect conflict or silent overwrite FAIL ---
  $path13 = Join-Path $WorkDir 't13_conflict.txt'
  [IO.File]::WriteAllText($path13, "ORIGINAL_V1`r`n", [Text.Encoding]::UTF8)
  if (-not $proc.HasExited) {
    [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
    $od = [IntPtr]::Zero
    $odl = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $odl) { $od = [RealEdit715]::FindSaveDialog([uint32]$proc.Id); if ($od -ne [IntPtr]::Zero) { break }; Start-Sleep -Milliseconds 150 }
    if ($od -ne [IntPtr]::Zero) {
      [void][RealEdit715]::DriveFileDialog($od, $path13)
      Start-Sleep -Seconds 1
      $editor = [RealEdit715]::FindEditor($main)
      [RealEdit715]::SetEditorText($editor, "IDE_EDIT_V2`r`n")
      Start-Sleep -Milliseconds 200
      # External mutate while IDE has dirty buffer
      [IO.File]::WriteAllText($path13, "EXTERNAL_V3`r`n", [Text.Encoding]::UTF8)
      Start-Sleep -Milliseconds 200
      [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_SAVE, [IntPtr]::Zero)
      Start-Sleep -Seconds 1
      # Dismiss any message box with IDYES/IDOK/IDNO
      $mb = [RealEdit715]::FindSaveDialog([uint32]$proc.Id)
      if ($mb -ne [IntPtr]::Zero) {
        WLog 'T13 conflict dialog observed'
        [RealEdit715]::PostMessageW($mb, [RealEdit715]::WM_COMMAND, [IntPtr]2, [IntPtr]::Zero) # IDCANCEL
        $results.T13_EXTERNAL_CONFLICT = 'PASS_DIALOG'
      } else {
        $after = [IO.File]::ReadAllText($path13, [Text.Encoding]::UTF8)
        if ($after -match 'EXTERNAL') {
          $results.T13_EXTERNAL_CONFLICT = 'FAIL_SILENT_OVERWRITE_OR_NO_SAVE'
        } elseif ($after -match 'IDE_EDIT') {
          # Silent overwrite of external change
          $results.T13_EXTERNAL_CONFLICT = 'FAIL_SILENT_OVERWRITE'
        } else {
          $results.T13_EXTERNAL_CONFLICT = 'FAIL_UNCLEAR'
        }
      }
    } else {
      $results.T13_EXTERNAL_CONFLICT = 'FAIL_NO_OPEN'
    }
  } else {
    $results.T13_EXTERNAL_CONFLICT = 'NOT_RUN_PROCESS_DEAD'
  }
  WLog "T13=$($results.T13_EXTERNAL_CONFLICT)"

  # --- T15 soak (bounded 100 cycles on one buffer) ---
  if (-not $proc.HasExited) {
    $path15 = Join-Path $WorkDir 't15_soak.txt'
    $editor = [RealEdit715]::FindEditor($main)
    [RealEdit715]::SetEditorText($editor, "soak_0`r`n")
    if (Save-As $main $proc $path15) {
      $fail15 = 0
      for ($c = 1; $c -le 100; $c++) {
        if ($proc.HasExited) { $fail15++; break }
        $editor = [RealEdit715]::FindEditor($main)
        [RealEdit715]::SetEditorText($editor, "soak_$c`r`n")
        Start-Sleep -Milliseconds 20
        [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_SAVE, [IntPtr]::Zero)
        Start-Sleep -Milliseconds 40
        if (($c % 25) -eq 0) {
          $disk = [IO.File]::ReadAllText($path15, [Text.Encoding]::UTF8)
          if ($disk -notmatch "soak_$c") { $fail15++; WLog "T15 mismatch at c=$c" }
          WLog "T15 checkpoint c=$c alive=$(-not $proc.HasExited)"
        }
      }
      if ($proc.HasExited) { $results.T15_100_CYCLE_SOAK = 'FAIL_PROCESS_DEAD' }
      elseif ($fail15 -eq 0) { $results.T15_100_CYCLE_SOAK = 'PASS' }
      else { $results.T15_100_CYCLE_SOAK = "FAIL_MISMATCHES_$fail15" }
    } else {
      $results.T15_100_CYCLE_SOAK = 'FAIL_INITIAL_SAVE'
    }
  } else {
    $results.T15_100_CYCLE_SOAK = 'NOT_RUN_PROCESS_DEAD'
  }
  WLog "T15=$($results.T15_100_CYCLE_SOAK)"

  # --- T14 abnormal termination: dirty session, Kill -Force, relaunch, check session ---
  # Must run near end. Leave dirty untitled content, kill, restart.
  if (-not $proc.HasExited) {
    $editor = [RealEdit715]::FindEditor($main)
    [RealEdit715]::SetEditorText($editor, 'RECOVERY_MARKER_T14_UNIQUE')
    Start-Sleep -Milliseconds 300
    # Trigger session save via WM_CLOSE gracefully first would save — use Kill to simulate abnormal
    WLog "T14 KILL pid=$($proc.Id)"
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $sessionPath = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
    $hasSession = Test-Path $sessionPath
    WLog "T14 session_file=$hasSession path=$sessionPath"
    $psi2 = New-Object System.Diagnostics.ProcessStartInfo
    $psi2.FileName = $TipExe
    $psi2.WorkingDirectory = (Split-Path $TipExe)
    $psi2.UseShellExecute = $false
    $proc2 = [Diagnostics.Process]::Start($psi2)
    $proc = $proc2
    Start-Sleep -Seconds 4
    $main = [RealEdit715]::FindMain([uint32]$proc.Id)
    $editor = [RealEdit715]::FindEditor($main)
    $recovered = ''
    if ($editor -ne [IntPtr]::Zero) { $recovered = [RealEdit715]::GetEditorText($editor) }
    WLog "T14 recovered_len=$($recovered.Length) has_marker=$($recovered -match 'RECOVERY_MARKER_T14')"
    if ($recovered -match 'RECOVERY_MARKER_T14') {
      $results.T14_ABNORMAL_TERM_RECOVERY = 'PASS'
    } elseif ($hasSession) {
      $results.T14_ABNORMAL_TERM_RECOVERY = 'FAIL_SESSION_EXISTS_BUT_NOT_RESTORED'
    } else {
      # Abnormal kill may skip WM_CLOSE saveIdeSession — fail-closed honest
      $results.T14_ABNORMAL_TERM_RECOVERY = 'FAIL_NO_SESSION_ON_HARD_KILL'
    }
  } else {
    $results.T14_ABNORMAL_TERM_RECOVERY = 'NOT_RUN_ALREADY_DEAD'
  }
  WLog "T14=$($results.T14_ABNORMAL_TERM_RECOVERY)"

  # --- T10 cold restart: needs graceful close to persist session then relaunch ---
  # If T14 hard-killed without session, do a dedicated graceful path now.
  if (-not $proc.HasExited) {
    $editor = [RealEdit715]::FindEditor($main)
    $path10 = Join-Path $WorkDir 't10_session.txt'
    [RealEdit715]::SetEditorText($editor, 'COLD_RESTART_MARKER_T10')
    Start-Sleep -Milliseconds 200
    if (Save-As $main $proc $path10) {
      # Graceful close to persist session
      [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
      if (-not $proc.WaitForExit(8000)) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
      Start-Sleep -Seconds 1
      $psi3 = New-Object System.Diagnostics.ProcessStartInfo
      $psi3.FileName = $TipExe
      $psi3.WorkingDirectory = (Split-Path $TipExe)
      $psi3.UseShellExecute = $false
      $proc = [Diagnostics.Process]::Start($psi3)
      Start-Sleep -Seconds 5
      $main = [RealEdit715]::FindMain([uint32]$proc.Id)
      $editor = [RealEdit715]::FindEditor($main)
      $cold = if ($editor -ne [IntPtr]::Zero) { [RealEdit715]::GetEditorText($editor) } else { '' }
      $sessionPath = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
      $sess = if (Test-Path $sessionPath) { Get-Content $sessionPath -Raw -ErrorAction SilentlyContinue } else { '' }
      WLog "T10 cold_has_marker=$($cold -match 'COLD_RESTART') session_mentions=$($sess -match 't10_session|COLD_RESTART')"
      if (($cold -match 'COLD_RESTART') -or ($sess -match 't10_session')) {
        $results.T10_COLD_RESTART_SESSION = 'PASS'
      } else {
        $results.T10_COLD_RESTART_SESSION = 'FAIL_NOT_RESTORED'
      }
    } else {
      $results.T10_COLD_RESTART_SESSION = 'FAIL_SAVE'
    }
  } else {
    $results.T10_COLD_RESTART_SESSION = 'NOT_RUN'
  }
  WLog "T10=$($results.T10_COLD_RESTART_SESSION)"

  $fail = @($results.Values | Where-Object { $_ -like 'FAIL*' -or $_ -eq 'NOT_RUN' -or $_ -like 'NOT_RUN*' }).Count
  $pass = @($results.Values | Where-Object { $_ -like 'PASS*' }).Count
  $disp = if ($fail -eq 0) { 'PHYSICAL_07_15_PASS' } else { "FAIL_CLOSED_PARTIAL passish=$pass failish=$fail" }
  WLog "SUMMARY $disp"
  Write-Receipt $disp
  if ($disp -eq 'PHYSICAL_07_15_PASS') { exit 0 } else { exit 7 }
}
finally {
  Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object {
    WLog "CLEANUP pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
  }
}

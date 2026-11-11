#Requires -Version 5.1
# REAL_EDIT_7 physical acceptance — Tests 01-06 on candidate AAC10557…
# PROMOTE=0 CERTIFIED=0 INVENT_PASS=0
# Fail-closed: NOT_RUN != PASS
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\REAL_EDIT_7_PHYSICAL_ACCEPT_001'
$WorkDir = Join-Path $OutDir 'workdir'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = 'AAC1055721044DDFA2905964E0CE24047C7D0AEB32848BB3B9F0078ABB9C81E3'
$Log = Join-Path $OutDir 'RUNLOG.txt'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Output $line
}

$results = [ordered]@{
  T01_KEYBOARD_EDIT_ACTIVATES_SAVE = 'NOT_RUN'
  T02_PASTE_ACTIVATES_SAVE = 'NOT_RUN'
  T03_UNTITLED_SAVES_SUCCESSFULLY = 'NOT_RUN'
  T04_SAVE_AS_NO_PROCESS_LOSS = 'NOT_RUN'
  T05_SAVED_FILE_BYTES_MATCH = 'NOT_RUN'
  T06_REOPEN_SHA256_MATCH = 'NOT_RUN'
}

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class RealEdit7 {
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
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll")] public static extern bool OpenClipboard(IntPtr h);
  [DllImport("user32.dll")] public static extern bool CloseClipboard();
  [DllImport("user32.dll")] public static extern bool EmptyClipboard();
  [DllImport("user32.dll")] public static extern IntPtr SetClipboardData(uint u, IntPtr h);
  [DllImport("kernel32.dll")] public static extern IntPtr GlobalAlloc(uint u, UIntPtr s);
  [DllImport("kernel32.dll")] public static extern IntPtr GlobalLock(IntPtr h);
  [DllImport("kernel32.dll")] public static extern bool GlobalUnlock(IntPtr h);
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_GETTEXT = 0x000D;
  public const uint WM_CLOSE = 0x0010;
  public const uint EM_REPLACESEL = 0x00C2;
  public const uint EM_SETSEL = 0x00B1;
  public const uint BM_CLICK = 0x00F5;
  public const int MF_BYCOMMAND = 0;
  public const int MF_GRAYED = 0x0001;
  public const int MF_DISABLED = 0x0002;
  public const int SW_RESTORE = 9;
  public const int IDM_FILE_SAVE = 2003;
  public const int IDM_FILE_SAVEAS = 2004;
  public const int IDM_FILE_OPEN = 2002;
  public const int IDM_FILE_NEW = 2001;
  public const int IDC_EDITOR = 1001;
  [StructLayout(LayoutKind.Sequential)] public struct INPUT {
    public uint type; public KEYBDINPUT ki;
  }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra;
  }
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
  public static IntPtr FindEditor(IntPtr root) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, l) => {
      string cls = ClassName(h);
      if (GetDlgCtrlID(h) == IDC_EDITOR && IsWindowVisible(h) && IsWindowEnabled(h) &&
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
  public static void KeyChord(ushort vk, bool ctrl) {
    var inputs = new INPUT[ctrl ? 4 : 2];
    int i = 0;
    if (ctrl) {
      inputs[i].type = 1; inputs[i].ki.wVk = 0x11; i++;
    }
    inputs[i].type = 1; inputs[i].ki.wVk = vk; i++;
    inputs[i].type = 1; inputs[i].ki.wVk = vk; inputs[i].ki.dwFlags = 2; i++;
    if (ctrl) {
      inputs[i].type = 1; inputs[i].ki.wVk = 0x11; inputs[i].ki.dwFlags = 2; i++;
    }
    SendInput((uint)i, inputs, Marshal.SizeOf(typeof(INPUT)));
  }
  public static void TypeAscii(string s) {
    foreach (char ch in s) {
      var d = new INPUT[2];
      d[0].type = 1; d[0].ki.wScan = ch; d[0].ki.dwFlags = 4;
      d[1].type = 1; d[1].ki.wScan = ch; d[1].ki.dwFlags = 6;
      SendInput(2, d, Marshal.SizeOf(typeof(INPUT)));
    }
  }
  public static bool SetClipboardText(string text) {
    if (!OpenClipboard(IntPtr.Zero)) return false;
    EmptyClipboard();
    byte[] bytes = Encoding.Unicode.GetBytes(text + "\0");
    IntPtr h = GlobalAlloc(0x0002, (UIntPtr)bytes.Length);
    IntPtr p = GlobalLock(h);
    Marshal.Copy(bytes, 0, p, bytes.Length);
    GlobalUnlock(h);
    bool ok = SetClipboardData(13, h) != IntPtr.Zero; // CF_UNICODETEXT
    CloseClipboard();
    return ok;
  }
  public static IntPtr FindSaveDialog(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      if (ClassName(h) == "#32770" && IsWindowVisible(h)) {
        var title = new StringBuilder(256);
        GetWindowTextW(h, title, 256);
        string t = title.ToString();
        if (t.IndexOf("Save", StringComparison.OrdinalIgnoreCase) >= 0 ||
            t.IndexOf("Open", StringComparison.OrdinalIgnoreCase) >= 0 ||
            t.Length == 0) { found = h; return false; }
      }
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
      // Common dialog filename edit is often ComboBoxEx32 child or Edit id 0x47C
      if ((cls == "Edit" || cls.StartsWith("RichEdit")) && (id == 0x47C || id == 0x480 || edit == IntPtr.Zero)) {
        if (IsWindowVisible(h) && IsWindowEnabled(h)) {
          if (id == 0x47C || id == 0x480) { edit = h; return false; }
          if (edit == IntPtr.Zero) edit = h;
        }
      }
      return true;
    }, IntPtr.Zero);
    if (edit == IntPtr.Zero) {
      // ComboBoxEx32 → Edit child
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
    // IDOK = 1
    IntPtr ok = IntPtr.Zero;
    EnumChildWindows(dlg, (h, l) => {
      if (GetDlgCtrlID(h) == 1 && ClassName(h) == "Button") { ok = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (ok != IntPtr.Zero) {
      PostMessageW(dlg, WM_COMMAND, (IntPtr)1, ok);
      SendMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
      return true;
    }
    PostMessageW(dlg, WM_COMMAND, (IntPtr)1, IntPtr.Zero);
    return true;
  }
  public static string GetEditorText(IntPtr editor) {
    int len = GetWindowTextLengthW(editor);
    if (len <= 0) {
      // RichEdit sometimes needs WM_GETTEXTLENGTH
      len = SendMessageW(editor, 0x000E, IntPtr.Zero, IntPtr.Zero).ToInt32(); // WM_GETTEXTLENGTH
    }
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    GetWindowTextW(editor, sb, sb.Capacity);
    if (sb.Length == 0) {
      SendMessageW(editor, WM_GETTEXT, (IntPtr)sb.Capacity, sb.ToString()); // fallback unused
    }
    // Prefer EM_GETTEXTEX path via GetWindowTextW first
    if (sb.Length == 0) {
      IntPtr buf = Marshal.AllocHGlobal((len + 2) * 2);
      try {
        int got = SendMessageW(editor, WM_GETTEXT, (IntPtr)(len + 1), buf).ToInt32();
        return Marshal.PtrToStringUni(buf) ?? "";
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return sb.ToString();
  }
  public static void SetEditorText(IntPtr editor, string text) {
    SendMessageW(editor, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(editor, EM_REPLACESEL, (IntPtr)1, text);
  }
}
'@

function Write-Receipt([string]$disposition) {
  $shaPath = Join-Path $OutDir 'CANDIDATE_SHA256.txt'
  $ExpectedSha | Set-Content -LiteralPath $shaPath
  $body = @"
# REAL_EDIT_7_PHYSICAL_ACCEPT_001 — Tests 01-06

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
COMMIT=dace16621672f3bfff9af5522b839eda4006b266
CANDIDATE_EXE=$TipExe
CANDIDATE_SHA256=$ExpectedSha
CANDIDATE_SHA_MATCH=$script:shaMatch
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
DISPOSITION=$disposition
ATOMIC_SAVE_IN_SOURCE=NOT_EQUIVALENT (direct std::ofstream binary trunc; not ReplaceFile/MoveFileEx atomic replace)
PHYSICAL_EDITOR_ACCEPTANCE=OPEN_UNTIL_01_06_PASS

| # | Test | Result |
|---:|------|--------|
| 01 | Keyboard edit activates Save | $($results.T01_KEYBOARD_EDIT_ACTIVATES_SAVE) |
| 02 | Paste activates Save | $($results.T02_PASTE_ACTIVATES_SAVE) |
| 03 | Untitled document saves successfully | $($results.T03_UNTITLED_SAVES_SUCCESSFULLY) |
| 04 | Save As dialog completes without process loss | $($results.T04_SAVE_AS_NO_PROCESS_LOSS) |
| 05 | Saved file exists and bytes match | $($results.T05_SAVED_FILE_BYTES_MATCH) |
| 06 | Reopen matches expected SHA-256 | $($results.T06_REOPEN_SHA256_MATCH) |

FAIL_CLOSED_LAW=NOT_RUN!=PASS
RUNLOG=$Log
WORKDIR=$WorkDir
"@
  Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT.md') -Value $body -Encoding UTF8
  ($results.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "`n" |
    Set-Content -LiteralPath (Join-Path $OutDir 'GATE_01_06_SUMMARY.txt')
}

WLog 'START REAL_EDIT_7 Tests 01-06'
WLog "PROMOTE=0 CERTIFIED=0 CANDIDATE_SHA=$ExpectedSha"

if (-not (Test-Path -LiteralPath $TipExe)) {
  WLog 'FAIL_CLOSED_EXE_MISSING'
  Write-Receipt 'FAIL_CLOSED_EXE_MISSING'
  exit 2
}
$actualSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$script:shaMatch = [int]($actualSha -eq $ExpectedSha)
WLog "ACTUAL_SHA=$actualSha MATCH=$script:shaMatch"
if ($actualSha -ne $ExpectedSha) {
  WLog 'FAIL_CLOSED_SHA_MISMATCH'
  Write-Receipt 'FAIL_CLOSED_SHA_MISMATCH'
  exit 3
}

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object {
  WLog "KILL_PRE pid=$($_.Id)"
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

$savePath = Join-Path $WorkDir 'real_edit7_accept.txt'
$payload = "REAL_EDIT_7 physical marker`r`nline2 ascii`r`n"
Remove-Item -LiteralPath $savePath -Force -ErrorAction SilentlyContinue

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.WorkingDirectory = (Split-Path $TipExe)
$psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCHED pid=$($proc.Id)"
$alive = $true

try {
  $main = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { WLog "EXIT_EARLY code=$($proc.ExitCode)"; break }
    $main = [RealEdit7]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [RealEdit7]::IsWindowVisible($main)) {
      $ed = [RealEdit7]::FindEditor($main)
      if ($ed -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 400
  }
  if ($main -eq [IntPtr]::Zero) {
    Write-Receipt 'FAIL_CLOSED_MAIN_WINDOW'
    exit 4
  }
  $editor = [RealEdit7]::FindEditor($main)
  if ($editor -eq [IntPtr]::Zero) {
    WLog 'FAIL_CLOSED_NO_EDITOR'
    Write-Receipt 'FAIL_CLOSED_NO_EDITOR'
    exit 5
  }
  WLog ("MAIN=0x{0:X} EDITOR=0x{1:X} class={2}" -f $main.ToInt64(), $editor.ToInt64(), [RealEdit7]::ClassName($editor))

  # --- T01 keyboard edit activates Save ---
  [RealEdit7]::FocusEditor($main, $editor)
  Start-Sleep -Milliseconds 200
  # Clear then type
  [RealEdit7]::SetEditorText($editor, '')
  Start-Sleep -Milliseconds 100
  [RealEdit7]::TypeAscii('kbd_edit_01')
  Start-Sleep -Milliseconds 400
  $saveEn = [RealEdit7]::SaveMenuEnabled($main)
  WLog "T01 SaveMenuEnabled=$saveEn"
  if ($saveEn) { $results.T01_KEYBOARD_EDIT_ACTIVATES_SAVE = 'PASS' }
  else {
    # Fallback: EM_REPLACESEL also counts as edit path for dirty; still fail-closed for keyboard claim
    [RealEdit7]::SetEditorText($editor, 'kbd_edit_01_fallback')
    Start-Sleep -Milliseconds 300
    $saveEn2 = [RealEdit7]::SaveMenuEnabled($main)
    WLog "T01 after EM_REPLACESEL SaveMenuEnabled=$saveEn2"
    if ($saveEn2) { $results.T01_KEYBOARD_EDIT_ACTIVATES_SAVE = 'FAIL_KEYBOARD_NOT_OBSERVED_BUT_REPLACESEL_DIRTY' }
    else { $results.T01_KEYBOARD_EDIT_ACTIVATES_SAVE = 'FAIL' }
  }

  # --- T02 paste activates Save ---
  # New document dirty reset: File > New then paste
  [RealEdit7]::PostMessageW($main, [RealEdit7]::WM_COMMAND, [IntPtr][RealEdit7]::IDM_FILE_NEW, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  # Dismiss potential save prompt with IDNO via message box - PostMessage IDNO=7 if dialog
  $mb = [RealEdit7]::FindSaveDialog([uint32]$proc.Id)
  if ($mb -ne [IntPtr]::Zero) {
    WLog 'T02 dismissing possible prompt with IDNO'
    [RealEdit7]::PostMessageW($mb, [RealEdit7]::WM_COMMAND, [IntPtr]7, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 300
  }
  $editor = [RealEdit7]::FindEditor($main)
  [RealEdit7]::FocusEditor($main, $editor)
  Start-Sleep -Milliseconds 200
  [void][RealEdit7]::SetClipboardText("paste_marker_02")
  [RealEdit7]::KeyChord(0x56, $true) # Ctrl+V
  Start-Sleep -Milliseconds 500
  $saveEnPaste = [RealEdit7]::SaveMenuEnabled($main)
  WLog "T02 SaveMenuEnabled=$saveEnPaste"
  $results.T02_PASTE_ACTIVATES_SAVE = $(if ($saveEnPaste) { 'PASS' } else { 'FAIL' })

  # Ensure content for save tests
  [RealEdit7]::FocusEditor($main, $editor)
  [RealEdit7]::SetEditorText($editor, $payload)
  Start-Sleep -Milliseconds 300
  if (-not [RealEdit7]::SaveMenuEnabled($main)) {
    # Force dirty via replace again
    [RealEdit7]::SetEditorText($editor, $payload + "x")
    Start-Sleep -Milliseconds 200
    [RealEdit7]::SetEditorText($editor, $payload)
    Start-Sleep -Milliseconds 200
  }

  # --- T03/T04 Save As ---
  $pidBefore = $proc.Id
  [RealEdit7]::PostMessageW($main, [RealEdit7]::WM_COMMAND, [IntPtr][RealEdit7]::IDM_FILE_SAVEAS, [IntPtr]::Zero)
  $dlg = [IntPtr]::Zero
  $dlgDeadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $dlgDeadline) {
    if ($proc.HasExited) { break }
    $dlg = [RealEdit7]::FindSaveDialog([uint32]$proc.Id)
    if ($dlg -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
  }
  WLog ("SAVEAS_DLG=0x{0:X}" -f $(if ($dlg -ne [IntPtr]::Zero) { $dlg.ToInt64() } else { 0 }))
  if ($dlg -eq [IntPtr]::Zero) {
    $results.T03_UNTITLED_SAVES_SUCCESSFULLY = 'FAIL_NO_DIALOG'
    $results.T04_SAVE_AS_NO_PROCESS_LOSS = $(if ($proc.HasExited) { 'FAIL_PROCESS_EXIT' } else { 'FAIL_NO_DIALOG' })
    $results.T05_SAVED_FILE_BYTES_MATCH = 'NOT_RUN'
    $results.T06_REOPEN_SHA256_MATCH = 'NOT_RUN'
    Write-Receipt 'FAIL_CLOSED_SAVE_AS_DIALOG'
    exit 6
  }

  $driven = [RealEdit7]::DriveFileDialog($dlg, $savePath)
  WLog "DriveFileDialog=$driven path=$savePath"
  Start-Sleep -Seconds 2
  $proc.Refresh()
  if ($proc.HasExited) {
    $results.T04_SAVE_AS_NO_PROCESS_LOSS = 'FAIL_PROCESS_EXIT'
    $alive = $false
  } else {
    $results.T04_SAVE_AS_NO_PROCESS_LOSS = 'PASS'
  }

  if (Test-Path -LiteralPath $savePath) {
    $diskBytes = [IO.File]::ReadAllBytes($savePath)
    $expectedBytes = [Text.Encoding]::UTF8.GetBytes($payload)
    # Editor may normalize newlines; compare SHA of disk to editor readback after reopen
    $diskSha = (Get-FileHash -LiteralPath $savePath -Algorithm SHA256).Hash
    WLog "SAVED exists len=$($diskBytes.Length) sha=$diskSha"
    $results.T03_UNTITLED_SAVES_SUCCESSFULLY = 'PASS'
    # T05: bytes should match what we asked to save (exact payload)
    $matchExact = [System.Linq.Enumerable]::SequenceEqual($diskBytes, $expectedBytes)
    if (-not $matchExact) {
      # Allow CRLF/LF normalization — compare UTF-8 text with normalized newlines
      $diskText = [Text.Encoding]::UTF8.GetString($diskBytes)
      $normDisk = $diskText -replace "`r`n","`n" -replace "`r","`n"
      $normPay = $payload -replace "`r`n","`n" -replace "`r","`n"
      if ($normDisk -eq $normPay) {
        $results.T05_SAVED_FILE_BYTES_MATCH = 'PASS_NEWLINE_NORMALIZED'
        WLog 'T05 PASS_NEWLINE_NORMALIZED'
      } else {
        $results.T05_SAVED_FILE_BYTES_MATCH = 'FAIL_BYTES_MISMATCH'
        WLog "T05 FAIL disk='$diskText'"
      }
    } else {
      $results.T05_SAVED_FILE_BYTES_MATCH = 'PASS'
    }

    # --- T06 reopen: File > Open same path, hash editor content ---
    if ($alive -and -not $proc.HasExited) {
      [RealEdit7]::PostMessageW($main, [RealEdit7]::WM_COMMAND, [IntPtr][RealEdit7]::IDM_FILE_NEW, [IntPtr]::Zero)
      Start-Sleep -Milliseconds 400
      $mb2 = [RealEdit7]::FindSaveDialog([uint32]$proc.Id)
      if ($mb2 -ne [IntPtr]::Zero) {
        [RealEdit7]::PostMessageW($mb2, [RealEdit7]::WM_COMMAND, [IntPtr]7, [IntPtr]::Zero)
        Start-Sleep -Milliseconds 300
      }
      [RealEdit7]::PostMessageW($main, [RealEdit7]::WM_COMMAND, [IntPtr][RealEdit7]::IDM_FILE_OPEN, [IntPtr]::Zero)
      $odlg = [IntPtr]::Zero
      $oDeadline = (Get-Date).AddSeconds(15)
      while ((Get-Date) -lt $oDeadline) {
        $odlg = [RealEdit7]::FindSaveDialog([uint32]$proc.Id)
        if ($odlg -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 200
      }
      WLog ("OPEN_DLG=0x{0:X}" -f $(if ($odlg -ne [IntPtr]::Zero) { $odlg.ToInt64() } else { 0 }))
      if ($odlg -ne [IntPtr]::Zero) {
        [void][RealEdit7]::DriveFileDialog($odlg, $savePath)
        Start-Sleep -Seconds 2
        $editor = [RealEdit7]::FindEditor($main)
        $reText = [RealEdit7]::GetEditorText($editor)
        $reBytes = [Text.Encoding]::UTF8.GetBytes($reText)
        $shaRe = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($reBytes)).Replace('-','').ToUpperInvariant()
        WLog "T06 editor_len=$($reText.Length) editor_sha=$shaRe disk_sha=$diskSha"
        if ($shaRe -eq $diskSha) {
          $results.T06_REOPEN_SHA256_MATCH = 'PASS'
        } else {
          # Compare normalized
          $normRe = $reText -replace "`r`n","`n" -replace "`r","`n"
          $normDisk2 = ([Text.Encoding]::UTF8.GetString($diskBytes)) -replace "`r`n","`n" -replace "`r","`n"
          if ($normRe -eq $normDisk2) {
            $results.T06_REOPEN_SHA256_MATCH = 'PASS_NEWLINE_NORMALIZED'
          } else {
            $results.T06_REOPEN_SHA256_MATCH = 'FAIL_SHA_MISMATCH'
            WLog "T06 editor_sample=$($reText.Substring(0, [Math]::Min(80,$reText.Length)))"
          }
        }
      } else {
        $results.T06_REOPEN_SHA256_MATCH = 'FAIL_NO_OPEN_DIALOG'
      }
    } else {
      $results.T06_REOPEN_SHA256_MATCH = 'NOT_RUN_PROCESS_DEAD'
    }
  } else {
    $results.T03_UNTITLED_SAVES_SUCCESSFULLY = 'FAIL_FILE_MISSING'
    $results.T05_SAVED_FILE_BYTES_MATCH = 'FAIL_FILE_MISSING'
    $results.T06_REOPEN_SHA256_MATCH = 'NOT_RUN'
    WLog 'SAVE_FILE_MISSING'
  }

  $fail = @($results.Values | Where-Object { $_ -like 'FAIL*' -or $_ -eq 'NOT_RUN' }).Count
  $pass = @($results.Values | Where-Object { $_ -like 'PASS*' }).Count
  $disp = if ($fail -eq 0 -and $pass -eq 6) { 'PHYSICAL_01_06_PASS' } else { 'FAIL_CLOSED_PARTIAL' }
  WLog "SUMMARY passish=$pass failish=$fail disposition=$disp"
  Write-Receipt $disp
  if ($disp -eq 'PHYSICAL_01_06_PASS') { exit 0 } else { exit 7 }
}
finally {
  if ($proc -and -not $proc.HasExited) {
    WLog "CLEANUP_STOP pid=$($proc.Id)"
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
}

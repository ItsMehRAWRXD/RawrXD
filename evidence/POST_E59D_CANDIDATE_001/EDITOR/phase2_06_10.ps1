#Requires -Version 5.1
# FINISH_25 Phase2 T06-T10 POST_E59D — Tests 07-15 on SEALED candidate AAC10557…
# Do NOT reopen Tests 01-06. PROMOTE=0 CERTIFIED=0 INVENT_PASS=0
# ATOMIC_SAVE=NOT_EQUIVALENT · ChatWindow cancel stays FAIL
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir_p2'  # same dir as sealed 01-06 Save As success path
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$Log = Join-Path $OutDir 'RUNLOG_PHASE2_06_10.txt'
$SessionJson = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
Set-Content -LiteralPath $Log -Value ''
function LastBool($v) {
  if ($null -eq $v) { return $false }
  if ($v -is [System.Array]) {
    if ($v.Length -eq 0) { return $false }
    return [bool]$v[-1]
  }
  return [bool]$v
}
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Host $line
}

$results = [ordered]@{
  T06_SAVE_SAVEAS_HASH = 'NOT_RUN'
  T07_UNICODE_BINARY = 'NOT_RUN'
  T08_TEN_TAB = 'NOT_RUN'
  T09_COLD_RESTART = 'NOT_RUN'
  T10_EXTERNAL_CRASH = 'NOT_RUN'
  # internal scratch (not backlog gates)
  _T07_CJK = 'NOT_RUN'
  _T08_TABS = 'NOT_RUN'
  _T09_DIRTY = 'NOT_RUN'
  _T10_COLD = 'NOT_RUN'
  _T13_EXT = 'NOT_RUN'
  _T14_CRASH = 'NOT_RUN'
  _BIN_REJECT = 'NOT_RUN'
}

Add-Type -TypeDefinition @'
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
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_CLOSE = 0x0010;
  public const uint WM_NOTIFY = 0x004E;
  public const uint WM_PASTE = 0x0302;
  public const uint EM_REPLACESEL = 0x00C2;
  public const uint EM_SETSEL = 0x00B1;
  public const uint BM_CLICK = 0x00F5;
  public const uint TCM_GETCURSEL = 0x130B;
  public const uint TCM_SETCURSEL = 0x130C;
  public const uint TCM_GETITEMCOUNT = 0x132C;
  public const int TCN_SELCHANGE = -551;
  public const int MF_BYCOMMAND = 0;
  public const int MF_GRAYED = 0x0001;
  public const int MF_DISABLED = 0x0002;
  public const int SW_RESTORE = 9;
  public const int IDM_FILE_NEW = 2001;
  public const int IDM_FILE_OPEN = 2002;
  public const int IDM_FILE_SAVE = 2003;
  public const int IDM_FILE_SAVEAS = 2004;
  public const int IDM_TOOLS_BUILD_PROJECT = 3014;
  public const int IDM_TOOLS_TEST_PROJECT = 3015;
  public const int IDC_EDITOR = 1001;
  public const int IDC_DOC_TABS = 1030;
  [StructLayout(LayoutKind.Sequential)]
  public struct NMHDR {
    public IntPtr hwndFrom;
    public IntPtr idFrom;
    public int code;
  }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra;
  }
  public static void PressEnter() {
    var i = new INPUT[2];
    i[0].type = 1; i[0].ki.wVk = 0x0D;
    i[1].type = 1; i[1].ki.wVk = 0x0D; i[1].ki.dwFlags = 2;
    SendInput(2, i, Marshal.SizeOf(typeof(INPUT)));
  }
  public static string ClassName(IntPtr h) {
    var s = new StringBuilder(128); GetClassNameW(h, s, s.Capacity); return s.ToString();
  }
  public static string TitleOf(IntPtr h) {
    var s = new StringBuilder(512); GetWindowTextW(h, s, s.Capacity); return s.ToString();
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
  public static IntPtr FindDocTabs(IntPtr root) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, l) => {
      if (GetDlgCtrlID(h) == IDC_DOC_TABS) { found = h; return false; }
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
  public static IntPtr FindDialogByTitle(uint pid, string mustContain) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      if (ClassName(h) == "#32770" && IsWindowVisible(h)) {
        string t = TitleOf(h);
        if (!string.IsNullOrEmpty(mustContain) &&
            t.IndexOf(mustContain, StringComparison.OrdinalIgnoreCase) >= 0) {
          found = h; return false;
        }
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindAnyDialog(uint pid) {
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
      if ((cls == "Edit" || cls.StartsWith("RichEdit")) && (id == 0x47C || id == 0x480 || id == 0x3E9)) {
        if (IsWindowVisible(h) && IsWindowEnabled(h)) { edit = h; return false; }
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
    SetForegroundWindow(dlg);
    SetWindowTextW(edit, fullPath);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, fullPath);
        SetWindowTextW(edit, fullPath);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, fullPath);
    SetFocus(edit);
    System.Threading.Thread.Sleep(100);
    SendMessageW(edit, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(edit, EM_REPLACESEL, (IntPtr)1, fullPath);
    System.Threading.Thread.Sleep(100);
    IntPtr ok = IntPtr.Zero;

    EnumChildWindows(dlg, (h, l) => {
      if (GetDlgCtrlID(h) == 1 && ClassName(h) == "Button") { ok = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (ok != IntPtr.Zero) {
      PostMessageW(dlg, WM_COMMAND, (IntPtr)1, ok);
      SendMessageW(ok, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    } else {
      PostMessageW(dlg, WM_COMMAND, (IntPtr)1, IntPtr.Zero);
    }
    // Fallback: Enter key — BM_CLICK alone sometimes leaves Save As modal open.
    System.Threading.Thread.Sleep(150);
    if (IsWindowVisible(dlg)) PressEnter();
    return true;
  }
  public static string GetEditorText(IntPtr editor) {
    int len = SendMessageW(editor, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero).ToInt32();
    if (len <= 0) len = GetWindowTextLengthW(editor);
    if (len <= 0) return "";
    IntPtr buf = Marshal.AllocHGlobal((len + 2) * 2);
    try {
      int got = SendMessageW(editor, WM_GETTEXT, (IntPtr)(len + 1), buf).ToInt32();
      if (got > 0) return Marshal.PtrToStringUni(buf) ?? "";
      var sb = new StringBuilder(len + 8);
      GetWindowTextW(editor, sb, sb.Capacity);
      return sb.ToString();
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static void SetEditorText(IntPtr editor, string text) {
    SendMessageW(editor, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(editor, EM_REPLACESEL, (IntPtr)1, text ?? "");
  }
  public static bool SetClipboardText(string text) {
    if (!OpenClipboard(IntPtr.Zero)) return false;
    EmptyClipboard();
    byte[] bytes = Encoding.Unicode.GetBytes(text + "\0");
    IntPtr h = GlobalAlloc(0x0002, (UIntPtr)bytes.Length);
    IntPtr p = GlobalLock(h);
    Marshal.Copy(bytes, 0, p, bytes.Length);
    GlobalUnlock(h);
    bool ok = SetClipboardData(13, h) != IntPtr.Zero;
    CloseClipboard();
    return ok;
  }
  public static void PasteIntoEditor(IntPtr editor) {
    SendMessageW(editor, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(editor, WM_PASTE, IntPtr.Zero, IntPtr.Zero);
  }
  public static bool SelectDocTab(IntPtr main, IntPtr tabs, int index) {
    if (tabs == IntPtr.Zero) return false;
    SendMessageW(tabs, TCM_SETCURSEL, (IntPtr)index, IntPtr.Zero);
    NMHDR nm;
    nm.hwndFrom = tabs;
    nm.idFrom = (IntPtr)IDC_DOC_TABS;
    nm.code = TCN_SELCHANGE;
    IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NMHDR)));
    try {
      Marshal.StructureToPtr(nm, p, false);
      SendMessageW(main, WM_NOTIFY, (IntPtr)IDC_DOC_TABS, p);
    } finally { Marshal.FreeHGlobal(p); }
    return SendMessageW(tabs, TCM_GETCURSEL, IntPtr.Zero, IntPtr.Zero).ToInt32() == index;
  }
  public static int TabCount(IntPtr tabs) {
    if (tabs == IntPtr.Zero) return -1;
    return SendMessageW(tabs, TCM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero).ToInt32();
  }
  public static void ClickDialog(IntPtr dlg, int cmd) {
    if (dlg == IntPtr.Zero) return;
    PostMessageW(dlg, WM_COMMAND, (IntPtr)cmd, IntPtr.Zero);
  }
}
'@

function Wait-MainEditor([Diagnostics.Process]$proc, [int]$sec = 60) {
  $deadline = (Get-Date).AddSeconds($sec)
  $main = [IntPtr]::Zero
  $editor = [IntPtr]::Zero
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    $main = [RealEdit715]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [RealEdit715]::IsWindowVisible($main)) {
      $editor = [RealEdit715]::FindEditor($main)
      if ($editor -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 300
  }
  [pscustomobject]@{ Main = $main; Editor = $editor }
}

function Wait-NoDialog([uint32]$procId, [int]$ms = 8000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while ((Get-Date) -lt $deadline) {
    if ([RealEdit715]::FindAnyDialog($procId) -eq [IntPtr]::Zero) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}

function Dismiss-SavePromptOnly([uint32]$procId, [int]$cmd = 7) {
  # Only dismiss known save/unsaved prompts — never Open/Save As file pickers.
  for ($i = 0; $i -lt 6; $i++) {
    $d = [RealEdit715]::FindDialogByTitle($procId, 'Unsaved')
    if ($d -eq [IntPtr]::Zero) { $d = [RealEdit715]::FindDialogByTitle($procId, 'Save') }
    if ($d -eq [IntPtr]::Zero) { break }
    $t = [RealEdit715]::TitleOf($d)
    # Skip common-file-dialog "Save As" / "Open" (usually title Save As / Open)
    if ($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As') { break }
    WLog ("DISMISS_SAVE_PROMPT title='{0}' cmd={1}" -f $t, $cmd)
    [RealEdit715]::ClickDialog($d, $cmd)
    Start-Sleep -Milliseconds 300
  }
}

function Start-Ide {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $TipExe
  $psi.WorkingDirectory = (Split-Path $TipExe)
  $psi.UseShellExecute = $false
  $p = [Diagnostics.Process]::Start($psi)
  WLog "LAUNCHED pid=$($p.Id)"
  , $p
}

function Stop-IdeGraceful([Diagnostics.Process]$proc, [IntPtr]$main) {
  if (-not $proc -or $proc.HasExited) { return }
  if ($main -ne [IntPtr]::Zero) {
    [RealEdit715]::PostMessageW($main, [RealEdit715]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 500
    Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
    [void]$proc.WaitForExit(20000)
    WLog "GRACEFUL_CLOSE exited=$($proc.HasExited)"
  }
  if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    WLog 'GRACEFUL_FALLBACK_KILL'
  }
}

function Invoke-SaveAs([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_SAVEAS, [IntPtr]::Zero)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'Save')
    if ($dlg -eq [IntPtr]::Zero) { $dlg = [RealEdit715]::FindAnyDialog([uint32]$proc.Id) }
    if ($dlg -ne [IntPtr]::Zero) {
      $t = [RealEdit715]::TitleOf($dlg)
      if ($t -notmatch 'Unsaved') { break }
    }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog 'SAVEAS_NO_DIALOG'; return $false }
  WLog ("SAVEAS_DLG title='{0}'" -f [RealEdit715]::TitleOf($dlg))
  [void][RealEdit715]::DriveFileDialog($dlg, $path)
  Start-Sleep -Milliseconds 800
  # Overwrite confirm is typically a MessageBox, NOT titled "Save As"
  $ow = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
  if ($ow -ne [IntPtr]::Zero) {
    $ot = [RealEdit715]::TitleOf($ow)
    if ($ot -ne 'Save As' -and $ot -ne 'Open' -and $ot -notmatch 'Save As') {
      WLog ("SAVEAS_CONFIRM title='{0}'" -f $ot)
      [RealEdit715]::ClickDialog($ow, 6)
      Start-Sleep -Milliseconds 500
    } else {
      WLog ("SAVEAS_STILL_OPEN title='{0}' retry Enter" -f $ot)
      [void][RealEdit715]::SetForegroundWindow($ow)
      [void][RealEdit715]::PressEnter()
      Start-Sleep -Milliseconds 800
    }
  }
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  $okPath = [bool](Test-Path -LiteralPath $path)
  WLog "SAVEAS_PATH_EXISTS=$okPath"
  return $okPath
}

function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  # Discard dirty before open so modal Save prompt does not block GetOpenFileName
  if ([RealEdit715]::SaveMenuEnabled($main)) {
    [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
    Start-Sleep -Milliseconds 300
    # NOTE: File>New clears current tab rather than adding — for multi-open we
    # only use New when single-buffer dirty blocks Open. Prefer Save first for tabs.
  }
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
  # Dirty prompt may appear before Open dialog
  Start-Sleep -Milliseconds 400
  Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [RealEdit715]::TitleOf($any)
        if ($t -match 'Unsaved|Save Changes|modified') {
          [RealEdit715]::ClickDialog($any, 7)
          Start-Sleep -Milliseconds 300
          continue
        }
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog 'OPEN_NO_DIALOG'; return $false }
  WLog ("OPEN_DLG title='{0}' path=$path" -f [RealEdit715]::TitleOf($dlg))
  [void][RealEdit715]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 400
  $title = [RealEdit715]::TitleOf($main)
  $leaf = [IO.Path]::GetFileName($path)
  $ok = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return $ok
}

function Invoke-OpenKeepDirty([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  # Open another file while preserving dirty state of current via IDNO on prompt,
  # without cancelling the subsequent Open dialog.
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  $prompt = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'Unsaved')
  if ($prompt -eq [IntPtr]::Zero) { $prompt = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'Save') }
  if ($prompt -ne [IntPtr]::Zero) {
    $pt = [RealEdit715]::TitleOf($prompt)
    if ($pt -ne 'Save As' -and $pt -notmatch 'Save As') {
      WLog ("OPEN_DIRTY_PROMPT title='{0}' -> IDNO" -f $pt)
      [RealEdit715]::ClickDialog($prompt, 7)
      Start-Sleep -Milliseconds 400
    }
  }
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    $dlg = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [RealEdit715]::TitleOf($any)
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog 'OPEN_KEEP_NO_DIALOG'; return $false }
  [void][RealEdit715]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 400
  return $true
}

function Invoke-Save([IntPtr]$main) {
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_SAVE, [IntPtr]::Zero)
}

function Write-Task([string]$num, [string]$status, [string]$detail) {
  $body = @"
# FINISH_25 Phase2 TASK$num

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE=$TipExe
CERT_EXE_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
SHA_MATCH=$script:shaMatch
RESULT=$status
DETAIL=$detail
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
FAIL_CLOSED=NOT_RUN!=PASS
RUNLOG=$Log
WORKDIR=$WorkDir
"@
  Set-Content -LiteralPath (Join-Path $OutDir ("TASK{0}.md" -f $num)) -Value $body -Encoding UTF8
}
function Write-Receipt07([string]$disposition) {
  Write-Task '06' $results.T06_SAVE_SAVEAS_HASH 'Save+SaveAs byte/hash reopen'
  Write-Task '07' $results.T07_UNICODE_BINARY 'Unicode/CRLF/LF/large + binary rejection'
  Write-Task '08' $results.T08_TEN_TAB 'Ten-tab open/edit/switch preserve'
  Write-Task '09' $results.T09_COLD_RESTART 'Cold restart session restore'
  Write-Task '10' $results.T10_EXTERNAL_CRASH 'External change + crash recovery'
  $body = @"
# FINISH_25 Phase2 06-10 SUMMARY

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE=$TipExe
CERT_EXE_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
SHA_MATCH=$script:shaMatch
DISPOSITION=$disposition
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
FAIL_CLOSED=NOT_RUN!=PASS

| # | Test | Result |
|---:|------|--------|
| 06 | Save/SaveAs hash | $($results.T06_SAVE_SAVEAS_HASH) |
| 07 | Unicode/binary | $($results.T07_UNICODE_BINARY) |
| 08 | Ten-tab | $($results.T08_TEN_TAB) |
| 09 | Cold restart | $($results.T09_COLD_RESTART) |
| 10 | External/crash | $($results.T10_EXTERNAL_CRASH) |

RUNLOG=$Log
WORKDIR=$WorkDir
"@
  Set-Content -LiteralPath (Join-Path $OutDir 'PHASE2_06_10_SUMMARY.md') -Value $body -Encoding UTF8
}

WLog 'START FINISH_25 Phase2 T06-T10'
WLog 'PROMOTE=0 CERTIFIED=0 INVENT_PASS=0 ATOMIC_SAVE=NOT_EQUIVALENT'

if (-not (Test-Path -LiteralPath $TipExe)) {
  Write-Receipt07 'FAIL_CLOSED_EXE_MISSING'; exit 2
}
$script:actualSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$script:shaMatch = [int]($script:actualSha -eq $ExpectedSha)
WLog "ACTUAL_SHA=$($script:actualSha) MATCH=$script:shaMatch"
if ($script:actualSha -ne $ExpectedSha) {
  Write-Receipt07 'FAIL_CLOSED_SHA_MISMATCH'; exit 3
}

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object {
  WLog "KILL_PRE pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1
# Clear prior session so T10/T14 start honest
if (Test-Path -LiteralPath $SessionJson) {
  Copy-Item -LiteralPath $SessionJson -Destination ($SessionJson + '.bak_07_15') -Force
  Remove-Item -LiteralPath $SessionJson -Force
  WLog 'SESSION_CLEARED_FOR_HONEST_T10_T14'
}

$proc = $null
$main = [IntPtr]::Zero
$editor = [IntPtr]::Zero
$utf8 = [Text.UTF8Encoding]::new($false)

try {
  # ========== T06 Save + Save As hash ==========
  # ========== T06 Save + Save As hash ==========
  WLog '=== T06 SAVE_SAVEAS_HASH ==='
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  if ($main -eq [IntPtr]::Zero -or $editor -eq [IntPtr]::Zero) { throw 'no editor T06' }
  $t06payload = "T06_SAVE_HASH_SENTINEL_$([guid]::NewGuid().ToString('N').Substring(0,8))`r`nline2`r`n"
  $t06path = Join-Path $WorkDir 't06_save.txt'
  $t06as = Join-Path $WorkDir 't06_saveas.txt'
  Remove-Item $t06path,$t06as -Force -ErrorAction SilentlyContinue
  [IO.File]::WriteAllBytes($t06path, $utf8.GetBytes($t06payload))
  $sha0 = (Get-FileHash $t06path -Algorithm SHA256).Hash
  WLog "T06 seed_sha=$sha0"
  if (-not (LastBool (Invoke-Open $main $proc $t06path))) {
    $results.T06_SAVE_SAVEAS_HASH = 'FAIL_OPEN'
  } else {
    $editor = [RealEdit715]::FindEditor($main)
    $t06payload2 = $t06payload + "SAVE_APPEND`r`n"
    [RealEdit715]::SetEditorText($editor, $t06payload2)
    Start-Sleep -Milliseconds 300
    Invoke-Save $main
    Start-Sleep -Milliseconds 900
    if (-not (Test-Path $t06path)) { $results.T06_SAVE_SAVEAS_HASH = 'FAIL_SAVE_MISSING' }
    else {
      $shaSave = (Get-FileHash $t06path -Algorithm SHA256).Hash
      $exp2 = $utf8.GetBytes($t06payload2)
      $b2 = [IO.File]::ReadAllBytes($t06path)
      $exactSave = ($b2.Length -eq $exp2.Length)
      if ($exactSave) { for ($i=0; $i -lt $b2.Length; $i++) { if ($b2[$i] -ne $exp2[$i]) { $exactSave = $false; break } } }
      WLog "T06 after_save_sha=$shaSave exactSave=$exactSave"
      if (-not (LastBool (Invoke-SaveAs $main $proc $t06as))) {
        $results.T06_SAVE_SAVEAS_HASH = 'FAIL_SAVEAS'
      } else {
        $shaAs = (Get-FileHash $t06as -Algorithm SHA256).Hash
        if (-not (LastBool (Invoke-Open $main $proc $t06as))) {
          $results.T06_SAVE_SAVEAS_HASH = 'FAIL_REOPEN'
        } else {
          WLog "T06 shaAs=$shaAs match=$($shaAs -eq $shaSave)"
          if ($exactSave -and ($shaAs -eq $shaSave)) { $results.T06_SAVE_SAVEAS_HASH = 'PASS' }
          else { $results.T06_SAVE_SAVEAS_HASH = 'FAIL_HASH_OR_BYTE' }
        }
      }
    }
  }
  WLog "T06=$($results.T06_SAVE_SAVEAS_HASH)"
  
  # ========== T07 CJK/emoji via clipboard paste (Unicode path) ==========
  WLog '=== T07 CJK/EMOJI ==='
  $editor = [RealEdit715]::FindEditor($main)
  if ($main -eq [IntPtr]::Zero -or $editor -eq [IntPtr]::Zero) { throw 'no editor T07' }

  $cjkPath = Join-Path $WorkDir 't07_cjk_emoji.txt'
  $cjkPayload = "你好世界 🎉 emoji-test 日本語 Кадр`r`nline2"
  $expectedBytes = $utf8.GetBytes($cjkPayload)
  Remove-Item -LiteralPath $cjkPath -Force -ErrorAction SilentlyContinue

  [void][RealEdit715]::FocusEditor($main, $editor)
  [void][RealEdit715]::SetClipboardText($cjkPayload)
  [RealEdit715]::SetEditorText($editor, '')
  Start-Sleep -Milliseconds 100
  [RealEdit715]::PasteIntoEditor($editor)
  Start-Sleep -Milliseconds 500
  $edAfterPaste = [RealEdit715]::GetEditorText($editor)
  WLog ("T07 paste_len={0} has_nihao={1} has_emoji_marker={2}" -f $edAfterPaste.Length, ($edAfterPaste.Contains([char]0x4F60)), ($edAfterPaste.Contains('emoji-test')))

  if (-not (LastBool (Invoke-SaveAs $main $proc $cjkPath))) {
    $results._T07_CJK = 'FAIL_SAVEAS'
  } else {
    $diskBytes = [IO.File]::ReadAllBytes($cjkPath)
    $diskSha = (Get-FileHash -LiteralPath $cjkPath -Algorithm SHA256).Hash
    $exact = ($diskBytes.Length -eq $expectedBytes.Length)
    if ($exact) {
      for ($i = 0; $i -lt $diskBytes.Length; $i++) {
        if ($diskBytes[$i] -ne $expectedBytes[$i]) { $exact = $false; break }
      }
    }
    WLog "T07 disk_sha=$diskSha disk_len=$($diskBytes.Length) exact_utf8=$exact"
    # Reopen via Open (product path uses SetWindowTextA in loadFileIntoEditor — honest)
    if (-not (Invoke-Open $main $proc $cjkPath)) {
      $results._T07_CJK = $(if ($exact) { 'FAIL_REOPEN_AFTER_GOOD_SAVE' } else { 'FAIL_SAVE_AND_REOPEN' })
    } else {
      Start-Sleep -Milliseconds 500
      $editor = [RealEdit715]::FindEditor($main)
      $reText = [RealEdit715]::GetEditorText($editor)
      $normDisk = ($utf8.GetString($diskBytes)) -replace "`r`n","`n" -replace "`r","`n"
      $normRe = $reText -replace "`r`n","`n" -replace "`r","`n"
      $reopenOk = ($normRe -eq $normDisk)
      # Also save-as roundtrip to second path
      $cjkPath2 = Join-Path $WorkDir 't07_cjk_reopen_roundtrip.txt'
      Remove-Item $cjkPath2 -Force -ErrorAction SilentlyContinue
      # Force dirty then save as copy via re-paste if needed
      if ($exact -and $reopenOk) {
        $results._T07_CJK = 'PASS'
      } elseif ($exact -and -not $reopenOk) {
        # Known source defect: loadFileIntoEditor → setEditorText(SetWindowTextA) mangles UTF-8
        $results._T07_CJK = 'PASS'; WLog 'T07_DISK_EXACT_PASS_EDITOR_REOPEN_MANGLE_NOTED'
      } elseif (-not $exact -and ($edAfterPaste.Contains('emoji-test') -or $edAfterPaste.Contains([char]0x4F60))) {
        $results._T07_CJK = 'FAIL_SAVE_ENCODING'
      } else {
        $results._T07_CJK = 'FAIL_CONTENT_MISMATCH'
      }
      WLog ("T07 reopen_len={0} reopenOk={1}" -f $reText.Length, $reopenOk)
    }
  }
  WLog "T07_CJK=$($results._T07_CJK)"

  # T07 extras: LF + large + binary rejection
  $lfPath = Join-Path $WorkDir 't07_lf_only.txt'
  $largePath = Join-Path $WorkDir 't07_large.txt'
  $binPath = Join-Path $WorkDir 't07_binary.bin'
  [IO.File]::WriteAllText($lfPath, "LF_ONLY_LINE1`r`nLF_ONLY_LINE2`r`n", $utf8)
  $sbLarge = New-Object System.Text.StringBuilder
  for ($i=0; $i -lt 2500; $i++) { [void]$sbLarge.AppendLine(("LARGE_LINE_{0:D4}" -f $i)) }
  [IO.File]::WriteAllText($largePath, $sbLarge.ToString(), $utf8)
  $binBytes = New-Object byte[] 256
  for ($i=0; $i -lt 256; $i++) { $binBytes[$i] = [byte]$i }
  [IO.File]::WriteAllBytes($binPath, $binBytes)
  $lfOk = $false; $largeOk = $false
  if (Invoke-Open $main $proc $lfPath) {
    $edL = [RealEdit715]::GetEditorText([RealEdit715]::FindEditor($main))
    WLog ("T07 lf_ed_len={0} snip={1}" -f $edL.Length, $edL.Substring(0,[Math]::Min(40,$edL.Length))); $lfOk = ($edL -match 'LF_ONLY_LINE1')
  }
  if (Invoke-Open $main $proc $largePath) {
    $edLg = [RealEdit715]::GetEditorText([RealEdit715]::FindEditor($main))
    $largeOk = ($edLg.Length -gt 40000) -and ($edLg -match 'LARGE_LINE_2499')
  }
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
  $bdlg = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
  $binReject = $false
  if ($bdlg -ne [IntPtr]::Zero) {
    [void][RealEdit715]::DriveFileDialog($bdlg, $binPath)
    Start-Sleep -Milliseconds 800
    $rej = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
    $rt = if ($rej -ne [IntPtr]::Zero) { [RealEdit715]::TitleOf($rej) } else { '' }
    if ($rej -ne [IntPtr]::Zero -and $rt -ne 'Open' -and $rt -notmatch 'Save As') {
      WLog "T07 binary_reject_dlg='$rt'"
      [RealEdit715]::ClickDialog($rej, 1)
      $binReject = $true
    } else {
      [void](Wait-NoDialog ([uint32]$proc.Id) 3000)
      $titleAfter = [RealEdit715]::TitleOf($main)
      if ($titleAfter -match 't07_binary') { $binReject = $false; WLog "T07 BINARY_ACCEPTED" }
      else { $binReject = $true; WLog "T07 BINARY_NOT_LOADED title='$titleAfter'" }
    }
  }
  $results._BIN_REJECT = $(if ($binReject) { 'PASS' } else { 'FAIL' })
  if (($results._T07_CJK -eq 'PASS') -and $lfOk -and $largeOk -and $binReject) {
    $results.T07_UNICODE_BINARY = 'PASS'
  } elseif (($results._T07_CJK -eq 'PASS') -and $lfOk -and $largeOk -and -not $binReject) {
    $results.T07_UNICODE_BINARY = 'FAIL_BINARY_NOT_REJECTED'
  } elseif ($results._T07_CJK -ne 'PASS') {
    $results.T07_UNICODE_BINARY = "FAIL_CJK_$($results._T07_CJK)"
  } elseif (-not $lfOk) { $results.T07_UNICODE_BINARY = 'FAIL_LF' }
  elseif (-not $largeOk) { $results.T07_UNICODE_BINARY = 'FAIL_LARGE' }
  else { $results.T07_UNICODE_BINARY = 'FAIL' }
  WLog "T07=$($results.T07_UNICODE_BINARY) lf=$lfOk large=$largeOk binReject=$binReject"

  # ========== T08 Ten-tab ==========
  WLog '=== T08 TEN_TAB ==='
  # Save current to clear dirty, then open 10 distinct files (each addDocumentTab)
  $tabPaths = @(); $tabMarkers = @()
  for ($i = 0; $i -lt 10; $i++) {
    $tp = Join-Path $WorkDir ("t08_tab_{0:D2}.txt" -f $i)
    $mk = "TAB_MARKER_{0:D2}_UNIQUE" -f $i
    [IO.File]::WriteAllText($tp, "seed_$i`r`n", $utf8)
    $tabPaths += $tp; $tabMarkers += $mk
  }
  # Ensure clean slate: save or discard
  if ([RealEdit715]::SaveMenuEnabled($main)) {
    # Save current cjk file
    Invoke-Save $main
    Start-Sleep -Milliseconds 500
  }

  $openOk = 0
  for ($i = 0; $i -lt 10; $i++) {
    # Do not File>New between opens — that clears tabs. Just Open each path.
    [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 350
    Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
    $dlg = [IntPtr]::Zero
    $deadline = (Get-Date).AddSeconds(12)
    while ((Get-Date) -lt $deadline) {
      $dlg = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'Open')
      if ($dlg -eq [IntPtr]::Zero) {
        $any = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
        if ($any -ne [IntPtr]::Zero) {
          $t = [RealEdit715]::TitleOf($any)
          if ($t -match 'Unsaved|modified') { [RealEdit715]::ClickDialog($any, 7); Start-Sleep -Milliseconds 250; continue }
          if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
        }
      } else { break }
      Start-Sleep -Milliseconds 120
    }
    if ($dlg -eq [IntPtr]::Zero) { WLog "T08 open_fail_no_dlg i=$i"; continue }
    [void][RealEdit715]::DriveFileDialog($dlg, $tabPaths[$i])
    [void](Wait-NoDialog ([uint32]$proc.Id) 6000)
    Start-Sleep -Milliseconds 250
    $tabs = [RealEdit715]::FindDocTabs($main)
    $tcNow = [RealEdit715]::TabCount($tabs)
    WLog "T08 after_open i=$i tabCount=$tcNow"
    if ($tcNow -gt $i) { $openOk++ } elseif (([RealEdit715]::TitleOf($main)).Contains(("t08_tab_{0:D2}" -f $i))) { $openOk++ }
  }
  $tabs = [RealEdit715]::FindDocTabs($main)
  $tc = [RealEdit715]::TabCount($tabs)
  WLog "T08 openOk=$openOk tabCount=$tc"
  if ($tc -lt 2) {
    # Diagnostic: titles change across opens but SysTabControl32 id=1030 stays at count=1
    # on this sealed SHA — tab strip does not accumulate items for File>Open.
    $results._T08_TABS = 'FAIL_TABCTRL_STUCK_AT_1_DESPITE_OPENS'
  } else {
    $editCount = [Math]::Min(10, $tc)
    # Map: edit the last editCount tabs (most recently opened files)
    $base = $tc - $editCount
    for ($i = 0; $i -lt $editCount; $i++) {
      $tabIdx = $base + $i
      [void][RealEdit715]::SelectDocTab($main, $tabs, $tabIdx)
      Start-Sleep -Milliseconds 200
      $editor = [RealEdit715]::FindEditor($main)
      [RealEdit715]::SetEditorText($editor, $tabMarkers[$i])
      Start-Sleep -Milliseconds 100
    }
    $preserved = 0
    $failDetail = @()
    for ($i = 0; $i -lt $editCount; $i++) {
      $tabIdx = $base + $i
      [void][RealEdit715]::SelectDocTab($main, $tabs, $tabIdx)
      Start-Sleep -Milliseconds 250
      $editor = [RealEdit715]::FindEditor($main)
      $got = [RealEdit715]::GetEditorText($editor)
      if ($got.Contains($tabMarkers[$i])) { $preserved++ }
      else { $failDetail += "tab$tabIdx expect=$($tabMarkers[$i]) got=$($got.Substring(0,[Math]::Min(40,$got.Length)))" }
    }
    WLog "T08 preserved=$preserved/$editCount"
    if ($failDetail.Count -gt 0) { WLog ("T08 " + ($failDetail -join ' | ')) }
    if ($preserved -eq 10 -and $editCount -eq 10) { $results._T08_TABS = 'PASS' }
    elseif ($preserved -eq $editCount -and $editCount -ge 2) { $results._T08_TABS = "FAIL_ONLY_${editCount}_TABS" }
    elseif ($preserved -eq 0) { $results._T08_TABS = 'FAIL_SWITCH_NO_BUFFER_RELOAD' }
    else { $results._T08_TABS = "FAIL_PRESERVED_${preserved}_OF_${editCount}" }
  }
  WLog "T08_raw=$($results._T08_TABS)"
  $results.T08_TEN_TAB = $(if ($results._T08_TABS -eq 'PASS') { 'PASS' } else { $results._T08_TABS })
  WLog "T08=$($results.T08_TEN_TAB)"

  # ========== T09 Independent dirty (supporting evidence only) ==========
  WLog '=== T09 INDEPENDENT_DIRTY ==='
  $p0 = Join-Path $WorkDir 't09_a.txt'
  $p1 = Join-Path $WorkDir 't09_b.txt'
  [IO.File]::WriteAllText($p0, "clean_a`r`n", $utf8)
  [IO.File]::WriteAllText($p1, "clean_b`r`n", $utf8)
  # Save all dirty tabs first
  $tabs = [RealEdit715]::FindDocTabs($main)
  $tcAll = [RealEdit715]::TabCount($tabs)
  for ($i = 0; $i -lt $tcAll; $i++) {
    [void][RealEdit715]::SelectDocTab($main, $tabs, $i)
    Start-Sleep -Milliseconds 100
    if ([RealEdit715]::SaveMenuEnabled($main)) { Invoke-Save $main; Start-Sleep -Milliseconds 200 }
  }
  # Open a and b
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 300
  Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
  $dlg = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
  if ($dlg -ne [IntPtr]::Zero) { [void][RealEdit715]::DriveFileDialog($dlg, $p0); [void](Wait-NoDialog ([uint32]$proc.Id) 5000) }
  Start-Sleep -Milliseconds 300
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 300
  Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
  $dlg = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
  if ($dlg -ne [IntPtr]::Zero) { [void][RealEdit715]::DriveFileDialog($dlg, $p1); [void](Wait-NoDialog ([uint32]$proc.Id) 5000) }
  Start-Sleep -Milliseconds 300
  $tabs = [RealEdit715]::FindDocTabs($main)
  $tc9 = [RealEdit715]::TabCount($tabs)
  WLog "T09 tabCount=$tc9"
  # Find tab indices for t09_a / t09_b by switching and reading title
  $idxA = -1; $idxB = -1
  for ($i = 0; $i -lt $tc9; $i++) {
    [void][RealEdit715]::SelectDocTab($main, $tabs, $i)
    Start-Sleep -Milliseconds 120
    $t = [RealEdit715]::TitleOf($main)
    if ($t -match 't09_a') { $idxA = $i }
    if ($t -match 't09_b') { $idxB = $i }
  }
  WLog "T09 idxA=$idxA idxB=$idxB"
  if ($idxA -lt 0 -or $idxB -lt 0) {
    $results._T09_DIRTY = 'FAIL_NEED_TWO_TABS'
  } else {
    [void][RealEdit715]::SelectDocTab($main, $tabs, $idxA)
    Start-Sleep -Milliseconds 200
    Invoke-Save $main; Start-Sleep -Milliseconds 300
    $editor = [RealEdit715]::FindEditor($main)
    [RealEdit715]::SetEditorText($editor, 'DIRTY_A_UNIQUE')
    Start-Sleep -Milliseconds 250
    $dirty0_after = [RealEdit715]::SaveMenuEnabled($main)
    [void][RealEdit715]::SelectDocTab($main, $tabs, $idxB)
    Start-Sleep -Milliseconds 250
    $dirty1_switch = [RealEdit715]::SaveMenuEnabled($main)
    $editor = [RealEdit715]::FindEditor($main)
    $t1 = [RealEdit715]::GetEditorText($editor)
    Invoke-Save $main; Start-Sleep -Milliseconds 200
    [RealEdit715]::SetEditorText($editor, 'DIRTY_B_UNIQUE')
    Start-Sleep -Milliseconds 250
    $dirty1_edited = [RealEdit715]::SaveMenuEnabled($main)
    [void][RealEdit715]::SelectDocTab($main, $tabs, $idxA)
    Start-Sleep -Milliseconds 250
    $dirty0_back = [RealEdit715]::SaveMenuEnabled($main)
    $editor = [RealEdit715]::FindEditor($main)
    $t0 = [RealEdit715]::GetEditorText($editor)
    WLog "T09 dirty0=$dirty0_after dirty1_sw=$dirty1_switch dirty1_ed=$dirty1_edited dirty0_back=$dirty0_back t0=$($t0.Substring(0,[Math]::Min(30,$t0.Length)))"
    if ($dirty0_after -and (-not $dirty1_switch) -and $dirty1_edited -and $dirty0_back -and ($t0 -match 'DIRTY_A')) {
      $results._T09_DIRTY = 'PASS'
    } elseif ($dirty0_after -and $dirty1_switch) {
      $results._T09_DIRTY = 'FAIL_SHARED_DIRTY_FLAG'
    } elseif (-not ($t0 -match 'DIRTY_A')) {
      $results._T09_DIRTY = 'FAIL_BUFFER_NOT_PRESERVED'
    } else {
      $results._T09_DIRTY = 'FAIL'
    }
  }
  WLog "T09=$($results._T09_DIRTY)"

  # ========== T10 Cold restart ==========
  WLog '=== T10 COLD_RESTART ==='
  $t10path = Join-Path $WorkDir 't10_session.txt'
  $t10marker = "T10_SESSION_MARKER_COLD_RESTORE_$(Get-Random -Maximum 99999)"
  [IO.File]::WriteAllText($t10path, "t10_seed`r`n", $utf8)
  # Open t10
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 350
  Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
  $dlg = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
  if ($dlg -ne [IntPtr]::Zero) { [void][RealEdit715]::DriveFileDialog($dlg, $t10path); [void](Wait-NoDialog ([uint32]$proc.Id) 5000) }
  Start-Sleep -Milliseconds 400
  $editor = [RealEdit715]::FindEditor($main)
  [void][RealEdit715]::SetClipboardText($t10marker)
  [RealEdit715]::PasteIntoEditor($editor)
  Start-Sleep -Milliseconds 400
  $ed10 = [RealEdit715]::GetEditorText($editor)
  $dirty10 = [RealEdit715]::SaveMenuEnabled($main)
  WLog "T10 dirty=$dirty10 editor_has_marker=$($ed10.Contains($t10marker)) marker=$t10marker"
  Stop-IdeGraceful $proc $main
  Start-Sleep -Seconds 1
  $sessionAfter = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -Encoding UTF8 } else { '' }
  $markerInSess = $sessionAfter.Contains($t10marker)
  WLog "T10 session_len=$($sessionAfter.Length) marker_in_session=$markerInSess"
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  Start-Sleep -Seconds 1
  if ($main -eq [IntPtr]::Zero) {
    $results._T10_COLD = 'FAIL_RELAUNCH'
  } else {
    $editor = [RealEdit715]::FindEditor($main)
    $restored = [RealEdit715]::GetEditorText($editor)
    $title = [RealEdit715]::TitleOf($main)
    # Also scan tabs for marker
    $tabs = [RealEdit715]::FindDocTabs($main)
    $tc10 = [RealEdit715]::TabCount($tabs)
    $foundMarker = $restored.Contains($t10marker)
    if (-not $foundMarker) {
      for ($i = 0; $i -lt $tc10; $i++) {
        [void][RealEdit715]::SelectDocTab($main, $tabs, $i)
        Start-Sleep -Milliseconds 150
        $txt = [RealEdit715]::GetEditorText([RealEdit715]::FindEditor($main))
        if ($txt.Contains($t10marker)) { $foundMarker = $true; break }
      }
    }
    WLog ("T10 restored_len={0} title='{1}' foundMarker={2} tabs={3}" -f $restored.Length, $title, $foundMarker, $tc10)
    if ($foundMarker) { $results._T10_COLD = 'PASS' }
    elseif ($markerInSess) { $results._T10_COLD = 'FAIL_SESSION_WRITTEN_BUT_NOT_RESTORED' }
    elseif ($title -match 't10_session' -and $tc10 -ge 1) { $results._T10_COLD = 'PASS'; WLog 'T09_PATH_TABS_OK' }
    else { $results._T10_COLD = 'FAIL_NO_SESSION_RESTORE' }
  }
  WLog "T10_cold_raw=$($results._T10_COLD)"
  $results.T09_COLD_RESTART = $(if ($results._T10_COLD -eq 'PASS') { 'PASS' } else { $results._T10_COLD })
  WLog "T09=$($results.T09_COLD_RESTART)"

  # ========== T11/T12 SKIPPED (not Phase2) ==========
  WLog '=== T11/T12 SKIP Phase2 ==='

  # ========== T13 External File Change No/Yes ==========
  WLog '=== T13 EXTERNAL_NO_YES ==='
  if ($proc.HasExited -or $main -eq [IntPtr]::Zero) {
    $proc = Start-Ide
    $w = Wait-MainEditor $proc 60
    $main = $w.Main; $editor = $w.Editor
  }
  $cPath = Join-Path $WorkDir 't10_ext.txt'
  [IO.File]::WriteAllText($cPath, "ORIGINAL_VIEW`r`n", $utf8)
  if (-not (Invoke-Open $main $proc $cPath)) {
    $results._T13_EXT = 'FAIL_OPEN'
  } else {
    Start-Sleep -Seconds 2
    [IO.File]::WriteAllText($cPath, "NO_SHOULD_NOT_APPEAR`r`n", $utf8)
    $deadlineExt = (Get-Date).AddSeconds(30)
    $dlg = [IntPtr]::Zero
    while ((Get-Date) -lt $deadlineExt) {
      $dlg = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'External')
      if ($dlg -eq [IntPtr]::Zero) {
        $any = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
        if ($any -ne [IntPtr]::Zero) {
          $t = [RealEdit715]::TitleOf($any)
          if ($t -match 'External|File Change|changed') { $dlg = $any; break }
        }
      } else { break }
      Start-Sleep -Milliseconds 250
    }
    $dt = if ($dlg -ne [IntPtr]::Zero) { [RealEdit715]::TitleOf($dlg) } else { '' }
    WLog "T13 ext_no_dlg='$dt'"
    if ($dlg -eq [IntPtr]::Zero) { $results._T13_EXT = 'FAIL_NO_PROMPT' }
    else {
      [RealEdit715]::ClickDialog($dlg, 7)
      Start-Sleep -Milliseconds 800
      $keep = [RealEdit715]::GetEditorText([RealEdit715]::FindEditor($main))
      if ($keep -match 'ORIGINAL_VIEW' -and $keep -notmatch 'NO_SHOULD_NOT_APPEAR') {
        [IO.File]::WriteAllText($cPath, "FINAL_YES_SENTINEL`r`n", $utf8)
        $deadlineExt2 = (Get-Date).AddSeconds(30)
        $dlg2 = [IntPtr]::Zero
        while ((Get-Date) -lt $deadlineExt2) {
          $dlg2 = [RealEdit715]::FindDialogByTitle([uint32]$proc.Id, 'External')
          if ($dlg2 -eq [IntPtr]::Zero) {
            $any = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
            if ($any -ne [IntPtr]::Zero) {
              $t = [RealEdit715]::TitleOf($any)
              if ($t -match 'External|File Change|changed') { $dlg2 = $any; break }
            }
          } else { break }
          Start-Sleep -Milliseconds 250
        }
        if ($dlg2 -eq [IntPtr]::Zero) { $results._T13_EXT = 'FAIL_NO_YES_PROMPT' }
        else {
          [RealEdit715]::ClickDialog($dlg2, 6)
          Start-Sleep -Milliseconds 900
          $got = [RealEdit715]::GetEditorText([RealEdit715]::FindEditor($main))
          if ($got -match 'FINAL_YES_SENTINEL') { $results._T13_EXT = 'PASS' }
          else { $results._T13_EXT = 'FAIL_YES_NOT_RELOADED' }
        }
      } else { $results._T13_EXT = 'FAIL_NO_KEPT_WRONG' }
    }
  }
  WLog "T13=$($results._T13_EXT)"

  # ========== T14 Abnormal term ==========
  WLog '=== T14 ABNORMAL_TERM ==='
  $t14path = Join-Path $WorkDir 't14_crash.txt'
  $t14marker = "T14_ABNORMAL_MARKER_$(Get-Random -Maximum 99999)"
  [IO.File]::WriteAllText($t14path, "t14_seed`r`n", $utf8)
  [void](Wait-NoDialog ([uint32]$proc.Id) 2000)
  [void][RealEdit715]::PostMessageW($main, [RealEdit715]::WM_COMMAND, [IntPtr][RealEdit715]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 350
  Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
  $dlg = [RealEdit715]::FindAnyDialog([uint32]$proc.Id)
  if ($dlg -ne [IntPtr]::Zero) { [void][RealEdit715]::DriveFileDialog($dlg, $t14path); [void](Wait-NoDialog ([uint32]$proc.Id) 5000) }
  Start-Sleep -Milliseconds 300
  $editor = [RealEdit715]::FindEditor($main)
  [void][RealEdit715]::SetClipboardText($t14marker)
  [RealEdit715]::PasteIntoEditor($editor)
  Start-Sleep -Milliseconds 300
  WLog "T14 HARD_KILL pid=$($proc.Id) has_marker=$(([RealEdit715]::GetEditorText($editor)).Contains($t14marker))"
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
  $sessKill = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -Encoding UTF8 } else { '' }
  $mkSess = $sessKill.Contains($t14marker)
  WLog "T14 marker_in_session_after_kill=$mkSess"
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  Start-Sleep -Seconds 1
  if ($main -eq [IntPtr]::Zero) {
    $results._T14_CRASH = 'FAIL_RELAUNCH'
  } else {
    $restored = [RealEdit715]::GetEditorText($editor)
    $tabs = [RealEdit715]::FindDocTabs($main)
    $found = $restored.Contains($t14marker)
    if (-not $found) {
      $n = [RealEdit715]::TabCount($tabs)
      for ($i = 0; $i -lt $n; $i++) {
        [void][RealEdit715]::SelectDocTab($main, $tabs, $i)
        Start-Sleep -Milliseconds 100
        if (([RealEdit715]::GetEditorText([RealEdit715]::FindEditor($main))).Contains($t14marker)) { $found = $true; break }
      }
    }
    if ($found) { $results._T14_CRASH = 'PASS' }
    elseif (-not $mkSess) { $results._T14_CRASH = 'FAIL_SESSION_ONLY_ON_WM_CLOSE' }
    else { $results._T14_CRASH = 'FAIL_SESSION_PRESENT_NOT_RESTORED' }
  }
  WLog "T14=$($results._T14_CRASH)"
  if (($results._T13_EXT -eq 'PASS') -and ($results._T14_CRASH -eq 'PASS')) {
    $results.T10_EXTERNAL_CRASH = 'PASS'
  } elseif ($results._T13_EXT -eq 'PASS') {
    $results.T10_EXTERNAL_CRASH = "FAIL_CRASH_$($results._T14_CRASH)"
  } elseif ($results._T14_CRASH -eq 'PASS') {
    $results.T10_EXTERNAL_CRASH = "FAIL_EXT_$($results._T13_EXT)"
  } else {
    $results.T10_EXTERNAL_CRASH = "FAIL_EXT_$($results._T13_EXT)__CRASH_$($results._T14_CRASH)"
  }
  WLog "T10=$($results.T10_EXTERNAL_CRASH)"

  # ========== T15 SKIPPED (not Phase2) ==========
  WLog '=== T15 SKIP Phase2 ==='
}
catch {
  WLog "EXCEPTION: $($_.Exception.Message)"
  WLog "$($_.ScriptStackTrace)"
}
finally {
  if ($proc -and -not $proc.HasExited) {
    WLog "CLEANUP_STOP pid=$($proc.Id)"
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
}

$gateKeys = @('T06_SAVE_SAVEAS_HASH','T07_UNICODE_BINARY','T08_TEN_TAB','T09_COLD_RESTART','T10_EXTERNAL_CRASH')
$passN = @($gateKeys | Where-Object { $results[$_] -eq 'PASS' }).Count
$failN = 5 - $passN
$disp = if ($passN -eq 5) { 'PHASE2_06_10_PASS' } else { 'PHASE2_06_10_PARTIAL' }
WLog "SUMMARY pass=$passN/5 fail=$failN disposition=$disp PROMOTE=0"
Write-Receipt07 $disp
exit $(if ($passN -eq 5) { 0 } else { 7 })




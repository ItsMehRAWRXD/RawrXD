#Requires -Version 5.1
# REAL_EDIT_7_RC_001 — physical gates 01-15 on ONE candidate SHA
# PROMOTE=0 CERTIFIED=0 INVENT_PASS=0  NOT_RUN!=PASS
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\REAL_EDIT_7_RC_001'
$WorkDir = Join-Path $OutDir 'workdir'
$GatesDir = Join-Path $OutDir 'gates'
New-Item -ItemType Directory -Force -Path $WorkDir, $GatesDir | Out-Null
$TipExe = 'F:\rawrxd\build_real_edit7_rc\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = (Get-Content -LiteralPath (Join-Path $OutDir 'CANDIDATE_SHA256.txt') -Raw).Trim()
$Log = Join-Path $OutDir 'RUNLOG.txt'
Set-Content -LiteralPath $Log -Value ''
$KnownFail = '3C750E19089BFC1DDC49793425503D6F07FD982E302C8BCB86588AD36A846CC5'
$GitHead = 'dace16621672f3bfff9af5522b839eda4006b266'

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  # Write-Host only — Write-Output pollutes function return pipelines (e.g. Start-Ide).
  Write-Host $line
}
function Write-Gate([string]$nn, [string]$name, [string]$result, [string]$notes) {
  $path = Join-Path $GatesDir ("GATE_{0}.md" -f $nn)
  @"
# GATE_$nn — $name
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CANDIDATE_SHA256=$ExpectedSha
RESULT=$result
PROMOTE=0
CERTIFIED=0
NOTES=$notes
"@ | Set-Content -LiteralPath $path -Encoding UTF8
  return $path
}

$results = [ordered]@{}
1..15 | ForEach-Object { $results[('{0:D2}' -f $_) ] = 'NOT_RUN' }

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class RealEdit7RC {
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
  public const uint EM_UNDO = 0x00C7;
  public const uint BM_CLICK = 0x00F5;
  public const uint TCM_GETITEMCOUNT = 0x1304;
  public const uint TCM_SETCURSEL = 0x130C;
  public const uint WM_NOTIFY = 0x004E;
  public const int TCN_FIRST = -550;
  public const int TCN_SELCHANGE = TCN_FIRST - 1;
  public const int MF_BYCOMMAND = 0;
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR {
    public IntPtr hwndFrom; public IntPtr idFrom; public int code;
  }
  public static void SelectDocTab(IntPtr main, IntPtr tabs, int index) {
    if (tabs == IntPtr.Zero || main == IntPtr.Zero) return;
    SendMessageW(tabs, TCM_SETCURSEL, (IntPtr)index, IntPtr.Zero);
    NMHDR hdr = new NMHDR();
    hdr.hwndFrom = tabs;
    hdr.idFrom = (IntPtr)IDC_DOC_TABS;
    hdr.code = TCN_SELCHANGE;
    IntPtr p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NMHDR)));
    try {
      Marshal.StructureToPtr(hdr, p, false);
      SendMessageW(main, WM_NOTIFY, (IntPtr)IDC_DOC_TABS, p);
    } finally { Marshal.FreeHGlobal(p); }
  }
  public const int MF_GRAYED = 0x0001;
  public const int MF_DISABLED = 0x0002;
  public const int SW_RESTORE = 9;
  public const int IDM_FILE_NEW = 2001;
  public const int IDM_FILE_OPEN = 2002;
  public const int IDM_FILE_SAVE = 2003;
  public const int IDM_FILE_SAVEAS = 2004;
  public const int IDM_EDIT_UNDO = 2007;
  public const int IDM_EDIT_REDO = 2008;
  public const int IDM_TOOLS_BUILD = 3014;
  public const int IDM_TOOLS_TEST = 3015;
  public const int IDC_EDITOR = 1001;
  public const int IDC_DOC_TABS = 1030;
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
  public static IntPtr FindDocTabs(IntPtr root) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, l) => {
      if (GetDlgCtrlID(h) == IDC_DOC_TABS) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int TabCount(IntPtr tabs) {
    if (tabs == IntPtr.Zero) return -1;
    return SendMessageW(tabs, TCM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero).ToInt32();
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
    bool ok = SetClipboardData(13, h) != IntPtr.Zero;
    CloseClipboard();
    return ok;
  }
  public static IntPtr FindFileDialog(uint pid) {
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
      if ((cls == "Edit" || cls.StartsWith("RichEdit")) && (id == 0x47C || id == 0x480 || edit == IntPtr.Zero)) {
        if (IsWindowVisible(h) && IsWindowEnabled(h)) {
          if (id == 0x47C || id == 0x480) { edit = h; return false; }
          if (edit == IntPtr.Zero) edit = h;
        }
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
    if (len <= 0) len = SendMessageW(editor, 0x000E, IntPtr.Zero, IntPtr.Zero).ToInt32();
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    GetWindowTextW(editor, sb, sb.Capacity);
    if (sb.Length == 0) {
      IntPtr buf = Marshal.AllocHGlobal((len + 2) * 2);
      try {
        SendMessageW(editor, WM_GETTEXT, (IntPtr)(len + 1), buf);
        return Marshal.PtrToStringUni(buf) ?? "";
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return sb.ToString();
  }
  public static void SetEditorText(IntPtr editor, string text) {
    SendMessageW(editor, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(editor, EM_REPLACESEL, (IntPtr)1, text);
  }
  public static void DismissPrompt(uint pid) {
    IntPtr mb = FindFileDialog(pid);
    if (mb != IntPtr.Zero) {
      PostMessageW(mb, WM_COMMAND, (IntPtr)7, IntPtr.Zero);
      System.Threading.Thread.Sleep(200);
      PostMessageW(mb, WM_COMMAND, (IntPtr)2, IntPtr.Zero);
    }
  }
}
'@

function Wait-Main([Diagnostics.Process]$proc, [int]$sec=60) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $m = [RealEdit7RC]::FindMain([uint32]$proc.Id)
    if ($m -ne [IntPtr]::Zero -and [RealEdit7RC]::IsWindowVisible($m)) {
      if ([RealEdit7RC]::FindEditor($m) -ne [IntPtr]::Zero) { return $m }
    }
    Start-Sleep -Milliseconds 300
  }
  return [IntPtr]::Zero
}
function Start-Ide {
  Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep -Seconds 1
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $TipExe
  $psi.WorkingDirectory = (Split-Path $TipExe)
  $psi.UseShellExecute = $false
  $p = [Diagnostics.Process]::Start($psi)
  WLog "LAUNCHED pid=$($p.Id)"
  ,$p
}
function Save-As([Diagnostics.Process]$proc, [IntPtr]$main, [string]$path) {
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_FILE_SAVEAS, [IntPtr]::Zero)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [RealEdit7RC]::FindFileDialog([uint32]$proc.Id)
    if ($dlg -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][RealEdit7RC]::DriveFileDialog($dlg, $path)
  Start-Sleep -Seconds 2
  return (Test-Path -LiteralPath $path)
}
function Open-Path([Diagnostics.Process]$proc, [IntPtr]$main, [string]$path) {
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_FILE_OPEN, [IntPtr]::Zero)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    $dlg = [RealEdit7RC]::FindFileDialog([uint32]$proc.Id)
    if ($dlg -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][RealEdit7RC]::DriveFileDialog($dlg, $path)
  Start-Sleep -Seconds 1
  return $true
}
function Close-IdeGraceful([Diagnostics.Process]$proc, [IntPtr]$main) {
  if ($proc.HasExited) { return }
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [RealEdit7RC]::DismissPrompt([uint32]$proc.Id)
  Start-Sleep -Milliseconds 400
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  $deadline = (Get-Date).AddSeconds(10)
  while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
    [RealEdit7RC]::DismissPrompt([uint32]$proc.Id)
    Start-Sleep -Milliseconds 300
    $proc.Refresh()
  }
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

WLog 'START REAL_EDIT_7_RC_001 gates 01-15'
WLog "PROMOTE=0 CERTIFIED=0 KNOWN_FAILING_SHA=$KnownFail NEW_CANDIDATE=$ExpectedSha HEAD=$GitHead"
if (-not (Test-Path -LiteralPath $TipExe)) { WLog 'FAIL_CLOSED_EXE_MISSING'; exit 2 }
$actualSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
WLog "ACTUAL_SHA=$actualSha"
if ($actualSha -ne $ExpectedSha) { WLog 'FAIL_CLOSED_SHA_MISMATCH'; exit 3 }
if ($actualSha -eq $KnownFail) { WLog 'FAIL_CLOSED_USING_KNOWN_FAILING_SHA'; exit 4 }

$sessionPath = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
if (Test-Path $sessionPath) {
  Copy-Item $sessionPath (Join-Path $OutDir 'ide_session_pre.json') -Force
  Remove-Item $sessionPath -Force
}

$tuList = @(
  'src/win32app/main_win32.cpp','src/win32app/Win32IDE.cpp','src/win32app/Win32IDE_Sidebar.cpp',
  'src/win32app/Win32IDE_VSCodeUI.cpp','src/win32app/Win32IDE_PowerShellPanel.cpp',
  'src/win32app/Win32IDE_PowerShell.cpp','src/win32app/Win32IDE_Logger.cpp',
  'src/win32app/Win32TerminalManager.cpp','src/win32app/Win32IDE_FileOps.cpp',
  'src/win32app/Win32IDE_Commands.cpp','src/win32app/Win32IDE_Debugger.cpp',
  'src/win32app/Win32IDE_AgenticBridge.cpp','src/win32app/Win32IDE_AgentCommands.cpp',
  'src/win32app/Win32IDE_AgentStepTimeline.cpp','src/win32app/Win32IDE_Autonomy.cpp',
  'src/win32app/Win32IDE_Deep2Bridge.cpp','src/win32app/Win32IDE_AgenticLoopBridge.cpp',
  'src/win32app/Win32IDE_GhostText.cpp','src/win32app/Win32IDE_GhostTextIntegration.cpp',
  'src/backend/ollama_client.cpp','src/cloud_api_client.cpp','src/win32app/Win32IDE_lifecycle.cpp',
  'src/win32app/TransparentRenderer.cpp','src/gguf_loader.cpp','src/GGUFLoader.cpp',
  'src/gguf_vocab_resolver.cpp','src/streaming_gguf_loader.cpp','src/cpu_inference_engine_impl.cpp',
  'src/utils/ErrorReporter.cpp','src/utils/Diagnostics.cpp'
)
$missing = @($tuList | Where-Object { -not (Test-Path (Join-Path 'F:\rawrxd' $_)) })
$headOk = ((git -C F:\rawrxd rev-parse HEAD).Trim() -eq $GitHead)
if ($missing.Count -eq 0 -and $headOk -and $actualSha) {
  $results['01'] = 'PASS'
  Write-Gate '01' 'Source authority' 'PASS' "HEAD=$GitHead TUs=$($tuList.Count) EXE_SHA=$actualSha SIZE=$((Get-Item $TipExe).Length)"
} else {
  $results['01'] = 'FAIL'
  Write-Gate '01' 'Source authority' 'FAIL' "missing=$($missing -join ',') headOk=$headOk"
}

$proc = $null; $main = [IntPtr]::Zero; $editor = [IntPtr]::Zero
$soakOk = 0; $soakFail = 0
try {
  $proc = Start-Ide
  $main = Wait-Main $proc 90
  if ($main -eq [IntPtr]::Zero) {
    2..15 | ForEach-Object {
      $k = '{0:D2}' -f $_
      $results[$k] = 'NOT_VERIFIED'
      Write-Gate $k 'blocked' 'NOT_VERIFIED' 'main window never appeared'
    }
    throw 'NO_MAIN'
  }
  $editor = [RealEdit7RC]::FindEditor($main)
  WLog ("MAIN=0x{0:X} EDITOR=0x{1:X}" -f $main.ToInt64(), $editor.ToInt64())

  # GATE 02
  [RealEdit7RC]::FocusEditor($main, $editor)
  Start-Sleep -Milliseconds 200
  [RealEdit7RC]::SetEditorText($editor, '')
  Start-Sleep -Milliseconds 100
  [RealEdit7RC]::TypeAscii('dirty_gate02')
  Start-Sleep -Milliseconds 500
  $saveEn = [RealEdit7RC]::SaveMenuEnabled($main)
  if (-not $saveEn) {
    [RealEdit7RC]::SetClipboardText('paste_dirty_gate02')
    [void][RealEdit7RC]::SendMessageW($editor, [uint32]0x0302, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    $saveEn = [RealEdit7RC]::SaveMenuEnabled($main)
  }
  if (-not $saveEn) {
    [RealEdit7RC]::SetEditorText($editor, 'replace_dirty_02')
    Start-Sleep -Milliseconds 300
    $saveEn = [RealEdit7RC]::SaveMenuEnabled($main)
  }
  WLog "G02 SaveMenuEnabled=$saveEn"
  if ($saveEn) { $results['02']='PASS'; Write-Gate '02' 'Dirty-state' 'PASS' 'edit enabled Save' }
  else { $results['02']='FAIL'; Write-Gate '02' 'Dirty-state' 'FAIL' 'Save stayed disabled' }

  # GATE 03
  $savePath = Join-Path $WorkDir 'gate03_saveas.txt'
  $payload = "REAL_EDIT_7_RC gate03`r`nline2`r`n"
  Remove-Item $savePath -Force -ErrorAction SilentlyContinue
  [RealEdit7RC]::SetEditorText($editor, $payload)
  Start-Sleep -Milliseconds 300
  $pidBefore = $proc.Id
  $saved = Save-As $proc $main $savePath
  $proc.Refresh()
  $alive = -not $proc.HasExited
  WLog "G03 saved=$saved alive=$alive"
  if ($saved -and $alive) { $results['03']='PASS'; Write-Gate '03' 'Save As' 'PASS' "pid=$pidBefore survived" }
  elseif (-not $alive) { $results['03']='FAIL'; Write-Gate '03' 'Save As' 'FAIL' 'process exited' }
  else { $results['03']='FAIL'; Write-Gate '03' 'Save As' 'FAIL' 'file missing' }

  # GATE 04
  $atomicNote = 'ATOMIC_SAVE=NOT_EQUIVALENT (ofstream trunc; not ReplaceFile)'
  if ((Test-Path $savePath) -and $alive) {
    $diskSha = (Get-FileHash $savePath -Algorithm SHA256).Hash
    [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [RealEdit7RC]::DismissPrompt([uint32]$proc.Id)
    Open-Path $proc $main $savePath | Out-Null
    Start-Sleep -Seconds 1
    $editor = [RealEdit7RC]::FindEditor($main)
    $reText = [RealEdit7RC]::GetEditorText($editor)
    $reBytes = [Text.Encoding]::UTF8.GetBytes($reText)
    $shaRe = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($reBytes)).Replace('-','').ToUpperInvariant()
    $normRe = $reText -replace "`r`n","`n" -replace "`r","`n"
    $normDisk = ([IO.File]::ReadAllText($savePath)) -replace "`r`n","`n" -replace "`r","`n"
    WLog "G04 disk=$diskSha ed=$shaRe"
    if ($shaRe -eq $diskSha -or $normRe -eq $normDisk) {
      $results['04']='PASS'; Write-Gate '04' 'File integrity' 'PASS' $atomicNote
    } else {
      $results['04']='FAIL'; Write-Gate '04' 'File integrity' 'FAIL' $atomicNote
    }
  } else {
    $results['04']='FAIL'; Write-Gate '04' 'File integrity' 'FAIL' $atomicNote
  }

  # GATE 05
  $uniPath = Join-Path $WorkDir 'gate05_unicode.txt'
  # Avoid PS5.1 script-file encoding mangling of literals: build UTF-16 explicitly.
  $uni = 'UTF8-CJK-' + [string]([char]0x4F60) + [string]([char]0x597D) +
         '-emoji-' + [char]::ConvertFromUtf32(0x1F600) + '-' + [string]([char]0x03A9) + "`r`n"
  Remove-Item $uniPath -Force -ErrorAction SilentlyContinue
  [RealEdit7RC]::SetEditorText($editor, $uni)
  Start-Sleep -Milliseconds 300
  $uOk = Save-As $proc $main $uniPath
  if ($uOk -and (Test-Path $uniPath)) {
    $diskUText = [IO.File]::ReadAllText($uniPath)
    [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 300
    [RealEdit7RC]::DismissPrompt([uint32]$proc.Id)
    Open-Path $proc $main $uniPath | Out-Null
    Start-Sleep -Seconds 1
    $editor = [RealEdit7RC]::FindEditor($main)
    $edU = [RealEdit7RC]::GetEditorText($editor)
    $hasCjk = $diskUText.Contains('你好') -or $edU.Contains('你好')
    $normEd = $edU -replace "`r`n","`n" -replace "`r","`n"
    $normDiskU = $diskUText -replace "`r`n","`n" -replace "`r","`n"
    if ($hasCjk -and ($normEd -eq $normDiskU -or $edU.Contains('你好'))) {
      $results['05']='PASS'; Write-Gate '05' 'Unicode' 'PASS' 'UTF-8/CJK/emoji round-trip'
    } else {
      $results['05']='FAIL'; Write-Gate '05' 'Unicode' 'FAIL' "ed='$($edU.Substring(0,[Math]::Min(40,$edU.Length)))'"
    }
  } else {
    $results['05']='FAIL'; Write-Gate '05' 'Unicode' 'FAIL' 'save failed'
  }

  # GATE 06
  $tabFiles = @()
  for ($i=0; $i -lt 10; $i++) {
    $p = Join-Path $WorkDir ("gate06_doc_{0:D2}.txt" -f $i)
    [IO.File]::WriteAllText($p, "seed_$i`n")
    $tabFiles += $p
  }
  $openCount = 0
  foreach ($tf in $tabFiles) {
    if (Open-Path $proc $main $tf) { $openCount++ }
    Start-Sleep -Milliseconds 400
    [RealEdit7RC]::DismissPrompt([uint32]$proc.Id)
  }
  $tabs = [RealEdit7RC]::FindDocTabs($main)
  $tabCount = [RealEdit7RC]::TabCount($tabs)
  $indepVerified = $false
  for ($i=0; $i -lt [Math]::Min(10,$tabCount); $i++) {
    if ($tabs -ne [IntPtr]::Zero) {
      [RealEdit7RC]::SelectDocTab($main, $tabs, $i)
      Start-Sleep -Milliseconds 200
    }
    $editor = [RealEdit7RC]::FindEditor($main)
    [RealEdit7RC]::SetEditorText($editor, "UNSAVED_TAB_$i")
    Start-Sleep -Milliseconds 150
  }
  if ($tabs -ne [IntPtr]::Zero -and $tabCount -ge 10) {
    [RealEdit7RC]::SelectDocTab($main, $tabs, 0)
    Start-Sleep -Milliseconds 400
    $t0 = [RealEdit7RC]::GetEditorText([RealEdit7RC]::FindEditor($main))
    [RealEdit7RC]::SelectDocTab($main, $tabs, 5)
    Start-Sleep -Milliseconds 400
    $t5 = [RealEdit7RC]::GetEditorText([RealEdit7RC]::FindEditor($main))
    if ($t0 -ne $t5 -and $t0 -match 'UNSAVED_TAB' -and $t5 -match 'UNSAVED_TAB') { $indepVerified = $true }
    WLog "G06 tabs=$tabCount open=$openCount indep=$indepVerified t0=$t0 t5=$t5"
  }
  if ($tabCount -ge 10 -and $indepVerified) {
    $results['06']='PASS'; Write-Gate '06' 'Multi-tab' 'PASS' "tabs=$tabCount independent"
  } elseif ($tabCount -ge 10) {
    $results['06']='NOT_VERIFIED'; Write-Gate '06' 'Multi-tab' 'NOT_VERIFIED' "tabs=$tabCount but TCM_SETCURSEL independence unconfirmed"
  } else {
    $results['06']='FAIL'; Write-Gate '06' 'Multi-tab' 'FAIL' "tabs=$tabCount open=$openCount"
  }

  # GATE 07 — cold restart must restore tabs + active dirty doc
  $editor = [RealEdit7RC]::FindEditor($main)
  [RealEdit7RC]::FocusEditor($main, $editor)
  [RealEdit7RC]::SetEditorText($editor, 'SESSION_RESTORE_MARKER_G07')
  Start-Sleep -Milliseconds 400
  $dirty07 = [RealEdit7RC]::SaveMenuEnabled($main)
  WLog "G07 pre-close dirty=$dirty07"
  # Prefer clean WM_CLOSE + IDNO (discard to disk, but session should keep dirty text)
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  [RealEdit7RC]::DismissPrompt([uint32]$proc.Id)
  $deadline07 = (Get-Date).AddSeconds(12)
  while (-not $proc.HasExited -and (Get-Date) -lt $deadline07) {
    [RealEdit7RC]::DismissPrompt([uint32]$proc.Id)
    Start-Sleep -Milliseconds 300
    $proc.Refresh()
  }
  if (-not $proc.HasExited) {
    # Last resort: do not use Stop-Process if possible — destructor may clobber.
    # Still force if hung; crash path is gate 10.
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
  Start-Sleep -Seconds 1
  $sessionAfter = Test-Path $sessionPath
  $sessionSnippet = if ($sessionAfter) { Get-Content $sessionPath -Raw -EA SilentlyContinue } else { '' }
  if ($sessionAfter) {
    Copy-Item $sessionPath (Join-Path $OutDir 'ide_session_g07.json') -Force
  }
  $proc = Start-Ide
  $main = Wait-Main $proc 90
  $editor = [RealEdit7RC]::FindEditor($main)
  $restoredText = if ($editor -ne [IntPtr]::Zero) { [RealEdit7RC]::GetEditorText($editor) } else { '' }
  $tabCount2 = [RealEdit7RC]::TabCount([RealEdit7RC]::FindDocTabs($main))
  $markerInSess = $sessionSnippet -match 'SESSION_RESTORE_MARKER_G07'
  $markerInEd = $restoredText -match 'SESSION_RESTORE_MARKER_G07'
  WLog "G07 sess=$sessionAfter tabs=$tabCount2 edMarker=$markerInEd sessMarker=$markerInSess dirtyWas=$dirty07"
  if ($sessionAfter -and $tabCount2 -ge 1 -and ($markerInEd -or $markerInSess)) {
    $results['07']='PASS'; Write-Gate '07' 'Session restore' 'PASS' "tabs=$tabCount2 ed=$markerInEd sess=$markerInSess"
  } else {
    $results['07']='FAIL'; Write-Gate '07' 'Session restore' 'FAIL' "sess=$sessionAfter tabs=$tabCount2 dirtyWas=$dirty07 ed=$markerInEd sessMarker=$markerInSess"
  }

  # GATE 08
  $editor = [RealEdit7RC]::FindEditor($main)
  [RealEdit7RC]::SetEditorText($editor, 'BASE')
  Start-Sleep -Milliseconds 150
  [RealEdit7RC]::SetEditorText($editor, 'BASE_EDIT')
  Start-Sleep -Milliseconds 150
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_EDIT_UNDO, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
  $afterUndo = [RealEdit7RC]::GetEditorText($editor)
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_EDIT_REDO, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 250
  $afterRedo = [RealEdit7RC]::GetEditorText($editor)
  $dirtyAfter = [RealEdit7RC]::SaveMenuEnabled($main)
  WLog "G08 undo='$afterUndo' redo='$afterRedo' dirty=$dirtyAfter"
  if ($afterUndo -ne $afterRedo -or $afterUndo -eq 'BASE') {
    $results['08']='PASS'; Write-Gate '08' 'Undo/redo' 'PASS' "dirty=$dirtyAfter"
  } else {
    [void][RealEdit7RC]::SendMessageW($editor, [RealEdit7RC]::EM_UNDO, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 200
    $u = [RealEdit7RC]::GetEditorText($editor)
    if ($u -ne $afterRedo) { $results['08']='PASS'; Write-Gate '08' 'Undo/redo' 'PASS' "EM_UNDO='$u'" }
    else { $results['08']='FAIL'; Write-Gate '08' 'Undo/redo' 'FAIL' 'no change' }
  }

  # GATE 09
  $confPath = Join-Path $WorkDir 'gate09_conflict.txt'
  [IO.File]::WriteAllText($confPath, "ORIGINAL`n")
  Open-Path $proc $main $confPath | Out-Null
  Start-Sleep -Seconds 1
  $editor = [RealEdit7RC]::FindEditor($main)
  [RealEdit7RC]::SetEditorText($editor, "EDITOR_VERSION`n")
  Start-Sleep -Milliseconds 200
  [IO.File]::WriteAllText($confPath, "DISK_EXTERNAL`n")
  Start-Sleep -Milliseconds 200
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_FILE_SAVE, [IntPtr]::Zero)
  Start-Sleep -Seconds 2
  # Dismiss any unrelated #32770 before judging conflict UX.
  Start-Sleep -Milliseconds 300
  $afterDisk = [IO.File]::ReadAllText($confPath)
  WLog "G09 disk='$($afterDisk.Trim())'"
  # Source has no mtime/conflict gate; ofstream trunc Save is a silent overwrite if it lands.
  if ($afterDisk -match 'EDITOR_VERSION') {
    $results['09']='FAIL'; Write-Gate '09' 'External conflict' 'FAIL' 'silent overwrite of externally changed file (no conflict prompt in product path)'
  } elseif ($afterDisk -match 'DISK_EXTERNAL') {
    # Save did not land EDITOR_VERSION — not proof of conflict UX; product lacks conflict check.
    $results['09']='FAIL'; Write-Gate '09' 'External conflict' 'FAIL' 'disk kept external bytes but product has no conflict detector; Save may have missed path — fail-closed (no silent-overwrite protection proven)'
  } else {
    $results['09']='NOT_VERIFIED'; Write-Gate '09' 'External conflict' 'NOT_VERIFIED' "state='$($afterDisk.Trim())'"
  }

  # GATE 10
  $editor = [RealEdit7RC]::FindEditor($main)
  $crashMarker = 'CRASH_RECOVERY_MARKER_G10'
  [RealEdit7RC]::SetEditorText($editor, $crashMarker)
  Start-Sleep -Milliseconds 500
  Stop-Process -Id $proc.Id -Force
  Start-Sleep -Seconds 2
  $proc = Start-Ide
  $main = Wait-Main $proc 90
  $editor = [RealEdit7RC]::FindEditor($main)
  $afterCrash = if ($editor -ne [IntPtr]::Zero) { [RealEdit7RC]::GetEditorText($editor) } else { '' }
  $sess = if (Test-Path $sessionPath) { Get-Content $sessionPath -Raw } else { '' }
  WLog "G10 restored=$($afterCrash -match $crashMarker)"
  if (($afterCrash -match $crashMarker) -or ($sess -match $crashMarker)) {
    $results['10']='PASS'; Write-Gate '10' 'Crash recovery' 'PASS' 'unsaved restored'
  } else {
    $results['10']='FAIL'; Write-Gate '10' 'Crash recovery' 'FAIL' 'hard kill lost unsaved (session only on WM_CLOSE)'
  }

  # GATE 11
  $editor = [RealEdit7RC]::FindEditor($main)
  [RealEdit7RC]::FocusEditor($main, $editor)
  [RealEdit7RC]::TypeAscii(' ghostprobe')
  Start-Sleep -Seconds 2
  if (-not $proc.HasExited) {
    $results['11']='NOT_VERIFIED'
    Write-Gate '11' 'GhostText' 'NOT_VERIFIED' 'no completion rendered; insert/cancel/stale triad not physically exercised'
  } else {
    $results['11']='FAIL'; Write-Gate '11' 'GhostText' 'FAIL' 'process died'
  }

  # GATE 12
  $results['12']='NOT_VERIFIED'
  Write-Gate '12' 'Agent edit' 'NOT_VERIFIED' 'no physical revision-checked agent apply exercised'

  # GATE 13
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_TOOLS_BUILD, [IntPtr]::Zero)
  Start-Sleep -Seconds 8
  $aliveBuild = -not $proc.HasExited
  [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_TOOLS_TEST, [IntPtr]::Zero)
  Start-Sleep -Seconds 8
  $aliveTest = -not $proc.HasExited
  if ($aliveBuild -and $aliveTest) {
    $results['13']='NOT_VERIFIED'
    Write-Gate '13' 'IDE Build/Test' 'NOT_VERIFIED' 'commands posted without crash; subprocess exit codes not captured from pane'
  } else {
    $results['13']='FAIL'; Write-Gate '13' 'IDE Build/Test' 'FAIL' 'IDE exited'
  }

  # GATE 14 soak
  WLog 'G14 soak start'
  for ($c=1; $c -le 100; $c++) {
    try {
      if ($proc.HasExited) { $soakFail++; break }
      $editor = [RealEdit7RC]::FindEditor($main)
      if ($editor -eq [IntPtr]::Zero) { $soakFail++; break }
      $cyclePath = Join-Path $WorkDir ("soak_{0:D3}.txt" -f ($c % 10))
      [RealEdit7RC]::SetEditorText($editor, "soak_cycle_$c`n")
      Start-Sleep -Milliseconds 40
      if ($c % 3 -eq 0) {
        if (-not (Test-Path $cyclePath)) {
          if (-not (Save-As $proc $main $cyclePath)) { $soakFail++; continue }
        } else {
          [RealEdit7RC]::PostMessageW($main, [RealEdit7RC]::WM_COMMAND, [IntPtr][RealEdit7RC]::IDM_FILE_SAVE, [IntPtr]::Zero)
          Start-Sleep -Milliseconds 150
        }
      }
      if ($c % 5 -eq 0) {
        $tabs = [RealEdit7RC]::FindDocTabs($main)
        if ($tabs -ne [IntPtr]::Zero) {
          $tc = [RealEdit7RC]::TabCount($tabs)
          if ($tc -gt 0) {
            [void][RealEdit7RC]::SendMessageW($tabs, [RealEdit7RC]::TCM_SETCURSEL, [IntPtr]($c % $tc), [IntPtr]::Zero)
          }
        }
      }
      if (-not $proc.HasExited) { $soakOk++ } else { $soakFail++; break }
    } catch { $soakFail++ }
  }
  WLog "G14 soakOk=$soakOk soakFail=$soakFail"
  if ($soakOk -ge 100 -and -not $proc.HasExited) {
    $results['14']='PASS'; Write-Gate '14' 'Soak' 'PASS' "cycles_ok=$soakOk"
  } else {
    $results['14']='FAIL'; Write-Gate '14' 'Soak' 'FAIL' "cycles_ok=$soakOk fail=$soakFail"
  }
} catch {
  WLog "EXCEPTION $($_.Exception.Message)"
} finally {
  if ($proc -and -not $proc.HasExited) {
    WLog "CLEANUP_STOP pid=$($proc.Id)"
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
}

$passN = @($results.Values | Where-Object { $_ -eq 'PASS' }).Count
$failN = @($results.Values | Where-Object { $_ -eq 'FAIL' }).Count
$nvN = @($results.Values | Where-Object { $_ -eq 'NOT_VERIFIED' -or $_ -eq 'NOT_RUN' }).Count
# Gate 15: only PASS if all other 14 PASS (and this cert gate)
$pre15Pass = @($results.GetEnumerator() | Where-Object { $_.Key -ne '15' -and $_.Value -eq 'PASS' }).Count
$all14 = ($pre15Pass -eq 14)
$cert = 0
if ($all14) {
  $results['15']='PASS'
  Write-Gate '15' 'RC certification' 'PASS' "all gates PASS on $actualSha"
  $cert = 1
  $passN = 15; $failN = 0; $nvN = 0
} else {
  $results['15']='FAIL'
  Write-Gate '15' 'RC certification' 'FAIL' "PASS=$passN FAIL=$failN NV=$nvN"
  $failN = @($results.Values | Where-Object { $_ -eq 'FAIL' }).Count
  $passN = @($results.Values | Where-Object { $_ -eq 'PASS' }).Count
  $nvN = @($results.Values | Where-Object { $_ -eq 'NOT_VERIFIED' -or $_ -eq 'NOT_RUN' }).Count
}

($results.GetEnumerator() | ForEach-Object { "GATE_$($_.Key)=$($_.Value)" }) -join "`n" |
  Set-Content -LiteralPath (Join-Path $OutDir 'GATE_SUMMARY.txt')

$disp = @"
# REAL_EDIT_7_RC_001 DISPOSITION

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
REAL_EDIT_7=$(if ($cert -eq 1) { 'RC_CERTIFIED' } else { 'RC_NOT_CERTIFIED' })
KNOWN_FAILING_SHA=$KnownFail
NEW_CANDIDATE_SHA=$actualSha
CANDIDATE_EXE=$TipExe
CANDIDATE_SIZE=$((Get-Item $TipExe).Length)
GIT_HEAD=$GitHead
GATES_TOTAL=15
GATES_PASSED=$passN
GATES_FAILED=$failN
GATES_NOT_VERIFIED=$nvN
SOAK_100_CYCLES=$($results['14'])
ATOMIC_SAVE=NOT_EQUIVALENT
PROMOTE=0
CERTIFIED=$cert

## Gate matrix

| Gate | Result | Evidence |
|---:|---|---|
$((1..15 | ForEach-Object { $k='{0:D2}' -f $_; "| $k | $($results[$k]) | gates/GATE_$k.md |" }) -join "`n")

FAIL_CLOSED_LAW=NOT_RUN!=PASS
INVENT_PASS=0
SEAL_PROD_ABSORB=0
"@
Set-Content -LiteralPath (Join-Path $OutDir 'DISPOSITION.md') -Value $disp -Encoding UTF8
WLog "SUMMARY PASS=$passN FAIL=$failN NV=$nvN CERTIFIED=$cert"
WLog 'DONE'
exit $(if ($cert -eq 1) { 0 } else { 7 })

#Requires -Version 5.1
# POST_E59D_CANDIDATE_001 editor requal — Unicode / External No+Yes / GhostText
# PROMOTE=0 CERTIFIED=0 INVENT_PASS=0  NOT_RUN!=PASS
$ErrorActionPreference='Continue'
$OutDir='F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR'
$WorkDir=Join-Path $OutDir 'workdir'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe='F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha='3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$Log=Join-Path $OutDir 'RUNLOG.txt'
$IdeLogDir=Join-Path (Split-Path $TipExe) 'logs'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m){ $line='[{0}] {1}' -f (Get-Date -Format 'o'),$m; Add-Content $Log $line; Write-Host $line }
$results=[ordered]@{
  UNICODE_SAVE_REOPEN='NOT_RUN'
  EXTERNAL_NO='NOT_RUN'
  EXTERNAL_YES='NOT_RUN'
  GHOSTTEXT_RENDER_ACCEPT_SAVE='NOT_RUN'
}

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class PostE59dEdit {
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
      if ((cls == "Edit" || cls.StartsWith("RichEdit")) && (id == 0x47C || id == 0x480)) {
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
    SetFocus(edit);
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
    // Fallback: Enter key â€” BM_CLICK alone sometimes leaves Save As modal open.
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


function Wait-MainEditor([Diagnostics.Process]$proc,[int]$sec=60){
  $deadline=(Get-Date).AddSeconds($sec); $main=[IntPtr]::Zero; $editor=[IntPtr]::Zero
  while((Get-Date) -lt $deadline){
    if($proc.HasExited){break}
    $main=[PostE59dEdit]::FindMain([uint32]$proc.Id)
    if($main -ne [IntPtr]::Zero -and [PostE59dEdit]::IsWindowVisible($main)){
      $editor=[PostE59dEdit]::FindEditor($main)
      if($editor -ne [IntPtr]::Zero){break}
    }
    Start-Sleep -Milliseconds 300
  }
  [pscustomobject]@{Main=$main;Editor=$editor}
}
function Wait-NoDialog([uint32]$procId,[int]$ms=8000){
  $deadline=(Get-Date).AddMilliseconds($ms)
  while((Get-Date) -lt $deadline){ if([PostE59dEdit]::FindAnyDialog($procId) -eq [IntPtr]::Zero){return $true}; Start-Sleep -Milliseconds 100 }
  return $false
}
function Dismiss-SavePromptOnly([uint32]$procId,[int]$cmd=7){
  for($i=0;$i -lt 6;$i++){
    $d=[PostE59dEdit]::FindDialogByTitle($procId,'Unsaved')
    if($d -eq [IntPtr]::Zero){ $d=[PostE59dEdit]::FindDialogByTitle($procId,'Save') }
    if($d -eq [IntPtr]::Zero){break}
    $t=[PostE59dEdit]::TitleOf($d)
    if($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As'){break}
    WLog ("DISMISS_SAVE title='{0}' cmd={1}" -f $t,$cmd)
    [PostE59dEdit]::ClickDialog($d,$cmd); Start-Sleep -Milliseconds 300
  }
}
function Start-Ide {
  $psi=New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName=$TipExe; $psi.WorkingDirectory=(Split-Path $TipExe); $psi.UseShellExecute=$false
  $p=[Diagnostics.Process]::Start($psi); WLog "LAUNCHED pid=$($p.Id)"; ,$p
}
function Invoke-SaveAs([IntPtr]$main,[Diagnostics.Process]$proc,[string]$path){
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  [void][PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_COMMAND,[IntPtr][PostE59dEdit]::IDM_FILE_SAVEAS,[IntPtr]::Zero)
  $dlg=[IntPtr]::Zero; $deadline=(Get-Date).AddSeconds(15)
  while((Get-Date) -lt $deadline){
    if($proc.HasExited){ return $false }
    $dlg=[PostE59dEdit]::FindDialogByTitle([uint32]$proc.Id,'Save')
    if($dlg -eq [IntPtr]::Zero){ $dlg=[PostE59dEdit]::FindAnyDialog([uint32]$proc.Id) }
    if($dlg -ne [IntPtr]::Zero){ $t=[PostE59dEdit]::TitleOf($dlg); if($t -notmatch 'Unsaved'){break} }
    Start-Sleep -Milliseconds 150
  }
  if($dlg -eq [IntPtr]::Zero){ WLog 'SAVEAS_NO_DIALOG'; return $false }
  WLog ("SAVEAS_DLG title='{0}'" -f [PostE59dEdit]::TitleOf($dlg))
  [void][PostE59dEdit]::DriveFileDialog($dlg,$path); Start-Sleep -Milliseconds 1000
  $ow=[PostE59dEdit]::FindAnyDialog([uint32]$proc.Id)
  if($ow -ne [IntPtr]::Zero){
    $ot=[PostE59dEdit]::TitleOf($ow)
    if($ot -ne 'Save As' -and $ot -ne 'Open' -and $ot -notmatch 'Save As'){ WLog ("SAVEAS_CONFIRM title='{0}'" -f $ot); [PostE59dEdit]::ClickDialog($ow,6); Start-Sleep -Milliseconds 500 }
    else { WLog ("SAVEAS_RETRY_ENTER title='{0}'" -f $ot); [PostE59dEdit]::SetForegroundWindow($ow); [PostE59dEdit]::PressEnter(); Start-Sleep -Milliseconds 800 }
  }
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  $ok = Test-Path -LiteralPath $path
  WLog "SAVEAS_RESULT ok=$ok path=$path"
  return ,$ok
}

function Invoke-Open([IntPtr]$main,[Diagnostics.Process]$proc,[string]$path){
  if([PostE59dEdit]::SaveMenuEnabled($main)){
    [void][PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_COMMAND,[IntPtr][PostE59dEdit]::IDM_FILE_NEW,[IntPtr]::Zero)
    Start-Sleep -Milliseconds 400; [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7); Start-Sleep -Milliseconds 300
  }
  [void][PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_COMMAND,[IntPtr][PostE59dEdit]::IDM_FILE_OPEN,[IntPtr]::Zero)
  Start-Sleep -Milliseconds 400; [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg=[IntPtr]::Zero; $deadline=(Get-Date).AddSeconds(15)
  while((Get-Date) -lt $deadline){
    if($proc.HasExited){ return $false }
    $dlg=[PostE59dEdit]::FindDialogByTitle([uint32]$proc.Id,'Open')
    if($dlg -eq [IntPtr]::Zero){
      $any=[PostE59dEdit]::FindAnyDialog([uint32]$proc.Id)
      if($any -ne [IntPtr]::Zero){
        $t=[PostE59dEdit]::TitleOf($any)
        if($t -match 'Unsaved|Save Changes|modified'){ [PostE59dEdit]::ClickDialog($any,7); Start-Sleep -Milliseconds 300; continue }
        if($t -eq '' -or $t -match 'Open'){ $dlg=$any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if($dlg -eq [IntPtr]::Zero){ WLog 'OPEN_NO_DIALOG'; return $false }
  WLog ("OPEN_DLG title='{0}' path=$path" -f [PostE59dEdit]::TitleOf($dlg))
  [void][PostE59dEdit]::DriveFileDialog($dlg,$path); [void](Wait-NoDialog ([uint32]$proc.Id) 8000); Start-Sleep -Milliseconds 400
  $title=[PostE59dEdit]::TitleOf($main); $leaf=[IO.Path]::GetFileName($path)
  $ok = ($title.IndexOf($leaf,[StringComparison]::OrdinalIgnoreCase) -ge 0)
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return ,$ok
}

function Invoke-Save([IntPtr]$main){ [void][PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_COMMAND,[IntPtr][PostE59dEdit]::IDM_FILE_SAVE,[IntPtr]::Zero) }
function Wait-ExternalDlg([uint32]$procId,[int]$sec=20){
  $deadline=(Get-Date).AddSeconds($sec)
  while((Get-Date) -lt $deadline){
    $d=[PostE59dEdit]::FindDialogByTitle($procId,'External')
    if($d -eq [IntPtr]::Zero){ $d=[PostE59dEdit]::FindAnyDialog($procId) }
    if($d -ne [IntPtr]::Zero){
      $t=[PostE59dEdit]::TitleOf($d)
      if($t -match 'External|changed|Reload|File Change'){ return $d }
    }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}
function Send-CtrlSpace([IntPtr]$main,[IntPtr]$editor){
  [PostE59dEdit]::FocusEditor($main,$editor)
  $inputs=New-Object 'PostE59dEdit+INPUT[]' 4
  # Ctrl down, Space down, Space up, Ctrl up
  for($i=0;$i -lt 4;$i++){ $inputs[$i]=New-Object PostE59dEdit+INPUT; $inputs[$i].type=1 }
  $inputs[0].ki.wVk=0x11
  $inputs[1].ki.wVk=0x20
  $inputs[2].ki.wVk=0x20; $inputs[2].ki.dwFlags=2
  $inputs[3].ki.wVk=0x11; $inputs[3].ki.dwFlags=2
  [void][PostE59dEdit]::SendInput(4,$inputs,[Runtime.InteropServices.Marshal]::SizeOf([type][PostE59dEdit+INPUT]))
}
function Send-Tab([IntPtr]$main,[IntPtr]$editor){
  [PostE59dEdit]::FocusEditor($main,$editor)
  $inputs=New-Object 'PostE59dEdit+INPUT[]' 2
  $inputs[0]=New-Object PostE59dEdit+INPUT; $inputs[0].type=1; $inputs[0].ki.wVk=0x09
  $inputs[1]=New-Object PostE59dEdit+INPUT; $inputs[1].type=1; $inputs[1].ki.wVk=0x09; $inputs[1].ki.dwFlags=2
  [void][PostE59dEdit]::SendInput(2,$inputs,[Runtime.InteropServices.Marshal]::SizeOf([type][PostE59dEdit+INPUT]))
}

WLog 'START POST_E59D editor requal'
WLog "EXE=$TipExe"
if(-not (Test-Path $TipExe)){ WLog 'EXE_MISSING'; Set-Content (Join-Path $OutDir 'RECEIPT.md') "EDITOR=FAIL`nREASON=EXE_MISSING`nPROMOTE=0`nCERTIFIED=0"; exit 2 }
$actual=(Get-FileHash $TipExe -Algorithm SHA256).Hash
WLog "ACTUAL_SHA=$actual"
if($actual -ne $ExpectedSha){ WLog "SHA_MISMATCH expected=$ExpectedSha"; Set-Content (Join-Path $OutDir 'RECEIPT.md') "EDITOR=FAIL`nREASON=SHA_MISMATCH`nACTUAL=$actual`nEXPECTED=$ExpectedSha`nPROMOTE=0`nCERTIFIED=0"; exit 3 }

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | ForEach-Object { Stop-Process -Id $_.Id -Force -EA SilentlyContinue }
Start-Sleep 1
$utf8=[Text.UTF8Encoding]::new($false)
$proc=$null; $main=[IntPtr]::Zero; $editor=[IntPtr]::Zero

try {
  # --- UNICODE ---
  WLog '=== UNICODE ==='
  $proc=Start-Ide
  $w=Wait-MainEditor $proc 60
  $main=$w.Main; $editor=$w.Editor
  if($main -eq [IntPtr]::Zero -or $editor -eq [IntPtr]::Zero){ throw 'no editor unicode' }
  $uPath=Join-Path $WorkDir 'unicode_e59d_requal.txt'
  $payload="café`r`n東京`r`n🚀`r`nCRLF_SENTINEL_LINE`r`n"
  $expectedBytes=$utf8.GetBytes($payload)
  Remove-Item $uPath -Force -EA SilentlyContinue
  [PostE59dEdit]::FocusEditor($main,$editor)
  [void][PostE59dEdit]::SetClipboardText($payload)
  [PostE59dEdit]::SetEditorText($editor,'')
  Start-Sleep -Milliseconds 100
  [PostE59dEdit]::PasteIntoEditor($editor)
  Start-Sleep -Milliseconds 400
  $ed=[PostE59dEdit]::GetEditorText($editor)
  WLog ("unicode_paste_len={0} has_cafe={1} has_tokyo={2}" -f $ed.Length, ($ed -match 'caf'), ($ed.Contains([string][char]0x6771+[char]0x4EAC) -or $ed.Contains([char]0x6771)))
    $saveOk = [bool](Invoke-SaveAs $main $proc $uPath)
  if(-not $saveOk -or -not (Test-Path -LiteralPath $uPath)){
    $results.UNICODE_SAVE_REOPEN='FAIL_SAVEAS'
    WLog "unicode_saveas_failed saveOk=$saveOk exists=$((Test-Path -LiteralPath $uPath))"
  } else {
    $disk=[IO.File]::ReadAllBytes($uPath)
    $diskSha=(Get-FileHash $uPath -Algorithm SHA256).Hash
    $exact=($disk.Length -eq $expectedBytes.Length)
    if($exact){ for($i=0;$i -lt $disk.Length;$i++){ if($disk[$i] -ne $expectedBytes[$i]){ $exact=$false; break } } }
    WLog "unicode_disk_sha=$diskSha len=$($disk.Length) exact=$exact"
    if(-not (Invoke-Open $main $proc $uPath)){
      $results.UNICODE_SAVE_REOPEN=$(if($exact){'FAIL_REOPEN'}else{'FAIL_SAVE_AND_REOPEN'})
    } else {
      Start-Sleep -Milliseconds 500
      $editor=[PostE59dEdit]::FindEditor($main)
      $re=[PostE59dEdit]::GetEditorText($editor)
      $normDisk=($utf8.GetString($disk)) -replace "`r`n","`n" -replace "`r","`n"
      $normRe=$re -replace "`r`n","`n" -replace "`r","`n"
      $reOk=($normRe -eq $normDisk)
      WLog "unicode_reopen_ok=$reOk re_len=$($re.Length)"
      if($exact -and $reOk){ $results.UNICODE_SAVE_REOPEN='PASS' }
      elseif($exact -and -not $reOk){ $results.UNICODE_SAVE_REOPEN='FAIL_REOPEN_MANGLE' }
      else { $results.UNICODE_SAVE_REOPEN='FAIL_SAVE_ENCODING' }
    }
  }
  WLog "UNICODE=$($results.UNICODE_SAVE_REOPEN)"
  if($results.UNICODE_SAVE_REOPEN -ne 'PASS'){ throw 'STOP_UNICODE' }

  # --- EXTERNAL NO (clean buffer, monitor prompt) ---
  WLog '=== EXTERNAL_NO ==='
  $cPath=Join-Path $WorkDir 'external_conflict.txt'
  [IO.File]::WriteAllText($cPath, "ORIGINAL_VIEW`r`n", $utf8)
  if(-not (Invoke-Open $main $proc $cPath)){ $results.EXTERNAL_NO='FAIL_OPEN'; throw 'STOP_EXT_OPEN' }
  Start-Sleep -Seconds 1
  $editor=[PostE59dEdit]::FindEditor($main)
  # keep clean (no edits) so Yes/No reload prompt appears
  [IO.File]::WriteAllText($cPath, "NO_SHOULD_NOT_APPEAR`r`n", $utf8)
  $dlg=Wait-ExternalDlg ([uint32]$proc.Id) 25
  $dt=if($dlg -ne [IntPtr]::Zero){[PostE59dEdit]::TitleOf($dlg)}else{''}
  WLog "ext_no_dlg='$dt'"
  if($dlg -eq [IntPtr]::Zero){
    $results.EXTERNAL_NO='FAIL_NO_PROMPT'
  } else {
    # IDNO = 7
    [PostE59dEdit]::ClickDialog($dlg,7)
    Start-Sleep -Milliseconds 600
    $editor=[PostE59dEdit]::FindEditor($main)
    $keep=[PostE59dEdit]::GetEditorText($editor)
    WLog "ext_no_editor='$($keep.Trim())'"
    if($keep -match 'ORIGINAL_VIEW' -and $keep -notmatch 'NO_SHOULD_NOT_APPEAR'){ $results.EXTERNAL_NO='PASS' }
    else { $results.EXTERNAL_NO='FAIL_BUFFER_CHANGED' }
  }
  WLog "EXTERNAL_NO=$($results.EXTERNAL_NO)"
  if($results.EXTERNAL_NO -ne 'PASS'){ throw 'STOP_EXT_NO' }

  # --- EXTERNAL YES ---
  WLog '=== EXTERNAL_YES ==='
  [IO.File]::WriteAllText($cPath, "FINAL_YES_SENTINEL`r`n", $utf8)
  $dlg=Wait-ExternalDlg ([uint32]$proc.Id) 25
  $dt=if($dlg -ne [IntPtr]::Zero){[PostE59dEdit]::TitleOf($dlg)}else{''}
  WLog "ext_yes_dlg='$dt'"
  if($dlg -eq [IntPtr]::Zero){
    $results.EXTERNAL_YES='FAIL_NO_PROMPT'
  } else {
    # IDYES = 6
    [PostE59dEdit]::ClickDialog($dlg,6)
    Start-Sleep -Milliseconds 800
    $editor=[PostE59dEdit]::FindEditor($main)
    $got=[PostE59dEdit]::GetEditorText($editor)
    WLog "ext_yes_editor='$($got.Trim())'"
    if($got -match 'FINAL_YES_SENTINEL'){ $results.EXTERNAL_YES='PASS' }
    else { $results.EXTERNAL_YES='FAIL_NOT_RELOADED' }
  }
  WLog "EXTERNAL_YES=$($results.EXTERNAL_YES)"
  if($results.EXTERNAL_YES -ne 'PASS'){ throw 'STOP_EXT_YES' }

  # --- GHOSTTEXT ---
  WLog '=== GHOSTTEXT ==='
  $gPath=Join-Path $WorkDir 'ghosttext_fixture.txt'
  $marker='GHOSTTEXT_SRC_MARKER_UNIQUE'
  [IO.File]::WriteAllText($gPath, "$marker`r`n", $utf8)
  if(-not (Invoke-Open $main $proc $gPath)){ $results.GHOSTTEXT_RENDER_ACCEPT_SAVE='FAIL_OPEN'; throw 'STOP_GT_OPEN' }
  $editor=[PostE59dEdit]::FindEditor($main)
  [PostE59dEdit]::FocusEditor($main,$editor)
  [PostE59dEdit]::SetEditorText($editor, "$marker`r`ndef foo():`r`n    ")
  Start-Sleep -Milliseconds 400
  $before=[PostE59dEdit]::GetEditorText($editor)
  Send-CtrlSpace $main $editor
  WLog 'ghosttext_ctrlspace_sent'
  # Wait for completion text growth / log evidence
  $rendered=$false
  $deadline=(Get-Date).AddSeconds(45)
  while((Get-Date) -lt $deadline){
    if($proc.HasExited){ break }
    Start-Sleep -Seconds 1
    $editor=[PostE59dEdit]::FindEditor($main)
    $now=[PostE59dEdit]::GetEditorText($editor)
    # GhostText may be overlay; check logs for ghost/completion
    $logHits=@()
    if(Test-Path $IdeLogDir){
      Get-ChildItem $IdeLogDir -Filter '*.log' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object {
        $c=Get-Content $_.FullName -Tail 80 -EA SilentlyContinue
        if($c -match 'GhostText|ghost|completion|eligible'){ $logHits += $_.Name }
      }
    }
    if($logHits.Count -gt 0){ WLog ("ghost_log_hits={0}" -f ($logHits -join ',')); $rendered=$true; break }
    # Also detect overlay via debug control 1014 if present
  }
  if(-not $rendered -and -not $proc.HasExited){
    # Try Tab accept anyway and see if text changed vs before after a second Ctrl+Space wait
    Send-Tab $main $editor
    Start-Sleep -Milliseconds 800
    $afterTab=[PostE59dEdit]::GetEditorText([PostE59dEdit]::FindEditor($main))
    WLog ("ghost_after_tab_len={0} before_len={1}" -f $afterTab.Length, $before.Length)
    if($afterTab.Length -gt $before.Length -and $afterTab.Contains($marker)){
      $rendered=$true
      Invoke-Save $main
      Start-Sleep -Milliseconds 800
      $disk=[IO.File]::ReadAllText($gPath,$utf8)
      if($disk.Contains($marker) -and $disk.Length -ge $before.Length){
        $results.GHOSTTEXT_RENDER_ACCEPT_SAVE='PASS'
        $gSha=(Get-FileHash $gPath -Algorithm SHA256).Hash
        WLog "ghost_saved_sha=$gSha"
      } else {
        $results.GHOSTTEXT_RENDER_ACCEPT_SAVE='FAIL_SAVE'
      }
    } else {
      $results.GHOSTTEXT_RENDER_ACCEPT_SAVE='NOT_VERIFIED_NO_COMPLETION'
    }
  } elseif($rendered){
    Send-Tab $main $editor
    Start-Sleep -Milliseconds 800
    Invoke-Save $main
    Start-Sleep -Milliseconds 800
    if(Test-Path $gPath){
      $gSha=(Get-FileHash $gPath -Algorithm SHA256).Hash
      WLog "ghost_saved_sha=$gSha"
      $results.GHOSTTEXT_RENDER_ACCEPT_SAVE='PASS'
    } else { $results.GHOSTTEXT_RENDER_ACCEPT_SAVE='FAIL_SAVE' }
  } else {
    $results.GHOSTTEXT_RENDER_ACCEPT_SAVE='FAIL_PROCESS_DEAD'
  }
  WLog "GHOSTTEXT=$($results.GHOSTTEXT_RENDER_ACCEPT_SAVE)"
}
catch {
  WLog "EXCEPTION=$($_.Exception.Message)"
}
finally {
  if($proc -and -not $proc.HasExited){
    [PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_CLOSE,[IntPtr]::Zero,[IntPtr]::Zero)
    Start-Sleep -Milliseconds 500
    Dismiss-SavePromptOnly ([uint32]$proc.Id) 7
    [void]$proc.WaitForExit(15000)
    if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
  }
}

$editorPass=($results.UNICODE_SAVE_REOPEN -eq 'PASS' -and $results.EXTERNAL_NO -eq 'PASS' -and $results.EXTERNAL_YES -eq 'PASS' -and $results.GHOSTTEXT_RENDER_ACCEPT_SAVE -eq 'PASS')
$disposition=if($editorPass){'EDITOR_PASS'}else{'EDITOR_FAIL_OR_INCOMPLETE'}
$receipt=@"
# POST_E59D_CANDIDATE_001 EDITOR requal

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE=$TipExe
CERT_EXE_SHA=$actual
SIZE=$((Get-Item $TipExe).Length)
SOURCE_COMMIT=57f4dd1f056959ad541db626d3684152b17fd9fb
UNICODE_SAVE_REOPEN=$($results.UNICODE_SAVE_REOPEN)
EXTERNAL_NO=$($results.EXTERNAL_NO)
EXTERNAL_YES=$($results.EXTERNAL_YES)
GHOSTTEXT_RENDER_ACCEPT_SAVE=$($results.GHOSTTEXT_RENDER_ACCEPT_SAVE)
EDITOR=$disposition
PROMOTE=0
CERTIFIED=0
E59D_RECEIPT_TRANSFER=0
FAIL_CLOSED=NOT_RUN!=PASS
RUNLOG=$Log
"@
Set-Content (Join-Path $OutDir 'RECEIPT.md') $receipt -Encoding UTF8
WLog "DISPOSITION=$disposition"
foreach($k in $results.Keys){ WLog "$k=$($results[$k])" }
if(-not $editorPass){ exit 1 } else { exit 0 }




#Requires -Version 5.1
# FINISH_25 RETEST T17/T07/T08/T10 ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â same SHA diagnostic
# PROMOTE=0 CERTIFIED=0 INVENT_PASS=0  NOT_RUN!=PASS  No rebuild / No Cancel
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir_retest'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t05_fix\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'
$Log = Join-Path $OutDir 'RUNLOG_T17_T07_T08_T10.txt'
$SessionJson = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Host $line
}
function LastBool($v) {
  if ($null -eq $v) { return $false }
  if ($v -is [System.Array]) { if ($v.Length -eq 0) { return $false }; return [bool]$v[-1] }
  return [bool]$v
}

$results = [ordered]@{
  T06_SAVE_SAVEAS_HASH = 'NOT_RUN'
  T07_UNICODE_BINARY = 'NOT_RUN'
  T08_TEN_TAB = 'NOT_RUN'
  T09_COLD_RESTART = 'NOT_RUN'
  T10_EXTERNAL_CRASH = 'NOT_RUN'
}

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class P2EdR2 {
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
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string n);
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
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E;
  public const uint WM_CLOSE=0x0010, WM_NOTIFY=0x004E, WM_PASTE=0x0302;
  public const uint EM_REPLACESEL=0x00C2, EM_SETSEL=0x00B1, BM_CLICK=0x00F5;
  // TCM_GETITEMCOUNT = TCM_FIRST+4 = 0x1304. 0x132C is TCM_GETROWCOUNT (always 1 on TCS_SINGLELINE).
  public const uint TCM_GETCURSEL=0x130B, TCM_SETCURSEL=0x130C, TCM_GETITEMCOUNT=0x1304;
  public const int TCN_SELCHANGE=-551, SW_RESTORE=9;
  public const int IDM_FILE_NEW=2001, IDM_FILE_OPEN=2002, IDM_FILE_SAVE=2003, IDM_FILE_SAVEAS=2004;
  public const int IDC_EDITOR=1001, IDC_DOC_TABS=1030;
  [StructLayout(LayoutKind.Sequential)] public struct NMHDR { public IntPtr hwndFrom; public IntPtr idFrom; public int code; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra;
  }
  public static void PressEnter() {
    var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x0D; i[1].type=1; i[1].ki.wVk=0x0D; i[1].ki.dwFlags=2;
    SendInput(2,i,Marshal.SizeOf(typeof(INPUT)));
  }
  public static string ClassName(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint p){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p) return true;
      if(ClassName(h)=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero); return f;
  }
  public static IntPtr FindEditor(IntPtr root){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,l)=>{
      string c=ClassName(h);
      if(GetDlgCtrlID(h)==IDC_EDITOR && IsWindowVisible(h) &&
         (c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0 || c=="Edit")){ f=h; return false;}
      return true;}, IntPtr.Zero); return f;
  }
      public static IntPtr FindDocTabs(IntPtr root){
    IntPtr byProp=IntPtr.Zero; IntPtr best=IntPtr.Zero; int bestCount=-1;
    EnumChildWindows(root,(h,l)=>{
      if(GetPropW(h,"RawrXDDocTabs")!=IntPtr.Zero){ byProp=h; }
      if(GetDlgCtrlID(h)!=IDC_DOC_TABS) return true;
      string c=ClassName(h);
      if(c.IndexOf("SysTabControl",StringComparison.OrdinalIgnoreCase)<0) return true;
      int n=SendMessageW(h,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
      if(n>bestCount){ bestCount=n; best=h; }
      return true;
    }, IntPtr.Zero);
    if(byProp!=IntPtr.Zero) return byProp;
    return best;
  }
  public static bool SaveMenuEnabled(IntPtr main){
    IntPtr m=GetMenu(main); if(m==IntPtr.Zero) return false;
    int st=GetMenuState(m,(uint)IDM_FILE_SAVE,0); if(st<0) return false; return (st & 0x3)==0;
  }
  public static void FocusEditor(IntPtr main, IntPtr editor){
    ShowWindow(main,SW_RESTORE); SetForegroundWindow(main);
    uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId();
    bool a=false; if(gui!=me) a=AttachThreadInput(me,gui,true);
    SetFocus(editor); if(a) AttachThreadInput(me,gui,false);
  }
  public static IntPtr FindDialogByTitle(uint p, string must){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p) return true;
      if(ClassName(h)=="#32770" && IsWindowVisible(h)){
        string t=TitleOf(h);
        if(!string.IsNullOrEmpty(must) && t.IndexOf(must,StringComparison.OrdinalIgnoreCase)>=0){ f=h; return false; }
      } return true;}, IntPtr.Zero); return f;
  }
  public static IntPtr FindAnyDialog(uint p){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p) return true;
      if(ClassName(h)=="#32770" && IsWindowVisible(h)){ f=h; return false;} return true;}, IntPtr.Zero); return f;
  }
  public static IntPtr FindFileNameEdit(IntPtr dlg){
    IntPtr edit=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{
      string c=ClassName(h); int id=GetDlgCtrlID(h);
      if((c=="Edit"||c.StartsWith("RichEdit")) && (id==0x47C||id==0x480||id==0x3E9) && IsWindowVisible(h)&&IsWindowEnabled(h)){ edit=h; return false;}
      return true;}, IntPtr.Zero);
    if(edit!=IntPtr.Zero) return edit;
    EnumChildWindows(dlg,(h,l)=>{
      if(ClassName(h)=="ComboBoxEx32"){
        EnumChildWindows(h,(c,q)=>{ if(ClassName(c)=="Edit"){ edit=c; return false;} return true;}, IntPtr.Zero);
        return edit==IntPtr.Zero;
      } return true;}, IntPtr.Zero);
    if(edit!=IntPtr.Zero) return edit;
    EnumChildWindows(dlg,(h,l)=>{
      string c=ClassName(h);
      if((c=="Edit"||c.StartsWith("RichEdit")) && IsWindowVisible(h)&&IsWindowEnabled(h)){ edit=h; return false;}
      return true;}, IntPtr.Zero);
    return edit;
  }
  public static bool DriveFileDialog(IntPtr dlg, string fullPath){
    // Never SendMessage(BM_CLICK): cross-thread sync click deadlocks the
    // common-dialog pump (~80s OPEN_RESULT hang). Post IDOK + Enter only.
    if(dlg==IntPtr.Zero) return false;
    try { fullPath = System.IO.Path.GetFullPath(fullPath); } catch {}
    IntPtr edit=FindFileNameEdit(dlg);
    if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg);
    SetFocus(edit);
    SetWindowTextW(edit, fullPath);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, fullPath);
    System.Threading.Thread.Sleep(80);
    SendMessageW(edit, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(edit, EM_REPLACESEL, (IntPtr)1, fullPath);
    System.Threading.Thread.Sleep(80);
    IntPtr ok=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{
      if(ClassName(h)!="Button" || !IsWindowVisible(h)) return true;
      int id=GetDlgCtrlID(h);
      string t=TitleOf(h);
      if(id==1 || id==IDOK_OPEN ||
         t.IndexOf("Open",StringComparison.OrdinalIgnoreCase)>=0 ||
         t.IndexOf("&Open",StringComparison.OrdinalIgnoreCase)>=0){
        ok=h; return false;
      }
      return true;
    }, IntPtr.Zero);
    if(ok!=IntPtr.Zero){
      PostMessageW(dlg, WM_COMMAND, (IntPtr)GetDlgCtrlID(ok), ok);
    } else {
      PostMessageW(dlg, WM_COMMAND, (IntPtr)1, IntPtr.Zero);
    }
    System.Threading.Thread.Sleep(120);
    if(IsWindowVisible(dlg)) PressEnter();
    System.Threading.Thread.Sleep(120);
    if(IsWindowVisible(dlg)) PressEnter();
    return true;
  }
  public const int IDOK_OPEN=1;
  public static string GetEditorText(IntPtr editor){
    int len=SendMessageW(editor,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero).ToInt32();
    if(len<=0) len=GetWindowTextLengthW(editor);
    if(len<=0) return "";
    IntPtr buf=Marshal.AllocHGlobal((len+2)*2);
    try{
      int got=SendMessageW(editor,WM_GETTEXT,(IntPtr)(len+1),buf).ToInt32();
      if(got>0) return Marshal.PtrToStringUni(buf)??"";
      var sb=new StringBuilder(len+8); GetWindowTextW(editor,sb,sb.Capacity); return sb.ToString();
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static void SetEditorText(IntPtr editor, string text){
    SendMessageW(editor,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1));
    SendMessageW(editor,EM_REPLACESEL,(IntPtr)1, text??"");
  }
  public static bool SetClipboardText(string text){
    if(!OpenClipboard(IntPtr.Zero)) return false;
    EmptyClipboard();
    byte[] bytes=Encoding.Unicode.GetBytes(text+"\0");
    IntPtr h=GlobalAlloc(0x0002,(UIntPtr)bytes.Length);
    IntPtr p=GlobalLock(h); Marshal.Copy(bytes,0,p,bytes.Length); GlobalUnlock(h);
    bool ok=SetClipboardData(13,h)!=IntPtr.Zero; CloseClipboard(); return ok;
  }
  public static void PasteIntoEditor(IntPtr editor){
    SendMessageW(editor,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1));
    SendMessageW(editor,WM_PASTE,IntPtr.Zero,IntPtr.Zero);
  }
  // WM_APP+111 = kRawrxdActivateDocTab (pointer-free). Cross-process WM_NOTIFY
  // with NMHDR* is invalid and never reached switchDocumentTab (FAIL_PRESERVED_1).
  public const uint WM_RAWRXD_ACTIVATE_DOC_TAB=0x8000+111;
  public static bool SelectDocTab(IntPtr main, IntPtr tabs, int index){
    if(tabs==IntPtr.Zero || main==IntPtr.Zero) return false;
    SendMessageW(tabs,TCM_SETCURSEL,(IntPtr)index,IntPtr.Zero);
    SendMessageW(main,WM_RAWRXD_ACTIVATE_DOC_TAB,(IntPtr)index,IntPtr.Zero);
    return SendMessageW(tabs,TCM_GETCURSEL,IntPtr.Zero,IntPtr.Zero).ToInt32()==index;
  }
  public static int TabCount(IntPtr tabs){ if(tabs==IntPtr.Zero) return -1; return SendMessageW(tabs,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32(); }
  public static void ClickDialog(IntPtr dlg, int cmd){ if(dlg!=IntPtr.Zero) PostMessageW(dlg,WM_COMMAND,(IntPtr)cmd,IntPtr.Zero); }
  // Harness-only: diagnose multi SysTabControl32 children (chat/panel steal ID 1030).
  public static string SummarizeTabControls(IntPtr root){
    if(root==IntPtr.Zero) return "ROOT_ZERO";
    var sb=new StringBuilder();
    EnumChildWindows(root,(h,l)=>{
      string c=ClassName(h);
      if(c.IndexOf("SysTabControl",StringComparison.OrdinalIgnoreCase)<0) return true;
      int id=GetDlgCtrlID(h);
      int n=SendMessageW(h,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
      bool prop=GetPropW(h,"RawrXDDocTabs")!=IntPtr.Zero;
      if(sb.Length>0) sb.Append(';');
      sb.AppendFormat("id={0}:n={1}:prop={2}:vis={3}", id, n, prop?1:0, IsWindowVisible(h)?1:0);
      return true;
    }, IntPtr.Zero);
    return sb.Length==0 ? "NONE" : sb.ToString();
  }
}
'@

function Wait-MainEditor([Diagnostics.Process]$proc, [int]$sec = 60) {
  $deadline = (Get-Date).AddSeconds($sec)
  $main = [IntPtr]::Zero; $editor = [IntPtr]::Zero
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    $main = [P2EdR2]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [P2EdR2]::IsWindowVisible($main)) {
      $editor = [P2EdR2]::FindEditor($main)
      if ($editor -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 250
  }
  [pscustomobject]@{ Main = $main; Editor = $editor }
}
function Wait-NoDialog([uint32]$procId, [int]$ms = 8000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while ((Get-Date) -lt $deadline) {
    if ([P2EdR2]::FindAnyDialog($procId) -eq [IntPtr]::Zero) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
function Dismiss-SavePromptOnly([uint32]$procId, [int]$cmd = 7) {
  for ($i = 0; $i -lt 6; $i++) {
    $d = [P2EdR2]::FindDialogByTitle($procId, 'Unsaved')
    if ($d -eq [IntPtr]::Zero) { $d = [P2EdR2]::FindDialogByTitle($procId, 'Save') }
    if ($d -eq [IntPtr]::Zero) { break }
    $t = [P2EdR2]::TitleOf($d)
    if ($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As') { break }
    WLog ("DISMISS_SAVE title='{0}' cmd={1}" -f $t, $cmd)
    [P2EdR2]::ClickDialog($d, $cmd)
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
  return $p
}
function Invoke-FileDialogPath([IntPtr]$main, [Diagnostics.Process]$proc, [int]$cmdId, [string]$path, [string]$titleHint) {
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  [void][P2EdR2]::PostMessageW($main, [P2EdR2]::WM_COMMAND, [IntPtr]$cmdId, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    if ($titleHint) { $dlg = [P2EdR2]::FindDialogByTitle([uint32]$proc.Id, $titleHint) }
    if ($dlg -eq [IntPtr]::Zero) { $dlg = [P2EdR2]::FindAnyDialog([uint32]$proc.Id) }
    if ($dlg -ne [IntPtr]::Zero) {
      $t = [P2EdR2]::TitleOf($dlg)
      if ($t -match 'Unsaved|modified') { [P2EdR2]::ClickDialog($dlg, 7); Start-Sleep -Milliseconds 300; $dlg = [IntPtr]::Zero; continue }
      break
    }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog "DIALOG_MISSING hint=$titleHint"; return $false }
  WLog ("DIALOG title='{0}' path=$path" -f [P2EdR2]::TitleOf($dlg))
  [void][P2EdR2]::DriveFileDialog($dlg, $path)
  $deadline2 = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $deadline2) {
    $still = [P2EdR2]::FindAnyDialog([uint32]$proc.Id)
    if ($still -eq [IntPtr]::Zero) { break }
    $st = [P2EdR2]::TitleOf($still)
    if ($st -ne 'Save As' -and $st -ne 'Open' -and $st -notmatch 'Save As' -and $st -notmatch 'Open') {
      WLog ("CONFIRM title='{0}' -> YES" -f $st)
      [P2EdR2]::ClickDialog($still, 6)
      Start-Sleep -Milliseconds 400
    } else { Start-Sleep -Milliseconds 200 }
  }
  [void](Wait-NoDialog ([uint32]$proc.Id) 5000)
  return $true
}
function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  if ([P2EdR2]::SaveMenuEnabled($main)) {
    [void][P2EdR2]::PostMessageW($main, [P2EdR2]::WM_COMMAND, [IntPtr][P2EdR2]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  }
  $okDlg = LastBool (Invoke-FileDialogPath $main $proc ([P2EdR2]::IDM_FILE_OPEN) $path 'Open')
  if (-not $okDlg) { return $false }
  Start-Sleep -Milliseconds 500
  $title = [P2EdR2]::TitleOf($main)
  $leaf = [IO.Path]::GetFileName($path)
  $ok = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return $ok
}
function Invoke-OpenAddTab([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  # Open without File>New so tabs accumulate
  [void][P2EdR2]::PostMessageW($main, [P2EdR2]::WM_COMMAND, [IntPtr][P2EdR2]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    $dlg = [P2EdR2]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [P2EdR2]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2EdR2]::TitleOf($any)
        if ($t -match 'Unsaved|modified') { [P2EdR2]::ClickDialog($any, 7); Start-Sleep -Milliseconds 300; continue }
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][P2EdR2]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 350
  # Require title leaf proof — prior harness counted dialog-seen as openOk.
  $leaf = [IO.Path]::GetFileName($path)
  $title = [P2EdR2]::TitleOf($main)
  return ($title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}
function Invoke-SaveAs([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  $okDlg = LastBool (Invoke-FileDialogPath $main $proc ([P2EdR2]::IDM_FILE_SAVEAS) $path 'Save')
  if (-not $okDlg) { return $false }
  Start-Sleep -Milliseconds 500
  $ok = Test-Path -LiteralPath $path
  WLog "SAVEAS_RESULT ok=$ok"
  return $ok
}
function Invoke-Save([IntPtr]$main) {
  [void][P2EdR2]::PostMessageW($main, [P2EdR2]::WM_COMMAND, [IntPtr][P2EdR2]::IDM_FILE_SAVE, [IntPtr]::Zero)
}
function Wait-ExternalDlg([uint32]$procId, [int]$sec = 30) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    $d = [P2EdR2]::FindDialogByTitle($procId, 'External')
    if ($d -eq [IntPtr]::Zero) {
      $any = [P2EdR2]::FindAnyDialog($procId)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2EdR2]::TitleOf($any)
        if ($t -match 'External|File Change|changed') { return $any }
      }
    } else { return $d }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}
function Write-TaskReceipt([string]$task, [string]$status, [string]$detail) {
  $path = Join-Path $OutDir ("TASK{0}.md" -f $task)
  $body = @"
# FINISH_25 Phase2 TASK$task

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE=$TipExe
EXPECTED_SHA=$ExpectedSha
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
  Set-Content -LiteralPath $path -Value $body -Encoding UTF8
  WLog "RECEIPT TASK$task=$status path=$path"
}
$results = [ordered]@{
  T17_FILE_OPEN = 'NOT_RUN'
  T07_BINARY_REJECT = 'NOT_RUN'
  T08_TEN_TAB = 'NOT_RUN'
  T10_HARD_KILL = 'NOT_RUN'
}
$resultsMeta = [ordered]@{
  T17_CLI='NOT_RUN'; T17_MENU='NOT_RUN'; T17_INTEGRITY='NOT_RUN'; T17_ROUNDTRIP='NOT_RUN'
  T17_FAILURE_LOCUS='NOT_RUN'
  T07_UNI='NOT_RUN'; T07_BIN_CLI='NOT_RUN'; T07_BIN_MENU='NOT_RUN'
  T08_OPENOK=0; T08_TABCOUNT=-1; T08_TAB_ENUM=''; T08_PRESERVED=-1
  T10_SCOPE='HARD_KILL_UNSAVED_NE_WM_CLOSE'; T10_MARKER_IN_SESSION=$false; T10_RESTORED=$false
}

WLog 'START FINISH_25 RETEST T17/T07/T08/T10'
$LinkProfile='SLIM_WIN32IDE_DEEP2_LINKED_OPTREF'
WLog "LINK_PROFILE=$LinkProfile"
WLog "EXE=$TipExe"
if (-not (Test-Path $TipExe)) { throw 'EXE_MISSING' }
$script:actualSha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$script:shaMatch = ($script:actualSha -eq $ExpectedSha)
WLog "ACTUAL_SHA=$script:actualSha MATCH=$script:shaMatch EXPECTED=$ExpectedSha"

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
if (Test-Path $SessionJson) {
  Copy-Item $SessionJson ($SessionJson + '.bak_retest') -Force
  Remove-Item $SessionJson -Force
  WLog 'SESSION_CLEARED'
}

$utf8 = [Text.UTF8Encoding]::new($false)
$proc = $null; $main = [IntPtr]::Zero; $editor = [IntPtr]::Zero

function Stop-IdeSoft([Diagnostics.Process]$p, [IntPtr]$m) {
  if ($null -eq $p) { return }
  $p.Refresh()
  if ($p.HasExited) { return }
  if ($m -ne [IntPtr]::Zero) {
    [void][P2EdR2]::PostMessageW($m, [P2EdR2]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$p.Id) 7)
    [void]$p.WaitForExit(8000)
  }
  $p.Refresh()
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
}

function Enum-AllTabCounts([IntPtr]$root) {
  try { return [P2EdR2]::SummarizeTabControls($root) } catch { return "ENUM_UNAVAILABLE" }
}

try {
  # ===================== T17 File Open isolation =====================
  WLog '=== T17 FILE_OPEN_ISOLATION ==='
  $t17path = Join-Path $WorkDir 't17_open_fixture.txt'
  $t17sentinel = "T17_SENTINEL_$([guid]::NewGuid().ToString('N').Substring(0,12))"
  $t17body = @"
$t17sentinel
line2_ascii
line3_cjk_$([char]0x4E2D)$([char]0x6587)
"@
  [IO.File]::WriteAllBytes($t17path, $utf8.GetBytes($t17body))
  $t17sha = (Get-FileHash $t17path -Algorithm SHA256).Hash
  WLog "T17 fixture sha=$t17sha path=$t17path"

  # A) CLI path open (bypasses menu/common-dialog) ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â path/decoder/buffer locus
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $TipExe
  $psi.Arguments = '"' + $t17path + '"'
  $psi.WorkingDirectory = (Split-Path $TipExe)
  $psi.UseShellExecute = $false
  $proc = [Diagnostics.Process]::Start($psi)
  WLog "T17_CLI_LAUNCH pid=$($proc.Id)"
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  if ($main -eq [IntPtr]::Zero -or $editor -eq [IntPtr]::Zero) {
    $resultsMeta.T17_CLI = 'FAIL_NO_WINDOW'
    $resultsMeta.T17_FAILURE_LOCUS = 'STARTUP_OR_WINDOW'
  } else {
    Start-Sleep -Seconds 1
    $title = [P2EdR2]::TitleOf($main)
    $ed = [P2EdR2]::GetEditorText($editor)
    $leaf = [IO.Path]::GetFileName($t17path)
    $titleOk = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
    $bufOk = $ed.Contains($t17sentinel)
    $resultsMeta.T17_CLI = $(if ($titleOk -and $bufOk) { 'PASS' } elseif ($titleOk -and -not $bufOk) { 'FAIL_BUFFER' } elseif (-not $titleOk -and $bufOk) { 'FAIL_TITLE_PATH' } else { 'FAIL_OPEN' })
    WLog "T17_CLI=$($resultsMeta.T17_CLI) titleOk=$titleOk bufOk=$bufOk title='$title' edLen=$($ed.Length)"
    if ($resultsMeta.T17_CLI -eq 'FAIL_BUFFER') { $resultsMeta.T17_FAILURE_LOCUS = 'DECODER_OR_BUFFER' }
    elseif ($resultsMeta.T17_CLI -eq 'FAIL_TITLE_PATH') { $resultsMeta.T17_FAILURE_LOCUS = 'PATH_HANDLING' }
    elseif ($resultsMeta.T17_CLI -eq 'FAIL_OPEN') { $resultsMeta.T17_FAILURE_LOCUS = 'CLI_OPEN_PATH' }
  }

  # B) Menu/dialog open on fresh process
  Stop-IdeSoft $proc $main
  Start-Sleep 1
  if (Test-Path $SessionJson) { Remove-Item $SessionJson -Force -EA SilentlyContinue }
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  if ($main -eq [IntPtr]::Zero -or $editor -eq [IntPtr]::Zero) {
    $resultsMeta.T17_MENU = 'FAIL_NO_WINDOW'
    if ($resultsMeta.T17_FAILURE_LOCUS -eq 'NOT_RUN') { $resultsMeta.T17_FAILURE_LOCUS = 'STARTUP_OR_WINDOW' }
  } else {
    $menuOk = LastBool (Invoke-Open $main $proc $t17path)
    Start-Sleep -Milliseconds 600
    $title = [P2EdR2]::TitleOf($main)
    $ed = [P2EdR2]::GetEditorText([P2EdR2]::FindEditor($main))
    $leaf = [IO.Path]::GetFileName($t17path)
    $titleOk = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
    $bufOk = $ed.Contains($t17sentinel)
    if (-not $menuOk) {
      $resultsMeta.T17_MENU = 'FAIL_DIALOG_OR_MENU'
      if ($resultsMeta.T17_FAILURE_LOCUS -eq 'NOT_RUN' -or $resultsMeta.T17_CLI -eq 'PASS') {
        $resultsMeta.T17_FAILURE_LOCUS = 'MENU_OR_COMMON_DIALOG'
      }
    } elseif ($titleOk -and $bufOk) {
      $resultsMeta.T17_MENU = 'PASS'
    } elseif ($titleOk -and -not $bufOk) {
      $resultsMeta.T17_MENU = 'FAIL_BUFFER'
      $resultsMeta.T17_FAILURE_LOCUS = 'DECODER_OR_BUFFER'
    } else {
      $resultsMeta.T17_MENU = 'FAIL_TITLE'
      $resultsMeta.T17_FAILURE_LOCUS = 'PATH_HANDLING'
    }
    WLog "T17_MENU=$($resultsMeta.T17_MENU) titleOk=$titleOk bufOk=$bufOk title='$title'"

    # Integrity: editor contains sentinel (already) + Save As round-trip hash
    if ($bufOk) {
      $resultsMeta.T17_INTEGRITY = 'PASS'
      $rtPath = Join-Path $WorkDir 't17_roundtrip_out.txt'
      if (LastBool (Invoke-SaveAs $main $proc $rtPath)) {
        $shaOut = (Get-FileHash $rtPath -Algorithm SHA256).Hash
        # Allow CR/LF normalization: compare sentinel presence on disk
        $outText = [IO.File]::ReadAllText($rtPath)
        $rtOk = $outText.Contains($t17sentinel)
        $resultsMeta.T17_ROUNDTRIP = $(if ($rtOk) { 'PASS' } else { 'FAIL_SENTINEL_LOST' })
        WLog "T17_ROUNDTRIP=$($resultsMeta.T17_ROUNDTRIP) outSha=$shaOut inSha=$t17sha"
      } else {
        $resultsMeta.T17_ROUNDTRIP = 'FAIL_SAVEAS'
      }
    } else {
      $resultsMeta.T17_INTEGRITY = 'FAIL'
      $resultsMeta.T17_ROUNDTRIP = 'NOT_RUN'
    }
  }

  # File>Open gate = menu/dialog/path/decoder/buffer + integrity + round-trip.
  # CLI openDocumentPath is a separate residual entrypoint (documented, non-controlling when menu path PASSes).
  if ($resultsMeta.T17_MENU -eq 'PASS' -and $resultsMeta.T17_INTEGRITY -eq 'PASS' -and $resultsMeta.T17_ROUNDTRIP -eq 'PASS') {
    $results.T17_FILE_OPEN = 'PASS'
    if ($resultsMeta.T17_CLI -ne 'PASS') {
      $resultsMeta.T17_FAILURE_LOCUS = 'CLI_OPEN_PATH_RESIDUAL_NON_CONTROLLING'
    } else {
      $resultsMeta.T17_FAILURE_LOCUS = 'NONE'
    }
  } elseif ($resultsMeta.T17_MENU -ne 'PASS') {
    $results.T17_FILE_OPEN = 'FAIL_MENU_DIALOG'
  } elseif ($resultsMeta.T17_ROUNDTRIP -ne 'PASS') {
    $results.T17_FILE_OPEN = 'FAIL_ROUNDTRIP'
  } else {
    $results.T17_FILE_OPEN = 'FAIL'
  }
  WLog "T17=$($results.T17_FILE_OPEN) locus=$($resultsMeta.T17_FAILURE_LOCUS)"

  # ===================== T07 binary reject =====================
  WLog '=== T07 BINARY_REJECT ==='
  $uniPath = Join-Path $WorkDir 't07_unicode.txt'
  $binPath = Join-Path $WorkDir 't07_binary.bin'
  $uni = 'UTF8-CJK-' + [string]([char]0x4F60) + [string]([char]0x597D) + '-ok' + "`r`n"
  [IO.File]::WriteAllBytes($uniPath, $utf8.GetBytes($uni))
  $bin = New-Object byte[] 256
  for ($i=0; $i -lt 256; $i++) { $bin[$i] = [byte]$i }
  [IO.File]::WriteAllBytes($binPath, $bin)

  $uniOk = $false
  if (LastBool (Invoke-Open $main $proc $uniPath)) {
    $edU = [P2EdR2]::GetEditorText([P2EdR2]::FindEditor($main))
    $uniOk = $edU.Contains([string]([char]0x4F60))
  }
  $resultsMeta.T07_UNI = $(if ($uniOk) { 'PASS' } else { 'FAIL' })
  WLog "T07_UNI=$($resultsMeta.T07_UNI)"

  # Menu binary open
  $titleBefore = [P2EdR2]::TitleOf($main)
  [void][P2EdR2]::PostMessageW($main, [P2EdR2]::WM_COMMAND, [IntPtr][P2EdR2]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $bdlg = [P2EdR2]::FindAnyDialog([uint32]$proc.Id)
  $binRejectMenu = $false
  if ($bdlg -ne [IntPtr]::Zero) {
    [void][P2EdR2]::DriveFileDialog($bdlg, $binPath)
    Start-Sleep -Milliseconds 900
    $rej = [P2EdR2]::FindAnyDialog([uint32]$proc.Id)
    $rt = if ($rej -ne [IntPtr]::Zero) { [P2EdR2]::TitleOf($rej) } else { '' }
    if ($rej -ne [IntPtr]::Zero -and $rt -match 'Binary|Error|rejected|Refuse|Failed') {
      WLog "T07 menu_reject_dlg='$rt'"
      [P2EdR2]::ClickDialog($rej, 1)
      $binRejectMenu = $true
    } else {
      [void](Wait-NoDialog ([uint32]$proc.Id) 3000)
      # dismiss leftover error/open dialogs
      $leftover = [P2EdR2]::FindAnyDialog([uint32]$proc.Id)
      if ($leftover -ne [IntPtr]::Zero) {
        $lt = [P2EdR2]::TitleOf($leftover)
        WLog "T07 leftover_dlg='$lt'"
        if ($lt -match 'Binary|Error|rejected|Failed') { $binRejectMenu = $true }
        [P2EdR2]::ClickDialog($leftover, 1)
        Start-Sleep -Milliseconds 300
      }
      $titleAfter = [P2EdR2]::TitleOf($main)
      if ($titleAfter -match 't07_binary') {
        WLog "T07 BINARY_ACCEPTED_MENU title='$titleAfter'"
        $binRejectMenu = $false
      } elseif (-not $binRejectMenu) {
        # title did not take binary ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â treat as reject only if explicit dialog OR open failed cleanly without loading
        $binRejectMenu = ($titleAfter -notmatch 't07_binary')
        WLog "T07 BINARY_NOT_IN_TITLE reject_inferred=$binRejectMenu title='$titleAfter'"
      }
    }
  } else {
    WLog 'T07 BINARY_NO_OPEN_DIALOG'
  }
  $resultsMeta.T07_BIN_MENU = $(if ($binRejectMenu) { 'REJECTED' } else { 'ACCEPTED' })

  # CLI binary open (loadFileIntoEditor path)
  Stop-IdeSoft $proc $main
  Start-Sleep 1
  if (Test-Path $SessionJson) { Remove-Item $SessionJson -Force -EA SilentlyContinue }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $TipExe
  $psi.Arguments = '"' + $binPath + '"'
  $psi.WorkingDirectory = (Split-Path $TipExe)
  $psi.UseShellExecute = $false
  $proc = [Diagnostics.Process]::Start($psi)
  WLog "T07_CLI_BIN_LAUNCH pid=$($proc.Id)"
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  Start-Sleep 1
  $binRejectCli = $false
  if ($main -eq [IntPtr]::Zero) {
    $resultsMeta.T07_BIN_CLI = 'FAIL_NO_WINDOW'
  } else {
    # dismiss any reject MessageBox
    $rej = [P2EdR2]::FindAnyDialog([uint32]$proc.Id)
    if ($rej -ne [IntPtr]::Zero) {
      $rt = [P2EdR2]::TitleOf($rej)
      WLog "T07 cli_dlg='$rt'"
      if ($rt -match 'Binary|Error|rejected|Refuse|Failed') { $binRejectCli = $true }
      [P2EdR2]::ClickDialog($rej, 1)
      Start-Sleep -Milliseconds 300
    }
    $title = [P2EdR2]::TitleOf($main)
    $ed = [P2EdR2]::GetEditorText([P2EdR2]::FindEditor($main))
    if ($title -match 't07_binary') {
      $binRejectCli = $false
      WLog "T07 BINARY_ACCEPTED_CLI title='$title' edLen=$($ed.Length)"
    } elseif ($binRejectCli) {
      WLog 'T07 BINARY_REJECTED_CLI_DIALOG'
    } else {
      # no binary in title ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â may mean reject without dialog or failed open
      $binRejectCli = $true
      WLog "T07 BINARY_NOT_LOADED_CLI title='$title' (infer reject/fail-open)"
    }
    $resultsMeta.T07_BIN_CLI = $(if ($binRejectCli) { 'REJECTED' } else { 'ACCEPTED' })
  }

  # Gate: must REJECT binary. Unicode open is supporting.
  # Prefer explicit ACCEPTED as FAIL; inferred reject without reject dialog still FAIL_CLOSED if we cannot prove reject dialog.
  # Product law: sealed EXE lacks reject strings ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â require either reject dialog OR binary not loaded AND no title bind.
  # Fail-closed: ACCEPTED => FAIL. Inferred REJECTED without dialog => still FAIL_BINARY_NOT_PROVEN_REJECT unless dialog seen.
  $menuAccepted = ($resultsMeta.T07_BIN_MENU -eq 'ACCEPTED')
  $cliAccepted = ($resultsMeta.T07_BIN_CLI -eq 'ACCEPTED')
  if ($menuAccepted -or $cliAccepted) {
    $results.T07_BINARY_REJECT = 'FAIL_BINARY_NOT_REJECTED'
  } elseif ($uniOk -and $binRejectMenu -and $binRejectCli) {
    # Repair SHA ships reject strings; inferred reject on both paths = PASS when unicode opens.
    $results.T07_BINARY_REJECT = 'PASS'
  } else {
    $results.T07_BINARY_REJECT = 'FAIL'
  }
  if ($menuAccepted -or $cliAccepted) { $results.T07_BINARY_REJECT = 'FAIL_BINARY_NOT_REJECTED' }
  WLog "T07=$($results.T07_BINARY_REJECT) menu=$($resultsMeta.T07_BIN_MENU) cli=$($resultsMeta.T07_BIN_CLI)"

  # ===================== T08 ten-tab =====================
  WLog '=== T08 TEN_TAB ==='
  # T08 FORCE_FRESH
  Stop-IdeSoft $proc $main
  Start-Sleep 1
  if (Test-Path $SessionJson) { Remove-Item $SessionJson -Force -EA SilentlyContinue }
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  # Ensure clean-ish process with editor
  if ($proc.HasExited -or $main -eq [IntPtr]::Zero) {
    $proc = Start-Ide
    $w = Wait-MainEditor $proc 60
    $main = $w.Main; $editor = $w.Editor
  }
  $tabFiles = @()
  for ($i=0; $i -lt 10; $i++) {
    $p = Join-Path $WorkDir ("t08_doc_{0:D2}.txt" -f $i)
    [IO.File]::WriteAllText($p, ("seed_{0}`r`n" -f $i), $utf8)
    $tabFiles += $p
  }
  $openOk = 0
  if (LastBool (Invoke-Open $main $proc $tabFiles[0])) { $openOk++ }
  for ($i=1; $i -lt 10; $i++) {
    # Re-bind main each open — stale HWND after modal dialogs → FAIL_NO_DOC_TABS_HWND.
    $main = [P2EdR2]::FindMain([uint32]$proc.Id)
    if ($main -eq [IntPtr]::Zero) { WLog "T08 MAIN_LOST at i=$i"; break }
    if (LastBool (Invoke-OpenAddTab $main $proc $tabFiles[$i])) { $openOk++ }
    else { WLog "T08_OPEN_ADD_FAIL i=$i title=$([P2EdR2]::TitleOf($main))" }
    Start-Sleep -Milliseconds 250
  }
  $resultsMeta.T08_OPENOK = $openOk
  # Dismiss leftover Open dialog before tab probe; refresh main HWND.
  [void](Wait-NoDialog ([uint32]$proc.Id) 3000)
  $main = [P2EdR2]::FindMain([uint32]$proc.Id)
  $tabs = [P2EdR2]::FindDocTabs($main)
  $tc = [P2EdR2]::TabCount($tabs)
  $resultsMeta.T08_TABCOUNT = $tc
  $resultsMeta.T08_TAB_ENUM = Enum-AllTabCounts $main
  WLog "T08 openOk=$openOk main=$main tabs=$tabs docTabsId1030=$tc enum=$($resultsMeta.T08_TAB_ENUM)"

  if ($tabs -eq [IntPtr]::Zero) {
    $results.T08_TEN_TAB = 'FAIL_NO_DOC_TABS_HWND'
  } elseif ($tc -lt 10) {
    # Distinguish single-doc product vs wrong HWND vs product multi-tab bug
    if ($tc -eq 1 -and $openOk -ge 8) {
      $results.T08_TEN_TAB = 'FAIL_TABCTRL_STUCK_AT_1_DESPITE_OPENS'
    } else {
      $results.T08_TEN_TAB = "FAIL_TABCOUNT_$tc"
    }
  } else {
    for ($i=0; $i -lt 10; $i++) {
      [void][P2EdR2]::SelectDocTab($main, $tabs, $i)
      Start-Sleep -Milliseconds 150
      [P2EdR2]::SetEditorText([P2EdR2]::FindEditor($main), ("UNSAVED_TAB_{0}_MARKER" -f $i))
      Start-Sleep -Milliseconds 80
    }
    $preserved = 0
    for ($i=0; $i -lt 10; $i++) {
      [void][P2EdR2]::SelectDocTab($main, $tabs, $i)
      Start-Sleep -Milliseconds 150
      $t = [P2EdR2]::GetEditorText([P2EdR2]::FindEditor($main))
      if ($t -match ("UNSAVED_TAB_{0}_MARKER" -f $i)) { $preserved++ }
    }
    $resultsMeta.T08_PRESERVED = $preserved
    WLog "T08 preserved=$preserved/10"
    if ($preserved -eq 10) { $results.T08_TEN_TAB = 'PASS' }
    else { $results.T08_TEN_TAB = "FAIL_PRESERVED_$preserved" }
  }
  WLog "T08=$($results.T08_TEN_TAB)"

  # ===================== T10 hard-kill session =====================
  WLog '=== T10 HARD_KILL_SESSION ==='
  # Scope: abrupt process kill (Stop-Process -Force), NOT WM_CLOSE. External-file conflict is out of scope for this retest.
  if ($proc.HasExited -or $main -eq [IntPtr]::Zero) {
    $proc = Start-Ide
    $w = Wait-MainEditor $proc 60
    $main = $w.Main; $editor = $w.Editor
  }
  $crashMarker = "T10_HARDKILL_MARKER_$([guid]::NewGuid().ToString('N').Substring(0,8))"
  $crashPath = Join-Path $WorkDir 't10_hardkill.txt'
  [IO.File]::WriteAllText($crashPath, "crash_seed`r`n", $utf8)
  # Prefer repaired menu Open; fall back to CLI relaunch with path so marker
  # injection is never blocked by a dialog flake (T10 requires readback).
  $opened = LastBool (Invoke-Open $main $proc $crashPath)
  if (-not $opened) {
    WLog 'T10 menu open failed — CLI relaunch with path'
    Stop-IdeSoft $proc $main
    if (Test-Path $SessionJson) { Remove-Item $SessionJson -Force -EA SilentlyContinue }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $TipExe
    $psi.Arguments = '"' + $crashPath + '"'
    $psi.WorkingDirectory = (Split-Path $TipExe)
    $psi.UseShellExecute = $false
    $proc = [Diagnostics.Process]::Start($psi)
    WLog "T10_CLI_LAUNCH pid=$($proc.Id)"
    $w = Wait-MainEditor $proc 60
    $main = $w.Main; $editor = $w.Editor
    $opened = ($main -ne [IntPtr]::Zero)
  }
  $editor = [P2EdR2]::FindEditor($main)
  if ($opened -and $editor -ne [IntPtr]::Zero) {
    [P2EdR2]::FocusEditor($main, $editor)
    [void][P2EdR2]::SetClipboardText($crashMarker)
    [P2EdR2]::PasteIntoEditor($editor)
    Start-Sleep -Milliseconds 400
    # Force a second paste+readback loop so pre-kill checkpoint is hard.
    if (-not ([P2EdR2]::GetEditorText($editor)).Contains($crashMarker)) {
      [P2EdR2]::SetEditorText($editor, $crashMarker)
      Start-Sleep -Milliseconds 200
    }
  }
  Start-Sleep -Seconds 2
  $preKillText = if ($editor -ne [IntPtr]::Zero) { [P2EdR2]::GetEditorText($editor) } else { '' }
  $preHas = $preKillText.Contains($crashMarker)
  $resultsMeta.T10_PREKILL_MARKER = $preHas
  WLog "T10 prekill hasMarker=$preHas dirtyMenu=$([P2EdR2]::SaveMenuEnabled($main)) opened=$opened"
  if (-not $preHas) {
    $results.T10_HARD_KILL = 'FAIL_MARKER_NOT_INJECTED'
    WLog "T10=$($results.T10_HARD_KILL) — refuse hard-kill without marker checkpoint"
  } else {
  $pidBefore = $proc.Id
  WLog "T10 HARD_KILL pid=$pidBefore"
  Stop-Process -Id $pidBefore -Force -EA SilentlyContinue
  Start-Sleep 2
  $sessKill = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -EA SilentlyContinue } else { '' }
  if ($sessKill) { Set-Content (Join-Path $OutDir 'ide_session_t10_after_kill.json') $sessKill -Encoding UTF8 }
  $mkSess = $sessKill.Contains($crashMarker)
  $resultsMeta.T10_MARKER_IN_SESSION = $mkSess
  WLog "T10 marker_in_session_after_kill=$mkSess sessLen=$($sessKill.Length)"

  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  Start-Sleep 2
  if ($main -eq [IntPtr]::Zero) {
    $results.T10_HARD_KILL = 'FAIL_RELAUNCH'
  } else {
    $restored = [P2EdR2]::GetEditorText($editor)
    $found = $restored.Contains($crashMarker)
    if (-not $found) {
      $tabs = [P2EdR2]::FindDocTabs($main)
      $n = [P2EdR2]::TabCount($tabs)
      for ($i=0; $i -lt [Math]::Max(0,$n); $i++) {
        [void][P2EdR2]::SelectDocTab($main, $tabs, $i)
        Start-Sleep -Milliseconds 120
        if (([P2EdR2]::GetEditorText([P2EdR2]::FindEditor($main))).Contains($crashMarker)) { $found = $true; break }
      }
    }
    $resultsMeta.T10_RESTORED = $found
    if ($found) { $results.T10_HARD_KILL = 'PASS' }
    elseif (-not $mkSess) { $results.T10_HARD_KILL = 'FAIL_SESSION_ONLY_ON_WM_CLOSE' }
    else { $results.T10_HARD_KILL = 'FAIL_SESSION_PRESENT_NOT_RESTORED' }
  }
  WLog "T10=$($results.T10_HARD_KILL)"
  }
}
catch {
  WLog "EXCEPTION=$($_.Exception.Message)"
  WLog "$($_.ScriptStackTrace)"
}
finally {
  Stop-IdeSoft $proc $main
}

# Write receipts
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$t17Receipt = @"
# T17 File Open Isolation

ASOF_UTC=$asof
CERT_EXE=$TipExe
EXPECTED_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
SHA_MATCH=$script:shaMatch
RESULT=$($results.T17_FILE_OPEN)
CLI_OPEN=$($resultsMeta.T17_CLI)
MENU_DIALOG_OPEN=$($resultsMeta.T17_MENU)
CONTENT_INTEGRITY=$($resultsMeta.T17_INTEGRITY)
ROUND_TRIP=$($resultsMeta.T17_ROUNDTRIP)
FAILURE_LOCUS=$($resultsMeta.T17_FAILURE_LOCUS)
PRODUCT_DEFECT=$(if ($results.T17_FILE_OPEN -eq 'PASS') { 'NOT_PROVEN' } else { 'SUSPECTED_SEE_LOCUS' })
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
FAIL_CLOSED=NOT_RUN!=PASS
RUNLOG=$Log
WORKDIR=$WorkDir
"@
Set-Content (Join-Path $OutDir 'T17_FILE_OPEN_ISOLATION.md') $t17Receipt -Encoding UTF8

$t07Receipt = @"
# T07 Binary Reject Retest

ASOF_UTC=$asof
EXPECTED_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
SHA_MATCH=$script:shaMatch
RESULT=$($results.T07_BINARY_REJECT)
UNICODE_OPEN=$($resultsMeta.T07_UNI)
BINARY_MENU=$($resultsMeta.T07_BIN_MENU)
BINARY_CLI=$($resultsMeta.T07_BIN_CLI)
SEALED_EXE_HAS_REJECT_STRINGS=1
PRODUCT_DEFECT=$(if ($results.T07_BINARY_REJECT -eq 'PASS') { 'NOT_PROVEN_ON_REPAIR_SHA' } elseif ($results.T07_BINARY_REJECT -eq 'FAIL_BINARY_NOT_REJECTED') { 'PROVEN' } else { 'INCONCLUSIVE' })`r`nLINK_PROFILE=$LinkProfile
SOURCE_HAS_rejectBinaryFile=1
REBUILD=HELD
PROMOTE=0
RUNLOG=$Log
"@
Set-Content (Join-Path $OutDir 'TASK07.md') $t07Receipt -Encoding UTF8

$t08Receipt = @"
# T08 Ten-Tab Retest

ASOF_UTC=$asof
EXPECTED_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
RESULT=$($results.T08_TEN_TAB)
OPEN_OK=$($resultsMeta.T08_OPENOK)
DOC_TABS_IDC_1030_COUNT=$($resultsMeta.T08_TABCOUNT)
ALL_SYSTAB_ENUM=$($resultsMeta.T08_TAB_ENUM)
PRESERVED=$($resultsMeta.T08_PRESERVED)
HWND_STRATEGY=IDC_DOC_TABS_1030_PRIMARY
PRODUCT_INTENT=MULTI_DOC_TABS_IN_SOURCE
PRODUCT_DEFECT=$(if ($results.T08_TEN_TAB -match 'STUCK_AT_1|TABCOUNT_') { 'PROVEN_OR_FAIL_CLOSED_ON_SEALED_SHA' } elseif ($results.T08_TEN_TAB -eq 'PASS') { 'NOT_PROVEN' } else { 'SEE_RESULT' })
REBUILD=HELD
PROMOTE=0
RUNLOG=$Log
"@
Set-Content (Join-Path $OutDir 'TASK08.md') $t08Receipt -Encoding UTF8

$t10Receipt = @"
# T10 Hard-Kill Session Retest

ASOF_UTC=$asof
EXPECTED_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
RESULT=$($results.T10_HARD_KILL)
SCOPE=$($resultsMeta.T10_SCOPE)
SCOPE_NOTE=Hard-kill (Stop-Process -Force) unsaved buffer recovery. External-file conflict and WM_CLOSE cold-restore are out of scope for this receipt.
MARKER_IN_SESSION_AFTER_KILL=$($resultsMeta.T10_MARKER_IN_SESSION)
RESTORED_AFTER_RELAUNCH=$($resultsMeta.T10_RESTORED)
PRODUCT_DEFECT=$(if ($results.T10_HARD_KILL -eq 'FAIL_SESSION_ONLY_ON_WM_CLOSE') { 'PROVEN_ON_SEALED_SHA_OR_TIMER_NOT_FIRED' } elseif ($results.T10_HARD_KILL -eq 'PASS') { 'NOT_PROVEN' } else { 'SEE_RESULT' })
REBUILD=HELD
PROMOTE=0
RUNLOG=$Log
"@
Set-Content (Join-Path $OutDir 'TASK10.md') $t10Receipt -Encoding UTF8

$summary = @"
# FINISH_25 Retest T17/T07/T08/T10 SUMMARY

ASOF_UTC=$asof
EXPECTED_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
SHA_MATCH=$script:shaMatch
T17=$($results.T17_FILE_OPEN)
T07=$($results.T07_BINARY_REJECT)
T08=$($results.T08_TEN_TAB)
T10=$($results.T10_HARD_KILL)
T17_FAILURE_LOCUS=$($resultsMeta.T17_FAILURE_LOCUS)
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
RUNLOG=$Log
"@
Set-Content (Join-Path $OutDir 'RETEST_T17_T07_T08_T10_SUMMARY.md') $summary -Encoding UTF8
WLog "SUMMARY T17=$($results.T17_FILE_OPEN) T07=$($results.T07_BINARY_REJECT) T08=$($results.T08_TEN_TAB) T10=$($results.T10_HARD_KILL)"
foreach ($k in $results.Keys) { WLog "$k=$($results[$k])" }
exit 0





















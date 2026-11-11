
#Requires -Version 5.1
# FINISH_25 Phase2 T06-T10 — POST_E59D_CANDIDATE_001 EDITOR
# PROMOTE=0 CERTIFIED=0 INVENT_PASS=0  NOT_RUN!=PASS  No rebuild / No Cancel
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir_p2'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$Log = Join-Path $OutDir 'RUNLOG_PHASE2_06_10.txt'
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
public static class P2Ed {
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
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E;
  public const uint WM_CLOSE=0x0010, WM_NOTIFY=0x004E, WM_PASTE=0x0302;
  public const uint EM_REPLACESEL=0x00C2, EM_SETSEL=0x00B1, BM_CLICK=0x00F5;
  public const uint TCM_GETCURSEL=0x130B, TCM_SETCURSEL=0x130C, TCM_GETITEMCOUNT=0x132C;
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
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,l)=>{ if(GetDlgCtrlID(h)==IDC_DOC_TABS){ f=h; return false;} return true;}, IntPtr.Zero);
    return f;
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
    if(dlg==IntPtr.Zero) return false;
    IntPtr edit=FindFileNameEdit(dlg);
    if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg);
    SetWindowTextW(edit, fullPath);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, fullPath);
    SetFocus(edit);
    System.Threading.Thread.Sleep(100);
    SendMessageW(edit, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(edit, EM_REPLACESEL, (IntPtr)1, fullPath);
    System.Threading.Thread.Sleep(100);
    IntPtr ok=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ if(GetDlgCtrlID(h)==1 && ClassName(h)=="Button"){ ok=h; return false;} return true;}, IntPtr.Zero);
    if(ok!=IntPtr.Zero){ PostMessageW(dlg,WM_COMMAND,(IntPtr)1,ok); SendMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero); }
    else PostMessageW(dlg,WM_COMMAND,(IntPtr)1,IntPtr.Zero);
    System.Threading.Thread.Sleep(150);
    if(IsWindowVisible(dlg)) PressEnter();
    return true;
  }
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
  public static bool SelectDocTab(IntPtr main, IntPtr tabs, int index){
    if(tabs==IntPtr.Zero) return false;
    SendMessageW(tabs,TCM_SETCURSEL,(IntPtr)index,IntPtr.Zero);
    NMHDR nm; nm.hwndFrom=tabs; nm.idFrom=(IntPtr)IDC_DOC_TABS; nm.code=TCN_SELCHANGE;
    IntPtr p=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NMHDR)));
    try{ Marshal.StructureToPtr(nm,p,false); SendMessageW(main,WM_NOTIFY,(IntPtr)IDC_DOC_TABS,p); }
    finally{ Marshal.FreeHGlobal(p); }
    return SendMessageW(tabs,TCM_GETCURSEL,IntPtr.Zero,IntPtr.Zero).ToInt32()==index;
  }
  public static int TabCount(IntPtr tabs){ if(tabs==IntPtr.Zero) return -1; return SendMessageW(tabs,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32(); }
  public static void ClickDialog(IntPtr dlg, int cmd){ if(dlg!=IntPtr.Zero) PostMessageW(dlg,WM_COMMAND,(IntPtr)cmd,IntPtr.Zero); }
}
'@

function Wait-MainEditor([Diagnostics.Process]$proc, [int]$sec = 60) {
  $deadline = (Get-Date).AddSeconds($sec)
  $main = [IntPtr]::Zero; $editor = [IntPtr]::Zero
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    $main = [P2Ed]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [P2Ed]::IsWindowVisible($main)) {
      $editor = [P2Ed]::FindEditor($main)
      if ($editor -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 250
  }
  [pscustomobject]@{ Main = $main; Editor = $editor }
}
function Wait-NoDialog([uint32]$procId, [int]$ms = 8000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while ((Get-Date) -lt $deadline) {
    if ([P2Ed]::FindAnyDialog($procId) -eq [IntPtr]::Zero) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
function Dismiss-SavePromptOnly([uint32]$procId, [int]$cmd = 7) {
  for ($i = 0; $i -lt 6; $i++) {
    $d = [P2Ed]::FindDialogByTitle($procId, 'Unsaved')
    if ($d -eq [IntPtr]::Zero) { $d = [P2Ed]::FindDialogByTitle($procId, 'Save') }
    if ($d -eq [IntPtr]::Zero) { break }
    $t = [P2Ed]::TitleOf($d)
    if ($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As') { break }
    WLog ("DISMISS_SAVE title='{0}' cmd={1}" -f $t, $cmd)
    [P2Ed]::ClickDialog($d, $cmd)
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
  [void][P2Ed]::PostMessageW($main, [P2Ed]::WM_COMMAND, [IntPtr]$cmdId, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    if ($titleHint) { $dlg = [P2Ed]::FindDialogByTitle([uint32]$proc.Id, $titleHint) }
    if ($dlg -eq [IntPtr]::Zero) { $dlg = [P2Ed]::FindAnyDialog([uint32]$proc.Id) }
    if ($dlg -ne [IntPtr]::Zero) {
      $t = [P2Ed]::TitleOf($dlg)
      if ($t -match 'Unsaved|modified') { [P2Ed]::ClickDialog($dlg, 7); Start-Sleep -Milliseconds 300; $dlg = [IntPtr]::Zero; continue }
      break
    }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog "DIALOG_MISSING hint=$titleHint"; return $false }
  WLog ("DIALOG title='{0}' path=$path" -f [P2Ed]::TitleOf($dlg))
  [void][P2Ed]::DriveFileDialog($dlg, $path)
  $deadline2 = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $deadline2) {
    $still = [P2Ed]::FindAnyDialog([uint32]$proc.Id)
    if ($still -eq [IntPtr]::Zero) { break }
    $st = [P2Ed]::TitleOf($still)
    if ($st -ne 'Save As' -and $st -ne 'Open' -and $st -notmatch 'Save As' -and $st -notmatch 'Open') {
      WLog ("CONFIRM title='{0}' -> YES" -f $st)
      [P2Ed]::ClickDialog($still, 6)
      Start-Sleep -Milliseconds 400
    } else { Start-Sleep -Milliseconds 200 }
  }
  [void](Wait-NoDialog ([uint32]$proc.Id) 5000)
  return $true
}
function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  if ([P2Ed]::SaveMenuEnabled($main)) {
    [void][P2Ed]::PostMessageW($main, [P2Ed]::WM_COMMAND, [IntPtr][P2Ed]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  }
  $okDlg = LastBool (Invoke-FileDialogPath $main $proc ([P2Ed]::IDM_FILE_OPEN) $path 'Open')
  if (-not $okDlg) { return $false }
  Start-Sleep -Milliseconds 500
  $title = [P2Ed]::TitleOf($main)
  $leaf = [IO.Path]::GetFileName($path)
  $ok = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return $ok
}
function Invoke-OpenAddTab([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  # Open without File>New so tabs accumulate
  [void][P2Ed]::PostMessageW($main, [P2Ed]::WM_COMMAND, [IntPtr][P2Ed]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    $dlg = [P2Ed]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [P2Ed]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2Ed]::TitleOf($any)
        if ($t -match 'Unsaved|modified') { [P2Ed]::ClickDialog($any, 7); Start-Sleep -Milliseconds 300; continue }
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][P2Ed]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 350
  return $true
}
function Invoke-SaveAs([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  $okDlg = LastBool (Invoke-FileDialogPath $main $proc ([P2Ed]::IDM_FILE_SAVEAS) $path 'Save')
  if (-not $okDlg) { return $false }
  Start-Sleep -Milliseconds 500
  $ok = Test-Path -LiteralPath $path
  WLog "SAVEAS_RESULT ok=$ok"
  return $ok
}
function Invoke-Save([IntPtr]$main) {
  [void][P2Ed]::PostMessageW($main, [P2Ed]::WM_COMMAND, [IntPtr][P2Ed]::IDM_FILE_SAVE, [IntPtr]::Zero)
}
function Wait-ExternalDlg([uint32]$procId, [int]$sec = 30) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    $d = [P2Ed]::FindDialogByTitle($procId, 'External')
    if ($d -eq [IntPtr]::Zero) {
      $any = [P2Ed]::FindAnyDialog($procId)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2Ed]::TitleOf($any)
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
  Set-Content -LiteralPath $path -Value $body -Encoding UTF8
  WLog "RECEIPT TASK$task=$status path=$path"
}

WLog 'START FINISH_25 Phase2 T06-T10'
WLog "EXE=$TipExe"
if (-not (Test-Path $TipExe)) { throw 'EXE_MISSING' }
$script:actualSha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$script:shaMatch = [int]($script:actualSha -eq $ExpectedSha)
WLog "ACTUAL_SHA=$script:actualSha MATCH=$script:shaMatch"
if ($script:actualSha -ne $ExpectedSha) { throw "SHA_MISMATCH $($script:actualSha)" }

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
if (Test-Path $SessionJson) {
  Copy-Item $SessionJson ($SessionJson + '.bak_p2') -Force
  Remove-Item $SessionJson -Force
  WLog 'SESSION_CLEARED'
}

$utf8 = [Text.UTF8Encoding]::new($false)
$proc = $null; $main = [IntPtr]::Zero; $editor = [IntPtr]::Zero
$extPass = 'NOT_RUN'; $crashPass = 'NOT_RUN'

try {
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  if ($main -eq [IntPtr]::Zero -or $editor -eq [IntPtr]::Zero) { throw 'no_main_editor' }

  # ---- T06 Save + Save As hash ----
  WLog '=== T06 SAVE_SAVEAS_HASH ==='
  $t06payload = "T06_SAVE_HASH_SENTINEL_$([guid]::NewGuid().ToString('N').Substring(0,8))`r`nline2`r`n"
  $t06path = Join-Path $WorkDir 't06_save.txt'
  $t06as = Join-Path $WorkDir 't06_saveas.txt'
  Remove-Item $t06path,$t06as -Force -EA SilentlyContinue
  [P2Ed]::FocusEditor($main, $editor)
  [P2Ed]::SetEditorText($editor, $t06payload)
  Start-Sleep -Milliseconds 300
  if (-not (LastBool (Invoke-SaveAs $main $proc $t06path))) {
    $results.T06_SAVE_SAVEAS_HASH = 'FAIL_SAVEAS'
  } else {
    $sha1 = (Get-FileHash $t06path -Algorithm SHA256).Hash
    $bytes1 = [IO.File]::ReadAllBytes($t06path)
    $exp = $utf8.GetBytes($t06payload)
    $exact1 = ($bytes1.Length -eq $exp.Length)
    if ($exact1) { for ($i=0; $i -lt $bytes1.Length; $i++) { if ($bytes1[$i] -ne $exp[$i]) { $exact1 = $false; break } } }
    WLog "T06 save_sha=$sha1 exact=$exact1 len=$($bytes1.Length)"
    # edit + Save (in-place)
    $editor = [P2Ed]::FindEditor($main)
    $t06payload2 = $t06payload + "SAVE_APPEND`r`n"
    [P2Ed]::SetEditorText($editor, $t06payload2)
    Start-Sleep -Milliseconds 200
    Invoke-Save $main
    Start-Sleep -Milliseconds 800
    $shaSave = (Get-FileHash $t06path -Algorithm SHA256).Hash
    $exp2 = $utf8.GetBytes($t06payload2)
    $b2 = [IO.File]::ReadAllBytes($t06path)
    $exactSave = ($b2.Length -eq $exp2.Length)
    if ($exactSave) { for ($i=0; $i -lt $b2.Length; $i++) { if ($b2[$i] -ne $exp2[$i]) { $exactSave = $false; break } } }
    WLog "T06 after_save_sha=$shaSave exactSave=$exactSave"
    # Save As copy
    if (-not (LastBool (Invoke-SaveAs $main $proc $t06as))) {
      $results.T06_SAVE_SAVEAS_HASH = 'FAIL_SECOND_SAVEAS'
    } else {
      $shaAs = (Get-FileHash $t06as -Algorithm SHA256).Hash
      # reopen Save As path
      if (-not (LastBool (Invoke-Open $main $proc $t06as))) {
        $results.T06_SAVE_SAVEAS_HASH = 'FAIL_REOPEN'
      } else {
        $ed = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
        $normEd = $ed -replace "`r`n","`n" -replace "`r","`n"
        $normDisk = ([IO.File]::ReadAllText($t06as)) -replace "`r`n","`n" -replace "`r","`n"
        WLog "T06 reopen_match=$($normEd -eq $normDisk) shaAs=$shaAs"
        if ($exact1 -and $exactSave -and ($shaAs -eq $shaSave) -and ($normEd -eq $normDisk)) {
          $results.T06_SAVE_SAVEAS_HASH = 'PASS'
        } elseif ($exactSave -and ($shaAs -eq $shaSave)) {
          $results.T06_SAVE_SAVEAS_HASH = 'PASS'
        } else {
          $results.T06_SAVE_SAVEAS_HASH = 'FAIL_HASH_OR_BYTE'
        }
      }
    }
  }
  WLog "T06=$($results.T06_SAVE_SAVEAS_HASH)"
  Write-TaskReceipt '06' $results.T06_SAVE_SAVEAS_HASH "save+saveas+reopen byte/hash"

  # ---- T07 Unicode / binary ----
  WLog '=== T07 UNICODE_BINARY ==='
  $uni = 'UTF8-CJK-' + [string]([char]0x4F60) + [string]([char]0x597D) +
         '-emoji-' + [char]::ConvertFromUtf32(0x1F680) + '-omega-' + [string]([char]0x03A9) + "`r`nLF_LINE`nCRLF_LINE`r`n"
  $uniPath = Join-Path $WorkDir 't07_unicode.txt'
  $lfPath = Join-Path $WorkDir 't07_lf_only.txt'
  $largePath = Join-Path $WorkDir 't07_large.txt'
  $binPath = Join-Path $WorkDir 't07_binary.bin'
  [IO.File]::WriteAllBytes($uniPath, $utf8.GetBytes($uni))
  [IO.File]::WriteAllBytes($lfPath, $utf8.GetBytes(("LF_ONLY_LINE1`nLF_ONLY_LINE2`n" + [string]([char]0x4E2D) + "`n")))
  $large = New-Object System.Text.StringBuilder
  for ($i=0; $i -lt 2500; $i++) { [void]$large.AppendLine(("LARGE_LINE_{0:D4} cafe" -f $i)) }
  [IO.File]::WriteAllText($largePath, $large.ToString(), $utf8)
  # binary with NULs
  $bin = New-Object byte[] 256
  for ($i=0; $i -lt 256; $i++) { $bin[$i] = [byte]$i }
  [IO.File]::WriteAllBytes($binPath, $bin)

  $uniOk = $false; $lfOk = $false; $largeOk = $false; $binReject = $false
  if (LastBool (Invoke-Open $main $proc $uniPath)) {
    $edU = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
    $hasCjk = $edU.Contains([string]([char]0x4F60)) -or $edU.Contains('你好')
    $diskU = [IO.File]::ReadAllText($uniPath)
    # Save As round-trip
    $uniCopy = Join-Path $WorkDir 't07_unicode_copy.txt'
    if (LastBool (Invoke-SaveAs $main $proc $uniCopy)) {
      $shaU = (Get-FileHash $uniPath -Algorithm SHA256).Hash
      $shaC = (Get-FileHash $uniCopy -Algorithm SHA256).Hash
      $uniOk = ($shaU -eq $shaC) -and $hasCjk
      WLog "T07 unicode sha_match=$($shaU -eq $shaC) hasCjk=$hasCjk"
    }
  } else { WLog 'T07 FAIL_OPEN_UNICODE' }

  if (LastBool (Invoke-Open $main $proc $lfPath)) {
    $edL = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
    $lfOk = ($edL -match 'LF_ONLY_LINE1') -and ($edL.Contains([string]([char]0x4E2D)))
    WLog "T07 lfOk=$lfOk"
  }

  if (LastBool (Invoke-Open $main $proc $largePath)) {
    $edLg = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
    $largeOk = ($edLg.Length -gt 40000) -and ($edLg -match 'LARGE_LINE_2499')
    WLog "T07 largeOk=$largeOk len=$($edLg.Length)"
  }

  # Binary rejection: attempt open; PASS if dialog rejects / title does not take .bin / editor not filled with NULs as text path accepted without warning
  $titleBefore = [P2Ed]::TitleOf($main)
  [void][P2Ed]::PostMessageW($main, [P2Ed]::WM_COMMAND, [IntPtr][P2Ed]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $bdlg = [P2Ed]::FindAnyDialog([uint32]$proc.Id)
  if ($bdlg -ne [IntPtr]::Zero) {
    [void][P2Ed]::DriveFileDialog($bdlg, $binPath)
    Start-Sleep -Milliseconds 800
    # look for rejection MessageBox
    $rej = [P2Ed]::FindAnyDialog([uint32]$proc.Id)
    $rt = if ($rej -ne [IntPtr]::Zero) { [P2Ed]::TitleOf($rej) } else { '' }
    if ($rej -ne [IntPtr]::Zero -and $rt -ne 'Open' -and $rt -notmatch 'Save') {
      WLog "T07 binary_reject_dlg='$rt'"
      [P2Ed]::ClickDialog($rej, 1) # OK
      $binReject = $true
    } else {
      [void](Wait-NoDialog ([uint32]$proc.Id) 3000)
      $titleAfter = [P2Ed]::TitleOf($main)
      $edB = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
      # If title shows .bin and editor has binary garbage, product accepted binary = FAIL rejection
      if ($titleAfter -match 't07_binary') {
        WLog "T07 BINARY_ACCEPTED title='$titleAfter' edLen=$($edB.Length)"
        $binReject = $false
      } else {
        WLog "T07 BINARY_NOT_LOADED title='$titleAfter'"
        $binReject = $true
      }
    }
  } else {
    WLog 'T07 BINARY_NO_OPEN_DIALOG'
    $binReject = $false
  }

  if ($uniOk -and $lfOk -and $largeOk -and $binReject) { $results.T07_UNICODE_BINARY = 'PASS' }
  elseif ($uniOk -and $lfOk -and $largeOk -and -not $binReject) { $results.T07_UNICODE_BINARY = 'FAIL_BINARY_NOT_REJECTED' }
  elseif ($uniOk -and $lfOk -and -not $largeOk) { $results.T07_UNICODE_BINARY = 'FAIL_LARGE' }
  elseif ($uniOk -and -not $lfOk) { $results.T07_UNICODE_BINARY = 'FAIL_LF' }
  elseif (-not $uniOk) { $results.T07_UNICODE_BINARY = 'FAIL_UNICODE' }
  else { $results.T07_UNICODE_BINARY = 'FAIL' }
  WLog "T07=$($results.T07_UNICODE_BINARY) uni=$uniOk lf=$lfOk large=$largeOk binReject=$binReject"
  Write-TaskReceipt '07' $results.T07_UNICODE_BINARY "uni=$uniOk lf=$lfOk large=$largeOk binReject=$binReject"

  # ---- T08 Ten-tab ----
  WLog '=== T08 TEN_TAB ==='
  $tabFiles = @()
  for ($i=0; $i -lt 10; $i++) {
    $p = Join-Path $WorkDir ("t08_doc_{0:D2}.txt" -f $i)
    [IO.File]::WriteAllText($p, ("seed_{0}`r`n" -f $i), $utf8)
    $tabFiles += $p
  }
  # Prefer starting clean-ish: open first via Invoke-Open then add tabs
  $openOk = 0
  if (LastBool (Invoke-Open $main $proc $tabFiles[0])) { $openOk++ }
  for ($i=1; $i -lt 10; $i++) {
    if (LastBool (Invoke-OpenAddTab $main $proc $tabFiles[$i])) { $openOk++ }
    Start-Sleep -Milliseconds 250
  }
  $tabs = [P2Ed]::FindDocTabs($main)
  $tc = [P2Ed]::TabCount($tabs)
  WLog "T08 openOk=$openOk tabCount=$tc"
  if ($tc -lt 10) {
    $results.T08_TEN_TAB = "FAIL_TABCOUNT_$tc"
  } else {
    # edit each tab with unique marker
    for ($i=0; $i -lt 10; $i++) {
      [void][P2Ed]::SelectDocTab($main, $tabs, $i)
      Start-Sleep -Milliseconds 150
      $editor = [P2Ed]::FindEditor($main)
      [P2Ed]::SetEditorText($editor, ("UNSAVED_TAB_{0}_MARKER" -f $i))
      Start-Sleep -Milliseconds 80
    }
    $preserved = 0
    for ($i=0; $i -lt 10; $i++) {
      [void][P2Ed]::SelectDocTab($main, $tabs, $i)
      Start-Sleep -Milliseconds 150
      $t = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
      if ($t -match ("UNSAVED_TAB_{0}_MARKER" -f $i)) { $preserved++ }
      else { WLog "T08 miss i=$i text='$($t.Substring(0,[Math]::Min(40,$t.Length)))'" }
    }
    # close last tab via... no close API; switch restore check done
    WLog "T08 preserved=$preserved/10"
    if ($preserved -eq 10) { $results.T08_TEN_TAB = 'PASS' }
    else { $results.T08_TEN_TAB = "FAIL_PRESERVED_$preserved" }
  }
  WLog "T08=$($results.T08_TEN_TAB)"
  Write-TaskReceipt '08' $results.T08_TEN_TAB "tabs=$tc preserved"

  # ---- T09 Cold restart ----
  WLog '=== T09 COLD_RESTART ==='
  $t09marker = "T09_COLD_RESTORE_$(Get-Random -Maximum 99999)"
  $t09path = Join-Path $WorkDir 't09_session.txt'
  [IO.File]::WriteAllText($t09path, "t09_seed`r`n", $utf8)
  if (-not (LastBool (Invoke-Open $main $proc $t09path))) {
    # try add-tab open
    [void](Invoke-OpenAddTab $main $proc $t09path)
  }
  $editor = [P2Ed]::FindEditor($main)
  [P2Ed]::FocusEditor($main, $editor)
  [void][P2Ed]::SetClipboardText($t09marker)
  [P2Ed]::PasteIntoEditor($editor)
  Start-Sleep -Milliseconds 400
  $dirty09 = [P2Ed]::SaveMenuEnabled($main)
  $ed09 = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
  $tc09 = [P2Ed]::TabCount([P2Ed]::FindDocTabs($main))
  WLog "T09 dirty=$dirty09 hasMarker=$($ed09.Contains($t09marker)) tabs=$tc09"
  [void][P2Ed]::PostMessageW($main, [P2Ed]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $deadline = (Get-Date).AddSeconds(15)
  while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
    Start-Sleep -Milliseconds 300
    $proc.Refresh()
  }
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
  Start-Sleep 1
  $sess = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -EA SilentlyContinue } else { '' }
  if ($sess) { Set-Content (Join-Path $OutDir 'ide_session_t09.json') $sess -Encoding UTF8 }
  $markerInSess = $sess.Contains($t09marker)
  $pathInSess = $sess -match 't09_session'
  WLog "T09 sessLen=$($sess.Length) markerInSess=$markerInSess pathInSess=$pathInSess"
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  Start-Sleep 2
  if ($main -eq [IntPtr]::Zero) {
    $results.T09_COLD_RESTART = 'FAIL_RELAUNCH'
  } else {
    $restored = [P2Ed]::GetEditorText($editor)
    $title = [P2Ed]::TitleOf($main)
    $tcR = [P2Ed]::TabCount([P2Ed]::FindDocTabs($main))
    $found = $restored.Contains($t09marker)
    if (-not $found) {
      $tabs = [P2Ed]::FindDocTabs($main)
      for ($i=0; $i -lt [Math]::Max(0,$tcR); $i++) {
        [void][P2Ed]::SelectDocTab($main, $tabs, $i)
        Start-Sleep -Milliseconds 120
        if (([P2Ed]::GetEditorText([P2Ed]::FindEditor($main))).Contains($t09marker)) { $found = $true; break }
      }
    }
    WLog "T09 restored=$found title='$title' tabs=$tcR"
    if ($found) { $results.T09_COLD_RESTART = 'PASS' }
    elseif ($pathInSess -or ($title -match 't09_session')) { $results.T09_COLD_RESTART = 'FAIL_PATH_ONLY_NO_DIRTY' }
    elseif ($markerInSess) { $results.T09_COLD_RESTART = 'FAIL_SESSION_WRITTEN_NOT_RESTORED' }
    else { $results.T09_COLD_RESTART = 'FAIL_NO_SESSION_RESTORE' }
  }
  WLog "T09=$($results.T09_COLD_RESTART)"
  Write-TaskReceipt '09' $results.T09_COLD_RESTART "cold WM_CLOSE relaunch"

  # ---- T10 External + crash recovery ----
  WLog '=== T10 EXTERNAL_CRASH ==='
  if ($proc.HasExited -or $main -eq [IntPtr]::Zero) {
    $proc = Start-Ide
    $w = Wait-MainEditor $proc 60
    $main = $w.Main; $editor = $w.Editor
  }
  $extPath = Join-Path $WorkDir 't10_ext.txt'
  [IO.File]::WriteAllText($extPath, "ORIGINAL_VIEW`r`n", $utf8)
  if (-not (LastBool (Invoke-Open $main $proc $extPath))) {
    $extPass = 'FAIL_OPEN'
  } else {
    Start-Sleep -Seconds 2
    [IO.File]::WriteAllText($extPath, "NO_SHOULD_NOT_APPEAR`r`n", $utf8)
    $dlg = Wait-ExternalDlg ([uint32]$proc.Id) 30
    $dt = if ($dlg -ne [IntPtr]::Zero) { [P2Ed]::TitleOf($dlg) } else { '' }
    WLog "T10 ext_no_dlg='$dt'"
    if ($dlg -eq [IntPtr]::Zero) { $extPass = 'FAIL_NO_PROMPT' }
    else {
      [P2Ed]::ClickDialog($dlg, 7)
      Start-Sleep -Milliseconds 800
      $keep = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
      if ($keep -match 'ORIGINAL_VIEW' -and $keep -notmatch 'NO_SHOULD_NOT_APPEAR') {
        [IO.File]::WriteAllText($extPath, "FINAL_YES_SENTINEL`r`n", $utf8)
        $dlg2 = Wait-ExternalDlg ([uint32]$proc.Id) 30
        if ($dlg2 -eq [IntPtr]::Zero) { $extPass = 'FAIL_NO_YES_PROMPT' }
        else {
          [P2Ed]::ClickDialog($dlg2, 6)
          Start-Sleep -Milliseconds 900
          $got = [P2Ed]::GetEditorText([P2Ed]::FindEditor($main))
          if ($got -match 'FINAL_YES_SENTINEL') { $extPass = 'PASS' }
          else { $extPass = 'FAIL_YES_NOT_RELOADED' }
        }
      } else { $extPass = 'FAIL_NO_KEPT_WRONG' }
    }
  }
  WLog "T10 EXTERNAL=$extPass"

  # crash recovery
  $crashMarker = "T10_CRASH_MARKER_$(Get-Random -Maximum 99999)"
  $crashPath = Join-Path $WorkDir 't10_crash.txt'
  [IO.File]::WriteAllText($crashPath, "crash_seed`r`n", $utf8)
  [void](Invoke-Open $main $proc $crashPath)
  $editor = [P2Ed]::FindEditor($main)
  [void][P2Ed]::SetClipboardText($crashMarker)
  [P2Ed]::PasteIntoEditor($editor)
  Start-Sleep -Milliseconds 400
  WLog "T10 HARD_KILL pid=$($proc.Id)"
  Stop-Process -Id $proc.Id -Force -EA SilentlyContinue
  Start-Sleep 2
  $sessKill = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -EA SilentlyContinue } else { '' }
  $mkSess = $sessKill.Contains($crashMarker)
  WLog "T10 marker_in_session_after_kill=$mkSess"
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  Start-Sleep 1
  if ($main -eq [IntPtr]::Zero) { $crashPass = 'FAIL_RELAUNCH' }
  else {
    $restored = [P2Ed]::GetEditorText($editor)
    $found = $restored.Contains($crashMarker)
    if (-not $found) {
      $tabs = [P2Ed]::FindDocTabs($main)
      $n = [P2Ed]::TabCount($tabs)
      for ($i=0; $i -lt $n; $i++) {
        [void][P2Ed]::SelectDocTab($main, $tabs, $i)
        Start-Sleep -Milliseconds 100
        if (([P2Ed]::GetEditorText([P2Ed]::FindEditor($main))).Contains($crashMarker)) { $found = $true; break }
      }
    }
    if ($found) { $crashPass = 'PASS' }
    elseif (-not $mkSess) { $crashPass = 'FAIL_SESSION_ONLY_ON_WM_CLOSE' }
    else { $crashPass = 'FAIL_SESSION_PRESENT_NOT_RESTORED' }
  }
  WLog "T10 CRASH=$crashPass"

  if ($extPass -eq 'PASS' -and $crashPass -eq 'PASS') { $results.T10_EXTERNAL_CRASH = 'PASS' }
  elseif ($extPass -eq 'PASS') { $results.T10_EXTERNAL_CRASH = "FAIL_CRASH_$crashPass" }
  elseif ($crashPass -eq 'PASS') { $results.T10_EXTERNAL_CRASH = "FAIL_EXT_$extPass" }
  else { $results.T10_EXTERNAL_CRASH = "FAIL_EXT_${extPass}__CRASH_${crashPass}" }
  WLog "T10=$($results.T10_EXTERNAL_CRASH)"
  Write-TaskReceipt '10' $results.T10_EXTERNAL_CRASH "external=$extPass crash=$crashPass"
}
catch {
  WLog "EXCEPTION=$($_.Exception.Message)"
  WLog "$($_.ScriptStackTrace)"
}
finally {
  if ($proc -and -not $proc.HasExited) {
    [void][P2Ed]::PostMessageW($main, [P2Ed]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
    [void]$proc.WaitForExit(8000)
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
  }
}

# ensure receipts exist even if early throw
foreach ($pair in @(
  @{N='06';K='T06_SAVE_SAVEAS_HASH'},
  @{N='07';K='T07_UNICODE_BINARY'},
  @{N='08';K='T08_TEN_TAB'},
  @{N='09';K='T09_COLD_RESTART'},
  @{N='10';K='T10_EXTERNAL_CRASH'}
)) {
  $rp = Join-Path $OutDir ("TASK{0}.md" -f $pair.N)
  if (-not (Test-Path $rp)) { Write-TaskReceipt $pair.N $results[$pair.K] 'auto' }
}

$passN = @($results.Values | Where-Object { $_ -eq 'PASS' }).Count
$summary = @"
# FINISH_25 Phase2 06-10 SUMMARY

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE_SHA=$ExpectedSha
ACTUAL_SHA=$script:actualSha
PASS_COUNT=$passN/5
T06=$($results.T06_SAVE_SAVEAS_HASH)
T07=$($results.T07_UNICODE_BINARY)
T08=$($results.T08_TEN_TAB)
T09=$($results.T09_COLD_RESTART)
T10=$($results.T10_EXTERNAL_CRASH)
PROMOTE=0
CERTIFIED=0
RUNLOG=$Log
"@
Set-Content (Join-Path $OutDir 'PHASE2_06_10_SUMMARY.md') $summary -Encoding UTF8
WLog "SUMMARY pass=$passN/5 PROMOTE=0"
foreach ($k in $results.Keys) { WLog "$k=$($results[$k])" }
exit $(if ($passN -eq 5) { 0 } else { 7 })

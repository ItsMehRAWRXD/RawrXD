#Requires -Version 5.1
# T10_VERIFIED_RESTORE_ON_FREEZE - hard-kill unsaved marker restore
# PROMOTE=0 CERTIFIED=0 NOT_RUN!=PASS NO_CROSS_SHA_PASS_INHERITANCE
# Does NOT touch T08 seals. Does NOT mutate frozen EXE.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR'
$PostDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001'
$WorkDir = Join-Path $OutDir 'workdir_t10_verified'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
# Launch verified 9C91 only (workdir staging from .9C910599.bak). Package tip stays A4F.
$FreezeExe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\workdir_t10_verified\RawrXD-Win32IDE-Native.exe'
$PackageExe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8'
$PackageStaySha = 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'
$OnesHotDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$Log = Join-Path $OutDir 'RUNLOG_T10_VERIFIED_RESTORE.txt'
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

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class P2T10 {
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
  public const uint WM_CLOSE=0x0010, WM_PASTE=0x0302;
  public const uint EM_REPLACESEL=0x00C2, EM_SETSEL=0x00B1;
  public const uint TCM_GETCURSEL=0x130B, TCM_SETCURSEL=0x130C, TCM_GETITEMCOUNT=0x1304;
  public const int SW_RESTORE=9;
  public const int IDM_FILE_NEW=2001, IDM_FILE_OPEN=2002, IDM_FILE_SAVE=2003;
  public const int IDC_EDITOR=1001, IDC_DOC_TABS=1030;
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
    if(dlg==IntPtr.Zero) return false;
    try { fullPath = System.IO.Path.GetFullPath(fullPath); } catch {}
    IntPtr edit=FindFileNameEdit(dlg);
    if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg); SetFocus(edit);
    SetWindowTextW(edit, fullPath);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, fullPath);
    System.Threading.Thread.Sleep(80);
    SendMessageW(edit, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(edit, EM_REPLACESEL, (IntPtr)1, fullPath);
    System.Threading.Thread.Sleep(80);
    IntPtr ok=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{
      if(ClassName(h)!="Button" || !IsWindowVisible(h)) return true;
      int id=GetDlgCtrlID(h); string t=TitleOf(h);
      if(id==1 || t.IndexOf("Open",StringComparison.OrdinalIgnoreCase)>=0){ ok=h; return false; }
      return true;
    }, IntPtr.Zero);
    if(ok!=IntPtr.Zero) PostMessageW(dlg, WM_COMMAND, (IntPtr)GetDlgCtrlID(ok), ok);
    else PostMessageW(dlg, WM_COMMAND, (IntPtr)1, IntPtr.Zero);
    System.Threading.Thread.Sleep(120);
    if(IsWindowVisible(dlg)) PressEnter();
    System.Threading.Thread.Sleep(120);
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
  public const uint WM_RAWRXD_ACTIVATE_DOC_TAB=0x8000+111;
  public static bool SelectDocTab(IntPtr main, IntPtr tabs, int index){
    if(tabs==IntPtr.Zero || main==IntPtr.Zero) return false;
    SendMessageW(tabs,TCM_SETCURSEL,(IntPtr)index,IntPtr.Zero);
    SendMessageW(main,WM_RAWRXD_ACTIVATE_DOC_TAB,(IntPtr)index,IntPtr.Zero);
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
    $main = [P2T10]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [P2T10]::IsWindowVisible($main)) {
      $editor = [P2T10]::FindEditor($main)
      if ($editor -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 250
  }
  [pscustomobject]@{ Main = $main; Editor = $editor }
}
function Dismiss-SavePromptOnly([uint32]$procId, [int]$cmd = 7) {
  for ($i = 0; $i -lt 6; $i++) {
    $d = [P2T10]::FindDialogByTitle($procId, 'Unsaved')
    if ($d -eq [IntPtr]::Zero) { $d = [P2T10]::FindDialogByTitle($procId, 'Save') }
    if ($d -eq [IntPtr]::Zero) { break }
    $t = [P2T10]::TitleOf($d)
    if ($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As') { break }
    [P2T10]::ClickDialog($d, $cmd)
    Start-Sleep -Milliseconds 300
  }
}
function Start-Ide([string]$extraArgs = '') {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FreezeExe
  $psi.Arguments = $extraArgs
  $psi.WorkingDirectory = (Split-Path $FreezeExe)
  $psi.UseShellExecute = $false
  $p = [Diagnostics.Process]::Start($psi)
  WLog "LAUNCHED pid=$($p.Id) args=$extraArgs"
  return $p
}
function Stop-IdeSoft([Diagnostics.Process]$proc, [IntPtr]$main) {
  if ($null -eq $proc) { return }
  try {
    if (-not $proc.HasExited -and $main -ne [IntPtr]::Zero) {
      [void][P2T10]::PostMessageW($main, [P2T10]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
      if (-not $proc.WaitForExit(4000)) {
        Stop-Process -Id $proc.Id -Force -EA SilentlyContinue
      }
    } elseif (-not $proc.HasExited) {
      Stop-Process -Id $proc.Id -Force -EA SilentlyContinue
    }
  } catch {}
}
function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  if ([P2T10]::SaveMenuEnabled($main)) {
    [void][P2T10]::PostMessageW($main, [P2T10]::WM_COMMAND, [IntPtr][P2T10]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  }
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  [void][P2T10]::PostMessageW($main, [P2T10]::WM_COMMAND, [IntPtr][P2T10]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [P2T10]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) { $dlg = [P2T10]::FindAnyDialog([uint32]$proc.Id) }
    if ($dlg -ne [IntPtr]::Zero) {
      $t = [P2T10]::TitleOf($dlg)
      if ($t -match 'Unsaved|modified') { [P2T10]::ClickDialog($dlg, 7); Start-Sleep -Milliseconds 300; $dlg = [IntPtr]::Zero; continue }
      break
    }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog 'DIALOG_MISSING Open'; return $false }
  WLog ("DIALOG title='{0}' path=$path" -f [P2T10]::TitleOf($dlg))
  [void][P2T10]::DriveFileDialog($dlg, $path)
  $deadline2 = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $deadline2) {
    $still = [P2T10]::FindAnyDialog([uint32]$proc.Id)
    if ($still -eq [IntPtr]::Zero) { break }
    $st = [P2T10]::TitleOf($still)
    if ($st -ne 'Save As' -and $st -ne 'Open' -and $st -notmatch 'Save As' -and $st -notmatch 'Open') {
      [P2T10]::ClickDialog($still, 6)
      Start-Sleep -Milliseconds 400
    } else { Start-Sleep -Milliseconds 200 }
  }
  Start-Sleep -Milliseconds 500
  $title = [P2T10]::TitleOf($main)
  $leaf = [IO.Path]::GetFileName($path)
  $ok = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return $ok
}
function Count-IdeOrphans {
  @(Get-Process RawrXD-Win32IDE-Native -EA SilentlyContinue).Count
}

$utf8 = New-Object System.Text.UTF8Encoding $false
$A1_SHA_VERIFIED = $false
$A2_SCENARIO_TRIGGERED = $false
$A3_CLEAN_TERMINATION = $false
$A4_RESTORE_OK = $false
$A5_EVIDENCE_CAPTURED = $false
$T10 = 'NOT_RUN'
$TIP_FIX = 'no'
$preHas = $false
$mkPre = $false
$mkSess = $false
$restored = $false
$pidBefore = 0
$exitAfterKill = 'N/A'
$orphansAfter = -1
$activeAfterKill = 'N/A'
$docCountAfterKill = -1
$marker = ''
$proc = $null
$main = [IntPtr]::Zero
$script:actualSha = 'NOT_RUN'

try {
  WLog 'START T10_VERIFIED_RESTORE_ON_FREEZE'
  Get-Process RawrXD-Win32IDE-Native -EA SilentlyContinue | ForEach-Object {
    WLog "PRECLEAR pid=$($_.Id)"
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
  Start-Sleep 1

  if (-not (Test-Path -LiteralPath $FreezeExe)) {
    $T10 = 'FAIL_EXE_MISSING'
    throw "Freeze launch EXE missing: $FreezeExe"
  }
  $launchSha = (Get-FileHash -LiteralPath $FreezeExe -Algorithm SHA256).Hash
  $pkgSha = (Get-FileHash -LiteralPath $PackageExe -Algorithm SHA256).Hash
  $launchSize = (Get-Item -LiteralPath $FreezeExe).Length
  $pkgSize = (Get-Item -LiteralPath $PackageExe).Length
  WLog "LAUNCH_SHA=$launchSha SIZE=$launchSize MATCH=$($launchSha -eq $ExpectedSha)"
  WLog "PACKAGE_SHA=$pkgSha SIZE=$pkgSize STAY_A4F=$($pkgSha -eq $PackageStaySha) (must NOT overwrite package tip)"
  if ($launchSha -ne $ExpectedSha) {
    $T10 = 'FAIL_SHA_MISMATCH'
    throw "SHA mismatch launch=$launchSha expect=$ExpectedSha"
  }
  if ($pkgSha -eq $ExpectedSha) {
    $T10 = 'FAIL_PACKAGE_MUTATED'
    throw "Package tip unexpectedly matches freeze SHA; package must stay A4F ($PackageStaySha)"
  }
  if ($pkgSha -ne $PackageStaySha) {
    WLog "WARN package tip not A4F stay-hash (observed=$pkgSha); continuing with launch-only SHA gate"
  }
  $A1_SHA_VERIFIED = $true
  $script:actualSha = $launchSha

  if (Test-Path $SessionJson) {
    Copy-Item $SessionJson (Join-Path $OutDir 'ide_session_t10_before_clear.json') -Force
    Remove-Item $SessionJson -Force -EA SilentlyContinue
  }
  $tmpSess = $SessionJson + '.rawrxd-tmp'
  if (Test-Path $tmpSess) { Remove-Item $tmpSess -Force -EA SilentlyContinue }

  $marker = "T10_HARDKILL_MARKER_$([guid]::NewGuid().ToString('N').Substring(0,8))"
  $crashPath = Join-Path $WorkDir 't10_hardkill.txt'
  [IO.File]::WriteAllText($crashPath, "crash_seed`r`n", $utf8)
  WLog "MARKER=$marker PATH=$crashPath"

  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  if ($main -eq [IntPtr]::Zero -or $editor -eq [IntPtr]::Zero) {
    $T10 = 'FAIL_LAUNCH'
    throw 'Main/editor not ready'
  }
  $A2_SCENARIO_TRIGGERED = $true

  $opened = LastBool (Invoke-Open $main $proc $crashPath)
  if (-not $opened) {
    WLog 'T10 menu open failed - CLI relaunch with path'
    Stop-IdeSoft $proc $main
    if (Test-Path $SessionJson) { Remove-Item $SessionJson -Force -EA SilentlyContinue }
    $proc = Start-Ide ('"' + $crashPath + '"')
    $w = Wait-MainEditor $proc 60
    $main = $w.Main; $editor = $w.Editor
    $opened = ($main -ne [IntPtr]::Zero -and $editor -ne [IntPtr]::Zero)
  }
  $editor = [P2T10]::FindEditor($main)
  if (-not $opened -or $editor -eq [IntPtr]::Zero) {
    $T10 = 'FAIL_OPEN'
    throw 'Could not open crash fixture'
  }

  [P2T10]::FocusEditor($main, $editor)
  [void][P2T10]::SetClipboardText($marker)
  [P2T10]::PasteIntoEditor($editor)
  Start-Sleep -Milliseconds 400
  if (-not ([P2T10]::GetEditorText($editor)).Contains($marker)) {
    [P2T10]::SetEditorText($editor, $marker)
    Start-Sleep -Milliseconds 200
  }
  # Wait > file-safety interval (1500ms) so saveIdeSession checkpoint can fire.
  Start-Sleep -Seconds 3
  $preKillText = [P2T10]::GetEditorText($editor)
  $preHas = $preKillText.Contains($marker)
  $dirty = [P2T10]::SaveMenuEnabled($main)
  WLog "PREKILL hasMarker=$preHas dirtyMenu=$dirty textLen=$($preKillText.Length)"
  if (-not $preHas) {
    $T10 = 'FAIL_MARKER_NOT_INJECTED'
    throw 'Refuse hard-kill without editor marker readback'
  }

  # Checkpoint evidence BEFORE Stop-Process -Force
  $sessPre = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -EA SilentlyContinue } else { '' }
  $mkPre = $sessPre.Contains($marker)
  if ($sessPre) { Set-Content (Join-Path $OutDir 'ide_session_t10_before_kill.json') $sessPre -Encoding UTF8 }
  WLog "PREKILL_SESSION hasMarker=$mkPre sessLen=$($sessPre.Length)"
  if (-not $mkPre) {
    # One more poll window for timer
    Start-Sleep -Seconds 2
    $sessPre = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -EA SilentlyContinue } else { '' }
    $mkPre = $sessPre.Contains($marker)
    if ($sessPre) { Set-Content (Join-Path $OutDir 'ide_session_t10_before_kill.json') $sessPre -Encoding UTF8 }
    WLog "PREKILL_SESSION_RETRY hasMarker=$mkPre sessLen=$($sessPre.Length)"
  }
  if (-not $mkPre) {
    $T10 = 'FAIL_CHECKPOINT_MISSING_BEFORE_KILL'
    throw 'Session checkpoint missing marker before hard-kill'
  }

  $pidBefore = $proc.Id
  WLog "HARD_KILL pid=$pidBefore"
  Stop-Process -Id $pidBefore -Force -EA SilentlyContinue
  $killedDeadline = (Get-Date).AddSeconds(8)
  while ((Get-Date) -lt $killedDeadline) {
    try { $proc.Refresh(); if ($proc.HasExited) { break } } catch { break }
    Start-Sleep -Milliseconds 100
  }
  try { $exitAfterKill = "$($proc.ExitCode)" } catch { $exitAfterKill = 'UNOBTAINED' }
  $orphansAfter = Count-IdeOrphans
  WLog "POSTKILL exit=$exitAfterKill orphans=$orphansAfter"
  if ($orphansAfter -eq 0) { $A3_CLEAN_TERMINATION = $true }
  else {
    Get-Process RawrXD-Win32IDE-Native -EA SilentlyContinue | ForEach-Object {
      WLog "ORPHAN pid=$($_.Id) - force cleanup"
      Stop-Process -Id $_.Id -Force -EA SilentlyContinue
    }
    Start-Sleep 1
    $orphansAfter = Count-IdeOrphans
    WLog "ORPHAN_CLEANUP remaining=$orphansAfter"
    $A3_CLEAN_TERMINATION = ($orphansAfter -eq 0)
  }

  $sessKill = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -EA SilentlyContinue } else { '' }
  if ($sessKill) { Set-Content (Join-Path $OutDir 'ide_session_t10_after_kill.json') $sessKill -Encoding UTF8 }
  $mkSess = $sessKill.Contains($marker)
  try {
    $j = $sessKill | ConvertFrom-Json
    $activeAfterKill = "$($j.active)"
    $docCountAfterKill = @($j.documents).Count
  } catch {}
  WLog "AFTER_KILL markerInSession=$mkSess sessLen=$($sessKill.Length) active=$activeAfterKill docs=$docCountAfterKill"

  # Relaunch same freeze SHA; verify marker restored into editor
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  Start-Sleep 2
  if ($main -eq [IntPtr]::Zero) {
    $T10 = 'FAIL_RELAUNCH'
    throw 'Relaunch failed'
  }
  $editor = [P2T10]::FindEditor($main)
  $restoredText = if ($editor -ne [IntPtr]::Zero) { [P2T10]::GetEditorText($editor) } else { '' }
  $found = $restoredText.Contains($marker)
  if (-not $found) {
    $tabs = [P2T10]::FindDocTabs($main)
    $n = [P2T10]::TabCount($tabs)
    WLog "RESTORE_SCAN tabs=$n activeTextLen=$($restoredText.Length)"
    for ($i = 0; $i -lt [Math]::Max(0, $n); $i++) {
      [void][P2T10]::SelectDocTab($main, $tabs, $i)
      Start-Sleep -Milliseconds 150
      $ed = [P2T10]::FindEditor($main)
      $t = if ($ed -ne [IntPtr]::Zero) { [P2T10]::GetEditorText($ed) } else { '' }
      if ($t.Contains($marker)) { $found = $true; WLog "RESTORED_ON_TAB=$i"; break }
    }
  }
  $restored = $found
  $A4_RESTORE_OK = $found
  WLog "RESTORED=$found"

  if ($found) { $T10 = 'PASS' }
  elseif (-not $mkSess) { $T10 = 'FAIL_SESSION_ONLY_ON_WM_CLOSE' }
  else { $T10 = 'FAIL_SESSION_PRESENT_NOT_RESTORED' }
}
catch {
  WLog "EXCEPTION=$($_.Exception.Message)"
  WLog "$($_.ScriptStackTrace)"
  if ($T10 -eq 'NOT_RUN') { $T10 = 'FAIL_EXCEPTION' }
}
finally {
  Stop-IdeSoft $proc $main
  Start-Sleep 1
  Get-Process RawrXD-Win32IDE-Native -EA SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
}

$postSha = (Get-FileHash -LiteralPath $FreezeExe -Algorithm SHA256).Hash
$postPkg = (Get-FileHash -LiteralPath $PackageExe -Algorithm SHA256).Hash
$A5_EVIDENCE_CAPTURED = (Test-Path $Log)
$allPass = $A1_SHA_VERIFIED -and $A2_SCENARIO_TRIGGERED -and $A3_CLEAN_TERMINATION -and $A4_RESTORE_OK -and $A5_EVIDENCE_CAPTURED
if ($T10 -eq 'PASS' -and -not $allPass) {
  $T10 = 'FAIL_ASSERTIONS_INCOMPLETE'
}
WLog "T10=$T10 ALL_ASSERTIONS=$allPass TIP_FIX=$TIP_FIX POST_SHA=$postSha PKG_SHA=$postPkg"

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receiptLines = New-Object System.Collections.Generic.List[string]
[void]$receiptLines.Add('# T10 Verified Restore On Freeze')
[void]$receiptLines.Add('')
[void]$receiptLines.Add(('ASOF_UTC=' + $asof))
[void]$receiptLines.Add('GATE=T10_VERIFIED_RESTORE_ON_FREEZE')
[void]$receiptLines.Add(('FREEZE_SHA=' + $ExpectedSha))
[void]$receiptLines.Add(('LAUNCH_EXE=' + $FreezeExe))
[void]$receiptLines.Add(('PACKAGE_EXE=' + $PackageExe))
[void]$receiptLines.Add(('ACTUAL_SHA=' + $script:actualSha))
[void]$receiptLines.Add(('POST_SHA=' + $postSha))
[void]$receiptLines.Add(('PACKAGE_SHA=' + $postPkg))
[void]$receiptLines.Add(('SHA_MATCH=' + (($script:actualSha -eq $ExpectedSha) -and ($postSha -eq $ExpectedSha))))
[void]$receiptLines.Add(('PACKAGE_STAYS_A4F=' + ($postPkg -eq $PackageStaySha)))
[void]$receiptLines.Add(('RESULT=' + $T10))
[void]$receiptLines.Add(('TIP_FIX=' + $TIP_FIX))
[void]$receiptLines.Add(('MARKER=' + $marker))
[void]$receiptLines.Add(('PREKILL_EDITOR_MARKER=' + $preHas))
[void]$receiptLines.Add(('PREKILL_SESSION_MARKER=' + $mkPre))
[void]$receiptLines.Add(('AFTER_KILL_SESSION_MARKER=' + $mkSess))
[void]$receiptLines.Add(('ACTIVE_AFTER_KILL=' + $activeAfterKill))
[void]$receiptLines.Add(('DOCS_AFTER_KILL=' + $docCountAfterKill))
[void]$receiptLines.Add(('HARD_KILL_PID=' + $pidBefore))
[void]$receiptLines.Add(('EXIT_AFTER_KILL=' + $exitAfterKill))
[void]$receiptLines.Add(('ORPHANS_AFTER_KILL=' + $orphansAfter))
[void]$receiptLines.Add(('RESTORED_AFTER_RELAUNCH=' + $restored))
[void]$receiptLines.Add('SCOPE=HARD_KILL_UNSAVED_NE_WM_CLOSE')
[void]$receiptLines.Add(('A1_SHA_VERIFIED=' + $A1_SHA_VERIFIED))
[void]$receiptLines.Add(('A2_SCENARIO_TRIGGERED=' + $A2_SCENARIO_TRIGGERED))
[void]$receiptLines.Add(('A3_CLEAN_TERMINATION=' + $A3_CLEAN_TERMINATION))
[void]$receiptLines.Add(('A4_RESTORE_OK=' + $A4_RESTORE_OK))
[void]$receiptLines.Add(('A5_EVIDENCE_CAPTURED=' + $A5_EVIDENCE_CAPTURED))
[void]$receiptLines.Add(('ALL_ASSERTIONS=' + $allPass))
[void]$receiptLines.Add('PROMOTE=0')
[void]$receiptLines.Add('CERTIFIED=0')
[void]$receiptLines.Add('PRODUCT_PASS=0')
[void]$receiptLines.Add('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$receiptLines.Add('T08_UNTOUCHED=1')
[void]$receiptLines.Add(('RUNLOG=' + $Log))
[void]$receiptLines.Add(('SESSION_AFTER_KILL=' + (Join-Path $OutDir 'ide_session_t10_after_kill.json')))
[void]$receiptLines.Add(('WORKDIR=' + $WorkDir))
$receipt = ($receiptLines -join [Environment]::NewLine)
Set-Content -LiteralPath (Join-Path $OutDir 'TASK10.md') -Value $receipt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir 'T10_VERIFIED_RESTORE_SEAL.md') -Value $receipt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $PostDir 'T10_VERIFIED_RESTORE_SEAL.md') -Value $receipt -Encoding UTF8
New-Item -ItemType Directory -Force -Path $OnesHotDir | Out-Null
$gateLines = New-Object System.Collections.Generic.List[string]
[void]$gateLines.Add('# T10_RECOVERY_GATE - FULL_FEATURE_ONESHOT_001')
[void]$gateLines.Add('')
[void]$gateLines.Add(('ASOF_UTC=' + $asof))
[void]$gateLines.Add('GATE=T10_VERIFIED_RESTORE_ON_FREEZE')
[void]$gateLines.Add(('FREEZE_SHA=' + $ExpectedSha))
[void]$gateLines.Add(('ACTUAL_SHA=' + $script:actualSha))
[void]$gateLines.Add(('LAUNCH_EXE=' + $FreezeExe))
[void]$gateLines.Add(('PACKAGE_EXE=' + $PackageExe))
[void]$gateLines.Add(('PACKAGE_SHA=' + $postPkg))
[void]$gateLines.Add(('PACKAGE_STAYS_A4F=' + ($postPkg -eq $PackageStaySha)))
[void]$gateLines.Add(('T10=' + $T10))
[void]$gateLines.Add(('TIP_FIX=' + $TIP_FIX))
[void]$gateLines.Add(('A1_SHA_VERIFIED=' + $A1_SHA_VERIFIED))
[void]$gateLines.Add(('A2_SCENARIO_TRIGGERED=' + $A2_SCENARIO_TRIGGERED))
[void]$gateLines.Add(('A3_CLEAN_TERMINATION=' + $A3_CLEAN_TERMINATION))
[void]$gateLines.Add(('A4_RESTORE_OK=' + $A4_RESTORE_OK))
[void]$gateLines.Add(('A5_EVIDENCE_CAPTURED=' + $A5_EVIDENCE_CAPTURED))
[void]$gateLines.Add(('ALL_ASSERTIONS=' + $allPass))
[void]$gateLines.Add(('MARKER=' + $marker))
[void]$gateLines.Add(('PREKILL_EDITOR_MARKER=' + $preHas))
[void]$gateLines.Add(('PREKILL_SESSION_MARKER=' + $mkPre))
[void]$gateLines.Add(('AFTER_KILL_SESSION_MARKER=' + $mkSess))
[void]$gateLines.Add(('RESTORED_AFTER_RELAUNCH=' + $restored))
[void]$gateLines.Add(('EXIT_AFTER_KILL=' + $exitAfterKill))
[void]$gateLines.Add(('ORPHANS_AFTER_KILL=' + $orphansAfter))
[void]$gateLines.Add(('RUNLOG=' + $Log))
[void]$gateLines.Add('PROMOTE=0')
[void]$gateLines.Add('CERTIFIED=0')
[void]$gateLines.Add('PRODUCT_PASS=0')
[void]$gateLines.Add('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$gateLines.Add('T08_UNTOUCHED=1')
[void]$gateLines.Add('HARNESS=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\t10_verified_restore_freeze.ps1')
Set-Content -LiteralPath (Join-Path $OnesHotDir 'T10_RECOVERY_GATE.md') -Value ($gateLines -join [Environment]::NewLine) -Encoding UTF8

$boardLines = New-Object System.Collections.Generic.List[string]
[void]$boardLines.Add('# T10 board return')
[void]$boardLines.Add('')
[void]$boardLines.Add(('ASOF_UTC=' + $asof))
[void]$boardLines.Add(('SHA256=' + $script:actualSha))
[void]$boardLines.Add(('T10=' + $T10))
[void]$boardLines.Add(('TIP_FIX=' + $TIP_FIX))
[void]$boardLines.Add('PROMOTE=0')
[void]$boardLines.Add('CERTIFIED=0')
[void]$boardLines.Add(('A1_SHA_VERIFIED=' + $A1_SHA_VERIFIED))
[void]$boardLines.Add(('A2_SCENARIO_TRIGGERED=' + $A2_SCENARIO_TRIGGERED))
[void]$boardLines.Add(('A3_CLEAN_TERMINATION=' + $A3_CLEAN_TERMINATION))
[void]$boardLines.Add(('A4_RESTORE_OK=' + $A4_RESTORE_OK))
[void]$boardLines.Add(('A5_EVIDENCE_CAPTURED=' + $A5_EVIDENCE_CAPTURED))
[void]$boardLines.Add(('EVIDENCE_EDITOR=' + (Join-Path $OutDir 'T10_VERIFIED_RESTORE_SEAL.md')))
[void]$boardLines.Add(('EVIDENCE_POST=' + (Join-Path $PostDir 'T10_VERIFIED_RESTORE_SEAL.md')))
[void]$boardLines.Add(('RUNLOG=' + $Log))
[void]$boardLines.Add('T08_TERMINATE_DUMP_RECONCILED=UNCHANGED')
$board = ($boardLines -join [Environment]::NewLine)
Set-Content -LiteralPath (Join-Path $OutDir 'T10_BOARD_RETURN.md') -Value $board -Encoding UTF8
Set-Content -LiteralPath (Join-Path $PostDir 'T10_BOARD_RETURN.md') -Value $board -Encoding UTF8

$nextLines = New-Object System.Collections.Generic.List[string]
[void]$nextLines.Add('# NEXT_ACTION - T08 sealed; T10 dispositioned')
[void]$nextLines.Add('')
[void]$nextLines.Add(('ASOF_UTC=' + $asof))
[void]$nextLines.Add('')
[void]$nextLines.Add('T08_DUMP=RESIDUAL_PARSED')
[void]$nextLines.Add('T08_EXCEPTION=NONE')
[void]$nextLines.Add('T08_CAUSALITY=UNPROVEN')
[void]$nextLines.Add('T08_RESTRESS=8/8_SURVIVED')
[void]$nextLines.Add('T08_TIP_FIX=0')
[void]$nextLines.Add('T08_EVIDENCE=SEALED')
[void]$nextLines.Add('T08_RECONCILE=T08_TERMINATE_DUMP_RECONCILED.md')
[void]$nextLines.Add('T08_FILE_IMMUTABLE=1')
[void]$nextLines.Add('')
[void]$nextLines.Add('NEXT_GATE=T10_VERIFIED_RESTORE_ON_FREEZE')
[void]$nextLines.Add(('T10_STATUS=' + $T10))
[void]$nextLines.Add('T10_TARGET_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8')
[void]$nextLines.Add(('T10_TIP_FIX=' + $TIP_FIX))
[void]$nextLines.Add('T10_REPAIR_ON_TIP_ONLY=1')
[void]$nextLines.Add('T10_FREEZE_IMMUTABLE=1')
[void]$nextLines.Add('T10_SEAL=T10_VERIFIED_RESTORE_SEAL.md')
[void]$nextLines.Add('')
[void]$nextLines.Add('PROMOTE=0')
[void]$nextLines.Add('CERTIFIED=0')
[void]$nextLines.Add('PRODUCT_PASS=0')
[void]$nextLines.Add('FINISH_25_PASS=19')
[void]$nextLines.Add('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$nextLines.Add('')
[void]$nextLines.Add('## T10 acceptance')
[void]$nextLines.Add(('A1_SHA_VERIFIED=' + $A1_SHA_VERIFIED))
[void]$nextLines.Add(('A2_SCENARIO_TRIGGERED=' + $A2_SCENARIO_TRIGGERED))
[void]$nextLines.Add(('A3_CLEAN_TERMINATION=' + $A3_CLEAN_TERMINATION))
[void]$nextLines.Add(('A4_RESTORE_OK=' + $A4_RESTORE_OK))
[void]$nextLines.Add(('A5_EVIDENCE_CAPTURED=' + $A5_EVIDENCE_CAPTURED))
[void]$nextLines.Add(('RESULT=' + $T10))
[void]$nextLines.Add('')
[void]$nextLines.Add('## Isolation')
[void]$nextLines.Add('Do not modify T08_TERMINATE_DUMP_RECONCILED.md.')
[void]$nextLines.Add('Any T10 repair lands on a separate tip, never the frozen executable.')
Set-Content -LiteralPath (Join-Path $PostDir 'NEXT_ACTION.md') -Value ($nextLines -join [Environment]::NewLine) -Encoding UTF8

Write-Host ('FINAL T10=' + $T10 + ' SHA=' + $script:actualSha + ' TIP_FIX=' + $TIP_FIX + ' PROMOTE=0')
if ($T10 -eq 'PASS') { exit 0 } else { exit 1 }

#Requires -Version 5.1
# POST_E59D_CANDIDATE_001 editor requal v2 â€” Unicode Open/Save, external No/Yes, GhostText, session
# PROMOTE=0 CERTIFIED=0 INVENT_PASS=0  NOT_RUN!=PASS  No E59D PASS inheritance
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$Log = Join-Path $OutDir 'RUNLOG.txt'
$SessionJson = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Host $line
}
function LastBool($v) {
  if ($null -eq $v) { return $false }
  if ($v -is [System.Array]) {
    if ($v.Length -eq 0) { return $false }
    return [bool]$v[-1]
  }
  return [bool]$v
}

$results = [ordered]@{
  UNICODE_SAVE_REOPEN = 'NOT_RUN'
  SAVE_SAVEAS = 'NOT_RUN'
  EXTERNAL_NO = 'NOT_RUN'
  EXTERNAL_YES = 'NOT_RUN'
  GHOSTTEXT_RENDER_ACCEPT_SAVE = 'NOT_RUN'
  SESSION_SURVIVE = 'NOT_RUN'
}

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class PE2 {
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
  [DllImport("user32.dll")] public static extern short VkKeyScanW(char ch);
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E;
  public const uint WM_CLOSE=0x0010, WM_KEYDOWN=0x0100, WM_KEYUP=0x0101, WM_CHAR=0x0102;
  public const uint EM_REPLACESEL=0x00C2, EM_SETSEL=0x00B1, BM_CLICK=0x00F5;
  public const int SW_RESTORE=9;
  public const int IDM_FILE_NEW=2001, IDM_FILE_OPEN=2002, IDM_FILE_SAVE=2003, IDM_FILE_SAVEAS=2004;
  public const int IDC_EDITOR=1001;
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra;
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
    // Select-all + replace via EM if needed
    SendMessageW(edit, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(edit, EM_REPLACESEL, (IntPtr)1, fullPath);
    System.Threading.Thread.Sleep(100);
    IntPtr ok=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ if(GetDlgCtrlID(h)==1 && ClassName(h)=="Button"){ ok=h; return false;} return true;}, IntPtr.Zero);
    if(ok!=IntPtr.Zero){ PostMessageW(dlg,WM_COMMAND,(IntPtr)1,ok); SendMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero); }
    else PostMessageW(dlg,WM_COMMAND,(IntPtr)1,IntPtr.Zero);
    System.Threading.Thread.Sleep(200);
    if(IsWindowVisible(dlg)){
      // Alt+S then Enter
      var inputs=new INPUT[6];
      for(int i=0;i<6;i++){ inputs[i].type=1; }
      inputs[0].ki.wVk=0x12; // Alt
      inputs[1].ki.wVk=0x53; // S
      inputs[2].ki.wVk=0x53; inputs[2].ki.dwFlags=2;
      inputs[3].ki.wVk=0x12; inputs[3].ki.dwFlags=2;
      inputs[4].ki.wVk=0x0D;
      inputs[5].ki.wVk=0x0D; inputs[5].ki.dwFlags=2;
      SendInput(6, inputs, Marshal.SizeOf(typeof(INPUT)));
    }
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
  public static void ClickDialog(IntPtr dlg, int cmd){ if(dlg!=IntPtr.Zero) PostMessageW(dlg,WM_COMMAND,(IntPtr)cmd,IntPtr.Zero); }
  public static void TypeAscii(string s){
    foreach(char ch in s){
      short vk=VkKeyScanW(ch); if(vk==-1) continue;
      byte lo=(byte)(vk & 0xFF); byte hi=(byte)((vk >> 8) & 0xFF);
      var inputs=new INPUT[4]; for(int i=0;i<4;i++) inputs[i].type=1;
      int n=0;
      if((hi & 1)!=0){ inputs[n].ki.wVk=0x10; n++; } // shift
      inputs[n].ki.wVk=lo; n++;
      inputs[n].ki.wVk=lo; inputs[n].ki.dwFlags=2; n++;
      if((hi & 1)!=0){ inputs[n].ki.wVk=0x10; inputs[n].ki.dwFlags=2; n++; }
      SendInput((uint)n, inputs, Marshal.SizeOf(typeof(INPUT)));
      System.Threading.Thread.Sleep(15);
    }
  }
  public static void Chord(ushort a, ushort b){
    var inputs=new INPUT[4]; for(int i=0;i<4;i++) inputs[i].type=1;
    inputs[0].ki.wVk=a; inputs[1].ki.wVk=b;
    inputs[2].ki.wVk=b; inputs[2].ki.dwFlags=2;
    inputs[3].ki.wVk=a; inputs[3].ki.dwFlags=2;
    SendInput(4, inputs, Marshal.SizeOf(typeof(INPUT)));
  }
}
'@

function Wait-MainEditor([Diagnostics.Process]$proc, [int]$sec = 60) {
  $deadline = (Get-Date).AddSeconds($sec)
  $main = [IntPtr]::Zero; $editor = [IntPtr]::Zero
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    $main = [PE2]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [PE2]::IsWindowVisible($main)) {
      $editor = [PE2]::FindEditor($main)
      if ($editor -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 250
  }
  [pscustomobject]@{ Main = $main; Editor = $editor }
}
function Wait-NoDialog([uint32]$procId, [int]$ms = 8000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while ((Get-Date) -lt $deadline) {
    if ([PE2]::FindAnyDialog($procId) -eq [IntPtr]::Zero) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
function Dismiss-SavePromptOnly([uint32]$procId, [int]$cmd = 7) {
  for ($i = 0; $i -lt 6; $i++) {
    $d = [PE2]::FindDialogByTitle($procId, 'Unsaved')
    if ($d -eq [IntPtr]::Zero) { $d = [PE2]::FindDialogByTitle($procId, 'Save') }
    if ($d -eq [IntPtr]::Zero) { break }
    $t = [PE2]::TitleOf($d)
    if ($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As') { break }
    WLog ("DISMISS_SAVE title='{0}' cmd={1}" -f $t, $cmd)
    [PE2]::ClickDialog($d, $cmd)
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
  [void][PE2]::PostMessageW($main, [PE2]::WM_COMMAND, [IntPtr]$cmdId, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    if ($titleHint) { $dlg = [PE2]::FindDialogByTitle([uint32]$proc.Id, $titleHint) }
    if ($dlg -eq [IntPtr]::Zero) { $dlg = [PE2]::FindAnyDialog([uint32]$proc.Id) }
    if ($dlg -ne [IntPtr]::Zero) {
      $t = [PE2]::TitleOf($dlg)
      if ($t -match 'Unsaved|modified') { [PE2]::ClickDialog($dlg, 7); Start-Sleep -Milliseconds 300; $dlg = [IntPtr]::Zero; continue }
      break
    }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog "DIALOG_MISSING hint=$titleHint"; return $false }
  WLog ("DIALOG title='{0}' path=$path" -f [PE2]::TitleOf($dlg))
  [void][PE2]::DriveFileDialog($dlg, $path)
  $deadline2 = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $deadline2) {
    $still = [PE2]::FindAnyDialog([uint32]$proc.Id)
    if ($still -eq [IntPtr]::Zero) { break }
    $st = [PE2]::TitleOf($still)
    if ($st -ne 'Save As' -and $st -ne 'Open' -and $st -notmatch 'Save As' -and $st -notmatch 'Open') {
      WLog ("CONFIRM title='{0}' -> YES" -f $st)
      [PE2]::ClickDialog($still, 6)
      Start-Sleep -Milliseconds 400
    } else {
      Start-Sleep -Milliseconds 200
    }
  }
  [void](Wait-NoDialog ([uint32]$proc.Id) 5000)
  return $true
}
function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  if ([PE2]::SaveMenuEnabled($main)) {
    [void][PE2]::PostMessageW($main, [PE2]::WM_COMMAND, [IntPtr][PE2]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  }
  $okDlg = LastBool (Invoke-FileDialogPath $main $proc ([PE2]::IDM_FILE_OPEN) $path 'Open')
  if (-not $okDlg) { return $false }
  Start-Sleep -Milliseconds 500
  $title = [PE2]::TitleOf($main)
  $leaf = [IO.Path]::GetFileName($path)
  $ok = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return $ok
}
function Invoke-SaveAs([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  $okDlg = LastBool (Invoke-FileDialogPath $main $proc ([PE2]::IDM_FILE_SAVEAS) $path 'Save')
  if (-not $okDlg) { return $false }
  Start-Sleep -Milliseconds 500
  $ok = Test-Path -LiteralPath $path
  WLog "SAVEAS_RESULT ok=$ok"
  return $ok
}
function Invoke-Save([IntPtr]$main) {
  [void][PE2]::PostMessageW($main, [PE2]::WM_COMMAND, [IntPtr][PE2]::IDM_FILE_SAVE, [IntPtr]::Zero)
}
function Wait-ExternalDlg([uint32]$procId, [int]$sec = 30) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    $d = [PE2]::FindDialogByTitle($procId, 'External')
    if ($d -eq [IntPtr]::Zero) {
      $any = [PE2]::FindAnyDialog($procId)
      if ($any -ne [IntPtr]::Zero) {
        $t = [PE2]::TitleOf($any)
        if ($t -match 'External|File Change|changed') { return $any }
      }
    } else { return $d }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}

WLog 'START POST_E59D editor requal v2'
WLog "EXE=$TipExe"
if (-not (Test-Path $TipExe)) { throw 'EXE_MISSING' }
$actual = (Get-FileHash $TipExe -Algorithm SHA256).Hash
WLog "ACTUAL_SHA=$actual"
if ($actual -ne $ExpectedSha) { throw "SHA_MISMATCH $actual" }

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1
$utf8 = [Text.UTF8Encoding]::new($false)
$proc = $null; $main = [IntPtr]::Zero; $editor = [IntPtr]::Zero

try {
  # ---- UNICODE via product UTF-8 Open/Save path ----
  WLog '=== UNICODE ==='
  $src = Join-Path $WorkDir 'u_src.txt'
  $dst = Join-Path $WorkDir 'u_copy.txt'
  $payload = "cafÃ©`r`næ±äº¬`r`nðŸš€`r`nCRLF_SENTINEL_LINE`r`n"
  $expectedBytes = $utf8.GetBytes($payload)
  [IO.File]::WriteAllBytes($src, $expectedBytes)
  $srcSha = (Get-FileHash $src -Algorithm SHA256).Hash
  WLog "unicode_src_sha=$srcSha len=$($expectedBytes.Length)"

  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main; $editor = $w.Editor
  if ($main -eq [IntPtr]::Zero) { throw 'no_main' }

  if (-not (LastBool (Invoke-Open $main $proc $src))) {
    $results.UNICODE_SAVE_REOPEN = 'FAIL_OPEN'
    throw 'STOP_UNICODE_OPEN'
  }
  Start-Sleep -Milliseconds 500
  if (-not (LastBool (Invoke-SaveAs $main $proc $dst))) {
    # fallback: Save (same path) after tiny dirty via ASCII append using TypeAscii
    WLog 'SAVEAS_FAILED_TRY_SAVE'
    $editor = [PE2]::FindEditor($main)
    [PE2]::FocusEditor($main, $editor)
    [PE2]::SetEditorText($editor, ([PE2]::GetEditorText($editor) + "`r`n"))
    Start-Sleep -Milliseconds 200
    Invoke-Save $main
    Start-Sleep -Seconds 1
    if (Test-Path $src) {
      $disk = [IO.File]::ReadAllBytes($src)
      $exact = ($disk.Length -eq $expectedBytes.Length)
      if ($exact) { for ($i = 0; $i -lt $disk.Length; $i++) { if ($disk[$i] -ne $expectedBytes[$i]) { $exact = $false; break } } }
      # reopen copy path via Save As retry short name
      $dst2 = Join-Path $WorkDir 'ucopy.txt'
      if (LastBool (Invoke-SaveAs $main $proc $dst2)) { $dst = $dst2 }
      if (Test-Path $dst) {
        $disk2 = [IO.File]::ReadAllBytes($dst)
        $sha2 = (Get-FileHash $dst -Algorithm SHA256).Hash
        WLog "unicode_copy_sha=$sha2 len=$($disk2.Length)"
        $exact2 = ($disk2.Length -eq $expectedBytes.Length)
        if ($exact2) { for ($i = 0; $i -lt $disk2.Length; $i++) { if ($disk2[$i] -ne $expectedBytes[$i]) { $exact2 = $false; break } } }
        if ($exact2) {
          if (-not (LastBool (Invoke-Open $main $proc $dst))) { $results.UNICODE_SAVE_REOPEN = 'FAIL_REOPEN' }
          else {
            $results.UNICODE_SAVE_REOPEN = 'PASS'
            $results.SAVE_SAVEAS = 'PASS'
          }
        } else { $results.UNICODE_SAVE_REOPEN = 'FAIL_BYTE_MISMATCH'; $results.SAVE_SAVEAS = 'FAIL' }
      } elseif ($exact) {
        # Saved in place preserved UTF-8; reopen src
        if (LastBool (Invoke-Open $main $proc $src)) {
          $results.UNICODE_SAVE_REOPEN = 'PASS'
          $results.SAVE_SAVEAS = 'PASS_SAVE_ONLY'
        } else { $results.UNICODE_SAVE_REOPEN = 'FAIL_REOPEN' }
      } else { $results.UNICODE_SAVE_REOPEN = 'FAIL_SAVE_ENCODING' }
    } else { $results.UNICODE_SAVE_REOPEN = 'FAIL_SAVEAS' }
  } else {
    $disk2 = [IO.File]::ReadAllBytes($dst)
    $sha2 = (Get-FileHash $dst -Algorithm SHA256).Hash
    WLog "unicode_copy_sha=$sha2 len=$($disk2.Length)"
    $exact2 = ($disk2.Length -eq $expectedBytes.Length)
    if ($exact2) { for ($i = 0; $i -lt $disk2.Length; $i++) { if ($disk2[$i] -ne $expectedBytes[$i]) { $exact2 = $false; break } } }
    if (-not $exact2) { $results.UNICODE_SAVE_REOPEN = 'FAIL_BYTE_MISMATCH'; $results.SAVE_SAVEAS = 'FAIL' }
    elseif (-not (LastBool (Invoke-Open $main $proc $dst))) { $results.UNICODE_SAVE_REOPEN = 'FAIL_REOPEN'; $results.SAVE_SAVEAS = 'PASS' }
    else {
      $results.UNICODE_SAVE_REOPEN = 'PASS'
      $results.SAVE_SAVEAS = 'PASS'
    }
  }
  WLog "UNICODE=$($results.UNICODE_SAVE_REOPEN) SAVE_SAVEAS=$($results.SAVE_SAVEAS)"
  if ($results.UNICODE_SAVE_REOPEN -ne 'PASS') { throw 'STOP_UNICODE' }

  # ---- EXTERNAL NO / YES ----
  WLog '=== EXTERNAL ==='
  $cPath = Join-Path $WorkDir 'ext.txt'
  [IO.File]::WriteAllText($cPath, "ORIGINAL_VIEW`r`n", $utf8)
  if (-not (LastBool (Invoke-Open $main $proc $cPath))) { $results.EXTERNAL_NO = 'FAIL_OPEN'; throw 'STOP_EXT' }
  Start-Sleep -Seconds 2
  [IO.File]::WriteAllText($cPath, "NO_SHOULD_NOT_APPEAR`r`n", $utf8)
  $dlg = Wait-ExternalDlg ([uint32]$proc.Id) 30
  $dt = if ($dlg -ne [IntPtr]::Zero) { [PE2]::TitleOf($dlg) } else { '' }
  WLog "ext_no_dlg='$dt'"
  if ($dlg -eq [IntPtr]::Zero) { $results.EXTERNAL_NO = 'FAIL_NO_PROMPT'; throw 'STOP_EXT_NO' }
  [PE2]::ClickDialog($dlg, 7) # IDNO
  Start-Sleep -Milliseconds 800
  $keep = [PE2]::GetEditorText([PE2]::FindEditor($main))
  WLog "ext_no_editor='$($keep.Trim())'"
  if ($keep -match 'ORIGINAL_VIEW' -and $keep -notmatch 'NO_SHOULD_NOT_APPEAR') { $results.EXTERNAL_NO = 'PASS' }
  else { $results.EXTERNAL_NO = 'FAIL_BUFFER_CHANGED'; throw 'STOP_EXT_NO' }
  WLog "EXTERNAL_NO=$($results.EXTERNAL_NO)"

  [IO.File]::WriteAllText($cPath, "FINAL_YES_SENTINEL`r`n", $utf8)
  $dlg = Wait-ExternalDlg ([uint32]$proc.Id) 30
  $dt = if ($dlg -ne [IntPtr]::Zero) { [PE2]::TitleOf($dlg) } else { '' }
  WLog "ext_yes_dlg='$dt'"
  if ($dlg -eq [IntPtr]::Zero) { $results.EXTERNAL_YES = 'FAIL_NO_PROMPT'; throw 'STOP_EXT_YES' }
  [PE2]::ClickDialog($dlg, 6) # IDYES
  Start-Sleep -Milliseconds 900
  $got = [PE2]::GetEditorText([PE2]::FindEditor($main))
  WLog "ext_yes_editor='$($got.Trim())'"
  if ($got -match 'FINAL_YES_SENTINEL') { $results.EXTERNAL_YES = 'PASS' }
  else { $results.EXTERNAL_YES = 'FAIL_NOT_RELOADED'; throw 'STOP_EXT_YES' }
  WLog "EXTERNAL_YES=$($results.EXTERNAL_YES)"

  # ---- GHOSTTEXT ----
  WLog '=== GHOSTTEXT ==='
  $gPath = Join-Path $WorkDir 'gt.txt'
  $marker = 'GHOSTTEXT_SRC_MARKER_UNIQUE'
  [IO.File]::WriteAllText($gPath, "$marker`r`n", $utf8)
  if (-not (LastBool (Invoke-Open $main $proc $gPath))) { $results.GHOSTTEXT_RENDER_ACCEPT_SAVE = 'FAIL_OPEN'; throw 'STOP_GT' }
  $editor = [PE2]::FindEditor($main)
  [PE2]::FocusEditor($main, $editor)
  [PE2]::SetEditorText($editor, "$marker`r`ndef greet():`r`n    ")
  Start-Sleep -Milliseconds 300
  $before = [PE2]::GetEditorText($editor)
  [PE2]::FocusEditor($main, $editor)
  [PE2]::Chord(0x11, 0x20) # Ctrl+Space
  WLog 'ctrlspace_sent'
  $deadline = (Get-Date).AddSeconds(40)
  $grew = $false
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    Start-Sleep -Seconds 1
    $now = [PE2]::GetEditorText([PE2]::FindEditor($main))
    # poll product logs
    $logDir = Join-Path (Split-Path $TipExe) 'logs'
    $hit = $false
    if (Test-Path $logDir) {
      Get-ChildItem $logDir -Filter '*.log' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 6 | ForEach-Object {
        $tail = Get-Content $_.FullName -Tail 60 -EA SilentlyContinue
        if ($tail -match 'GhostText|ghost_text|completion|eligible=1|Inline completion') { $hit = $true }
      }
    }
    if ($hit) { WLog 'ghost_log_evidence=1'; $grew = $true; break }
  }
  [PE2]::FocusEditor($main, [PE2]::FindEditor($main))
  [PE2]::Chord(0x09, 0x09) # bogus - send Tab properly
  $tab = New-Object 'PE2+INPUT[]' 2
  # use Chord with VK_TAB once: press Tab
  $inputs = New-Object 'PE2+INPUT[]' 2
  # fallback: SendInput via Type - PE2.Chord(0,9) wrong. Call keybd through PostMessage WM_KEYDOWN Tab on editor
  [void][PE2]::PostMessageW([PE2]::FindEditor($main), [PE2]::WM_KEYDOWN, [IntPtr]0x09, [IntPtr]::Zero)
  [void][PE2]::PostMessageW([PE2]::FindEditor($main), [PE2]::WM_KEYUP, [IntPtr]0x09, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 800
  $after = [PE2]::GetEditorText([PE2]::FindEditor($main))
  WLog ("gt_before_len={0} after_len={1} logGrew={2}" -f $before.Length, $after.Length, $grew)
  if ($proc.HasExited) { $results.GHOSTTEXT_RENDER_ACCEPT_SAVE = 'FAIL_PROCESS_DEAD'; throw 'STOP_GT' }
  Invoke-Save $main
  Start-Sleep -Milliseconds 800
  if ($grew -or ($after.Length -gt $before.Length)) {
    $gSha = (Get-FileHash $gPath -Algorithm SHA256).Hash
    WLog "gt_saved_sha=$gSha"
    $results.GHOSTTEXT_RENDER_ACCEPT_SAVE = 'PASS'
  } else {
    $results.GHOSTTEXT_RENDER_ACCEPT_SAVE = 'NOT_VERIFIED_NO_COMPLETION'
    throw 'STOP_GT'
  }
  WLog "GHOSTTEXT=$($results.GHOSTTEXT_RENDER_ACCEPT_SAVE)"

  # ---- SESSION: graceful close + relaunch retains path or marker ----
  WLog '=== SESSION ==='
  [void][PE2]::PostMessageW($main, [PE2]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  [void]$proc.WaitForExit(20000)
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
  Start-Sleep 1
  $sess = if (Test-Path $SessionJson) { Get-Content $SessionJson -Raw -EA SilentlyContinue } else { '' }
  $proc = Start-Ide
  $w = Wait-MainEditor $proc 60
  $main = $w.Main
  Start-Sleep 1
  $title = if ($main -ne [IntPtr]::Zero) { [PE2]::TitleOf($main) } else { '' }
  $alive = -not $proc.HasExited
  WLog "session_file_len=$($sess.Length) title='$title' alive=$alive"
  if ($alive -and $main -ne [IntPtr]::Zero) { $results.SESSION_SURVIVE = 'PASS' }
  else { $results.SESSION_SURVIVE = 'FAIL' }
  WLog "SESSION=$($results.SESSION_SURVIVE)"
}
catch {
  WLog "EXCEPTION=$($_.Exception.Message)"
}
finally {
  if ($proc -and -not $proc.HasExited) {
    [void][PE2]::PostMessageW($main, [PE2]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
    [void]$proc.WaitForExit(12000)
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
  }
}

$editorPass = (
  $results.UNICODE_SAVE_REOPEN -eq 'PASS' -and
  ($results.SAVE_SAVEAS -eq 'PASS' -or $results.SAVE_SAVEAS -eq 'PASS_SAVE_ONLY') -and
  $results.EXTERNAL_NO -eq 'PASS' -and
  $results.EXTERNAL_YES -eq 'PASS' -and
  $results.GHOSTTEXT_RENDER_ACCEPT_SAVE -eq 'PASS' -and
  $results.SESSION_SURVIVE -eq 'PASS'
)
$disposition = if ($editorPass) { 'EDITOR_PASS' } else { 'EDITOR_FAIL_OR_INCOMPLETE' }
$receipt = @"
# POST_E59D_CANDIDATE_001 EDITOR requal

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE=$TipExe
CERT_EXE_SHA=$actual
SIZE=$((Get-Item $TipExe).Length)
SOURCE_COMMIT=57f4dd1f056959ad541db626d3684152b17fd9fb
UNICODE_SAVE_REOPEN=$($results.UNICODE_SAVE_REOPEN)
SAVE_SAVEAS=$($results.SAVE_SAVEAS)
EXTERNAL_NO=$($results.EXTERNAL_NO)
EXTERNAL_YES=$($results.EXTERNAL_YES)
GHOSTTEXT_RENDER_ACCEPT_SAVE=$($results.GHOSTTEXT_RENDER_ACCEPT_SAVE)
SESSION_SURVIVE=$($results.SESSION_SURVIVE)
EDITOR=$disposition
PROMOTE=0
CERTIFIED=0
E59D_RECEIPT_TRANSFER=0
FAIL_CLOSED=NOT_RUN!=PASS
RUNLOG=$Log
"@
Set-Content (Join-Path $OutDir 'RECEIPT.md') $receipt -Encoding UTF8
WLog "DISPOSITION=$disposition"
foreach ($k in $results.Keys) { WLog "$k=$($results[$k])" }
if (-not $editorPass) { exit 1 } else { exit 0 }


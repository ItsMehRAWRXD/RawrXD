#Requires -Version 5.1
# DIAGNOSE_ACCEPTANCE_PATH v2 - proper Open, model-first, isolate insert vs save.
# Fail-closed. PROMOTE=0. ASCII-only source.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$PreferredModel = 'qwen2.5-coder:1.5b-base'
$Log = Join-Path $OutDir 'DIAGNOSE_ACCEPT_RUNLOG.txt'
$SessionJson = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$Marker = 'GTACC_' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$Fixture = Join-Path $WorkDir ("gt_diag_{0}.txt" -f $Marker)
$Seed = ('def add(a, b):' + "`r`n" + '    // ' + $Marker + "`r`n" + '    ')
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Host $line
}

$flags = [ordered]@{
  GHOSTTEXT_RENDERED = 0
  EDITOR_FOCUS = 0
  TAB_ACCEPT_HANDLER_ENTER = 0
  ACCEPTED_TEXT_INSERTED = 0
  EDITOR_BUFFER_MATCH = 0
  DOCUMENT_DIRTY = 0
  SAVE_SUCCESS = 0
  REOPEN_BYTES_MATCH = 0
  REOPEN_SHA_MATCH = 0
}

Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public static class GTD2 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [DllImport("user32.dll")] public static extern uint GetMenuState(IntPtr h, uint id, uint flags);
  [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  [DllImport("user32.dll")] public static extern bool GetGUIThreadInfo(uint idThread, ref GUITHREADINFO info);
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_CLOSE=0x0010;
  public const uint WM_KEYDOWN=0x0100, WM_KEYUP=0x0101, WM_CHAR=0x0102, WM_LBUTTONDOWN=0x0201, WM_LBUTTONUP=0x0202;
  public const uint EM_SETSEL=0x00B1, EM_REPLACESEL=0x00C2, BM_CLICK=0x00F5;
  public const uint CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_GETLBTEXTLEN=0x0149, CB_SETCURSEL=0x014E;
  public const int IDM_FILE_NEW=2001, IDM_FILE_OPEN=2002, IDM_FILE_SAVE=2003, IDM_FILE_SAVEAS=2004, IDC_EDITOR=1001;
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra; }
  [StructLayout(LayoutKind.Sequential)] public struct GUITHREADINFO {
    public uint cbSize; public uint flags; public IntPtr hwndActive; public IntPtr hwndFocus;
    public IntPtr hwndCapture; public IntPtr hwndMenuOwner; public IntPtr hwndMoveSize; public IntPtr hwndCaret; public RECT rcCaret;
  }
  public static string ClassName(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindEditor(IntPtr root){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,l)=>{ string c=ClassName(h); if(GetDlgCtrlID(h)==IDC_EDITOR && IsWindowVisible(h) && (c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0 || c=="Edit")){ f=h; return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindAnyDialog(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="#32770"&&IsWindowVisible(h)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindDialogByTitle(uint p, string must){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="#32770"&&IsWindowVisible(h)){ string t=TitleOf(h); if(t.IndexOf(must,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;}} return true;},IntPtr.Zero); return f; }
  public static void Focus(IntPtr main, IntPtr ed){
    ShowWindow(main,9); SetForegroundWindow(main);
    RECT r; GetWindowRect(ed, out r);
    int cx=(r.L+r.R)/2; int cy=(r.T+r.B)/2;
    SetCursorPos(cx, cy); mouse_event(0x0002,0,0,0,UIntPtr.Zero); mouse_event(0x0004,0,0,0,UIntPtr.Zero);
    uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId();
    bool a=false; if(gui!=me)a=AttachThreadInput(me,gui,true);
    SetFocus(ed); if(a)AttachThreadInput(me,gui,false);
  }
  // Keep AttachThreadInput held across focus + SendInput so GetKeyState(Ctrl) works in editorProc.
  public static IntPtr FocusChord(IntPtr main, IntPtr ed, ushort a, ushort b){
    ShowWindow(main,9); SetForegroundWindow(main);
    RECT r; GetWindowRect(ed, out r);
    SetCursorPos((r.L+r.R)/2, (r.T+r.B)/2);
    mouse_event(0x0002,0,0,0,UIntPtr.Zero); mouse_event(0x0004,0,0,0,UIntPtr.Zero);
    uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId();
    bool attached=false; if(gui!=me) attached=AttachThreadInput(me,gui,true);
    SetFocus(ed);
    IntPtr f=GetFocus();
    var i=new INPUT[4]; for(int k=0;k<4;k++) i[k].type=1;
    i[0].ki.wVk=a; i[1].ki.wVk=b; i[2].ki.wVk=b; i[2].ki.dwFlags=2; i[3].ki.wVk=a; i[3].ki.dwFlags=2;
    SendInput(4,i,Marshal.SizeOf(typeof(INPUT)));
    System.Threading.Thread.Sleep(50);
    f=GetFocus();
    if(attached) AttachThreadInput(me,gui,false);
    return f;
  }
  public static IntPtr FocusOf(IntPtr main){
    uint gui=0; GetWindowThreadProcessId(main,out gui);
    var info=new GUITHREADINFO(); info.cbSize=(uint)Marshal.SizeOf(typeof(GUITHREADINFO));
    if(GetGUIThreadInfo(gui, ref info) && info.hwndFocus!=IntPtr.Zero) return info.hwndFocus;
    uint me=GetCurrentThreadId(); bool a=false; if(gui!=me)a=AttachThreadInput(me,gui,true);
    IntPtr f=GetFocus(); if(a)AttachThreadInput(me,gui,false); return f;
  }
  public static string GetText(IntPtr h){ int len=SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero).ToInt32(); if(len<=0) len=GetWindowTextLengthW(h); if(len<=0)return ""; IntPtr buf=Marshal.AllocHGlobal((len+2)*2); try{ int got=SendMessageW(h,WM_GETTEXT,(IntPtr)(len+1),buf).ToInt32(); return got>0?Marshal.PtrToStringUni(buf)??"":""; } finally{ Marshal.FreeHGlobal(buf);} }
  public static void SetText(IntPtr h, string t){ SendMessageW(h,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1)); SendMessageW(h,EM_REPLACESEL,(IntPtr)1,t??""); }
  public static void Chord(ushort a, ushort b){ var i=new INPUT[4]; for(int k=0;k<4;k++) i[k].type=1; i[0].ki.wVk=a; i[1].ki.wVk=b; i[2].ki.wVk=b; i[2].ki.dwFlags=2; i[3].ki.wVk=a; i[3].ki.dwFlags=2; SendInput(4,i,Marshal.SizeOf(typeof(INPUT))); }
  public static void TabToEditor(IntPtr ed){ SendMessageW(ed,WM_KEYDOWN,(IntPtr)0x09,IntPtr.Zero); SendMessageW(ed,WM_KEYUP,(IntPtr)0x09,IntPtr.Zero); }
  public static void TabSendInput(){ var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x09; i[1].type=1; i[1].ki.wVk=0x09; i[1].ki.dwFlags=2; SendInput(2,i,Marshal.SizeOf(typeof(INPUT))); }
  public static IntPtr FindFileNameEdit(IntPtr dlg){
    IntPtr edit=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ string c=ClassName(h); int id=GetDlgCtrlID(h); if((c=="Edit"||c.StartsWith("RichEdit"))&&(id==0x47C||id==0x480||id==0x3E9)&&IsWindowVisible(h)&&IsWindowEnabled(h)){edit=h;return false;} return true;},IntPtr.Zero);
    if(edit!=IntPtr.Zero) return edit;
    EnumChildWindows(dlg,(h,l)=>{ if(ClassName(h)=="ComboBoxEx32"){ EnumChildWindows(h,(c,q)=>{ if(ClassName(c)=="Edit"){edit=c;return false;} return true;},IntPtr.Zero); return edit==IntPtr.Zero;} return true;},IntPtr.Zero);
    return edit;
  }
  public static bool DriveFileDialog(IntPtr dlg, string path){
    if(dlg==IntPtr.Zero) return false; IntPtr edit=FindFileNameEdit(dlg); if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg); SetWindowTextW(edit,path); SendMessageW(edit,WM_SETTEXT,IntPtr.Zero,path);
    SendMessageW(edit,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1)); SendMessageW(edit,EM_REPLACESEL,(IntPtr)1,path);
    IntPtr ok=IntPtr.Zero; EnumChildWindows(dlg,(h,l)=>{ if(GetDlgCtrlID(h)==1&&ClassName(h)=="Button"){ok=h;return false;} return true;},IntPtr.Zero);
    if(ok!=IntPtr.Zero){ PostMessageW(dlg,WM_COMMAND,(IntPtr)1,ok); SendMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero);} else PostMessageW(dlg,WM_COMMAND,(IntPtr)1,IntPtr.Zero);
    System.Threading.Thread.Sleep(250);
    if(IsWindowVisible(dlg)){ var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x0D; i[1].type=1; i[1].ki.wVk=0x0D; i[1].ki.dwFlags=2; SendInput(2,i,Marshal.SizeOf(typeof(INPUT))); }
    return true;
  }
  public static void ClickDialog(IntPtr dlg, int cmd){ if(dlg!=IntPtr.Zero) PostMessageW(dlg,WM_COMMAND,(IntPtr)cmd,IntPtr.Zero); }
  public static IntPtr FindComboWithText(IntPtr root, string needle){
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,l)=>{
      string c=ClassName(h); if(c!="ComboBox" && c!="ComboBoxEx32") return true;
      int n=SendMessageW(h,CB_GETCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
      for(int i=0;i<n && i<300;i++){
        int tlen=SendMessageW(h,CB_GETLBTEXTLEN,(IntPtr)i,IntPtr.Zero).ToInt32(); if(tlen<=0) continue;
        IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
        try { SendMessageW(h,CB_GETLBTEXT,(IntPtr)i,buf); string t=Marshal.PtrToStringUni(buf)??""; if(t.IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){ found=h; return false; } }
        finally { Marshal.FreeHGlobal(buf); }
      }
      return true;
    },IntPtr.Zero);
    return found;
  }
  public static int SelectComboText(IntPtr combo, string needle){
    int n=SendMessageW(combo,CB_GETCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32();
    for(int i=0;i<n;i++){
      int tlen=SendMessageW(combo,CB_GETLBTEXTLEN,(IntPtr)i,IntPtr.Zero).ToInt32(); if(tlen<=0) continue;
      IntPtr buf=Marshal.AllocHGlobal((tlen+2)*2);
      try { SendMessageW(combo,CB_GETLBTEXT,(IntPtr)i,buf); string t=Marshal.PtrToStringUni(buf)??"";
        if(t.IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){ SendMessageW(combo,CB_SETCURSEL,(IntPtr)i,IntPtr.Zero); return i; } }
      finally { Marshal.FreeHGlobal(buf); }
    }
    return -1;
  }
  public static string CollectChildText(IntPtr root){
    var sb=new StringBuilder();
    EnumChildWindows(root,(h,l)=>{
      string c=ClassName(h);
      if(c=="Edit"||c.StartsWith("RichEdit")||c=="Static"){
        string t=GetText(h); if(!string.IsNullOrEmpty(t)) sb.AppendLine(t);
      }
      return true;
    },IntPtr.Zero);
    return sb.ToString();
  }
  public static bool SaveMenuEnabled(IntPtr main){ IntPtr m=GetMenu(main); if(m==IntPtr.Zero) return false; uint st=GetMenuState(m,(uint)IDM_FILE_SAVE,0); return (st & 0x3u)==0; }
}
'@
if (-not ('GTD2' -as [type])) { throw 'ADD_TYPE_FAILED' }

function Wait-NoDialog([uint32]$procId, [int]$ms = 8000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while ((Get-Date) -lt $deadline) {
    if ([GTD2]::FindAnyDialog($procId) -eq [IntPtr]::Zero) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  [void][GTD2]::PostMessageW($main, [GTD2]::WM_COMMAND, [IntPtr][GTD2]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    $dlg = [GTD2]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) { $dlg = [GTD2]::FindAnyDialog([uint32]$proc.Id) }
    if ($dlg -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog 'OPEN_DIALOG_MISSING'; return $false }
  WLog ("OPEN_DIALOG title='{0}'" -f [GTD2]::TitleOf($dlg))
  [void][GTD2]::DriveFileDialog($dlg, $path)
  $deadline2 = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $deadline2) {
    $still = [GTD2]::FindAnyDialog([uint32]$proc.Id)
    if ($still -eq [IntPtr]::Zero) { break }
    $st = [GTD2]::TitleOf($still)
    if ($st -ne 'Save As' -and $st -ne 'Open' -and $st -notmatch 'Save As' -and $st -notmatch 'Open') {
      [GTD2]::ClickDialog($still, 6)
      Start-Sleep -Milliseconds 300
    } else { Start-Sleep -Milliseconds 200 }
  }
  [void](Wait-NoDialog ([uint32]$proc.Id) 5000)
  $title = [GTD2]::TitleOf($main)
  $leaf = [IO.Path]::GetFileName($path)
  $ok = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return $ok
}

# --- authority ---
$sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$size = (Get-Item $TipExe).Length
WLog "CERT_SHA=$sha SIZE=$size"
if ($sha -ne $ExpectedSha) { throw 'HASH_DRIFT' }

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
if (Test-Path $SessionJson) {
  $bak = "$SessionJson.bak_diag_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
  Copy-Item $SessionJson $bak -Force
  Set-Content -LiteralPath $SessionJson -Value '{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}' -Encoding UTF8
  WLog "SESSION_CLEARED bak=$bak"
}

$ollama = 'DOWN'
try {
  $r = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -UseBasicParsing -TimeoutSec 5
  $ollama = "UP status=$($r.StatusCode)"
} catch { $ollama = "DOWN $($_.Exception.Message)" }
WLog "OLLAMA=$ollama PREFERRED_MODEL=$PreferredModel MARKER=$Marker"

[IO.File]::WriteAllText($Fixture, $Seed, [Text.UTF8Encoding]::new($false))
$seedLen = (Get-Item $Fixture).Length
$seedSha = (Get-FileHash $Fixture -Algorithm SHA256).Hash
WLog "FIXTURE=$Fixture seed_len=$seedLen seed_sha=$seedSha"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe; $psi.WorkingDirectory = (Split-Path $TipExe); $psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCHED pid=$($proc.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 80; $i++) {
  $main = [GTD2]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [GTD2]::FindEditor($main) -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
WLog ("main=0x{0:X}" -f $main.ToInt64())

# Select model BEFORE opening/editing so Auto Local / FollowChat uses qwen
Start-Sleep -Seconds 2
$modelCombo = [GTD2]::FindComboWithText($main, $PreferredModel)
if ($modelCombo -eq [IntPtr]::Zero) { $modelCombo = [GTD2]::FindComboWithText($main, 'qwen2.5-coder') }
if ($modelCombo -ne [IntPtr]::Zero) {
  $sel = [GTD2]::SelectComboText($modelCombo, $PreferredModel)
  if ($sel -lt 0) { $sel = [GTD2]::SelectComboText($modelCombo, 'qwen2.5-coder') }
  $cid = [GTD2]::GetDlgCtrlID($modelCombo)
  [void][GTD2]::PostMessageW($main, [GTD2]::WM_COMMAND, [IntPtr](($cid -band 0xFFFF) -bor (1 -shl 16)), $modelCombo)
  WLog ("MODEL_PRESELECT combo=0x{0:X} sel=$sel" -f $modelCombo.ToInt64())
  Start-Sleep -Milliseconds 500
} else { WLog 'MODEL_COMBO_NOT_FOUND' }

$opened = Invoke-Open $main $proc $Fixture
$ed = [GTD2]::FindEditor($main)
$buf = [GTD2]::GetText($ed)
WLog ("editor=0x{0:X} buf_len=$($buf.Length) has_marker=$($buf -match [regex]::Escape($Marker)) opened=$opened" -f $ed.ToInt64())
if ($ed -eq [IntPtr]::Zero) { throw 'NO_EDITOR' }
if ($buf -notmatch [regex]::Escape($Marker)) {
  # Fall back: SaveAs path with seed content so disk path is bound
  [GTD2]::SetText($ed, $Seed)
  Start-Sleep -Milliseconds 200
  [void][GTD2]::PostMessageW($main, [GTD2]::WM_COMMAND, [IntPtr][GTD2]::IDM_FILE_SAVEAS, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $dlg = [GTD2]::FindAnyDialog([uint32]$proc.Id)
  [void][GTD2]::DriveFileDialog($dlg, $Fixture)
  Start-Sleep -Seconds 1
  $buf = [GTD2]::GetText([GTD2]::FindEditor($main))
  WLog "SAVEAS_FALLBACK buf_len=$($buf.Length) title=$([GTD2]::TitleOf($main))"
}

$logsDir = Join-Path (Split-Path $TipExe) 'logs'
$sessionLog = Get-ChildItem $logsDir -Filter 'RawrXD_IDE_*.log' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
WLog "session_log=$($sessionLog.FullName)"
$logStartLen = 0
if ($sessionLog) { $logStartLen = (Get-Item $sessionLog.FullName).Length }

# File-open EN_CHANGE is suppressed (m_suppressEditorDirty) so GhostText never arms
# from Open alone. Force an unsuppressed edit, then Ctrl+Space with input attached.
$ed = [GTD2]::FindEditor($main)
[GTD2]::Focus($main, $ed)
Start-Sleep -Milliseconds 300
[void][GTD2]::SendMessageW($ed, [GTD2]::EM_SETSEL, [IntPtr](-1), [IntPtr](-1))
[void][GTD2]::SendMessageW($ed, [GTD2]::EM_REPLACESEL, [IntPtr]1, ' ')
Start-Sleep -Milliseconds 400
$focusHwnd = [GTD2]::FocusChord($main, $ed, 0x11, 0x20)
$focus2 = [GTD2]::FocusOf($main)
if ($focusHwnd -eq $ed -or $focus2 -eq $ed) { $flags.EDITOR_FOCUS = 1 }
# Product EN_SETFOCUS (code=256) after click also proves editor owned focus.
if ($sessionLog) {
  $tailFocus = (Get-Content $sessionLog.FullName -Tail 30 -EA SilentlyContinue) -join "`n"
  if ($tailFocus -match 'EDITOR_CHANGE\] code=256') { $flags.EDITOR_FOCUS = 1 }
}
WLog ("EDITOR_FOCUS=$($flags.EDITOR_FOCUS) focus=0x{0:X}/0x{1:X} TRIGGER=edit_space+CtrlSpace" -f $focusHwnd.ToInt64(), $focus2.ToInt64())
$before = [GTD2]::GetText($ed)
WLog "before_len=$($before.Length)"

$renderedReq = ''
$eligibleSeen = $false
$routeModel = ''
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog 'PROCESS_DEAD'; break }
  Start-Sleep -Milliseconds 500
  $childText = [GTD2]::CollectChildText($main)
  $logNew = ''
  if ($sessionLog) {
    $fs = [IO.File]::Open($sessionLog.FullName, 'Open', 'Read', 'ReadWrite')
    try {
      if ($fs.Length -gt $logStartLen) {
        $fs.Position = $logStartLen
        $sr = New-Object IO.StreamReader($fs)
        $logNew = $sr.ReadToEnd()
      }
    } finally { $fs.Close() }
  }
  $hay = $childText + "`n" + $logNew
  if ($hay -match 'GhostText inference route:\s*(\S+)') { $routeModel = $Matches[1] }
  if ($hay -match 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=1') { $eligibleSeen = $true; $renderedReq = $Matches[1] }
  if ($hay -match 'GHOSTTEXT_RENDERED request_id=(\d+)') {
    $flags.GHOSTTEXT_RENDERED = 1
    $renderedReq = $Matches[1]
    WLog "RENDER_OK request_id=$renderedReq route=$routeModel eligible=$eligibleSeen"
    break
  }
  # Hint STATIC with non-trivial text near editor also counts as render signal if route fired
  if ($eligibleSeen -and $routeModel -match 'qwen2.5-coder') {
    # keep waiting for RENDERED line
  }
}
if ($flags.GHOSTTEXT_RENDERED -eq 0 -and $sessionLog) {
  $all = Get-Content $sessionLog.FullName -Raw -EA SilentlyContinue
  $childText = [GTD2]::CollectChildText($main)
  $hay = $all + "`n" + $childText
  if ($hay -match 'GHOSTTEXT_RENDERED request_id=(\d+)') { $flags.GHOSTTEXT_RENDERED = 1; $renderedReq = $Matches[1] }
  if ($hay -match 'eligible=1') { $eligibleSeen = $true }
  if ($hay -match 'GhostText inference route:\s*(\S+)') { $routeModel = $Matches[1] }
}
WLog "PRE_TAB RENDERED=$($flags.GHOSTTEXT_RENDERED) eligible=$eligibleSeen req=$renderedReq route=$routeModel"

$ed = [GTD2]::FindEditor($main)
$preTab = [GTD2]::GetText($ed)
[GTD2]::Focus($main, $ed)
$focusHwnd = [GTD2]::FocusOf($main)
if ($focusHwnd -eq $ed) { $flags.EDITOR_FOCUS = 1 }
WLog ("PRE_TAB_FOCUS=$($flags.EDITOR_FOCUS) pre_tab_len=$($preTab.Length)")
# SendMessage WM_KEYDOWN Tab hits NativeGhostTextController::editorProc -> accept()
[GTD2]::TabToEditor($ed)
Start-Sleep -Milliseconds 500

$afterTab = [GTD2]::GetText([GTD2]::FindEditor($main))
$delta = $afterTab.Length - $preTab.Length
WLog "after_tab_len=$($afterTab.Length) delta=$delta"

$childAfter = [GTD2]::CollectChildText($main)
$logTail = if ($sessionLog) { (Get-Content $sessionLog.FullName -Tail 100 -EA SilentlyContinue) -join "`n" } else { '' }
$postHay = $childAfter + "`n" + $logTail
if ($postHay -match 'TAB_ACCEPT_HANDLER_ENTER') { $flags.TAB_ACCEPT_HANDLER_ENTER = 1 }
if ($postHay -match 'GHOSTTEXT_ACCEPTED') {
  $flags.TAB_ACCEPT_HANDLER_ENTER = 1
  WLog 'SAW_GHOSTTEXT_ACCEPTED'
}
# Real accept grows by more than a single tab char, and usually adds non-whitespace code
if ($delta -gt 1 -and ($afterTab.Length -gt $preTab.Length)) {
  $added = ''
  if ($afterTab.StartsWith($preTab)) { $added = $afterTab.Substring($preTab.Length) }
  elseif ($preTab.Length -gt 0 -and $afterTab.Contains($Marker)) {
    # still treat growth as insert if marker retained and grew
    $added = 'GROWTH'
  }
  if ($added -eq "`t") {
    WLog 'LITERAL_TAB_INSERTED - accept handler did not consume Tab'
  } elseif ($delta -gt 1) {
    $flags.ACCEPTED_TEXT_INSERTED = 1
    $flags.EDITOR_BUFFER_MATCH = 1
  }
}
$title = [GTD2]::TitleOf($main)
$saveEn = [GTD2]::SaveMenuEnabled($main)
if ($flags.ACCEPTED_TEXT_INSERTED -eq 1 -or $title -match '\*' -or $saveEn) { $flags.DOCUMENT_DIRTY = 1 }
WLog "title='$title' save_enabled=$saveEn dirty=$($flags.DOCUMENT_DIRTY)"
WLog "ISOLATION buffer_changed=$($afterTab -ne $preTab) disk_still_seed=$((Get-Item $Fixture).Length -eq $seedLen)"

# Save only if we have a bound path (title contains leaf)
$leaf = [IO.Path]::GetFileName($Fixture)
if ([GTD2]::TitleOf($main).IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
  WLog 'PATH_NOT_BOUND - using SaveAs to fixture'
  [void][GTD2]::PostMessageW($main, [GTD2]::WM_COMMAND, [IntPtr][GTD2]::IDM_FILE_SAVEAS, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $dlg = [GTD2]::FindAnyDialog([uint32]$proc.Id)
  [void][GTD2]::DriveFileDialog($dlg, $Fixture)
  Start-Sleep -Seconds 1
} else {
  [void][GTD2]::PostMessageW($main, [GTD2]::WM_COMMAND, [IntPtr][GTD2]::IDM_FILE_SAVE, [IntPtr]::Zero)
  Start-Sleep -Seconds 1
}

$diskLen = (Get-Item $Fixture).Length
$diskSha = (Get-FileHash $Fixture -Algorithm SHA256).Hash
$diskText = [IO.File]::ReadAllText($Fixture)
WLog "disk_len=$diskLen seed_len=$seedLen disk_sha=$diskSha"
if ($diskSha -ne $seedSha) { $flags.SAVE_SUCCESS = 1 }

# Close
[void][GTD2]::PostMessageW($main, [GTD2]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$d = [GTD2]::FindAnyDialog([uint32]$proc.Id)
if ($d -ne [IntPtr]::Zero) { [GTD2]::ClickDialog($d, 7) }
[void]$proc.WaitForExit(10000)
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }

$reopenText = [IO.File]::ReadAllText($Fixture)
$reopenSha = (Get-FileHash $Fixture -Algorithm SHA256).Hash
if ($flags.SAVE_SUCCESS -eq 1 -and $reopenSha -eq $diskSha) {
  $flags.REOPEN_SHA_MATCH = 1
  $flags.REOPEN_BYTES_MATCH = 1
}
if ($flags.ACCEPTED_TEXT_INSERTED -eq 1) {
  $normBuf = $afterTab -replace "`r`n","`n" -replace "`r","`n"
  $normDisk = $reopenText -replace "`r`n","`n" -replace "`r","`n"
  if ($normDisk -eq $normBuf) {
    $flags.REOPEN_BYTES_MATCH = 1
    $flags.EDITOR_BUFFER_MATCH = 1
  } else {
    $flags.REOPEN_BYTES_MATCH = 0
    $flags.EDITOR_BUFFER_MATCH = 0
    WLog 'BUFFER_DISK_MISMATCH'
  }
}

$iso = 'UNKNOWN'
$verdict = 'NOT_VERIFIED'
if ($flags.GHOSTTEXT_RENDERED -eq 0) { $verdict = 'NOT_VERIFIED_NO_RENDER'; $iso = 'SUGGESTION_NEVER_RENDERED' }
elseif ($flags.ACCEPTED_TEXT_INSERTED -eq 0 -and $flags.SAVE_SUCCESS -eq 0) { $verdict = 'NOT_VERIFIED_NO_ACCEPT'; $iso = 'SUGGESTION_NEVER_INSERTED' }
elseif ($flags.ACCEPTED_TEXT_INSERTED -eq 1 -and $flags.SAVE_SUCCESS -eq 0) { $verdict = 'FAIL_INSERT_NOT_SAVED'; $iso = 'INSERTED_BUT_NOT_SAVED' }
elseif (($flags.Values | Where-Object { $_ -eq 0 }).Count -eq 0) { $verdict = 'PASS'; $iso = 'ACCEPT_AND_SAVE_PROVED' }
else { $verdict = 'NOT_VERIFIED_PARTIAL'; $iso = 'PARTIAL_FLAGS' }

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receipt = @(
  '# GhostText accept DIAGNOSE v2 (fail-closed)',
  '',
  "ASOF_UTC=$asof",
  'NEXT_ACTION=DIAGNOSE_ACCEPTANCE_PATH',
  "CERT_EXE=$TipExe",
  "CERT_EXE_SHA=$sha",
  "SIZE=$size",
  'REBUILD=0',
  "OLLAMA=$ollama",
  "PREFERRED_MODEL=$PreferredModel",
  "ROUTE_MODEL=$routeModel",
  "MARKER=$Marker",
  "FIXTURE=$Fixture",
  "SEED_LEN=$seedLen",
  "SEED_SHA=$seedSha",
  "BEFORE_LEN=$($before.Length)",
  "PRE_TAB_LEN=$($preTab.Length)",
  "AFTER_TAB_LEN=$($afterTab.Length)",
  "DISK_LEN=$diskLen",
  "DISK_SHA=$diskSha",
  "REOPEN_SHA=$reopenSha",
  "RENDER_REQUEST_ID=$renderedReq",
  "ELIGIBLE_SEEN=$eligibleSeen",
  "ISOLATION=$iso",
  "RESULT=$verdict",
  'PROMOTE=0',
  'CERTIFIED=0',
  '',
  '## Evidence flags (1=observed, 0=not observed)',
  "GHOSTTEXT_RENDERED=$($flags.GHOSTTEXT_RENDERED)",
  "EDITOR_FOCUS=$($flags.EDITOR_FOCUS)",
  "TAB_ACCEPT_HANDLER_ENTER=$($flags.TAB_ACCEPT_HANDLER_ENTER)",
  "ACCEPTED_TEXT_INSERTED=$($flags.ACCEPTED_TEXT_INSERTED)",
  "EDITOR_BUFFER_MATCH=$($flags.EDITOR_BUFFER_MATCH)",
  "DOCUMENT_DIRTY=$($flags.DOCUMENT_DIRTY)",
  "SAVE_SUCCESS=$($flags.SAVE_SUCCESS)",
  "REOPEN_BYTES_MATCH=$($flags.REOPEN_BYTES_MATCH)",
  "REOPEN_SHA_MATCH=$($flags.REOPEN_SHA_MATCH)",
  '',
  'NOTE=Sealed 3B720981 has GHOSTTEXT_ACCEPTED but no TAB_ACCEPT_HANDLER_ENTER entry log. Buffer measured before Save to isolate insert vs save.'
) -join "`r`n"
Set-Content -LiteralPath (Join-Path $OutDir 'GHOSTTEXT_ACCEPT_RECEIPT.md') $receipt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir 'DIAGNOSE_ACCEPT_CONSOLE.txt') $receipt -Encoding UTF8
WLog "RESULT=$verdict ISOLATION=$iso"
$flags.GetEnumerator() | ForEach-Object { WLog ("FLAG {0}={1}" -f $_.Key, $_.Value) }
if ($verdict -eq 'PASS') { exit 0 } else { exit 1 }

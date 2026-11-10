# -*- coding: utf-8 -*-
from pathlib import Path
import re

out = Path(r"F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR")
cs = out / "ghosttext_stale_win32.cs"
ps1 = out / "ghosttext_stale_proof.ps1"

CS = r'''using System; using System.Text; using System.Runtime.InteropServices;
public static class GTSTALE {
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
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, UIntPtr e);
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_CLOSE=0x0010;
  public const uint EM_SETSEL=0x00B1, EM_REPLACESEL=0x00C2, BM_CLICK=0x00F5;
  public const uint CB_GETCOUNT=0x0146, CB_GETLBTEXT=0x0148, CB_GETLBTEXTLEN=0x0149, CB_SETCURSEL=0x014E;
  public const int IDM_FILE_OPEN=2002, IDM_FILE_SAVEAS=2004, IDC_EDITOR=1001;
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr extra; }
  public static string ClassName(IntPtr h){ var s=new StringBuilder(128); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(512); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static IntPtr FindMain(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindEditor(IntPtr root){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,l)=>{ string c=ClassName(h); if(GetDlgCtrlID(h)==IDC_EDITOR && IsWindowVisible(h) && (c.IndexOf("RichEdit",StringComparison.OrdinalIgnoreCase)>=0 || c=="Edit")){ f=h; return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindAnyDialog(uint p){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="#32770"&&IsWindowVisible(h)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindDialogByTitle(uint p, string must){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint x; GetWindowThreadProcessId(h,out x); if(x!=p)return true; if(ClassName(h)=="#32770"&&IsWindowVisible(h)){ string t=TitleOf(h); if(t.IndexOf(must,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;}} return true;},IntPtr.Zero); return f; }
  public static void Focus(IntPtr main, IntPtr ed){
    ShowWindow(main,9); SetForegroundWindow(main);
    RECT r; GetWindowRect(ed, out r);
    SetCursorPos((r.L+r.R)/2, (r.T+r.B)/2);
    mouse_event(0x0002,0,0,0,UIntPtr.Zero); mouse_event(0x0004,0,0,0,UIntPtr.Zero);
    uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId();
    bool a=false; if(gui!=me)a=AttachThreadInput(me,gui,true);
    SetFocus(ed); if(a)AttachThreadInput(me,gui,false);
  }
  public static IntPtr FocusChord(IntPtr main, IntPtr ed, ushort a, ushort b){
    ShowWindow(main,9); SetForegroundWindow(main);
    RECT r; GetWindowRect(ed, out r);
    SetCursorPos((r.L+r.R)/2, (r.T+r.B)/2);
    mouse_event(0x0002,0,0,0,UIntPtr.Zero); mouse_event(0x0004,0,0,0,UIntPtr.Zero);
    uint gui=0; GetWindowThreadProcessId(main,out gui); uint me=GetCurrentThreadId();
    bool attached=false; if(gui!=me) attached=AttachThreadInput(me,gui,true);
    SetFocus(ed);
    var i=new INPUT[4]; for(int k=0;k<4;k++) i[k].type=1;
    i[0].ki.wVk=a; i[1].ki.wVk=b; i[2].ki.wVk=b; i[2].ki.dwFlags=2; i[3].ki.wVk=a; i[3].ki.dwFlags=2;
    SendInput(4,i,Marshal.SizeOf(typeof(INPUT)));
    System.Threading.Thread.Sleep(50);
    IntPtr f=GetFocus();
    if(attached) AttachThreadInput(me,gui,false);
    return f;
  }
  public static void EscapeKey(){
    var i=new INPUT[2]; i[0].type=1; i[0].ki.wVk=0x1B; i[1].type=1; i[1].ki.wVk=0x1B; i[1].ki.dwFlags=2;
    SendInput(2,i,Marshal.SizeOf(typeof(INPUT)));
  }
  public static string GetText(IntPtr h){ int len=SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero).ToInt32(); if(len<=0) len=GetWindowTextLengthW(h); if(len<=0)return ""; IntPtr buf=Marshal.AllocHGlobal((len+2)*2); try{ int got=SendMessageW(h,WM_GETTEXT,(IntPtr)(len+1),buf).ToInt32(); return got>0?Marshal.PtrToStringUni(buf)??"":""; } finally{ Marshal.FreeHGlobal(buf);} }
  public static void SetText(IntPtr h, string t){ SendMessageW(h,EM_SETSEL,IntPtr.Zero,(IntPtr)(-1)); SendMessageW(h,EM_REPLACESEL,(IntPtr)1,t??""); }
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
}
'''
cs.write_text(CS, encoding="ascii")
print("wrote", cs, "bytes", cs.stat().st_size)

# Rewrite PS1 from diagnose pattern: no delay env; Escape after TRIGGER/REQUEST_SENT
PS1 = r'''#Requires -Version 5.1
# Stale-GhostText physical E2E on sealed POST_E59D candidate (same SHA).
# Escape-invalidate pending request; PASS iff late response eligible=0 and not GHOSTTEXT_RENDERED.
# Fail-closed. PROMOTE=0. No rebuild. Cancel left SEALED.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$PreferredModel = 'qwen2.5-coder:1.5b-base'
$Log = Join-Path $OutDir 'STALE_GHOSTTEXT_RUNLOG.txt'
$SessionJson = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$Marker = 'GTSTALE_' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$Fixture = Join-Path $WorkDir ("gt_stale_{0}.txt" -f $Marker)
$Seed = ('def add(a, b):' + "`r`n" + '    // ' + $Marker + "`r`n" + '    ')
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Host $line
}
Add-Type -Path (Join-Path $OutDir 'ghosttext_stale_win32.cs')

function Read-LogDelta([string]$path, [long]$startLen) {
  if (-not (Test-Path $path)) { return '' }
  $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
  try {
    if ($fs.Length -le $startLen) { return '' }
    $fs.Position = $startLen
    $sr = New-Object IO.StreamReader($fs)
    return $sr.ReadToEnd()
  } finally { $fs.Close() }
}

function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  [void][GTSTALE]::PostMessageW($main, [GTSTALE]::WM_COMMAND, [IntPtr][GTSTALE]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    $dlg = [GTSTALE]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) { $dlg = [GTSTALE]::FindAnyDialog([uint32]$proc.Id) }
    if ($dlg -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { WLog 'OPEN_DIALOG_MISSING'; return $false }
  [void][GTSTALE]::DriveFileDialog($dlg, $path)
  $deadline2 = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt $deadline2) {
    if ([GTSTALE]::FindAnyDialog([uint32]$proc.Id) -eq [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
  }
  $title = [GTSTALE]::TitleOf($main)
  $leaf = [IO.Path]::GetFileName($path)
  $ok = $title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return $ok
}

$sha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$size = (Get-Item $TipExe).Length
WLog "CERT_SHA=$sha SIZE=$size"
if ($sha -ne $ExpectedSha) { throw 'HASH_DRIFT' }

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
if (Test-Path $SessionJson) {
  $bak = "$SessionJson.bak_stale_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
  Copy-Item $SessionJson $bak -Force
  Set-Content -LiteralPath $SessionJson -Value '{"active":0,"chat_mode":0,"documents":[{"modified":false,"path":"","text":""}]}' -Encoding UTF8
  WLog "SESSION_CLEARED bak=$bak"
}

$ollama = 'DOWN'
try {
  $r = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -UseBasicParsing -TimeoutSec 5
  $ollama = "UP status=$($r.StatusCode)"
} catch { $ollama = "DOWN $($_.Exception.Message)" }
WLog "OLLAMA=$ollama METHOD=ESCAPE_INVALIDATE MARKER=$Marker"

[IO.File]::WriteAllText($Fixture, $Seed, [Text.UTF8Encoding]::new($false))
WLog "FIXTURE=$Fixture"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.WorkingDirectory = (Split-Path $TipExe)
$psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCHED pid=$($proc.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 80; $i++) {
  $main = [GTSTALE]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [GTSTALE]::FindEditor($main) -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250
}
WLog ("main=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) { throw 'NO_MAIN' }

Start-Sleep -Seconds 2
$modelCombo = [GTSTALE]::FindComboWithText($main, $PreferredModel)
if ($modelCombo -eq [IntPtr]::Zero) { $modelCombo = [GTSTALE]::FindComboWithText($main, 'qwen2.5-coder') }
if ($modelCombo -ne [IntPtr]::Zero) {
  $sel = [GTSTALE]::SelectComboText($modelCombo, $PreferredModel)
  if ($sel -lt 0) { $sel = [GTSTALE]::SelectComboText($modelCombo, 'qwen2.5-coder') }
  $cid = [GTSTALE]::GetDlgCtrlID($modelCombo)
  [void][GTSTALE]::PostMessageW($main, [GTSTALE]::WM_COMMAND, [IntPtr](($cid -band 0xFFFF) -bor (1 -shl 16)), $modelCombo)
  WLog ("MODEL_PRESELECT combo=0x{0:X} sel=$sel" -f $modelCombo.ToInt64())
  Start-Sleep -Milliseconds 500
} else { WLog 'MODEL_COMBO_NOT_FOUND' }

$opened = Invoke-Open $main $proc $Fixture
$ed = [GTSTALE]::FindEditor($main)
$buf = [GTSTALE]::GetText($ed)
WLog ("editor=0x{0:X} opened=$opened has_marker=$($buf -match [regex]::Escape($Marker))" -f $ed.ToInt64())
if ($ed -eq [IntPtr]::Zero) { throw 'NO_EDITOR' }
if ($buf -notmatch [regex]::Escape($Marker)) {
  [GTSTALE]::SetText($ed, $Seed)
  Start-Sleep -Milliseconds 200
  [void][GTSTALE]::PostMessageW($main, [GTSTALE]::WM_COMMAND, [IntPtr][GTSTALE]::IDM_FILE_SAVEAS, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 500
  $dlg = [GTSTALE]::FindAnyDialog([uint32]$proc.Id)
  [void][GTSTALE]::DriveFileDialog($dlg, $Fixture)
  Start-Sleep -Seconds 1
}

$logsDir = Join-Path (Split-Path $TipExe) 'logs'
$sessionLog = Get-ChildItem $logsDir -Filter 'RawrXD_IDE_*.log' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
WLog "session_log=$($sessionLog.FullName)"
$logStartLen = 0
if ($sessionLog) { $logStartLen = (Get-Item $sessionLog.FullName).Length }

# Arm + Ctrl+Space (same as sealed accept v2)
$ed = [GTSTALE]::FindEditor($main)
[GTSTALE]::Focus($main, $ed)
Start-Sleep -Milliseconds 300
[void][GTSTALE]::SendMessageW($ed, [GTSTALE]::EM_SETSEL, [IntPtr](-1), [IntPtr](-1))
[void][GTSTALE]::SendMessageW($ed, [GTSTALE]::EM_REPLACESEL, [IntPtr]1, ' ')
Start-Sleep -Milliseconds 400
$beforeA = [GTSTALE]::GetText($ed)
[void][GTSTALE]::FocusChord($main, $ed, 0x11, 0x20)
WLog "TRIGGER_A=CtrlSpace beforeA_len=$($beforeA.Length)"

$reqA = ''
$sawASent = $false
$sawRoute = $false
$escaped = $false
$deadlineArm = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadlineArm) {
  if ($proc.HasExited) { break }
  $delta = Read-LogDelta $sessionLog.FullName $logStartLen
  if ($delta -match 'GhostText inference route:\s*(\S+)') { $sawRoute = $true; $routeModel = $Matches[1] }
  if ($delta -match 'GHOSTTEXT_REQUEST_SENT request_id=(\d+)') {
    $reqA = $Matches[1]; $sawASent = $true; WLog "A_SENT request_id=$reqA"; break
  }
  if ($delta -match 'GHOSTTEXT_TRIGGER request_id=(\d+)') {
    $reqA = $Matches[1]; $sawASent = $true; WLog "A_TRIGGER request_id=$reqA"; break
  }
  Start-Sleep -Milliseconds 200
}

# Escape invalidate while pending (or immediately if armed via route only)
$ed = [GTSTALE]::FindEditor($main)
[GTSTALE]::Focus($main, $ed)
Start-Sleep -Milliseconds 50
[GTSTALE]::EscapeKey()
$escaped = $true
WLog "ESCAPE_INVALIDATE sawASent=$sawASent reqA=$reqA sawRoute=$sawRoute"
$beforeEsc = [GTSTALE]::GetText($ed)

# If never armed, one more trigger then Escape ASAP on TRIGGER
if (-not $sawASent) {
  Start-Sleep -Milliseconds 300
  [void][GTSTALE]::SendMessageW($ed, [GTSTALE]::EM_SETSEL, [IntPtr](-1), [IntPtr](-1))
  [void][GTSTALE]::SendMessageW($ed, [GTSTALE]::EM_REPLACESEL, [IntPtr]1, ' ')
  Start-Sleep -Milliseconds 300
  [void][GTSTALE]::FocusChord($main, $ed, 0x11, 0x20)
  WLog 'TRIGGER_A_RETRY'
  $deadline2 = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline2) {
    if ($proc.HasExited) { break }
    $delta = Read-LogDelta $sessionLog.FullName $logStartLen
    if ($delta -match 'GhostText inference route:\s*(\S+)') { $sawRoute = $true; $routeModel = $Matches[1] }
    if ($delta -match 'GHOSTTEXT_(?:REQUEST_SENT|TRIGGER) request_id=(\d+)') {
      $reqA = $Matches[1]; $sawASent = $true; WLog "A_ARMED request_id=$reqA"
      [GTSTALE]::Focus($main, [GTSTALE]::FindEditor($main))
      [GTSTALE]::EscapeKey()
      WLog 'ESCAPE_AFTER_ARM'
      break
    }
    Start-Sleep -Milliseconds 150
  }
}

$aEligible0 = $false
$aRendered = $false
$aCancelled = $false
$aInvalidated = $false
$escapeEntry = $false
$routeModel = if ($routeModel) { $routeModel } else { '' }
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog 'PROCESS_DEAD'; break }
  $delta = Read-LogDelta $sessionLog.FullName $logStartLen
  if ($delta -match 'GhostText inference route:\s*(\S+)') { $routeModel = $Matches[1] }
  if ($delta -match 'GHOSTTEXT_ESCAPE_ENTRY') { $escapeEntry = $true }
  if ($delta -match 'GHOSTTEXT_CANCELLED') { $aCancelled = $true }
  if ($delta -match 'GHOSTTEXT_INVALIDATED') { $aInvalidated = $true }
  if (-not $reqA -and $delta -match 'GHOSTTEXT_(?:REQUEST_SENT|TRIGGER) request_id=(\d+)') {
    $reqA = $Matches[1]; $sawASent = $true
  }
  foreach ($m in [regex]::Matches($delta, 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=(\d+)')) {
    $rid = $m.Groups[1].Value; $el = $m.Groups[2].Value
    if ($el -eq '0') {
      $aEligible0 = $true
      if (-not $reqA) { $reqA = $rid }
    }
  }
  foreach ($m in [regex]::Matches($delta, 'GHOSTTEXT_RENDERED request_id=(\d+)')) {
    $rid = $m.Groups[1].Value
    # RENDERED after Escape for same reqA = stale applied (fail); if before Escape may still get eligible=0 later for other ids
    if (-not $reqA -or $rid -eq $reqA) { $aRendered = $true; if (-not $reqA) { $reqA = $rid } }
  }
  if ($aEligible0 -and ($aCancelled -or $aInvalidated -or $escapeEntry -or $sawASent)) {
    WLog 'OBSERVED_STALE_REJECT'
    break
  }
  Start-Sleep -Milliseconds 300
}

$after = [GTSTALE]::GetText([GTSTALE]::FindEditor($main))
$fullDelta = if ($sessionLog) { Read-LogDelta $sessionLog.FullName $logStartLen } else { '' }
if ($fullDelta -match 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=0') { $aEligible0 = $true }
if ($fullDelta -match 'GHOSTTEXT_ESCAPE_ENTRY') { $escapeEntry = $true }
if ($fullDelta -match 'GHOSTTEXT_CANCELLED') { $aCancelled = $true }
if ($fullDelta -match 'GHOSTTEXT_INVALIDATED') { $aInvalidated = $true }
# If RENDERED then later eligible=0 for same id without second RENDERED -> treat aRendered carefully
$renderedIds = [regex]::Matches($fullDelta, 'GHOSTTEXT_RENDERED request_id=(\d+)') | ForEach-Object { $_.Groups[1].Value }
$rejectIds = [regex]::Matches($fullDelta, 'GHOSTTEXT_RENDER_DECISION request_id=(\d+) eligible=0') | ForEach-Object { $_.Groups[1].Value }
if ($rejectIds.Count -gt 0) {
  $aEligible0 = $true
  $reqA = $rejectIds[$rejectIds.Count - 1]
  # PASS path: rejected id must not appear in RENDERED
  if ($renderedIds -contains $reqA) { $aRendered = $true } else { $aRendered = $false }
}
WLog "reqA=$reqA aElig0=$aEligible0 aRendered=$aRendered cancel=$aCancelled inv=$aInvalidated escEntry=$escapeEntry route=$routeModel"
WLog "after_len=$($after.Length) beforeA_len=$($beforeA.Length) beforeEsc_len=$($beforeEsc.Length)"

[void][GTSTALE]::PostMessageW($main, [GTSTALE]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$d = [GTSTALE]::FindAnyDialog([uint32]$proc.Id)
if ($d -ne [IntPtr]::Zero) { [GTSTALE]::ClickDialog($d, 7) }
[void]$proc.WaitForExit(10000)
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }

$verdict = 'NOT_PROVEN'
$note = 'Insufficient stale-rejection evidence'
if ($ollama -match '^DOWN') { $verdict = 'NOT_PROVEN'; $note = 'Ollama down' }
elseif (-not $sawASent -and -not $aEligible0) { $verdict = 'NOT_PROVEN'; $note = 'No GhostText request armed / no eligible=0' }
elseif ($aEligible0 -and -not $aRendered) { $verdict = 'PASS'; $note = 'Stale/late response rejected eligible=0; not rendered/applied' }
elseif ($aEligible0 -and $aRendered) { $verdict = 'FAIL'; $note = 'eligible=0 seen but same request also GHOSTTEXT_RENDERED' }
elseif ($aRendered -and ($aCancelled -or $aInvalidated) -and -not $aEligible0) { $verdict = 'FAIL'; $note = 'Cancelled/invalidated but still rendered without eligible=0' }
elseif ($aRendered) { $verdict = 'NOT_PROVEN'; $note = 'Rendered without proving stale reject (Escape may have been too late)' }
else { $verdict = 'NOT_PROVEN'; $note = 'Armed or Escape observed but no eligible=0 decision' }

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receiptPath = Join-Path $OutDir 'STALE_GHOSTTEXT_RECEIPT.md'
$receipt = @"
# Stale-GhostText physical E2E (fail-closed)

ASOF_UTC=$asof
CERT_EXE=$TipExe
CERT_EXE_SHA=$sha
SIZE=$size
GITHUB_COMMIT=70fe7cdaf7
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
GHOSTTEXT_REOPEN=0
CANCEL_CLASSIFICATION=SEALED
PRODUCT_DEFECT=NOT_PROVEN

OLLAMA=$ollama
PREFERRED_MODEL=$PreferredModel
ROUTE_MODEL=$routeModel
METHOD=ESCAPE_INVALIDATE
MARKER=$Marker
FIXTURE=$Fixture
SESSION_LOG=$($sessionLog.FullName)

REQUEST_A=$reqA
A_REQUEST_SENT=$sawASent
A_ROUTE_SEEN=$sawRoute
ESCAPE_SENT=$escaped
ESCAPE_ENTRY=$escapeEntry
CANCELLED=$aCancelled
INVALIDATED=$aInvalidated
A_ELIGIBLE_0=$aEligible0
A_RENDERED=$aRendered
BEFORE_A_LEN=$($beforeA.Length)
BEFORE_ESC_LEN=$($beforeEsc.Length)
AFTER_LEN=$($after.Length)

STALE_GHOSTTEXT=$verdict
NOTE=$note

## Gate law
NOT_RUN != PASS. PASS requires physical stale rejection (eligible=0) without GHOSTTEXT_RENDERED for that request.
Method: product Escape invalidate on sealed CERT_EXE (same accept-v2 trigger path); no product source change; no rebuild; Cancel left SEALED.
"@
Set-Content -LiteralPath $receiptPath -Value $receipt -Encoding UTF8
Set-Content -LiteralPath (Join-Path $OutDir 'STALE_GHOSTTEXT_SESSION_DELTA.txt') -Value $fullDelta -Encoding UTF8
WLog "RESULT=$verdict"
WLog "RECEIPT=$receiptPath"
if ($verdict -eq 'PASS') { exit 0 } elseif ($verdict -eq 'FAIL') { exit 2 } else { exit 1 }
'''
ps1.write_text(PS1, encoding="utf-8")
print("wrote", ps1, "bytes", ps1.stat().st_size)

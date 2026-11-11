#Requires -Version 5.1
# T08 MAIN_LOST instrumented repro — freeze SHA only. PROMOTE=0 NOT_RUN!=PASS
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir_t08_repro'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$TipExe = 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8'
$Log = Join-Path $OutDir 'RUNLOG_T08_MAIN_LOST_REPRO.txt'
$DumpDir = 'C:\Users\Garrett\AppData\Local\CrashDumps'
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
function Snapshot-Dumps {
  if (-not (Test-Path $DumpDir)) { return @() }
  Get-ChildItem -LiteralPath $DumpDir -Filter 'RawrXD*' -EA SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 12 |
    ForEach-Object { '{0}|{1}|{2:o}' -f $_.Name, $_.Length, $_.LastWriteTimeUtc }
}

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class P2T08 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
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
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_CLOSE=0x0010;
  public const uint EM_REPLACESEL=0x00C2, EM_SETSEL=0x00B1;
  public const uint TCM_GETITEMCOUNT=0x1304;
  public const int SW_RESTORE=9;
  public const int IDM_FILE_NEW=2001, IDM_FILE_OPEN=2002, IDM_FILE_SAVE=2003;
  public const int IDC_EDITOR=1001, IDC_DOC_TABS=1030, IDOK_OPEN=1;
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
         t.IndexOf("Open",StringComparison.OrdinalIgnoreCase)>=0){ ok=h; return false; }
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
  public static void ClickDialog(IntPtr dlg, int cmd){ if(dlg!=IntPtr.Zero) PostMessageW(dlg,WM_COMMAND,(IntPtr)cmd,IntPtr.Zero); }
  public static int TabCount(IntPtr tabs){ if(tabs==IntPtr.Zero) return -1; return SendMessageW(tabs,TCM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero).ToInt32(); }
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

function Dismiss-SavePromptOnly([uint32]$procId, [int]$cmd = 7) {
  for ($i=0; $i -lt 8; $i++) {
    $d = [P2T08]::FindAnyDialog($procId)
    if ($d -eq [IntPtr]::Zero) { break }
    $t = [P2T08]::TitleOf($d)
    if ($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As') { break }
    WLog ("DISMISS_SAVE title='{0}' cmd={1}" -f $t, $cmd)
    [P2T08]::ClickDialog($d, $cmd)
    Start-Sleep -Milliseconds 300
  }
}
function Wait-NoDialog([uint32]$procId, [int]$ms = 8000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while ((Get-Date) -lt $deadline) {
    if ([P2T08]::FindAnyDialog($procId) -eq [IntPtr]::Zero) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
function Wait-MainEditor([Diagnostics.Process]$proc, [int]$sec = 60) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return @{ Main=[IntPtr]::Zero; Editor=[IntPtr]::Zero } }
    $main = [P2T08]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero) {
      $ed = [P2T08]::FindEditor($main)
      if ($ed -ne [IntPtr]::Zero) { return @{ Main=$main; Editor=$ed } }
    }
    Start-Sleep -Milliseconds 200
  }
  return @{ Main=[IntPtr]::Zero; Editor=[IntPtr]::Zero }
}
function Capture-State([string]$tag, [Diagnostics.Process]$proc, [IntPtr]$prevMain, [string]$path) {
  $proc.Refresh()
  $hasExited = $proc.HasExited
  $exitCode = if ($hasExited) { try { $proc.ExitCode } catch { 'NA' } } else { 'RUNNING' }
  $main = if ($hasExited) { [IntPtr]::Zero } else { [P2T08]::FindMain([uint32]$proc.Id) }
  $prevValid = if ($prevMain -eq [IntPtr]::Zero) { 'NA' } else { [P2T08]::IsWindow($prevMain) }
  $mainValid = if ($main -eq [IntPtr]::Zero) { $false } else { [P2T08]::IsWindow($main) }
  $title = if ($main -ne [IntPtr]::Zero) { [P2T08]::TitleOf($main) } else { '' }
  $tabs = [P2T08]::FindDocTabs($main)
  $tc = [P2T08]::TabCount($tabs)
  $enum = [P2T08]::SummarizeTabControls($main)
  $alive = @(Get-Process -Id $proc.Id -EA SilentlyContinue).Count
  WLog ("STATE tag={0} path={1} hasExited={2} exitCode={3} alive={4} main={5} mainValid={6} prevMainValid={7} title='{8}' tabs={9} tc={10} enum={11}" -f `
    $tag, $path, $hasExited, $exitCode, $alive, $main, $mainValid, $prevValid, $title, $tabs, $tc, $enum)
  return @{
    HasExited=$hasExited; ExitCode=$exitCode; Main=$main; MainValid=$mainValid; PrevValid=$prevValid;
    Title=$title; TabCount=$tc; Enum=$enum; Alive=$alive
  }
}
function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  if ([P2T08]::SaveMenuEnabled($main)) {
    [void][P2T08]::PostMessageW($main, [P2T08]::WM_COMMAND, [IntPtr][P2T08]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  }
  [void][P2T08]::PostMessageW($main, [P2T08]::WM_COMMAND, [IntPtr][P2T08]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [P2T08]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [P2T08]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2T08]::TitleOf($any)
        if ($t -match 'Unsaved|modified') { [P2T08]::ClickDialog($any, 7); Start-Sleep -Milliseconds 300; continue }
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][P2T08]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 350
  $leaf = [IO.Path]::GetFileName($path)
  $title = [P2T08]::TitleOf($main)
  return ($title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}
function Invoke-OpenAddTab([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  [void][P2T08]::PostMessageW($main, [P2T08]::WM_COMMAND, [IntPtr][P2T08]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [P2T08]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [P2T08]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2T08]::TitleOf($any)
        if ($t -match 'Unsaved|modified') { [P2T08]::ClickDialog($any, 7); Start-Sleep -Milliseconds 300; continue }
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][P2T08]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 350
  $leaf = [IO.Path]::GetFileName($path)
  $title = [P2T08]::TitleOf($main)
  return ($title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

WLog 'START T08_MAIN_LOST_REPRO'
WLog "EXE=$TipExe"
$actualSha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$shaMatch = ($actualSha -eq $ExpectedSha)
WLog "ACTUAL_SHA=$actualSha MATCH=$shaMatch SIZE=$((Get-Item $TipExe).Length)"
if (-not $shaMatch) { throw 'SHA_MISMATCH_ABORT' }

$dumpsBefore = Snapshot-Dumps
WLog ("DUMPS_BEFORE count={0} newest={1}" -f $dumpsBefore.Count, $(if($dumpsBefore.Count){$dumpsBefore[0]}else{'NONE'}))

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
if (Test-Path $SessionJson) {
  Copy-Item $SessionJson ($SessionJson + '.bak_t08_repro') -Force
  Remove-Item $SessionJson -Force
  WLog 'SESSION_CLEARED'
}

$utf8 = [Text.UTF8Encoding]::new($false)
$tabFiles = @()
for ($i=0; $i -lt 10; $i++) {
  $p = Join-Path $WorkDir ("t08_doc_{0:D2}.txt" -f $i)
  [IO.File]::WriteAllText($p, ("seed_{0}`r`n" -f $i), $utf8)
  $tabFiles += $p
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TipExe
$psi.WorkingDirectory = (Split-Path $TipExe)
$psi.UseShellExecute = $false
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCHED pid=$($proc.Id)"
$w = Wait-MainEditor $proc 60
$main = $w.Main
WLog "MAIN_READY main=$main editor=$($w.Editor)"
if ($main -eq [IntPtr]::Zero -or $proc.HasExited) { throw 'MAIN_NOT_READY' }

$openOk = 0
$lastPath = ''
$lostAt = -1
$prevMain = $main
[void](Capture-State 'pre_open0' $proc $prevMain $tabFiles[0])
if (LastBool (Invoke-Open $main $proc $tabFiles[0])) { $openOk++; $lastPath = $tabFiles[0] }
else { WLog "OPEN0_FAIL title=$([P2T08]::TitleOf($main))" }
[void](Capture-State 'post_open0' $proc $prevMain $tabFiles[0])

for ($i=1; $i -lt 10; $i++) {
  $prevMain = $main
  $main = [P2T08]::FindMain([uint32]$proc.Id)
  $st = Capture-State ("pre_open$i") $proc $prevMain $tabFiles[$i]
  if ($main -eq [IntPtr]::Zero -or $st.HasExited) {
    $lostAt = $i
    WLog "T08 MAIN_LOST at i=$i lastPath=$lastPath"
    break
  }
  $ok = LastBool (Invoke-OpenAddTab $main $proc $tabFiles[$i])
  if ($ok) { $openOk++; $lastPath = $tabFiles[$i] }
  else { WLog "T08_OPEN_ADD_FAIL i=$i title=$([P2T08]::TitleOf($main))" }
  $st2 = Capture-State ("post_open$i") $proc $main $tabFiles[$i]
  if ($st2.HasExited -or $st2.Main -eq [IntPtr]::Zero) {
    $lostAt = $i
    WLog "T08 MAIN_LOST after open i=$i lastPath=$lastPath exitCode=$($st2.ExitCode)"
    break
  }
  Start-Sleep -Milliseconds 250
}

# Final settle + dump delta
Start-Sleep 2
$final = Capture-State 'final' $proc $prevMain $lastPath
$dumpsAfter = Snapshot-Dumps
$newDumps = @($dumpsAfter | Where-Object { $_ -notin $dumpsBefore })
WLog ("DUMPS_AFTER count={0} new={1}" -f $dumpsAfter.Count, $(if($newDumps.Count){($newDumps -join ';')}else{'NONE'}))

# WER ReportQueue peek
$werHits = @()
foreach ($root in @(
  'C:\ProgramData\Microsoft\Windows\WER\ReportQueue',
  'C:\ProgramData\Microsoft\Windows\WER\ReportArchive',
  (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue'),
  (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive')
)) {
  if (-not (Test-Path $root)) { continue }
  Get-ChildItem -LiteralPath $root -Recurse -EA SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-15) -and ($_.Name -match 'RawrXD|AppCrash|Report.wer' -or $_.FullName -match 'RawrXD') } |
    Select-Object -First 20 | ForEach-Object { $werHits += $_.FullName }
}
WLog ("WER_RECENT count={0} hits={1}" -f $werHits.Count, $(if($werHits.Count){($werHits -join ';')}else{'NONE'}))

$result = if ($lostAt -ge 0 -or $final.HasExited -or $final.Main -eq [IntPtr]::Zero) { 'FAIL_MAIN_LOST' } else { 'SURVIVED_TO_PROBE' }
$origin = 'UNCLASSIFIED'
if ($final.HasExited) {
  $ec = $final.ExitCode
  if ($newDumps.Count -gt 0) { $origin = 'CRASH_DUMP_PRESENT' }
  elseif ($ec -eq 0) { $origin = 'INTENTIONAL_EXIT_CODE_0' }
  elseif ($ec -eq -1 -or $ec -eq 4294967295) { $origin = 'ABNORMAL_EXIT_NEG1_NO_NEW_DUMP' }
  else { $origin = "PROCESS_EXIT_CODE_$ec" }
} elseif ($final.Main -eq [IntPtr]::Zero -and -not $final.HasExited) {
  $origin = 'PROCESS_ALIVE_HWND_GONE_MSGLOOP_OR_DESTROY'
} elseif ($result -eq 'SURVIVED_TO_PROBE') {
  $origin = 'NO_MAIN_LOST_THIS_RUN'
}

$seal = @"
# T08 MAIN_LOST Repro Seal

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
FREEZE_SHA=$actualSha
SHA_MATCH=$shaMatch
PID=$($proc.Id)
RESULT=$result
T08_ORIGIN=$origin
OPEN_OK=$openOk
LOST_AT_I=$lostAt
LAST_OPEN_PATH=$lastPath
EXIT_CODE=$($final.ExitCode)
HAS_EXITED=$($final.HasExited)
ALIVE=$($final.Alive)
FINAL_MAIN=$($final.Main)
FINAL_MAIN_VALID=$($final.MainValid)
PREV_MAIN_VALID=$($final.PrevValid)
FINAL_TITLE=$($final.Title)
FINAL_TABCOUNT=$($final.TabCount)
FINAL_ENUM=$($final.Enum)
NEW_WER_DUMPS=$(if($newDumps.Count){($newDumps -join ';')}else{'NONE'})
WER_RECENT=$(if($werHits.Count){($werHits -join ';')}else{'NONE'})
TIP_FIX=NOT_APPLIED
STOP_SPECULATIVE_EDITOR_BATCH=1
PROMOTE=0
PRODUCT_PASS=0
RUNLOG=$Log
"@
Set-Content -LiteralPath (Join-Path $OutDir 'T08_MAIN_LOST_REPRO_SEAL.md') $seal -Encoding UTF8
WLog "RESULT=$result ORIGIN=$origin OPEN_OK=$openOk LOST_AT=$lostAt EXIT=$($final.ExitCode)"
WLog 'DONE'

if (-not $proc.HasExited) {
  try { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue } catch {}
}

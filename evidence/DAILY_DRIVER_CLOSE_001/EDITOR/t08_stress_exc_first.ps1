#Requires -Version 5.1
# T08 stress: multi-open until exit=-1; procdump -e -ma + LocalDumps. PROMOTE=0
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR'
$WorkDir = Join-Path $OutDir 'workdir_t08_repro'
$DumpRoot = Join-Path $OutDir 'dumps_t08_neg1'
$CrashDumps = 'C:\Users\Garrett\AppData\Local\CrashDumps'
New-Item -ItemType Directory -Force -Path $WorkDir,$DumpRoot | Out-Null
$TipExe = 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8'
$ProcDump = 'F:\rawrxd\scripts\procdump_tools\procdump64.exe'
$Log = Join-Path $OutDir 'RUNLOG_T08_STRESS_EXC_FIRST.txt'
$SessionJson = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$MaxRuns = 8
$SettleSec = 8
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
function Snapshot-AllDumps {
  $items = @()
  foreach ($d in @($DumpRoot,$CrashDumps)) {
    if (-not (Test-Path $d)) { continue }
    Get-ChildItem -LiteralPath $d -Include '*.dmp','*.mdmp' -Recurse -EA SilentlyContinue |
      ForEach-Object { $items += ('{0}|{1}|{2:o}' -f $_.FullName, $_.Length, $_.LastWriteTimeUtc) }
  }
  return $items
}

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class P2T08S {
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
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C;
  public const uint EM_REPLACESEL=0x00C2, EM_SETSEL=0x00B1;
  public const uint TCM_GETITEMCOUNT=0x1304;
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
      if(id==1 || id==IDOK_OPEN || t.IndexOf("Open",StringComparison.OrdinalIgnoreCase)>=0){ ok=h; return false; }
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
    $d = [P2T08S]::FindAnyDialog($procId)
    if ($d -eq [IntPtr]::Zero) { break }
    $t = [P2T08S]::TitleOf($d)
    if ($t -eq 'Save As' -or $t -eq 'Open' -or $t -match 'Save As') { break }
    [P2T08S]::ClickDialog($d, $cmd)
    Start-Sleep -Milliseconds 300
  }
}
function Wait-NoDialog([uint32]$procId, [int]$ms = 8000) {
  $deadline = (Get-Date).AddMilliseconds($ms)
  while ((Get-Date) -lt $deadline) {
    if ([P2T08S]::FindAnyDialog($procId) -eq [IntPtr]::Zero) { return $true }
    Start-Sleep -Milliseconds 100
  }
  return $false
}
function Wait-MainEditor([Diagnostics.Process]$proc, [int]$sec = 60) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return @{ Main=[IntPtr]::Zero; Editor=[IntPtr]::Zero } }
    $main = [P2T08S]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero) {
      $ed = [P2T08S]::FindEditor($main)
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
  $main = if ($hasExited) { [IntPtr]::Zero } else { [P2T08S]::FindMain([uint32]$proc.Id) }
  $prevValid = if ($prevMain -eq [IntPtr]::Zero) { 'NA' } else { [P2T08S]::IsWindow($prevMain) }
  $mainValid = if ($main -eq [IntPtr]::Zero) { $false } else { [P2T08S]::IsWindow($main) }
  $title = if ($main -ne [IntPtr]::Zero) { [P2T08S]::TitleOf($main) } else { '' }
  $tabs = [P2T08S]::FindDocTabs($main)
  $tc = [P2T08S]::TabCount($tabs)
  $enum = [P2T08S]::SummarizeTabControls($main)
  $alive = @(Get-Process -Id $proc.Id -EA SilentlyContinue).Count
  WLog ("STATE tag={0} path={1} hasExited={2} exitCode={3} alive={4} main={5} mainValid={6} prevMainValid={7} title='{8}' tabs={9} tc={10} enum={11}" -f `
    $tag, $path, $hasExited, $exitCode, $alive, $main, $mainValid, $prevValid, $title, $tabs, $tc, $enum)
  return @{
    HasExited=$hasExited; ExitCode=$exitCode; Main=$main; MainValid=$mainValid; PrevValid=$prevValid;
    Title=$title; TabCount=$tc; Enum=$enum; Alive=$alive
  }
}
function Invoke-Open([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  if ([P2T08S]::SaveMenuEnabled($main)) {
    [void][P2T08S]::PostMessageW($main, [P2T08S]::WM_COMMAND, [IntPtr][P2T08S]::IDM_FILE_NEW, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 400
    [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  }
  [void][P2T08S]::PostMessageW($main, [P2T08S]::WM_COMMAND, [IntPtr][P2T08S]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [P2T08S]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [P2T08S]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2T08S]::TitleOf($any)
        if ($t -match 'Unsaved|modified') { [P2T08S]::ClickDialog($any, 7); Start-Sleep -Milliseconds 300; continue }
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][P2T08S]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 350
  $leaf = [IO.Path]::GetFileName($path)
  $title = [P2T08S]::TitleOf($main)
  return ($title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}
function Invoke-OpenAddTab([IntPtr]$main, [Diagnostics.Process]$proc, [string]$path) {
  [void][P2T08S]::PostMessageW($main, [P2T08S]::WM_COMMAND, [IntPtr][P2T08S]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 400
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(15)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return $false }
    $dlg = [P2T08S]::FindDialogByTitle([uint32]$proc.Id, 'Open')
    if ($dlg -eq [IntPtr]::Zero) {
      $any = [P2T08S]::FindAnyDialog([uint32]$proc.Id)
      if ($any -ne [IntPtr]::Zero) {
        $t = [P2T08S]::TitleOf($any)
        if ($t -match 'Unsaved|modified') { [P2T08S]::ClickDialog($any, 7); Start-Sleep -Milliseconds 300; continue }
        if ($t -eq '' -or $t -match 'Open') { $dlg = $any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if ($dlg -eq [IntPtr]::Zero) { return $false }
  [void][P2T08S]::DriveFileDialog($dlg, $path)
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  Start-Sleep -Milliseconds 350
  $leaf = [IO.Path]::GetFileName($path)
  $title = [P2T08S]::TitleOf($main)
  return ($title.IndexOf($leaf, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

WLog 'START T08_STRESS_EXC_FIRST'
WLog "EXE=$TipExe"
$actualSha = (Get-FileHash $TipExe -Algorithm SHA256).Hash
$shaMatch = ($actualSha -eq $ExpectedSha)
WLog "ACTUAL_SHA=$actualSha MATCH=$shaMatch SIZE=$((Get-Item $TipExe).Length)"
if (-not $shaMatch) { throw 'SHA_MISMATCH_ABORT' }
WLog "PROCDUMP=$ProcDump EXISTS=$([bool](Test-Path $ProcDump))"
WLog "DUMPROOT=$DumpRoot LOCALDUMPS_HKLM=1 LOCALDUMPS_HKCU=1"

$utf8 = [Text.UTF8Encoding]::new($false)
$tabFiles = @()
for ($i=0; $i -lt 10; $i++) {
  $p = Join-Path $WorkDir ("t08_doc_{0:D2}.txt" -f $i)
  [IO.File]::WriteAllText($p, ("seed_{0}`r`n" -f $i), $utf8)
  $tabFiles += $p
}

$runResults = @()
$reproHit = $null

for ($run=1; $run -le $MaxRuns; $run++) {
  WLog "==== STRESS_RUN=$run ===="
  Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' -or $_.ProcessName -like 'procdump*' } |
    Stop-Process -Force -EA SilentlyContinue
  Start-Sleep 1
  if (Test-Path $SessionJson) {
    Copy-Item $SessionJson ($SessionJson + '.bak_t08_stress') -Force -EA SilentlyContinue
    Remove-Item $SessionJson -Force -EA SilentlyContinue
    WLog 'SESSION_CLEARED'
  }
  $dumpsBefore = Snapshot-AllDumps
  WLog ("DUMPS_BEFORE count={0}" -f $dumpsBefore.Count)

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $TipExe
  $psi.WorkingDirectory = (Split-Path $TipExe)
  $psi.UseShellExecute = $false
  $proc = [Diagnostics.Process]::Start($psi)
  WLog "LAUNCHED pid=$($proc.Id)"

  $pdOut = Join-Path $DumpRoot ("procdump_exc_r{0}_{1}" -f $run, $proc.Id)
  $pdProc = $null
  if (Test-Path $ProcDump) {
    # Exception-first: -e 1 first-chance + -t terminate backup; -n 2
    $pdArgs = @('-accepteula','-e','1','-t','-ma','-n','2', $proc.Id, $pdOut)
    $pdProc = Start-Process -FilePath $ProcDump -ArgumentList $pdArgs -PassThru -WindowStyle Hidden
    WLog "PROCDUMP_ATTACHED pdPid=$($pdProc.Id) outPrefix=$pdOut"
    Start-Sleep -Milliseconds 500
  }

  $w = Wait-MainEditor $proc 60
  $main = $w.Main
  WLog "MAIN_READY main=$main editor=$($w.Editor)"
  if ($main -eq [IntPtr]::Zero -or $proc.HasExited) {
    WLog 'MAIN_NOT_READY'
    $runResults += [pscustomobject]@{ Run=$run; Result='MAIN_NOT_READY'; OpenOk=0; Exit='NA'; Dump='NONE' }
    if ($pdProc -and -not $pdProc.HasExited) { Stop-Process -Id $pdProc.Id -Force -EA SilentlyContinue }
    continue
  }

  $openOk = 0
  $lastPath = ''
  $lostAt = -1
  $prevMain = $main
  [void](Capture-State "r${run}_pre_open0" $proc $prevMain $tabFiles[0])
  if (LastBool (Invoke-Open $main $proc $tabFiles[0])) { $openOk++; $lastPath = $tabFiles[0] }
  else { WLog "OPEN0_FAIL title=$([P2T08S]::TitleOf($main))" }
  [void](Capture-State "r${run}_post_open0" $proc $prevMain $tabFiles[0])

  for ($i=1; $i -lt 10; $i++) {
    $prevMain = $main
    $main = [P2T08S]::FindMain([uint32]$proc.Id)
    $st = Capture-State ("r${run}_pre_open$i") $proc $prevMain $tabFiles[$i]
    if ($main -eq [IntPtr]::Zero -or $st.HasExited) {
      $lostAt = $i
      WLog "T08 MAIN_LOST at i=$i lastPath=$lastPath"
      break
    }
    $ok = LastBool (Invoke-OpenAddTab $main $proc $tabFiles[$i])
    if ($ok) { $openOk++; $lastPath = $tabFiles[$i] }
    else { WLog "T08_OPEN_ADD_FAIL i=$i title=$([P2T08S]::TitleOf($main))" }
    $st2 = Capture-State ("r${run}_post_open$i") $proc $main $tabFiles[$i]
    if ($st2.HasExited -or $st2.Main -eq [IntPtr]::Zero) {
      $lostAt = $i
      WLog "T08 MAIN_LOST after open i=$i lastPath=$lastPath exitCode=$($st2.ExitCode)"
      break
    }
    Start-Sleep -Milliseconds 250
  }

  # Extended settle â€” prior exit=-1 was post-settle ~2.3s after openOk=10
  for ($s=0; $s -lt $SettleSec; $s++) {
    Start-Sleep 1
    $settle = Capture-State ("r${run}_settle_$s") $proc $prevMain $lastPath
    if ($settle.HasExited -or $settle.Main -eq [IntPtr]::Zero) {
      if ($lostAt -lt 0) { $lostAt = 99 }
      WLog "SETTLE_LOST s=$s exit=$($settle.ExitCode)"
      break
    }
  }
  $final = Capture-State "r${run}_final" $proc $prevMain $lastPath
  Start-Sleep 2
  $dumpsAfter = Snapshot-AllDumps
  $newDumps = @($dumpsAfter | Where-Object { $_ -notin $dumpsBefore })
  # Also catch procdump files by prefix
  $pdFiles = @(Get-ChildItem -LiteralPath $DumpRoot -Filter ("procdump_exc_r{0}_{1}*.dmp" -f $run,$proc.Id) -EA SilentlyContinue)
  foreach ($f in $pdFiles) {
    $sig = '{0}|{1}|{2:o}' -f $f.FullName, $f.Length, $f.LastWriteTimeUtc
    if ($sig -notin $newDumps) { $newDumps += $sig }
  }
  $dumpPath = if ($newDumps.Count) { ($newDumps -join ';') } else { 'NONE' }
  WLog ("DUMPS_NEW count={0} path={1}" -f $newDumps.Count, $dumpPath)

  $result = if ($lostAt -ge 0 -or $final.HasExited -or $final.Main -eq [IntPtr]::Zero) { 'FAIL_MAIN_LOST' } else { 'SURVIVED' }
  $origin = 'UNCLASSIFIED'
  if ($final.HasExited) {
    $ec = $final.ExitCode
    if ($newDumps.Count -gt 0) { $origin = 'CRASH_DUMP_PRESENT' }
    elseif ($ec -eq 0) { $origin = 'INTENTIONAL_EXIT_CODE_0' }
    elseif ($ec -eq -1 -or $ec -eq 4294967295) { $origin = 'ABNORMAL_EXIT_NEG1_NO_NEW_DUMP' }
    else { $origin = "PROCESS_EXIT_CODE_$ec" }
  } elseif ($final.Main -eq [IntPtr]::Zero -and -not $final.HasExited) {
    $origin = 'PROCESS_ALIVE_HWND_GONE_MSGLOOP_OR_DESTROY'
  } elseif ($result -eq 'SURVIVED') {
    $origin = 'NO_MAIN_LOST_THIS_RUN'
  }

  $row = [pscustomobject]@{
    Run=$run; Result=$result; Origin=$origin; OpenOk=$openOk; LostAt=$lostAt;
    Exit=$final.ExitCode; Dump=$dumpPath; Pid=$proc.Id; TabCount=$final.TabCount; Enum=$final.Enum
  }
  $runResults += $row
  WLog ("RUN_RESULT run={0} result={1} origin={2} openOk={3} exit={4} dump={5}" -f $run,$result,$origin,$openOk,$final.ExitCode,$dumpPath)

  if ($pdProc -and -not $pdProc.HasExited) {
    try { Stop-Process -Id $pdProc.Id -Force -EA SilentlyContinue } catch {}
  }
  if (-not $proc.HasExited) {
    try { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue } catch {}
  }
  Start-Sleep 1

  if ($result -eq 'FAIL_MAIN_LOST' -and ($final.ExitCode -eq -1 -or $final.ExitCode -eq 4294967295 -or $newDumps.Count -gt 0)) {
    $reproHit = $row
    WLog 'REPRO_HIT_STOPPING'
    break
  }
}

# Seal
$hitDump = if ($reproHit) { $reproHit.Dump } else { 'NONE' }
$hitOrigin = if ($reproHit) { $reproHit.Origin } else { 'NOT_REPRODUCED_THIS_TURN' }
$survived = @($runResults | Where-Object { $_.Result -eq 'SURVIVED' }).Count
$failed = @($runResults | Where-Object { $_.Result -eq 'FAIL_MAIN_LOST' }).Count
$seal = @"
# T08 STRESS NEG1 DUMP Seal

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
FREEZE_SHA=$actualSha
SHA_MATCH=$shaMatch
SIZE=$((Get-Item $TipExe).Length)
EXE=$TipExe
LOCALDUMPS_HKLM=1
LOCALDUMPS_HKCU=1
PROCDUMP=-e 1 -t -ma -n 2 (exception-first) ($ProcDump)
RUNS_ATTEMPTED=$($runResults.Count)
SURVIVED=$survived
FAIL_MAIN_LOST=$failed
REPRO_HIT=$(if($reproHit){'1'}else{'0'})
T08_ORIGIN=$hitOrigin
OPEN_OK=$(if($reproHit){$reproHit.OpenOk}else{'N/A'})
EXIT_CODE=$(if($reproHit){$reproHit.Exit}else{'N/A'})
DUMP_PATH=$hitDump
TIP_FIX=NOT_APPLIED
CAUSALITY_PROVEN=0
STOP_SPECULATIVE_EDITOR_BATCH=1
PROMOTE=0
PRODUCT_PASS=0
CERTIFIED=0
INVENT_PASS=0
NOT_RUN!=PASS=1
RUNLOG=$Log
"@
Set-Content -LiteralPath (Join-Path $OutDir 'T08_NEG1_EXC_CAPTURE_SEAL.md') $seal -Encoding UTF8
$runResults | Format-Table -AutoSize | Out-String | Add-Content $Log
WLog "SUMMARY survived=$survived fail=$failed origin=$hitOrigin dump=$hitDump tip=NOT_APPLIED"
WLog 'DONE'


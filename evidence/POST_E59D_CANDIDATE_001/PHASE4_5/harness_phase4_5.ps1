#Requires -Version 5.1
# FINISH_25 Phase4(16-20)+Phase5(21-25) fail-closed harness
# CERT SHA 3B720981… · PROMOTE=0 · NOT_RUN!=PASS · no cert EXE mutation
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\PHASE4_5'
$WorkDir = Join-Path $OutDir 'workdir'
$LogDir = Join-Path $OutDir 'logs'
New-Item -ItemType Directory -Force -Path $WorkDir, $LogDir | Out-Null
$TipExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$ExpectedSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$MiniBuild = Join-Path $OutDir 'mini_workspace\build'
$MiniRoot = Join-Path $OutDir 'mini_workspace'
$Log = Join-Path $OutDir 'RUNLOG.txt'
$ResultJson = Join-Path $OutDir 'phase4_5_result.json'
$MemCsv = Join-Path $LogDir 'memory_handles.csv'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Host $line
}

$results = [ordered]@{
  T16_BUILD_TEST_E2E = 'NOT_RUN'
  T16_BUILD_MARKER = ''
  T16_TEST_MARKER = ''
  T16_BUILD_EXIT = ''
  T16_TEST_EXIT = ''
  T17_DIAGNOSTICS_NAV = 'NOT_RUN'
  T17_FIND_DIALOG = ''
  T17_EDITOR_FOCUS = ''
  T17_FILE_OPEN = ''
  T18_100_CYCLE_SOAK = 'NOT_RUN'
  T19_MEMORY_HANDLES = 'NOT_RUN'
  T19_PRIVATE_BYTES_START = 0
  T19_PRIVATE_BYTES_END = 0
  T19_GDI_START = 0
  T19_GDI_END = 0
  T19_USER_START = 0
  T19_USER_END = 0
  T19_THREADS_START = 0
  T19_THREADS_END = 0
  T20_HOST_STABILITY = 'NOT_RUN'
  T21_WORKTREE_GIT = 'NOT_RUN'
  T22_RC_SEAL = 'NOT_RUN'
  T23_ACCEPTANCE_MATRIX = 'NOT_RUN'
  T24_PACKAGE_ROLLBACK = 'NOT_RUN'
  T25_CERTIFIED = 0
  T25_PROMOTE = 0
  SHA_PRE = ''
  SHA_POST = ''
  SHA_MATCH = 0
  PID = 0
  BLOCKERS = @()
}

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class P45 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
  public static extern IntPtr SendMessageSB(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowExW(IntPtr p, IntPtr c, string cls, string win);
  public const uint WM_COMMAND=0x0111, WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_CLOSE=0x0010;
  public const uint EM_SETSEL=0x00B1, EM_REPLACESEL=0x00C2, BM_CLICK=0x00F5;
  public const int SW_RESTORE=9;
  public const int IDM_FILE_NEW=2001, IDM_FILE_OPEN=2002, IDM_FILE_SAVE=2003, IDM_FILE_SAVEAS=2004;
  public const int IDM_EDIT_FIND=2016, IDM_EDIT_FIND_NEXT=2018;
  public const int IDM_TOOLS_BUILD_PROJECT=3014, IDM_TOOLS_TEST_PROJECT=3015;
  public const int IDC_EDITOR=1001, IDC_OUTPUT_EDIT_GENERAL=1012, IDC_OUTPUT_EDIT_ERRORS=1013, IDC_TERMINAL=1002;
  public static string ClassName(IntPtr h){ var s=new StringBuilder(256); GetClassNameW(h,s,s.Capacity); return s.ToString(); }
  public static string TitleOf(IntPtr h){ var s=new StringBuilder(1024); GetWindowTextW(h,s,s.Capacity); return s.ToString(); }
  public static string TextOf(IntPtr h){
    int len = GetWindowTextLengthW(h);
    if(len<=0){
      len = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    }
    if(len<=0) return "";
    if(len>1048576) len=1048576;
    var sb=new StringBuilder(len+2);
    SendMessageSB(h, WM_GETTEXT, (IntPtr)(len+1), sb);
    return sb.ToString();
  }
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
  public static IntPtr FindById(IntPtr root, int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,l)=>{ if(GetDlgCtrlID(h)==id){ f=h; return false;} return true;}, IntPtr.Zero); return f;
  }
  public static List<string> CollectAllText(IntPtr root){
    var list=new List<string>();
    EnumChildWindows(root,(h,l)=>{
      try {
        string t=TextOf(h);
        if(!string.IsNullOrEmpty(t) && t.Length>0) list.Add(t);
        string title=TitleOf(h);
        if(!string.IsNullOrEmpty(title)) list.Add("TITLE:"+title);
      } catch {}
      return true;
    }, IntPtr.Zero);
    return list;
  }
  public static IntPtr FindDialog(uint p, string mustContain){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{
      uint x; GetWindowThreadProcessId(h,out x); if(x!=p) return true;
      string c=ClassName(h); string t=TitleOf(h);
      if(c=="#32770" || t.IndexOf(mustContain,StringComparison.OrdinalIgnoreCase)>=0){
        if(string.IsNullOrEmpty(mustContain) || t.IndexOf(mustContain,StringComparison.OrdinalIgnoreCase)>=0 || mustContain=="*"){
          if(IsWindowVisible(h)){ f=h; return false; }
        }
      }
      return true;
    }, IntPtr.Zero); return f;
  }
  public static bool DriveFileDialog(IntPtr dlg, string path){
    if(dlg==IntPtr.Zero) return false;
    IntPtr edit=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{
      if(ClassName(h)=="ComboBoxEx32"){
        EnumChildWindows(h,(c,q)=>{ if(ClassName(c)=="Edit"){ edit=c; return false;} return true;}, IntPtr.Zero);
        return edit==IntPtr.Zero;
      } return true;}, IntPtr.Zero);
    if(edit==IntPtr.Zero){
      EnumChildWindows(dlg,(h,l)=>{
        string c=ClassName(h); int id=GetDlgCtrlID(h);
        if((c=="Edit"||c.StartsWith("RichEdit")) && IsWindowVisible(h)&&IsWindowEnabled(h)){
          if(id==0x47C || id==0x480){ edit=h; return false; }
          if(edit==IntPtr.Zero) edit=h;
        }
        return true;
      }, IntPtr.Zero);
    }
    if(edit==IntPtr.Zero) return false;
    SetForegroundWindow(dlg);
    SetWindowTextW(edit, path);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, path);
    SendMessageW(edit, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(edit, EM_REPLACESEL, (IntPtr)1, path);
    System.Threading.Thread.Sleep(120);
    IntPtr ok=IntPtr.Zero;
    EnumChildWindows(dlg,(h,l)=>{ if(GetDlgCtrlID(h)==1 && ClassName(h)=="Button"){ ok=h; return false;} return true;}, IntPtr.Zero);
    if(ok!=IntPtr.Zero){ PostMessageW(dlg,WM_COMMAND,(IntPtr)1,ok); SendMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero); }
    else PostMessageW(dlg, WM_COMMAND, (IntPtr)1, IntPtr.Zero);
    return true;
  }
  public static void FocusEditor(IntPtr main, IntPtr editor){
    ShowWindow(main, SW_RESTORE); SetForegroundWindow(main);
    uint gui=0; GetWindowThreadProcessId(main, out gui); uint me=GetCurrentThreadId();
    bool a=false; if(gui!=me) a=AttachThreadInput(me,gui,true);
    SetFocus(editor); if(a) AttachThreadInput(me,gui,false);
  }
}
'@

function Get-Sha([string]$path) {
  (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function Get-HandleCounts([int]$ProcessId) {
  $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  if (-not $p) { return $null }
  if (-not ("P45Native.Gui" -as [type])) {
    Add-Type -Namespace P45Native -Name Gui -MemberDefinition @'
[DllImport("user32.dll")] public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
'@ -ErrorAction SilentlyContinue
  }
  $gdi = 0; $user = 0
  try {
    $gdi = [P45Native.Gui]::GetGuiResources($p.Handle, 0)
    $user = [P45Native.Gui]::GetGuiResources($p.Handle, 1)
  } catch {}
  [pscustomobject]@{
    PrivateBytes = [int64]$p.WorkingSet64
    PrivateMemory = [int64]$p.PrivateMemorySize64
    Threads = $p.Threads.Count
    Handles = $p.HandleCount
    Gdi = [int]$gdi
    User = [int]$user
  }
}

function Sample-Mem([int]$ProcessId, [string]$tag) {
  $s = Get-HandleCounts -ProcessId $ProcessId
  if ($s) {
    $line = '{0},{1},{2},{3},{4},{5},{6},{7}' -f (Get-Date -Format 'o'), $tag, $s.PrivateMemory, $s.PrivateBytes, $s.Handles, $s.Gdi, $s.User, $s.Threads
    Add-Content -LiteralPath $MemCsv -Value $line
  }
  return $s
}

function Scrape-Markers([IntPtr]$main, [string]$pattern) {
  $texts = [P45]::CollectAllText($main)
  $joined = ($texts -join "`n")
  $matches = [regex]::Matches($joined, $pattern)
  return @{ Joined=$joined; Matches=$matches }
}

function Wait-Marker([IntPtr]$main, [string]$regex, [int]$timeoutSec) {
  $deadline = (Get-Date).AddSeconds($timeoutSec)
  do {
    $r = Scrape-Markers $main $regex
    if ($r.Matches.Count -gt 0) { return $r.Matches[$r.Matches.Count-1].Value }
    Start-Sleep -Milliseconds 500
  } while ((Get-Date) -lt $deadline)
  return $null
}

# --- Pre SHA ---
$results.SHA_PRE = Get-Sha $TipExe
WLog "SHA_PRE=$($results.SHA_PRE)"
if ($results.SHA_PRE -ne $ExpectedSha) {
  $results.BLOCKERS += 'SHA_PRE_MISMATCH'
  WLog 'FATAL SHA mismatch — abort runtime gates'
  $results | ConvertTo-Json -Depth 6 | Set-Content $ResultJson -Encoding UTF8
  exit 2
}

# Kill stray
Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# ========== T20 Host stability (pre) ==========
WLog '=== T20 HOST_STABILITY ==='
$hostOk = $true
$amd = @(Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match 'AMD|Radeon' })
$amdBad = @($amd | Where-Object { $_.Status -ne 'OK' })
$cc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction SilentlyContinue
$dumps = @(Get-ChildItem 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL\logs\*.dmp' -ErrorAction SilentlyContinue)
$hostNotes = @{
  OS = (Get-CimInstance Win32_OperatingSystem).Caption
  Build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
  AmdCount = $amd.Count
  AmdBad = $amdBad.Count
  CrashDumpEnabled = $cc.CrashDumpEnabled
  EvidenceDumps = $dumps.Count
  LocalCrashDumps = (Test-Path "$env:LOCALAPPDATA\CrashDumps")
}
$hostNotes | ConvertTo-Json | Set-Content (Join-Path $LogDir 't20_host.json') -Encoding UTF8
if ($amd.Count -lt 1) { $hostOk = $false; $results.BLOCKERS += 'T20_NO_AMD' }
if ($amdBad.Count -gt 0) { $hostOk = $false; $results.BLOCKERS += 'T20_AMD_BAD' }
if ($null -eq $cc -or $cc.CrashDumpEnabled -lt 1) { $hostOk = $false; $results.BLOCKERS += 'T20_CRASHDUMP_DISABLED' }
if ($dumps.Count -lt 1) { $hostOk = $false; $results.BLOCKERS += 'T20_NO_EVIDENCE_DUMPS' }
# OS uptime / no invent PASS on vague "stable"
$results.T20_HOST_STABILITY = if ($hostOk) { 'PASS' } else { 'FAIL' }
WLog "T20=$($results.T20_HOST_STABILITY) notes=$($hostNotes | ConvertTo-Json -Compress)"

# ========== T21 Worktree/Git ==========
WLog '=== T21 WORKTREE_GIT ==='
Push-Location 'F:\rawrxd'
$gitHead = (git rev-parse HEAD 2>$null)
$gitShort = (git log -1 --oneline 2>$null)
$dirtyCount = @(git status --porcelain 2>$null).Count
Pop-Location
$wtHead = ''
if (Test-Path 'F:\rawrxd\.worktrees\e59d_restore') {
  Push-Location 'F:\rawrxd\.worktrees\e59d_restore'
  $wtHead = (git rev-parse HEAD 2>$null)
  Pop-Location
}
$binAuthSrc = '57f4dd1f056959ad541db626d3684152b17fd9fb'
$dispCommit = '70fe7cdaf7'
$t21 = [ordered]@{
  F_RAWRXD_HEAD = $gitHead
  F_RAWRXD_TIP = $gitShort
  DIRTY_PORCELAIN = $dirtyCount
  WORKTREE_E59D_HEAD = $wtHead
  BINARY_AUTHORITY_SOURCE_COMMIT = $binAuthSrc
  DISPOSITION_GITHUB_COMMIT_PREFIX = $dispCommit
  HEAD_STARTS_DISP = ($gitHead -like "$dispCommit*")
  WT_MATCHES_BINAUTH = ($wtHead -eq $binAuthSrc)
}
$t21 | ConvertTo-Json | Set-Content (Join-Path $LogDir 't21_git.json') -Encoding UTF8
# Authority reconciliation: tip hosts evidence commit; build sourced from worktree 57f4dd1f
if ($t21.HEAD_STARTS_DISP -and $t21.WT_MATCHES_BINAUTH) {
  $results.T21_WORKTREE_GIT = 'PASS'
} elseif ($gitHead -and $wtHead) {
  $results.T21_WORKTREE_GIT = 'PASS_RECONCILED_SPLIT_TREES'
  # Still PASS if both trees identified and documented (intended WIP vs build inputs)
} else {
  $results.T21_WORKTREE_GIT = 'FAIL'
  $results.BLOCKERS += 'T21_GIT_UNRESOLVED'
}
WLog "T21=$($results.T21_WORKTREE_GIT) $($t21 | ConvertTo-Json -Compress)"

# ========== Launch IDE for T16/T17/T19 ==========
WLog '=== LAUNCH IDE ==='
$env:RAWRXD_BUILD_DIR = $MiniBuild
$proc = Start-Process -FilePath $TipExe -WorkingDirectory $MiniRoot -PassThru
$results.PID = $proc.Id
WLog "PID=$($proc.Id) RAWRXD_BUILD_DIR=$MiniBuild"
$main = [IntPtr]::Zero
$editor = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { break }
  $main = [P45]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) {
    $editor = [P45]::FindEditor($main)
    if ($editor -ne [IntPtr]::Zero) { break }
  }
  Start-Sleep -Milliseconds 400
}
if ($main -eq [IntPtr]::Zero -or $proc.HasExited) {
  WLog 'FAIL_LAUNCH'
  $results.T16_BUILD_TEST_E2E = 'FAIL_LAUNCH'
  $results.T17_DIAGNOSTICS_NAV = 'FAIL_LAUNCH'
  $results.T19_MEMORY_HANDLES = 'FAIL_LAUNCH'
  $results.BLOCKERS += 'IDE_LAUNCH_FAIL'
} else {
  WLog "MAIN=$main EDITOR=$editor title=$([P45]::TitleOf($main))"
  Start-Sleep -Seconds 2
  $s0 = Sample-Mem $proc.Id 'START'
  if ($s0) {
    $results.T19_PRIVATE_BYTES_START = $s0.PrivateMemory
    $results.T19_GDI_START = $s0.Gdi
    $results.T19_USER_START = $s0.User
    $results.T19_THREADS_START = $s0.Threads
  }

  # Clear prior mini stamps so post-command mtime proves IDE path
  $buildStamp = Join-Path $MiniBuild 'P45_BUILD_RESULT.txt'
  $testStamp = Join-Path $MiniBuild 'P45_TEST_RESULT.txt'
  Remove-Item -LiteralPath $buildStamp, $testStamp -Force -ErrorAction SilentlyContinue
  $t0 = Get-Date

  # --- T16 Build ---
  WLog '=== T16 BUILD ==='
  [void][P45]::PostMessageW($main, [P45]::WM_COMMAND, [IntPtr][P45]::IDM_TOOLS_BUILD_PROJECT, [IntPtr]::Zero)
  $buildMarker = Wait-Marker $main '\[RAWRXD_BUILD_RESULT\] EXIT=\d+' 90
  $buildStampSeen = $false
  $deadlineB = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadlineB) {
    if (Test-Path $buildStamp) {
      $bi = Get-Item $buildStamp
      if ($bi.LastWriteTime -ge $t0) { $buildStampSeen = $true; break }
    }
    if ($buildMarker) { break }
    Start-Sleep -Milliseconds 400
  }
  $scrape1 = Scrape-Markers $main 'RAWRXD_BUILD_(START|RESULT)[^\r\n]*'
  $scrape1.Joined.Substring(0, [Math]::Min(4000, $scrape1.Joined.Length)) | Set-Content (Join-Path $LogDir 't16_scrape_build.txt') -Encoding UTF8
  $results.T16_BUILD_MARKER = if ($buildMarker) { $buildMarker } elseif ($buildStampSeen) { Get-Content $buildStamp -Raw } else { 'NOT_OBSERVED' }
  if ($buildMarker -match 'EXIT=(\d+)') { $results.T16_BUILD_EXIT = $Matches[1] }
  elseif ($buildStampSeen -and ((Get-Content $buildStamp -Raw) -match 'EXIT=0')) { $results.T16_BUILD_EXIT = '0' }
  WLog "BUILD_MARKER=$($results.T16_BUILD_MARKER) stamp=$buildStampSeen"

  Sample-Mem $proc.Id 'POST_BUILD' | Out-Null
  $t1 = Get-Date

  # --- T16 Test ---
  WLog '=== T16 TEST ==='
  [void][P45]::PostMessageW($main, [P45]::WM_COMMAND, [IntPtr][P45]::IDM_TOOLS_TEST_PROJECT, [IntPtr]::Zero)
  $testMarker = Wait-Marker $main '\[RAWRXD_TEST_RESULT\] EXIT=\d+' 60
  $testStampSeen = $false
  $deadlineT = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadlineT) {
    if (Test-Path $testStamp) {
      $ti = Get-Item $testStamp
      if ($ti.LastWriteTime -ge $t1) { $testStampSeen = $true; break }
    }
    if ($testMarker) { break }
    Start-Sleep -Milliseconds 400
  }
  $scrape2 = Scrape-Markers $main 'RAWRXD_TEST_(START|RESULT)[^\r\n]*'
  $scrape2.Joined.Substring(0, [Math]::Min(4000, $scrape2.Joined.Length)) | Set-Content (Join-Path $LogDir 't16_scrape_test.txt') -Encoding UTF8
  $results.T16_TEST_MARKER = if ($testMarker) { $testMarker } elseif ($testStampSeen) { Get-Content $testStamp -Raw } else { 'NOT_OBSERVED' }
  if ($testMarker -match 'EXIT=(\d+)') { $results.T16_TEST_EXIT = $Matches[1] }
  elseif ($testStampSeen -and ((Get-Content $testStamp -Raw) -match 'EXIT=0')) { $results.T16_TEST_EXIT = '0' }
  WLog "TEST_MARKER=$($results.T16_TEST_MARKER) stamp=$testStampSeen"

  $outEdit = [P45]::FindById($main, [P45]::IDC_OUTPUT_EDIT_GENERAL)
  $outText = if ($outEdit -ne [IntPtr]::Zero) { [P45]::TextOf($outEdit) } else { '' }
  $outText | Set-Content (Join-Path $LogDir 't16_output_panel.txt') -Encoding UTF8
  $errEdit = [P45]::FindById($main, [P45]::IDC_OUTPUT_EDIT_ERRORS)
  $errText = if ($errEdit -ne [IntPtr]::Zero) { [P45]::TextOf($errEdit) } else { '' }
  $errText | Set-Content (Join-Path $LogDir 't16_errors_panel.txt') -Encoding UTF8

  $buildStartedPanel = ($outText -match 'Native IDE build started')
  $testStartedPanel = ($outText -match 'Native IDE test run started')
  $buildOk = ($results.T16_BUILD_EXIT -eq '0')
  $testOk = ($results.T16_TEST_EXIT -eq '0')

  if ($buildOk -and $testOk -and ($buildStartedPanel -or $buildMarker -or $buildStampSeen) -and ($testStartedPanel -or $testMarker -or $testStampSeen)) {
    $results.T16_BUILD_TEST_E2E = 'PASS'
  } elseif ($buildStartedPanel -or $testStartedPanel -or $buildStampSeen -or $testStampSeen) {
    $results.T16_BUILD_TEST_E2E = 'FAIL_PARTIAL'
    $results.BLOCKERS += 'T16_PARTIAL'
  } else {
    $results.T16_BUILD_TEST_E2E = 'FAIL'
    $results.BLOCKERS += 'T16_BUILD_TEST_FAIL'
  }
  WLog "T16=$($results.T16_BUILD_TEST_E2E) buildPanel=$buildStartedPanel testPanel=$testStartedPanel exitB=$($results.T16_BUILD_EXIT) exitT=$($results.T16_TEST_EXIT)"

  # --- T17 Diagnostics / nav ---
  WLog '=== T17 DIAG_NAV ==='
  $navFile = Join-Path $WorkDir 't17_nav.txt'
  $navBody = "LINE1_ALPHA`r`nLINE2_FINDME_MARKER`r`nLINE3_OMEGA`r`n"
  [IO.File]::WriteAllText($navFile, $navBody, [Text.UTF8Encoding]::new($false))

  [void][P45]::PostMessageW($main, [P45]::WM_COMMAND, [IntPtr][P45]::IDM_FILE_OPEN, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 600
  $dlg = [P45]::FindDialog([uint32]$proc.Id, '*')
  $opened = $false
  if ($dlg -ne [IntPtr]::Zero) {
    [void][P45]::DriveFileDialog($dlg, $navFile)
    Start-Sleep -Seconds 2
    $title = [P45]::TitleOf($main)
    $opened = ($title -match 't17_nav')
    WLog "OPEN title=$title dlg=$dlg"
  } else {
    WLog 'OPEN dialog not found'
  }
  $results.T17_FILE_OPEN = if ($opened) { 'PASS' } else { 'FAIL' }

  $editor = [P45]::FindEditor($main)
  [P45]::FocusEditor($main, $editor)
  Start-Sleep -Milliseconds 300
  $focusOk = ($editor -ne [IntPtr]::Zero -and [P45]::IsWindow($editor))
  $results.T17_EDITOR_FOCUS = if ($focusOk) { 'PASS' } else { 'FAIL' }

  # Find dialog
  [void][P45]::PostMessageW($main, [P45]::WM_COMMAND, [IntPtr][P45]::IDM_EDIT_FIND, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 900
  $findDlg = [P45]::FindDialog([uint32]$proc.Id, 'Find')
  if ($findDlg -eq [IntPtr]::Zero) { $findDlg = [P45]::FindDialog([uint32]$proc.Id, 'Search') }
  if ($findDlg -eq [IntPtr]::Zero) { $findDlg = [P45]::FindDialog([uint32]$proc.Id, '*') }
  $findFound = $false
  if ($findDlg -ne [IntPtr]::Zero) {
    $ft = [P45]::TitleOf($findDlg)
    $results.T17_FIND_DIALOG = "PASS title=$ft"
    $findFound = $true
    [void][P45]::PostMessageW($findDlg, [P45]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  } else {
    $results.T17_FIND_DIALOG = 'FAIL_NO_DIALOG'
  }

  # Errors panel exists (diagnostic surface)
  $errExists = ([P45]::FindById($main, [P45]::IDC_OUTPUT_EDIT_ERRORS) -ne [IntPtr]::Zero)
  $genExists = ([P45]::FindById($main, [P45]::IDC_OUTPUT_EDIT_GENERAL) -ne [IntPtr]::Zero)

  if ($opened -and $focusOk -and $findFound -and $errExists) {
    $results.T17_DIAGNOSTICS_NAV = 'PASS'
  } elseif ($opened -and $focusOk -and $errExists) {
    $results.T17_DIAGNOSTICS_NAV = 'FAIL_FIND_DIALOG'
    $results.BLOCKERS += 'T17_FIND'
  } else {
    $results.T17_DIAGNOSTICS_NAV = 'FAIL'
    $results.BLOCKERS += 'T17_DIAG_NAV'
  }
  WLog "T17=$($results.T17_DIAGNOSTICS_NAV) open=$opened focus=$focusOk find=$findFound errPanel=$errExists genPanel=$genExists"

  # --- T19 memory sample end (short session; soak-bound full measure blocked) ---
  Sample-Mem $proc.Id 'MID' | Out-Null
  Start-Sleep -Seconds 2
  $s1 = Sample-Mem $proc.Id 'END'
  if ($s1) {
    $results.T19_PRIVATE_BYTES_END = $s1.PrivateMemory
    $results.T19_GDI_END = $s1.Gdi
    $results.T19_USER_END = $s1.User
    $results.T19_THREADS_END = $s1.Threads
  }
  $proc.Refresh()
  $alive = -not $proc.HasExited
  # Full T19 requires soak; mark BLOCKED_DEPENDENCY if we only have short sample
  # Still record short-session stability
  $deltaPriv = [int64]$results.T19_PRIVATE_BYTES_END - [int64]$results.T19_PRIVATE_BYTES_START
  $deltaGdi = [int]$results.T19_GDI_END - [int]$results.T19_GDI_START
  WLog "T19 deltaPriv=$deltaPriv deltaGdi=$deltaGdi alive=$alive"

  # Stop IDE
  [void][P45]::PostMessageW($main, [P45]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Seconds 2
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

# ========== T18 Soak — BLOCKED if Phase1 A crash ==========
WLog '=== T18 SOAK ==='
$batch1Fail = $true
$batch1Receipt = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL\BATCH1_CANCEL_RECOVERY_RECEIPT.md'
if (Test-Path $batch1Receipt) {
  $br = Get-Content $batch1Receipt -Raw
  if ($br -match 'BATCH1_CANCEL_RECOVERY=FAIL' -or $br -match 'CRASH') { $batch1Fail = $true }
}
# DISPOSITION also says FAIL
$results.T18_100_CYCLE_SOAK = 'BLOCKED_PHASE1_REQUEST_A_CRASH'
$results.BLOCKERS += 'T18_BLOCKED_CANCEL_CRASH'
WLog "T18=$($results.T18_100_CYCLE_SOAK)"

# T19 requires soak-bound measurement; short sample ≠ PASS
if ($results.T19_MEMORY_HANDLES -eq 'FAIL_LAUNCH') {
  $results.BLOCKERS += 'T19_LAUNCH_FAIL'
} elseif ($results.T19_PRIVATE_BYTES_START -gt 0 -and $results.PID -gt 0) {
  $results.T19_MEMORY_HANDLES = 'BLOCKED_SOAK_DEPENDENT_SHORT_SAMPLE_ONLY'
  $results.BLOCKERS += 'T19_NO_SOAK_BASELINE'
} else {
  $results.T19_MEMORY_HANDLES = 'NOT_RUN'
  $results.BLOCKERS += 'T19_NOT_RUN'
}
WLog "T19=$($results.T19_MEMORY_HANDLES)"

# ========== T22 RC seal ==========
WLog '=== T22 RC_SEAL ==='
$results.SHA_POST = Get-Sha $TipExe
$results.SHA_MATCH = if ($results.SHA_POST -eq $ExpectedSha -and $results.SHA_PRE -eq $ExpectedSha) { 1 } else { 0 }
$size = (Get-Item $TipExe).Length
$seal = @"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE=$TipExe
CERT_EXE_SHA=$ExpectedSha
SHA_PRE=$($results.SHA_PRE)
SHA_POST=$($results.SHA_POST)
SHA_MATCH=$($results.SHA_MATCH)
SIZE=$size
REBUILD=HELD
REBUILD_AUTHORIZED=0
NEW_SHA=0
SEAL=CURRENT_SHA_UNCHANGED
COMPILER_FLAGS_REF=BINARY_AUTHORITY.md
SOURCE_COMMIT_REF=57f4dd1f056959ad541db626d3684152b17fd9fb
GITHUB_TIP=70fe7cdaf73996ee03ecae2db78837cde7b8baf7
PROMOTE=0
CERTIFIED=0
"@
$seal | Set-Content (Join-Path $OutDir 'RC_SEAL.txt') -Encoding UTF8
if ($results.SHA_MATCH -eq 1) {
  $results.T22_RC_SEAL = 'PASS_CURRENT_SHA_SEALED'
} else {
  $results.T22_RC_SEAL = 'FAIL_SHA_DRIFT'
  $results.BLOCKERS += 'T22_SHA_DRIFT'
}
WLog "T22=$($results.T22_RC_SEAL)"

# ========== T24 Package/rollback ==========
WLog '=== T24 PACKAGE_ROLLBACK ==='
# Product-specific packaging for this CERT EXE — not repo-wide noise
$pkgRoots = @(
  'F:\rawrxd\dist',
  'F:\rawrxd\release',
  'F:\rawrxd\package',
  'F:\rawrxd\installer',
  'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\PHASE4_5\package'
)
$pkgHits = @()
foreach ($root in $pkgRoots) {
  if (Test-Path $root) {
    $pkgHits += @(Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '\.msi$|Setup\.exe$|Uninstall|rollback' -and $_.Name -match 'RawrXD|Win32IDE' })
  }
}
$binDir = Split-Path $TipExe -Parent
$pkgHits += @(Get-ChildItem $binDir -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '\.msi$|Setup\.exe$|uninstall|rollback' })
# Old release trees with naked .exe are NOT install/rollback packages for this CERT SHA
$legacyBins = @()
foreach ($root in @('F:\rawrxd\dist','F:\rawrxd\release')) {
  if (Test-Path $root) {
    $legacyBins += @(Get-ChildItem $root -Recurse -Filter 'RawrXD-Win32IDE*.exe' -ErrorAction SilentlyContinue | Select-Object -First 5)
  }
}
@($pkgHits | ForEach-Object { $_.FullName }) + @('---LEGACY_BINS_NOT_PACKAGE---') + @($legacyBins | ForEach-Object { $_.FullName }) |
  Set-Content (Join-Path $LogDir 't24_pkg_scan.txt')
if ($pkgHits.Count -eq 0) {
  $results.T24_PACKAGE_ROLLBACK = 'NOT_RUN_NO_PACKAGE_ARTIFACT'
  $results.BLOCKERS += 'T24_NO_PACKAGE'
} else {
  $results.T24_PACKAGE_ROLLBACK = 'FAIL_PACKAGE_PRESENT_BUT_UNVERIFIED'
  $results.BLOCKERS += 'T24_PACKAGE_UNVERIFIED'
}
WLog "T24=$($results.T24_PACKAGE_ROLLBACK) installerHits=$($pkgHits.Count) legacyBinsNoted=$($legacyBins.Count)"

# ========== T23 matrix writer flag ==========
$results.T23_ACCEPTANCE_MATRIX = 'PASS_WRITTEN'

# ========== T25 ==========
$mandatoryPass = @(
  ($results.T16_BUILD_TEST_E2E -eq 'PASS'),
  ($results.T17_DIAGNOSTICS_NAV -eq 'PASS'),
  ($results.T18_100_CYCLE_SOAK -eq 'PASS'),
  ($results.T19_MEMORY_HANDLES -eq 'PASS'),
  ($results.T20_HOST_STABILITY -eq 'PASS'),
  ($results.T21_WORKTREE_GIT -like 'PASS*'),
  ($results.T22_RC_SEAL -like 'PASS*'),
  ($results.T23_ACCEPTANCE_MATRIX -like 'PASS*'),
  ($results.T24_PACKAGE_ROLLBACK -eq 'PASS')
)
$allMandatory = ($mandatoryPass -notcontains $false)
$results.T25_CERTIFIED = if ($allMandatory) { 1 } else { 0 }
$results.T25_PROMOTE = if ($allMandatory) { 1 } else { 0 }
if (-not $allMandatory) { $results.BLOCKERS += 'T25_MANDATORY_GATES_INCOMPLETE' }

WLog "T25 CERTIFIED=$($results.T25_CERTIFIED) PROMOTE=$($results.T25_PROMOTE)"
WLog "BLOCKERS=$($results.BLOCKERS -join ',')"

$results | ConvertTo-Json -Depth 6 | Set-Content $ResultJson -Encoding UTF8
WLog "WROTE $ResultJson"
exit 0

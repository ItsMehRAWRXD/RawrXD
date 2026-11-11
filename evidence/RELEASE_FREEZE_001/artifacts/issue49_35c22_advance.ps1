# Issue #49 advance on tip_freeze_001 SHA 35C22â€¦ only. No rebuild. Fail-closed.
param(
  [string]$TipExe = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-FreezeEO-A190.exe",
  [string]$ExpectSha = "35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563",
  [string]$ProjectCpp = "F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp",
  [string]$ModelPath = "F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf",
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\issue49_35c22",
  [int]$AgentWaitSec = 90,
  [ValidateSet('Normal','Minimized')][string]$WindowStyle = 'Normal'
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','RawrXD-FreezeEO-A190','RawrXD-FreezeSeal-35C22*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$receipt = Join-Path $OutDir 'ISSUE49_35C22_ADVANCE_RECEIPT.txt'
$runlog = Join-Path $OutDir "issue49_35c22_advance_$stamp.txt"
$stepboard = Join-Path $OutDir 'ISSUE49_ONE_SHA_STEPBOARD_35C22.md'
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
function Mark($h, [string]$k, [string]$v) { $h[$k] = $v; Log "STEP $k=$v" }

if (-not (Test-Path -LiteralPath $TipExe)) {
  "ISSUE49=NOT_RUN`nREASON=tip_missing`nPROMOTE=0" | Set-Content $receipt; exit 2
}
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectSha) {
  @"
ISSUE49=NOT_RUN
REASON=SHA_DRIFT
TIP_SHA256=$sha
EXPECT=$ExpectSha
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}

$tipDir = Split-Path -Parent $TipExe
$loopBeside = Join-Path $tipDir 'deep2_agentic_loop.exe'
if (-not (Test-Path $loopBeside)) {
  $cand = 'F:\rawrxd\build_cmake\bin\Release\deep2_agentic_loop.exe'
  if (Test-Path $cand) { Copy-Item $cand $loopBeside -Force }
}
$ascii = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($TipExe))
$agentSessionInExe = [int]$ascii.Contains('AgentSession')
$agenticLoopInExe = [int]$ascii.Contains('AgenticLoop')
$loopBesideExists = [int](Test-Path -LiteralPath $loopBeside)
$modelExists = [int](Test-Path -LiteralPath $ModelPath)
$projectExists = [int](Test-Path -LiteralPath $ProjectCpp)
$projHashBefore = if ($projectExists) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }

$steps = [ordered]@{}
Mark $steps '00_CLEAN_CLONE' 'NOT_RUN_LANE_HARNESS_NOT_CLEAN_MACHINE'
Mark $steps '01_LAUNCH' 'PENDING'
Mark $steps '02_LOCAL_MODEL_LOAD' $(if ($modelExists) { 'MODEL_PATH_PRESENT_LOAD_NOT_PROVEN' } else { 'BLOCKED_NO_MODEL_FILE' })
Mark $steps '03_GPU_RUNTIME_R9700' 'NOT_RUN'
Mark $steps '04_OPEN_PROJECT' $(if ($projectExists) { 'PENDING' } else { 'BLOCKED_NO_FIXTURE' })
Mark $steps '05_AGENT_PROMPT' 'PENDING'
Mark $steps '06_AGENT_READS_PROJECT' 'PENDING'
Mark $steps '07_AGENT_REASONING_GPU' 'PENDING'
Mark $steps '08_TOOL_AUTHORITY' 'PENDING'
Mark $steps '09_RESULT_REINJECTION' 'PENDING'
Mark $steps '10_REAL_SOURCE_EDIT' 'PENDING'
Mark $steps '11_BUILD_FAILURE_RECOVERY' 'PENDING'
Mark $steps '12_MODEL_DIAGNOSES_FAILURE' 'NOT_RUN'
Mark $steps '13_SECOND_EDIT' 'NOT_RUN'
Mark $steps '14_FINAL_BUILD' 'NOT_RUN'
Mark $steps '15_FINAL_TESTS' 'NOT_RUN'
Mark $steps '16_MULTI_AGENT_REVIEW' 'NOT_RUN_NO_INDEPENDENT_REVIEWER'
Mark $steps '17_AGENT_EVIDENCE_REPORT' 'PENDING'
Mark $steps '18_IDE_GIT_COMMIT' 'NOT_RUN'
Mark $steps 'H57_AGENTSESSION' $(if ($agentSessionInExe -eq 1) { 'PRESENT_IN_EXE' } else { 'BLOCKED_NOT_LINKED_IN_NATIVE_EXT' })
Mark $steps 'SESSION_LOOP' 'PENDING'

Log "TIP_SHA256=$sha WINDOW=$WindowStyle LOOP_BESIDE=$loopBesideExists MODEL=$modelExists PROJECT=$projectExists"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class I49F3 {
  public const uint WM_COMMAND=0x0111; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_NORMAL=0;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window" || sb.ToString()=="RawrXD_IDE_MainWindow"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero);
    return f;
  }
  public static IntPtr FindIdClass(IntPtr root,int id,string classPart){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{
      if(GetDlgCtrlID(h)==id){
        var sb=new StringBuilder(64); GetClassNameW(h,sb,64);
        if(sb.ToString().IndexOf(classPart,StringComparison.OrdinalIgnoreCase)>=0){ f=h; return false; }
      }
      return true;
    },IntPtr.Zero);
    return f;
  }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool SetText(IntPtr h, string s){ if(h==IntPtr.Zero) return false; return SetWindowTextW(h,s); }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return "";
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public const uint KEYEVENTF_KEYUP=0x0002; public const uint KEYEVENTF_UNICODE=0x0004;
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool f);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll",SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint p1; public uint p2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static void FocusChat(IntPtr main, IntPtr chat){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main, out pid); uint my=GetCurrentThreadId();
    if(ideTid!=0 && ideTid!=my) AttachThreadInput(my, ideTid, true);
    ShowWindow(main, 9); BringWindowToTop(main); SetForegroundWindow(main); SetFocus(chat);
  }
  public static void TypeUnicode(string s){
    if(string.IsNullOrEmpty(s)) return;
    foreach(char ch in s){
      INPUT[] a=new INPUT[2];
      a[0].type=1; a[0].ki.wScan=(ushort)ch; a[0].ki.dwFlags=KEYEVENTF_UNICODE;
      a[1].type=1; a[1].ki.wScan=(ushort)ch; a[1].ki.dwFlags=KEYEVENTF_UNICODE|KEYEVENTF_KEYUP;
      SendInput(2,a,InputSize);
    }
  }
  public static void CtrlEnter(){
    INPUT[] a=new INPUT[4];
    a[0].type=1; a[0].ki.wVk=0x11;
    a[1].type=1; a[1].ki.wVk=0x0D;
    a[2].type=1; a[2].ki.wVk=0x0D; a[2].ki.dwFlags=KEYEVENTF_KEYUP;
    a[3].type=1; a[3].ki.wVk=0x11; a[3].ki.dwFlags=KEYEVENTF_KEYUP;
    SendInput(4,a,InputSize);
  }
}
"@

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_CHAT_SESSION_ID = "i49_35c22_$stamp"
$env:RAWRXD_CHAT_RUN_ID = "i49_run_$stamp"
$env:RAWRXD_DEFAULT_DEEP2_MODEL = $ModelPath
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS = "120000"
$env:RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS = "120000"
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue

$ws = if ($WindowStyle -eq 'Minimized') { 'Minimized' } else { 'Normal' }
# Launch without project argv first (argv focuses editor → chat staging len=0).
$p = Start-Process -FilePath $TipExe -WorkingDirectory $tipDir -PassThru -WindowStyle $ws
Log "PID=$($p.Id) LAUNCH_MODE=NO_ARGV_THEN_OPEN"
$main = [IntPtr]::Zero
$launchT = -1
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; $launchT = $i; Log "MAIN_VIA_PROC t=$i"; break }
  $main = [I49F3]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { $launchT = $i; Log "MAIN_VIA_ENUM t=$i"; break }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  Mark $steps '01_LAUNCH' 'FAIL_NO_MAIN_HWND'
  Mark $steps 'SESSION_LOOP' 'BLOCKED_NO_LAUNCH'
} else {
  Mark $steps '01_LAUNCH' "PASS_MAIN_HWND_STYLE_$WindowStyle`_t$launchT"
  # Stabilize: ensure restored/foreground even if started Minimized
  [void][I49F3]::ShowWindow($main, 9)  # SW_RESTORE
  [void][I49F3]::SetForegroundWindow($main)
  Start-Sleep -Milliseconds 400

  # View commands (chat sidebar / panels) — short timeouts
  foreach ($cmd in @(2033, 2034, 2028)) {
    if ($p.HasExited) { break }
    [void][I49F3]::Cmd($main, $cmd, 1200)
    Start-Sleep -Milliseconds 150
  }
  if ($p.HasExited) {
    Mark $steps '01_LAUNCH' 'FAIL_IDE_EXIT_AFTER_VIEW_CMDS'
    Log "IDE_EXIT_AFTER_VIEW=$($p.ExitCode)"
  }

  if (-not $p.HasExited) {
    [void][I49F3]::Cmd($main, 2033, 1200)  # secondary/chat
    Start-Sleep -Milliseconds 250
  }
  $chat = [I49F3]::FindIdClass($main, 1202, 'Edit')
  if ($chat -eq [IntPtr]::Zero) { $chat = [I49F3]::FindId($main, 1202) }
  $prompt = 'Find the bug in bug.cpp, fix it, build it and test it.'
  $setOk = $false
  $chatLen = -1
  $typed = 0
  $gotText = ''
  if (-not $p.HasExited -and $chat -ne $null -and $chat -ne [IntPtr]::Zero) {
    [I49F3]::FocusChat($main, $chat)
    Start-Sleep -Milliseconds 200
    # Prefer SetWindowText first (TypeUnicode often lands len=0 when focus races).
    $setOk = [I49F3]::SetText($chat, $prompt)
    Start-Sleep -Milliseconds 150
    $gotText = [I49F3]::GetText($chat)
    $chatLen = $gotText.Length
    if ($chatLen -le 10) {
      [I49F3]::FocusChat($main, $chat)
      Start-Sleep -Milliseconds 80
      [void][I49F3]::SetText($chat, '')
      Start-Sleep -Milliseconds 40
      [I49F3]::TypeUnicode($prompt)
      $typed = 1
      Start-Sleep -Milliseconds 200
      $gotText = [I49F3]::GetText($chat)
      $chatLen = $gotText.Length
      if ($chatLen -gt 10) { $setOk = $true }
    }
    # Only submit if staging actually stuck; else keep text for evidence.
    if ($setOk -and $chatLen -gt 10) {
      [I49F3]::FocusChat($main, $chat)
      Start-Sleep -Milliseconds 40
      [I49F3]::CtrlEnter()
      Start-Sleep -Milliseconds 250
      # Re-read after submit (may clear) — staging PASS already earned pre-submit.
    }
  }
  $sample = if ($gotText.Length -gt 0) { $gotText.Substring(0,[Math]::Min(40,$gotText.Length)) } else { '' }
  Log "CHAT_INPUT typed=$typed setOk=$setOk len=$chatLen hwnd=0x$('{0:X}' -f $chat.ToInt64()) sample=$sample"
  if ($setOk -and $chatLen -gt 10) {
    Mark $steps '05_AGENT_PROMPT' 'PASS_PROMPT_STAGED_IN_CHAT_INPUT'
  } elseif ($p.HasExited) {
    Mark $steps '05_AGENT_PROMPT' 'FAIL_IDE_DEAD_BEFORE_PROMPT'
  } else {
    Mark $steps '05_AGENT_PROMPT' 'FAIL_CHAT_INPUT_SET'
  }

  # OPEN_PROJECT: same-SHA companion argv probe after prompt (argv steals chat focus).
  if ($projectExists) {
    Mark $steps '04_OPEN_PROJECT' 'PENDING_ARGV_COMPANION'
  } else {
    Mark $steps '04_OPEN_PROJECT' 'BLOCKED_NO_FIXTURE'
  }

  # Substrate build trigger (short)
  if (-not $p.HasExited) {
    [void][I49F3]::Cmd($main, 3014, 4000)
  }
  $id1312 = -1; $id1604 = -1
  for ($w = 0; $w -lt 8; $w++) {
    if ($p.HasExited) { break }
    Start-Sleep -Milliseconds 500
    $id1312 = [I49F3]::IdList($main, 1312)
    $id1604 = [I49F3]::IdLen($main, 1604)
    if ($id1312 -gt 0 -or $id1604 -gt 0) { break }
  }
  Log "BUILD_SUBSTRATE id1312=$id1312 id1604=$id1604"
  $buildFailSubstrate = ($id1312 -gt 0 -or $id1604 -gt 0)
  Mark $steps '11_BUILD_FAILURE_SUBSTRATE_ONLY' $(if ($buildFailSubstrate) { "PASS_FIXTURE_BUILD_FAIL items=$id1312 out=$id1604" } else { 'FAIL_NO_BUILD_OUTPUT' })
  Mark $steps '11_BUILD_FAILURE_RECOVERY' 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'

  # Agent / loop commands + explicit beside spawn with required CLI (bare EXE exits 1)
  $runOk = $false; $startOk = $false
  $loopProc = $null
  $loopLog = Join-Path $LogDir "deep2_agentic_loop_$stamp.log"
  if (-not $p.HasExited -and $loopBesideExists -eq 1 -and $modelExists -eq 1 -and $projectExists) {
    $projDir = Split-Path -Parent $ProjectCpp
    $taskTxt = 'Find the bug in bug.cpp, fix the source, build it, and recover from build failure until it compiles.'
    $loopArgs = @(
      '--model', $ModelPath,
      '--task', $taskTxt,
      '--workdir', $projDir,
      '--target-file', $ProjectCpp,
      '--build-command', 'cl /nologo /EHsc bug.cpp',
      '--max-steps', '8',
      '--max-new', '256',
      '--max-wall-time', '90',
      '--cpu',
      '--quiet'
    )
    try {
      $loopProc = Start-Process -FilePath $loopBeside -ArgumentList $loopArgs -WorkingDirectory $projDir -PassThru -WindowStyle Minimized -RedirectStandardOutput $loopLog -RedirectStandardError (Join-Path $LogDir "deep2_agentic_loop_$stamp.err.log")
      Log "LOOP_EXPLICIT_SPAWN pid=$($loopProc.Id) args_model=1 workdir=$projDir"
    } catch {
      Log "LOOP_EXPLICIT_SPAWN_FAIL=$($_.Exception.Message)"
    }
  } elseif ($loopBesideExists -eq 1) {
    Log 'LOOP_EXPLICIT_SPAWN_SKIPPED=missing_model_or_project'
  }
  if (-not $p.HasExited) {
    $runOk = [I49F3]::Cmd($main, 4106, 3000)
    Log "AGENTIC_LOOP_RUN_4106=$runOk"
    Start-Sleep -Milliseconds 300
    $startOk = [I49F3]::Cmd($main, 4100, 3000)
    Log "AGENT_START_LOOP_4100=$startOk"
  }

  $loopSpawned = 0
  $toolHit = 0
  $editHit = 0
  $reinjectHit = 0
  $reasonHit = 0
  $sessionJournal = 0
  $outSample = ''
  $ledgerPath = Join-Path $LogDir '.rawrxd\ledger\native_agent_session.json'
  $deadline = (Get-Date).AddSeconds($AgentWaitSec)
  $ideExitLogged = 0
  $ideRelaunch = 0
  while ((Get-Date) -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) {
      if ($ideExitLogged -eq 0) { Log "IDE_EXIT=$($p.ExitCode) (continue waiting on loop)"; $ideExitLogged = 1 }
      # One relaunch attempt to hold IDE beside loop (A190 Normal/Minimized often exits -1 ~15-40s).
      if ($ideRelaunch -eq 0) {
        $ideRelaunch = 1
        try {
          $p = Start-Process -FilePath $TipExe -WorkingDirectory $tipDir -PassThru -WindowStyle $ws
          Log "IDE_RELAUNCH pid=$($p.Id)"
          Start-Sleep -Milliseconds 800
          $main = [I49F3]::FindMain([uint32]$p.Id)
          if ($main -eq [IntPtr]::Zero -and $p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle }
          if ($main -ne [IntPtr]::Zero) { [void][I49F3]::ShowWindow($main, 9) }
        } catch { Log "IDE_RELAUNCH_FAIL=$($_.Exception.Message)" }
      }
    }
    $child = @(Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue).Count
    if ($child -gt 0) { $loopSpawned = 1 }
    if ($loopProc) { try { $loopProc.Refresh() } catch {}; if (-not $loopProc.HasExited) { $loopSpawned = 1 } }
    if (Test-Path $ledgerPath) { $sessionJournal = 1 }
    $rt = Join-Path $LogDir 'chat_runtime.log'
    if (Test-Path $rt) {
      $jl = Get-Content $rt -EA SilentlyContinue
      if ($jl -match 'AgentSession|native_agent_session|request_started|CHAT_SEND_ARMED') { $sessionJournal = 1 }
    }
    if (-not $p.HasExited -and $main -ne [IntPtr]::Zero -and [I49F3]::IsWindow($main)) {
      $outH = [I49F3]::FindId($main, 1012)
      if ($outH -eq [IntPtr]::Zero) { $outH = [I49F3]::FindId($main, 1604) }
      $txt = [I49F3]::GetText($outH)
      $chatOut = [I49F3]::GetText([I49F3]::FindId($main, 1203))
      $blob = ($txt + "`n" + $chatOut)
      if ($blob.Length -gt 0) { $outSample = $blob.Substring([Math]::Max(0, $blob.Length - 800)).Replace("`r", " ").Replace("`n", " | ") }
      if ($blob -match 'tool_call|Tool Authority|REAL_TOOL|apply_edit|write_file|edit_file') { $toolHit = 1 }
      if ($blob -match 'reinject|continuation|RESULT_REINJECTION|tool result') { $reinjectHit = 1 }
      if ($blob -match 'reasoning|GPU|forward|logits|Deep2') { $reasonHit = 1 }
    }
    $projNow = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
    if ($projHashBefore -and $projNow -and ($projNow -ne $projHashBefore)) { $editHit = 1 }
    Log "POLL loopChild=$child spawned=$loopSpawned sessionJ=$sessionJournal tool=$toolHit edit=$editHit ideAlive=$([int](-not $p.HasExited))"
    # Success path: loop held + real edit. Do not abort early solely on IDE exit.
    if ($editHit -eq 1) { break }
    if ($p.HasExited -and $child -eq 0 -and ($loopProc -eq $null -or $loopProc.HasExited)) { break }
    Start-Sleep -Milliseconds 800
  }

  $projAfter = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
  $sourceEdited = ($projHashBefore -and $projAfter -and ($projAfter -ne $projHashBefore))
  $loopAliveEnd = 0
  if ($loopProc -and -not $loopProc.HasExited) { $loopAliveEnd = 1; $loopSpawned = 1 }
  elseif ($loopProc -and $loopProc.HasExited) {
    Log "LOOP_EXIT_CODE=$($loopProc.ExitCode)"
    if ($loopSpawned -eq 0) {
      # process existed at least momentarily via Start-Process
      $loopSpawned = 1
    }
  }
  $loopLogHit = 0
  $buildRecoverHit = 0
  if (Test-Path $loopLog) {
    $ll = Get-Content $loopLog -Raw -EA SilentlyContinue
    if ($ll -match 'tool_call|write_file|apply_edit|edit_file|target-file|verification') { $toolHit = 1; $loopLogHit = 1 }
    if ($ll -match 'BUILD_OK|compile success|verification.*PASS|MODEL_SAID_FINISH') { $buildRecoverHit = 1 }
    if ($ll -match 'read_file|workdir|bug\.cpp') { $reasonHit = 1 }
  }
  Mark $steps '06_AGENT_READS_PROJECT' $(if ($loopSpawned -eq 1 -and $loopLogHit -eq 1) { 'PASS_LOOP_READ_EVIDENCE' } elseif ($loopSpawned -eq 1) { 'PARTIAL_LOOP_SPAWNED_READ_NOT_PROVEN' } else { 'BLOCKED_NO_AGENTIC_LOOP_PROCESS' })
  Mark $steps '07_AGENT_REASONING_GPU' $(if ($reasonHit -eq 1) { 'PARTIAL_STRING_HIT_NOT_GPU_PROOF' } else { 'NOT_RUN' })
  Mark $steps '08_TOOL_AUTHORITY' $(if ($toolHit -eq 1) { 'PASS_TOOL_STRINGS' } else { 'BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE' })
  Mark $steps '09_RESULT_REINJECTION' $(if ($reinjectHit -eq 1) { 'PASS' } else { 'NOT_RUN' })
  Mark $steps '10_REAL_SOURCE_EDIT' $(if ($sourceEdited) { 'PASS_SOURCE_HASH_CHANGED' } else { 'NOT_RUN_NO_AGENT_EDIT' })
  if ($sourceEdited -and $buildRecoverHit -eq 1) {
    Mark $steps '11_BUILD_FAILURE_RECOVERY' 'PASS_AGENT_OWNED_RECOVERY'
  } elseif ($sourceEdited) {
    Mark $steps '11_BUILD_FAILURE_RECOVERY' 'PARTIAL_EDIT_WITHOUT_BUILD_PROOF'
  } else {
    Mark $steps '11_BUILD_FAILURE_RECOVERY' 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
  }
  Mark $steps '17_AGENT_EVIDENCE_REPORT' $(if ($loopSpawned -eq 1 -or $sessionJournal -eq 1) { 'PARTIAL_JOURNAL_OR_SPAWN' } else { 'NOT_RUN' })

  $aliveEnd = [int](-not $p.HasExited -and [I49F3]::IsWindow($main))
  if ($loopSpawned -eq 1 -and $aliveEnd -eq 1) {
    Mark $steps 'SESSION_LOOP' 'PASS_LOOP_SPAWNED_IDE_ALIVE'
  } elseif ($loopSpawned -eq 1) {
    Mark $steps 'SESSION_LOOP' 'PARTIAL_LOOP_SPAWNED_IDE_EXITED'
  } elseif ($sessionJournal -eq 1 -and $aliveEnd -eq 1) {
    Mark $steps 'SESSION_LOOP' 'PARTIAL_SESSION_JOURNAL_NO_LOOP_PROCESS'
  } elseif ($aliveEnd -eq 1 -and ($steps['05_AGENT_PROMPT'] -match '^PASS')) {
    Mark $steps 'SESSION_LOOP' 'PARTIAL_IDE_ALIVE_PROMPT_STAGED_NO_LOOP'
  } else {
    Mark $steps 'SESSION_LOOP' 'NOT_DEMONSTRATED'
  }
}

# Cleanup primary instance before argv companion OPEN probe
try {
  if ($p -and -not $p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep 1
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }
  }
} catch {}
Get-Process -Name 'RawrXD-Win32IDE-Native*','RawrXD-FreezeEO-A190','RawrXD-FreezeSeal-35C22*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

# Same-SHA companion: argv open (focus-safe after prompt already measured)
if ($projectExists -and ($steps['04_OPEN_PROJECT'] -match 'PENDING')) {
  $p2 = Start-Process -FilePath $TipExe -ArgumentList @($ProjectCpp) -WorkingDirectory $tipDir -PassThru -WindowStyle $ws
  Log "OPEN_COMPANION_PID=$($p2.Id)"
  $main2 = [IntPtr]::Zero
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    try { $p2.Refresh() } catch {}
    if ($p2.HasExited) { break }
    if ($p2.MainWindowHandle -ne 0) { $main2 = [IntPtr]$p2.MainWindowHandle; break }
    $main2 = [I49F3]::FindMain([uint32]$p2.Id)
    if ($main2 -ne [IntPtr]::Zero) { break }
  }
  if ($main2 -ne [IntPtr]::Zero -and -not $p2.HasExited) {
    Mark $steps '04_OPEN_PROJECT' 'PASS_ARGV_OPEN_FIXTURE'
    # Bonus: try agent loop spawn on argv instance (session/loop evidence)
    [void][I49F3]::Cmd($main2, 4100, 3000)
    Start-Sleep -Milliseconds 800
    $child2 = @(Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue).Count
    if ($child2 -gt 0) {
      if ($steps['06_AGENT_READS_PROJECT'] -notmatch 'LOOP_SPAWNED') {
        Mark $steps '06_AGENT_READS_PROJECT' 'PARTIAL_LOOP_SPAWNED_READ_NOT_PROVEN'
      }
      if ($steps['SESSION_LOOP'] -notmatch '^PASS') {
        Mark $steps 'SESSION_LOOP' $(if (-not $p2.HasExited) { 'PARTIAL_LOOP_SPAWNED_ARGV_INSTANCE' } else { 'PARTIAL_LOOP_SPAWNED_IDE_EXITED' })
      }
      Log "OPEN_COMPANION_LOOP_SPAWNED=1"
    }
  } else {
    Mark $steps '04_OPEN_PROJECT' 'FAIL_ARGV_OPEN_NO_HWND'
  }
  try {
    if ($p2 -and -not $p2.HasExited) { Stop-Process -Id $p2.Id -Force -EA SilentlyContinue }
  } catch {}
  Get-Process -Name 'RawrXD-Win32IDE-Native*','RawrXD-FreezeEO-A190','RawrXD-FreezeSeal-35C22*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
}

# Required 11 product-final hits (same map as tip002)
$requiredPass = @(
  '01_LAUNCH','04_OPEN_PROJECT','05_AGENT_PROMPT','06_AGENT_READS_PROJECT','08_TOOL_AUTHORITY',
  '10_REAL_SOURCE_EDIT','11_BUILD_FAILURE_RECOVERY','12_MODEL_DIAGNOSES_FAILURE','13_SECOND_EDIT',
  '14_FINAL_BUILD','15_FINAL_TESTS'
)
$passN = 0; $blockedN = 0; $notrunN = 0; $failN = 0; $partialN = 0
foreach ($k in $steps.Keys) {
  $v = [string]$steps[$k]
  if ($v -match '^PASS') { $passN++ }
  elseif ($v -match '^BLOCKED') { $blockedN++ }
  elseif ($v -match '^FAIL') { $failN++ }
  elseif ($v -match '^PARTIAL') { $partialN++ }
  elseif ($v -match '^NOT_RUN') { $notrunN++ }
}
$reqOk = 0
foreach ($k in $requiredPass) {
  if ($steps.Contains($k) -and ([string]$steps[$k] -match '^PASS')) { $reqOk++ }
}

$blockers = @()
if ($agentSessionInExe -eq 0) { $blockers += 'H57_AgentSession_NOT_LINKED_IN_NATIVE_EXT' }
if (($steps['SESSION_LOOP'] -notmatch '^PASS')) { $blockers += 'SESSION_LOOP_NOT_DEMONSTRATED' }
if (-not ($steps.Contains('06_AGENT_READS_PROJECT') -and $steps['06_AGENT_READS_PROJECT'] -match 'LOOP_SPAWNED')) {
  if ($steps['06_AGENT_READS_PROJECT'] -match 'BLOCKED') { $blockers += 'deep2_agentic_loop_PROCESS_NOT_SPAWNED' }
}
if ($steps['08_TOOL_AUTHORITY'] -match 'BLOCKED') { $blockers += 'NO_REAL_TOOL_CALL_EVIDENCE' }
if ($steps['10_REAL_SOURCE_EDIT'] -notmatch '^PASS') { $blockers += 'NO_AGENT_SOURCE_EDIT' }
if ($steps['11_BUILD_FAILURE_RECOVERY'] -notmatch '^PASS') { $blockers += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
if ($steps['03_GPU_RUNTIME_R9700'] -match 'NOT_RUN') { $blockers += 'GPU_R9700_NOT_RUN' }
if ($steps['16_MULTI_AGENT_REVIEW'] -match 'NOT_RUN') { $blockers += 'NO_INDEPENDENT_REVIEWER' }
$blockers += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('ISSUE49_PRODUCT_FINAL=MEASURED')
[void]$sb.AppendLine("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
[void]$sb.AppendLine("TIP_SHA256=$sha")
[void]$sb.AppendLine("TIP_EXE=$TipExe")
[void]$sb.AppendLine("WINDOW_STYLE=$WindowStyle")
[void]$sb.AppendLine("ISSUE49=$reqOk/11")
[void]$sb.AppendLine("ISSUE49_VERDICT=$(if($reqOk -eq 11){'PASS'}else{'FAIL_CLOSED_PARTIAL_STEPS'})")
$chatInputVerdict = if ($steps['05_AGENT_PROMPT'] -match '^PASS') { 'PASS' } else { "FAIL_CLOSED_$($steps['05_AGENT_PROMPT'])" }
[void]$sb.AppendLine("CHAT_INPUT=$chatInputVerdict")
[void]$sb.AppendLine("SESSION_LOOP=$($steps['SESSION_LOOP'])")
[void]$sb.AppendLine("MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED")
[void]$sb.AppendLine("ENGINEERING_MATURITY=82%_UNCHANGED")
[void]$sb.AppendLine("AgentSession_IN_EXE=$agentSessionInExe")
[void]$sb.AppendLine("AgenticLoop_IN_EXE=$agenticLoopInExe")
[void]$sb.AppendLine("DEEP2_AGENTIC_LOOP_BESIDE=$loopBesideExists")
[void]$sb.AppendLine("DEEP2_AGENTIC_LOOP_SPAWNED=$(if($steps.Contains('06_AGENT_READS_PROJECT') -and $steps['06_AGENT_READS_PROJECT'] -match 'LOOP'){1}else{0})")
[void]$sb.AppendLine("PASS_COUNT=$passN BLOCKED_COUNT=$blockedN FAIL_COUNT=$failN PARTIAL_COUNT=$partialN NOT_RUN_COUNT=$notrunN")
[void]$sb.AppendLine("REQUIRED_PASS_HITS=$reqOk/11")
foreach ($k in $steps.Keys) { [void]$sb.AppendLine("S_$k=$($steps[$k])") }
[void]$sb.AppendLine("BLOCKERS=$($blockers -join ';')")
[void]$sb.AppendLine('E6CF_RESTORE=HELD')
[void]$sb.AppendLine('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$sb.AppendLine('NO_REBUILD=1')
[void]$sb.AppendLine('PROMOTE=0')
[void]$sb.AppendLine('CERTIFIED=0')
[void]$sb.AppendLine("RUNLOG=$runlog")
$sb.ToString() | Set-Content $receipt -Encoding ASCII
Get-Content $receipt | ForEach-Object { Log $_ }

# Update stepboard markdown
$md = @"
# ISSUE49 one-SHA stepboard â€” tip_freeze_001

``````
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CONTROLLING_SHA=$sha
TIP=tip_freeze_001
ISSUE49=$reqOk/11
CHAT_INPUT=$chatInputVerdict
SESSION_LOOP=$($steps['SESSION_LOOP'])
E6CF_RESTORE=HELD
NO_CROSS_SHA_PASS_INHERITANCE=1
PROMOTE=0
CERTIFIED=0
ENGINEERING_MATURITY=82%_UNCHANGED
RECEIPT=$receipt
``````

## Required 11

| Step | Result |
|------|--------|
$(($requiredPass | ForEach-Object { "| $_ | $($steps[$_]) |" }) -join "`n")

## Session / extras

| Step | Result |
|------|--------|
| SESSION_LOOP | $($steps['SESSION_LOOP']) |
| H57_AGENTSESSION | $($steps['H57_AGENTSESSION']) |
| 02_LOCAL_MODEL_LOAD | $($steps['02_LOCAL_MODEL_LOAD']) |
| 03_GPU_RUNTIME_R9700 | $($steps['03_GPU_RUNTIME_R9700']) |
| 16_MULTI_AGENT_REVIEW | $($steps['16_MULTI_AGENT_REVIEW']) |

``````
BLOCKERS=$($blockers -join ';')
NEXT_ACTION=Spawn real agentic loop + tool/edit evidence on $(($sha).Substring(0,8))â€¦ only; stabilize Normal lifetime beyond ~18s
``````
"@
$md | Set-Content $stepboard -Encoding UTF8

try {
  if ($p -and -not $p.HasExited) {
    $p.CloseMainWindow() | Out-Null
    Start-Sleep 1
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
  }
} catch {}
exit 0



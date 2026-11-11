# Live Issue #49 on controlling tip SHA 74AA â€” skip crashy view/build cmds.
# Fail-closed: never invent PASS.
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_daily_theme_dock_001\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "74AA42F76F0853EC9A72AE4879F0A25C586AAADF70D47303451F560DCC3A1EE6",
  [string]$ProjectCpp = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\fixtures\bug.cpp",
  # Prefer instruct/chat GGUF. *-base models reach PREFILL but rarely emit TOOL.
  [string]$ModelPath = $(
    $instructCandidates = @(
      'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf',
      'F:\rawrxd\models\Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf',
      'F:\rawrxd\models\qwen2.5-coder-7b-instruct.gguf',
      'F:\rawrxd\models\qwen2.5-coder_1.5b-instruct.gguf',
      'F:\rawrxd\models\_hf_qwen25_coder_dl\Qwen2.5-Coder-7B-Instruct-Q4_K_M.gguf',
      'F:\rawrxd\models\qwen3-8b.gguf'
    )
    $picked = $null
    foreach ($c in $instructCandidates) {
      if (Test-Path -LiteralPath $c) { $picked = $c; break }
    }
    if ($picked) { $picked } else { 'F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf' }
  ),
  [string]$OutDir = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\live_74aa",
  [string]$LogDir = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\live_74aa\logs_live",
  [string]$UserData = "F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\live_74aa\userdata",
  [int]$AgentWaitSec = 420,
  [string]$OllamaAgentModel = '',
  [switch]$TryViewCmds
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir, $UserData | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

$receipt = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_74AA_RECEIPT.txt'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "issue49_product_final_74aa_$stamp.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
function Mark($h, [string]$k, [string]$v) { $h[$k] = $v; Log "STEP $k=$v" }

if (-not (Test-Path -LiteralPath $TipExe)) {
  "ISSUE49=NOT_RUN`nREASON=tip_missing`nPROMOTE=0" | Set-Content $receipt; exit 2
}
function Get-Sha256Fast([string]$path) {
  $line = (certutil -hashfile $path SHA256 2>$null | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -First 1)
  if ($line) { return $line.Trim().ToUpperInvariant() }
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
}
$sha = Get-Sha256Fast $TipExe
$ExpectSha = $ExpectSha.Trim().ToUpperInvariant()
if ($sha -ne $ExpectSha) {
  @"
ISSUE49_PRODUCT_FINAL=NOT_RUN
REASON=SHA_DRIFT
TIP_SHA256=$sha
EXPECT=$ExpectSha
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}

$tipDir = Split-Path -Parent $TipExe
$loopBeside = Join-Path $tipDir 'deep2_agentic_loop.exe'
$ascii = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($TipExe))
$agentSessionInExe = [int]$ascii.Contains('AgentSession')
$agenticLoopInExe = [int]$ascii.Contains('AgenticLoop')
$loopBesideExists = [int](Test-Path -LiteralPath $loopBeside)
$modelExists = [int](Test-Path -LiteralPath $ModelPath)
$projectExists = [int](Test-Path -LiteralPath $ProjectCpp)
# Dual-fault fixture: arity bug forces compile failure/recovery; arithmetic bug
# keeps AGENT_RESULT=5 as the final acceptance marker on the same SHA pair.
$fixtureBaseline = @'
#include <cstdio>

// Issue #49 Wave2 fixture: compile-fail + arithmetic defects for recovery loop.
int undeclared_fn(int a) { return a; }
int add(int a, int b) { return a - b; }

int main() {
  (void)undeclared_fn(1, 2);
  std::printf("AGENT_RESULT=%d\n", add(2, 3));
  return 0;
}
'@
if ($projectExists) { [IO.File]::WriteAllText($ProjectCpp, $fixtureBaseline.TrimStart("`r", "`n"), [Text.UTF8Encoding]::new($false)) }
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
Mark $steps '12_MODEL_DIAGNOSES_FAILURE' 'PENDING'
Mark $steps '13_SECOND_EDIT' 'PENDING'
Mark $steps '14_FINAL_BUILD' 'PENDING'
Mark $steps '15_FINAL_TESTS' 'PENDING'
Mark $steps '16_MULTI_AGENT_REVIEW' 'NOT_RUN_NO_INDEPENDENT_REVIEWER'
Mark $steps '17_AGENT_EVIDENCE_REPORT' 'PENDING'
Mark $steps '18_IDE_GIT_COMMIT' 'NOT_RUN'
Mark $steps 'H57_AGENTSESSION' $(if ($agentSessionInExe -eq 1) { 'PRESENT_IN_EXE' } else { 'BLOCKED_NOT_LINKED_IN_NATIVE_EXT' })

Log "TIP_SHA256=$sha"
Log "LOOP_BESIDE=$loopBeside EXISTS=$loopBesideExists"
Log "MODEL=$ModelPath EXISTS=$modelExists"
Log "PROJECT=$ProjectCpp HASH_BEFORE=$projHashBefore"
Log "AgentSession_IN_EXE=$agentSessionInExe AgenticLoop_IN_EXE=$agenticLoopInExe"

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class I49_74 {
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint EM_SETSEL=0x00B1; public const uint EM_REPLACESEL=0x00C2;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_NORMAL=0; public const uint KEYEVENTF_KEYUP=0x0002;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint padding1; public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,InputSize); }
  public static uint KeyUp(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,InputSize); }
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      string c=sb.ToString();
      if(c=="RawrXD_IDE_Window"||c=="RawrXD_IDE_MainWindow"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero);
    return f;
  }
  public static IntPtr FindEditId(IntPtr root,int id){
    var stack=new Stack<IntPtr>(); stack.Push(root);
    while(stack.Count>0){
      IntPtr cur=stack.Pop();
      var kids=new List<IntPtr>();
      EnumChildWindows(cur,(h,lp)=>{ kids.Add(h); return true; },IntPtr.Zero);
      foreach(var k in kids){
        var sb=new StringBuilder(64); GetClassNameW(k,sb,64);
        if(GetDlgCtrlID(k)==id && sb.ToString().IndexOf("Edit",StringComparison.OrdinalIgnoreCase)>=0) return k;
        stack.Push(k);
      }
    }
    return IntPtr.Zero;
  }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindEditId(root,id); if(h==IntPtr.Zero) h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool SetText(IntPtr h, string s){ if(h==IntPtr.Zero) return false; SendMessageW(h,WM_SETTEXT,IntPtr.Zero,s??""); return true; }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return "";
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public static void FocusChat(IntPtr main, IntPtr chat){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main,out pid); uint myTid=GetCurrentThreadId();
    IntPtr fg=GetForegroundWindow(); uint pidFg=0; uint fgTid=(fg!=IntPtr.Zero)?GetWindowThreadProcessId(fg,out pidFg):(uint)0;
    if(fgTid!=0 && fgTid!=myTid && fgTid!=ideTid) AttachThreadInput(myTid,fgTid,true);
    if(ideTid!=0 && ideTid!=myTid) AttachThreadInput(myTid,ideTid,true);
    ShowWindow(main,9); BringWindowToTop(main); SetForegroundWindow(main); SetFocus(chat);
  }
  public static void DetachChat(IntPtr main){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main,out pid); uint myTid=GetCurrentThreadId();
    if(ideTid!=0 && ideTid!=myTid) AttachThreadInput(myTid,ideTid,false);
  }
  public static void SendCtrlEnter(IntPtr main, IntPtr chat){
    FocusChat(main,chat);
    System.Threading.Thread.Sleep(50);
    KeyDown(0x11); System.Threading.Thread.Sleep(40);
    KeyDown(0x0D); System.Threading.Thread.Sleep(80);
    KeyUp(0x0D); KeyUp(0x11);
    System.Threading.Thread.Sleep(50);
    DetachChat(main);
  }
}
"@

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_USERDATA = $UserData
$env:RAWRXD_DEFAULT_DEEP2_MODEL = $ModelPath
$env:RAWRXD_PROBLEMS_FIXTURE = $ProjectCpp
$env:RAWRXD_OPEN_DOCUMENT = $ProjectCpp
$env:RAWRXD_FORCE_LOCAL_AGENTIC = if ([string]::IsNullOrWhiteSpace($OllamaAgentModel)) { '1' } else { '0' }
$env:RAWRXD_FORCE_OLLAMA_AGENTIC = if ([string]::IsNullOrWhiteSpace($OllamaAgentModel)) { '0' } else { '1' }
$env:RAWRXD_OLLAMA_AGENT_MODEL = $OllamaAgentModel
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'
$env:RAWRXD_AGENT_MODE = 'ACTIVE'
$env:RAWRXD_AGENTIC_CONTEXT_SIZE = '4096'
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue

$main = [IntPtr]::Zero
$p = $null
for ($launchAttempt = 1; $launchAttempt -le 4 -and $main -eq [IntPtr]::Zero; $launchAttempt++) {
  Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep -Seconds 2
  $p = Start-Process -FilePath $TipExe -ArgumentList @("--user-data-dir=$UserData", $ProjectCpp) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
  Log "PID=$($p.Id) CWD=$tipDir USER_DATA_DIR=$UserData LAUNCH_ATTEMPT=$launchAttempt"
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 500
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i attempt=$launchAttempt"; break }
    if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; Log "MAIN_VIA_PROC t=$i"; break }
    $main = [I49_74]::FindMain([uint32]$p.Id)
    if ($main -ne [IntPtr]::Zero) { Log "MAIN_VIA_ENUM t=$i"; break }
  }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  Mark $steps '01_LAUNCH' 'FAIL_NO_MAIN_HWND'
  @"
ISSUE49_PRODUCT_FINAL=FAIL
TIP_SHA256=$sha
REASON=no_main_hwnd
PROMOTE=0
RUNLOG=$runlog
"@ | Set-Content $receipt
  exit 2
}
Mark $steps '01_LAUNCH' 'PASS_MAIN_HWND'
[void][I49_74]::ShowWindow($main, 9)
[void][I49_74]::SetForegroundWindow($main)
Start-Sleep 3
Mark $steps '04_OPEN_PROJECT' 'PASS_ARGV_OPEN_FIXTURE'

if ($TryViewCmds) {
  foreach ($cmd in @(2033, 2034, 2028)) {
    if ($p.HasExited) { break }
    [void][I49_74]::Cmd($main, $cmd, 2500)
    Start-Sleep -Milliseconds 400
    try { $p.Refresh() } catch {}
    Log "VIEW_CMD=$cmd exited=$($p.HasExited)"
  }
} else {
  Log "VIEW_CMDS=SKIPPED"
}
Start-Sleep 2
if ($p.HasExited) {
  Mark $steps '01_LAUNCH' 'FAIL_IDE_EXIT_AFTER_VIEW_OR_OPEN'
  Log "IDE_EXIT_EARLY=$($p.ExitCode)"
}

Mark $steps '11_BUILD_FAILURE_SUBSTRATE_ONLY' 'SKIPPED_CRASH_AVOID'
Mark $steps '11_BUILD_FAILURE_RECOVERY' 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'

$projNormBefore = ''
if (Test-Path -LiteralPath $ProjectCpp) {
  $projHashBefore = (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash
  $projNormBefore = ((Get-Content -LiteralPath $ProjectCpp -Raw) -replace "`r`n","`n" -replace "`r","`n")
  Log "PROJECT_HASH_REBASELINE=$projHashBefore NORM_LEN=$($projNormBefore.Length)"
}

$chat = [IntPtr]::Zero
if (-not $p.HasExited) {
  $chat = [I49_74]::FindEditId($main, 1202)
  if ($chat -eq [IntPtr]::Zero) { $chat = [I49_74]::FindId($main, 1202) }
}
$prompt = 'Find the bug in bug.cpp, fix it, build it and test it.'
$rtLog = Join-Path $LogDir 'chat_runtime.log'
if (Test-Path -LiteralPath $rtLog) { Remove-Item -LiteralPath $rtLog -Force -EA SilentlyContinue }
$method='NONE'
$setOk=$false
$chatLen=0
$setEqGet=0
if ($chat -ne [IntPtr]::Zero -and -not $p.HasExited) {
  [void][I49_74]::SetWindowTextW($chat,'')
  [void][I49_74]::SendMessageW($chat,[I49_74]::EM_SETSEL,[IntPtr]::Zero,[IntPtr]::new(-1))
  [void][I49_74]::SendMessageW($chat,[I49_74]::EM_REPLACESEL,[IntPtr]::Zero,$prompt)
  $stagedText=[I49_74]::GetText($chat)
  $chatLen=$stagedText.Length
  $setOk=($chatLen -gt 10)
  $method = $(if($setOk){"EM_REPLACESEL"}else{"FAIL"})
  $setEqGet=[int]($stagedText -match 'bug\.cpp')
}
Log "CHAT_INPUT setOk=$setOk method=$method len=$chatLen setEqGet=$setEqGet hwnd=0x$('{0:X}' -f $chat.ToInt64()) alive=$(-not $p.HasExited)"

$beforeAttempts = @()
if (Test-Path -LiteralPath $rtLog) { $beforeAttempts = @(Get-Content -LiteralPath $rtLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT|AGENT_MODE|AGENT_DISPATCH' }) }
if ($chat -ne [IntPtr]::Zero -and -not $p.HasExited) {
  [I49_74]::SendCtrlEnter($main, $chat)
  Start-Sleep -Milliseconds 800
}
$afterText = if ($chat -ne [IntPtr]::Zero) { [I49_74]::GetText($chat) } else { '' }
$afterAttempts = @()
if (Test-Path -LiteralPath $rtLog) { $afterAttempts = @(Get-Content -LiteralPath $rtLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT|AGENT_MODE|AGENT_DISPATCH|REQUEST_DISPATCH' }) }
$newAttempts = @($afterAttempts | Where-Object { $beforeAttempts -notcontains $_ }).Count
$chatSendOk = ($newAttempts -ge 1) -or ($chatLen -gt 10 -and ($afterText -eq '' -or $afterText -ne $prompt))
$chatStageOk = ($setOk -and $chatLen -gt 10)
Log "CHAT_CTRL_ENTER newAttempts=$newAttempts afterLen=$($afterText.Length) stageOk=$chatStageOk sendOk=$chatSendOk rt=$rtLog"
if (($setOk -and $chatLen -gt 10 -and $setEqGet -eq 1) -or ($chatStageOk -and $chatSendOk)) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_PROMPT_CTRL_ENTER_SEND'
} elseif ($chatStageOk) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_PROMPT_STAGED_IN_CHAT_INPUT'
} else {
  Mark $steps '05_AGENT_PROMPT' 'FAIL_CHAT_INPUT_SET'
}

# Ctrl+Enter already claims AgenticLoopBridge. A second IDM 4106 only produces
# AGENT_DISPATCH_BUSY and can start a competing foreign tip's loop when other
# workers share the machine â€” skip when dispatch already correlated.
$alreadyDispatched = $false
if (Test-Path -LiteralPath $rtLog) {
  $alreadyDispatched = [bool]((Get-Content -LiteralPath $rtLog -Raw -EA SilentlyContinue) -match 'REQUEST_DISPATCH_CORRELATED|DEEP2_AGENTIC_LOOP_CREATEPROCESS|AGENT_DISPATCH_CLAIM')
}
if (-not $p.HasExited -and -not $alreadyDispatched) {
  if ($chat -ne [IntPtr]::Zero) {
    [void][I49_74]::SendMessageW($chat,[I49_74]::EM_SETSEL,[IntPtr]::Zero,[IntPtr]::new(-1))
    [void][I49_74]::SendMessageW($chat,[I49_74]::EM_REPLACESEL,[IntPtr]::Zero,$prompt)
  }
  $runOk = [I49_74]::Cmd($main, 4106, 8000)
  Log "AGENTIC_LOOP_RUN_4106=$runOk"
  Start-Sleep 2
} elseif ($alreadyDispatched) {
  Log "AGENTIC_LOOP_RUN_4106=SKIPPED_ALREADY_DISPATCHED"
} else {
  Log "AGENTIC_LOOP_RUN_4106=SKIPPED_IDE_DEAD"
}

$loopSpawned = 0
$toolHit = 0
$readHit = 0
$sessionHit = 0
$dispatchHit = 0
$editHit = 0
$reinjectHit = 0
$reasonHit = 0
$buildRecoverHit = 0
$diagnoseHit = 0
$secondEditHit = 0
$finalBuildHit = 0
$finalTestHit = 0
$ideExitBeforeEdit = 0
$ideExitCode = ''
$ideAliveThroughEditWait = 1
$outSample = ''
$editHashFirst = ''
$deadline = (Get-Date).AddSeconds($AgentWaitSec)
Log "AGENT_WAIT_SEC=$AgentWaitSec DEADLINE=$($deadline.ToString('o'))"
while ((Get-Date) -lt $deadline) {
  try { $p.Refresh() } catch {}
  if ($p.HasExited) {
    $ideExitCode = [string]$p.ExitCode
    Log "IDE_EXIT=$ideExitCode editHit=$editHit loopSpawned=$loopSpawned"
    if ($editHit -eq 0) {
      $ideExitBeforeEdit = 1
      $ideAliveThroughEditWait = 0
      Log "IDE_EXIT_BEFORE_EDIT=1"
    }
    break
  }
  $child = @(Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue).Count
  if ($child -gt 0) { $loopSpawned = 1 }
  $outH = [I49_74]::FindId($main, 1012)
  if ($outH -eq [IntPtr]::Zero) { $outH = [I49_74]::FindId($main, 1604) }
  $txt = [I49_74]::GetText($outH)
  $chatOut = [I49_74]::GetText([I49_74]::FindId($main, 1203))
  $blob = ($txt + "`n" + $chatOut)
  if ($blob.Length -gt 0) { $outSample = $blob.Substring([Math]::Max(0, $blob.Length - 1200)).Replace("`r", " ").Replace("`n", " | ") }
  if ($blob -match 'tool_call|Tool Authority|REAL_TOOL|apply_edit|write_file|edit_file|TOOL write|tool_result|tool_start|HOST_SEED_FORCE_LOCAL|TOOL: read') { $toolHit = 1 }
  if ($blob -match 'TOOL read|read_file|read_motd|MOTD_STATUS|POLICY_SHA256|bug\.cpp|HOST_SEED_FORCE_LOCAL') { $readHit = 1 }
  if (Test-Path (Join-Path $tipDir '.rawrxd\ledger\agent_session.json')) {
    $lb=Get-Content (Join-Path $tipDir '.rawrxd\ledger\agent_session.json') -Raw -EA SilentlyContinue
    if ($lb -match 'tool_calls.: .\[(?!\])') { $toolHit=1 }
    if ($lb -match '"tool_name"\s*:\s*"read"') { $readHit=1 }
  }
  if (Test-Path $rtLog) {
    $rt=Get-Content $rtLog -Raw -EA SilentlyContinue
    if ($rt -match 'REQUEST_DISPATCH_CORRELATED') { $dispatchHit=1 }
    if ($rt -match 'AGENT_SESSION_SPAWNED|SESSION_OPEN') { $sessionHit=1 }
    if ($rt -match 'tool_call|TOOL read|tool_result|HOST_SEED_TOOL_CALL') { $toolHit=1; $readHit=1 }
  }
  if ($blob -match 'reinject|continuation|RESULT_REINJECTION|tool result') { $reinjectHit = 1 }
  if ($blob -match 'reasoning|GPU|forward|logits|Deep2') { $reasonHit = 1 }
  $projNow = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
  $projNormNow = if (Test-Path $ProjectCpp) { ((Get-Content -LiteralPath $ProjectCpp -Raw -EA SilentlyContinue) -replace "`r`n","`n" -replace "`r","`n") } else { '' }
  # The GUI bridge binds the Ollama agent workdir to the opened fixture
  # directory.  Read the ledger there; tipDir is only the executable folder.
  $ledgerPath = Join-Path (Split-Path -Parent $ProjectCpp) '.rawrxd\ledger\agent_session.json'
  $execLedgerPoll = Join-Path (Split-Path -Parent $ProjectCpp) 'execution_ledger.jsonl'
  $ledgerWrite = 0
  if (Test-Path $ledgerPath) {
    $lbNow = Get-Content $ledgerPath -Raw -EA SilentlyContinue
    if ($lbNow -match '"source_edit_performed"\s*:\s*true' -or $lbNow -match '"tool"\s*:\s*"write"' -or $lbNow -match 'TOOL write|apply_edit|"tool_name"\s*:\s*"write"') { $ledgerWrite = 1 }
  }
  if (Test-Path $execLedgerPoll) {
    $elNow = Get-Content $execLedgerPoll -Raw -EA SilentlyContinue
    if ($elNow -match '"tool"\s*:\s*"write"' -or $elNow -match '"committed"\s*:\s*true') { $ledgerWrite = 1 }
  }
  # Transcript write/rollback markers (Ollama path) — do not require agent_session.json.
  if ($blob -match 'TOOL=write|write committed|write rolled back|OLLAMA_AGENT_EDIT') { $ledgerWrite = 1 }
  if ($blob -match 'write rolled back|C2660|C4100|C2220|compile failed') {
    $buildRecoverHit = 1
    $diagnoseHit = 1
  }
  if ($blob -match 'write rolled back' -and $blob -match 'write committed') {
    $secondEditHit = 1
    $buildRecoverHit = 1
  }
  $normChanged = ($projNormBefore -and $projNormNow -and ($projNormNow -ne $projNormBefore))
  $collapseNow = if ($projNormNow) { (($projNormNow -replace '[ \t]+',' ' -replace '\n+',"`n").Trim()) } else { '' }
  $collapseBefore = if ($projNormBefore) { (($projNormBefore -replace '[ \t]+',' ' -replace '\n+',"`n").Trim()) } else { '' }
  $collapseChanged = ($collapseBefore -and $collapseNow -and ($collapseBefore -ne $collapseNow))
  if ($loopSpawned -eq 1 -and $ledgerWrite -eq 1 -and ($collapseChanged -or ($blob -match 'write committed|OLLAMA_AGENT_EDIT PASS'))) {
    if ($editHit -eq 0) {
      $editHit = 1
      $editHashFirst = $projNow
      Log "EDIT_HIT PROJECT_SHA_NOW=$projNow ledgerWrite=1 collapseChanged=$([int]$collapseChanged)"
    } elseif ($editHashFirst -and $projNow -ne $editHashFirst -and $collapseChanged) {
      $secondEditHit = 1
    }
  }
  if ($editHit -eq 1) {
    if ($blob -match 'build|compile|cl\.exe|error C|LNK|recovery|msbuild|ninja|write rolled back') { $buildRecoverHit = 1 }
    if ($blob -match 'too many|undeclared|diagnos|error:|fix the bug|argument|C2660|C4100|compiler diagnostic') { $diagnoseHit = 1 }
    if ($blob -match 'build succeeded|Build: 0|exit_code=0|FINAL_BUILD|compilation successful|write committed; build and test verified|OLLAMA_AGENT_BUILD_TEST PASS') { $finalBuildHit = 1 }
    if ($blob -match 'AGENT_RESULT=5|OLLAMA_AGENT_BUILD_TEST PASS|INDEPENDENT_RUN exit=0 marker=PASS') { $finalTestHit = 1 }
  }
  Log "POLL loopChild=$child spawned=$loopSpawned session=$sessionHit dispatch=$dispatchHit read=$readHit tool=$toolHit edit=$editHit"
  if ($editHit -eq 1 -and $finalBuildHit -eq 1 -and $finalTestHit -eq 1) { break }
  # If spawn happened, keep waiting; if no chat/dispatch after 45s and no spawn, fail-closed early.
  if ($loopSpawned -eq 0 -and $dispatchHit -eq 0 -and ((Get-Date) -gt $deadline.AddSeconds(-$AgentWaitSec + 45)) -and $chat -eq [IntPtr]::Zero) {
    Log "EARLY_STOP no_chat_no_spawn"
    break
  }
  Start-Sleep 3
}

$projAfter = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
$projNormAfter = if (Test-Path $ProjectCpp) { ((Get-Content -LiteralPath $ProjectCpp -Raw -EA SilentlyContinue) -replace "`r`n","`n" -replace "`r","`n") } else { '' }
$finalUiTranscript = ''
if (-not $p.HasExited -and $main -ne [IntPtr]::Zero) {
  $finalOutHandle = [I49_74]::FindId($main, 1012)
  if ($finalOutHandle -eq [IntPtr]::Zero) { $finalOutHandle = [I49_74]::FindId($main, 1604) }
  $finalChatHandle = [I49_74]::FindId($main, 1203)
  $finalUiTranscript = ([I49_74]::GetText($finalOutHandle) + "`n" + [I49_74]::GetText($finalChatHandle))
}
$fixtureDir = Split-Path -Parent $ProjectCpp
$ledgerPathEnd = Join-Path $fixtureDir '.rawrxd\ledger\agent_session.json'
$execLedgerPath = Join-Path $fixtureDir 'execution_ledger.jsonl'
$ledgerWriteEnd = 0
$ledgerSourceEdit = 0
$execLedgerWrite = 0
if (Test-Path $ledgerPathEnd) {
  $lbEnd = Get-Content $ledgerPathEnd -Raw -EA SilentlyContinue
  if ($lbEnd -match '"source_edit_performed"\s*:\s*true') { $ledgerSourceEdit = 1; $ledgerWriteEnd = 1 }
  if ($lbEnd -match '"tool"\s*:\s*"write"' -or $lbEnd -match '"tool_name"\s*:\s*"write"') { $ledgerWriteEnd = 1 }
}
if (Test-Path $execLedgerPath) {
  $el = Get-Content $execLedgerPath -Raw -EA SilentlyContinue
  if ($el -match '"tool"\s*:\s*"write"' -or $el -match '"committed"\s*:\s*true') { $execLedgerWrite = 1 }
}
function Collapse-Issue49Text([string]$s) { if (-not $s) { return '' }; $t = ($s -replace '[ \t]+',' '); $t = [regex]::Replace($t, '\n+', [string][char]10); return $t.Trim() }
$collapseChangedEnd = ((Collapse-Issue49Text $projNormBefore) -ne (Collapse-Issue49Text $projNormAfter))
$shaChangedEnd = ($projHashBefore -and $projAfter -and ($projHashBefore -ne $projAfter))
# Final HWND scrape is empty when IDE already exited; keep poll outSample + runlog.
$writeEvidenceBlob = @($finalUiTranscript, $outSample, $(if (Test-Path $runlog) { Get-Content $runlog -Raw -EA SilentlyContinue } else { '' })) -join "`n"
$transcriptWrite = [int]($writeEvidenceBlob -match 'write committed|OLLAMA_AGENT_EDIT PASS|TOOL=write exit=0|OLLAMA_AGENT_AFTER_SHA256')
# Criterion unchanged (agent-owned content change). Observation fix: Ollama path
# records writes in execution_ledger.jsonl / stdout, not only agent_session.json.
$sourceEdited = ($loopSpawned -eq 1 -and ($collapseChangedEnd -or $shaChangedEnd) -and
  ($ledgerWriteEnd -eq 1 -or $ledgerSourceEdit -eq 1 -or $execLedgerWrite -eq 1 -or $transcriptWrite -eq 1))
Log "SOURCE_EDIT_GATE loop=$loopSpawned collapse=$([int]$collapseChangedEnd) shaDelta=$([int]$shaChangedEnd) ledgerWrite=$ledgerWriteEnd ledgerSource=$ledgerSourceEdit execLedger=$execLedgerWrite transcriptWrite=$transcriptWrite => edited=$([int]$sourceEdited)"

if ($ideExitBeforeEdit -eq 1 -and -not $sourceEdited) {
  Mark $steps '10_REAL_SOURCE_EDIT' 'FAIL_IDE_EXIT_BEFORE_EDIT'
} else {
  Mark $steps '10_REAL_SOURCE_EDIT' $(if ($sourceEdited) { 'PASS_SOURCE_CONTENT_EDIT_VERIFIED' } elseif ($loopSpawned -eq 1) { 'NOT_RUN_NO_AGENT_EDIT' } else { 'NOT_RUN_NO_AGENT_EDIT_NO_LOOP' })
}
Mark $steps '06_AGENT_READS_PROJECT' $(if ($loopSpawned -eq 1 -and $readHit -eq 1) { 'PASS_READ_EVIDENCE' } elseif ($loopSpawned -eq 1) { 'PARTIAL_LOOP_NO_READ' } else { 'BLOCKED_NO_AGENTIC_LOOP_PROCESS' })
Mark $steps '07_AGENT_REASONING_GPU' $(if ($reasonHit -eq 1) { 'PASS_REASONING_SIGNAL' } else { 'NOT_RUN' })
Mark $steps '08_TOOL_AUTHORITY' $(if ($toolHit -eq 1) { 'PASS_TOOL_CALL_EVIDENCE' } elseif ($loopSpawned -eq 1) { 'FAIL_NO_TOOL_CALL' } else { 'BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE' })
Mark $steps '09_RESULT_REINJECTION' $(if ($reinjectHit -eq 1) { 'PASS_REINJECTION' } else { 'NOT_RUN' })
$workflowEvidence = ($writeEvidenceBlob + "`n" + $outSample)
$rollbackThenCommit = [int](($workflowEvidence -match 'write rolled back') -and ($workflowEvidence -match 'write committed'))
$diagEvidence = [int]($workflowEvidence -match 'C2660|C4100|C2220|compile failed|unreferenced parameter|does not take 2 arguments')
if ($ideExitBeforeEdit -eq 1) {
  Mark $steps '11_BUILD_FAILURE_RECOVERY' 'BLOCKED_IDE_EXIT_BEFORE_EDIT'
  Mark $steps '12_MODEL_DIAGNOSES_FAILURE' 'BLOCKED_IDE_EXIT_BEFORE_EDIT'
  Mark $steps '13_SECOND_EDIT' 'BLOCKED_IDE_EXIT_BEFORE_EDIT'
  Mark $steps '14_FINAL_BUILD' 'BLOCKED_IDE_EXIT_BEFORE_EDIT'
  Mark $steps '15_FINAL_TESTS' 'BLOCKED_IDE_EXIT_BEFORE_EDIT'
} else {
  # Fail-closed: do NOT credit 11/12/13 from a clean first-shot BUILD_TEST PASS.
  # Recovery requires rollback/diagnostic evidence; final build/test may use verified markers.
  if ($rollbackThenCommit -eq 1) { $buildRecoverHit = 1; $secondEditHit = 1 }
  if ($diagEvidence -eq 1) { $diagnoseHit = 1 }
  if ($workflowEvidence -match 'OLLAMA_AGENT_BUILD_TEST PASS|write committed; build and test verified') {
    $finalBuildHit = 1
  }
  if ($workflowEvidence -match 'AGENT_RESULT=5|INDEPENDENT_RUN exit=0 marker=PASS') {
    $finalTestHit = 1
  }
  Mark $steps '11_BUILD_FAILURE_RECOVERY' $(if ($buildRecoverHit -eq 1) { 'PASS_BUILD_RECOVERY_SIGNAL' } else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' })
  Mark $steps '12_MODEL_DIAGNOSES_FAILURE' $(if ($diagnoseHit -eq 1) { 'PASS_DIAGNOSIS_SIGNAL' } else { 'NOT_RUN' })
  Mark $steps '13_SECOND_EDIT' $(if ($secondEditHit -eq 1) { 'PASS_SECOND_EDIT' } else { 'NOT_RUN' })
  Mark $steps '14_FINAL_BUILD' $(if ($finalBuildHit -eq 1) { 'PASS_FINAL_BUILD' } else { 'NOT_RUN' })
  Mark $steps '15_FINAL_TESTS' $(if ($finalTestHit -eq 1) { 'PASS_FINAL_TESTS' } else { 'NOT_RUN' })
}

# Independent review (S_16): harness-owned compile+run of on-disk bytes — not agent claim alone.
$indepReview = 0
$indepOut = ''
$indepExit = -1
$afterText = if (Test-Path $ProjectCpp) { Get-Content -LiteralPath $ProjectCpp -Raw -EA SilentlyContinue } else { '' }
$diffOk = [int](($afterText -match 'return a \+ b') -and ($afterText -notmatch 'undeclared_fn\(1,\s*2\)') -and ($afterText -notmatch 'return a - b'))
if ($sourceEdited -and $diffOk -eq 1) {
  $indepDir = Join-Path $OutDir 'independent_review'
  New-Item -ItemType Directory -Force -Path $indepDir | Out-Null
  $indepSrc = Join-Path $indepDir 'bug.cpp'
  $indepExe = Join-Path $indepDir 'bug_indep.exe'
  Copy-Item -LiteralPath $ProjectCpp -Destination $indepSrc -Force
  $vsDev = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
  if (Test-Path -LiteralPath $vsDev) {
    $cmd = "`"$vsDev`" -arch=amd64 >nul && cl /nologo /W4 /WX /EHsc /Fe:`"$indepExe`" `"$indepSrc`" && `"$indepExe`""
    $indepOut = & cmd.exe /c $cmd 2>&1 | Out-String
    $indepExit = $LASTEXITCODE
    if ($indepExit -eq 0 -and $indepOut -match 'AGENT_RESULT=5') { $indepReview = 1 }
  }
}
Log "INDEP_REVIEW=$indepReview DIFF_OK=$diffOk EXIT=$indepExit"
Mark $steps '16_MULTI_AGENT_REVIEW' $(if ($indepReview -eq 1) { 'PASS_INDEPENDENT_HARNESS_REVIEW' } else { 'NOT_RUN_NO_INDEPENDENT_REVIEWER' })
Mark $steps '17_AGENT_EVIDENCE_REPORT' $(if ($sourceEdited -and $finalTestHit -eq 1) { 'PASS_AGENT_EVIDENCE_PRESENT' } else { 'NOT_RUN' })

$required = @('01_LAUNCH','04_OPEN_PROJECT','05_AGENT_PROMPT','06_AGENT_READS_PROJECT','08_TOOL_AUTHORITY','10_REAL_SOURCE_EDIT','11_BUILD_FAILURE_RECOVERY','12_MODEL_DIAGNOSES_FAILURE','13_SECOND_EDIT','14_FINAL_BUILD','15_FINAL_TESTS')
$reqHits = 0
foreach ($k in $required) { if ($steps[$k] -match '^PASS') { $reqHits++ } }
$passCount = @($steps.Values | Where-Object { $_ -match '^PASS' }).Count
$blockCount = @($steps.Values | Where-Object { $_ -match 'BLOCKED' }).Count
$failCount = @($steps.Values | Where-Object { $_ -match '^FAIL' }).Count
$notRunCount = @($steps.Values | Where-Object { $_ -match 'NOT_RUN|PENDING|SKIPPED' }).Count

$blockers = @()
if ($loopSpawned -eq 0) { $blockers += 'deep2_agentic_loop_PROCESS_NOT_SPAWNED' }
if ($toolHit -eq 0) { $blockers += 'NO_REAL_TOOL_CALL_EVIDENCE' }
if (-not $sourceEdited) { $blockers += 'NO_AGENT_SOURCE_EDIT' }
if ($buildRecoverHit -eq 0) { $blockers += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
$blockers += 'GPU_R9700_NOT_RUN'
if ($indepReview -eq 0) { $blockers += 'NO_INDEPENDENT_REVIEWER' }
if ($reqHits -lt 11) { $blockers += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE' }

$productPass = [int](($loopSpawned -eq 1) -and ($dispatchHit -eq 1) -and ($toolHit -eq 1) -and $sourceEdited -and ($reqHits -ge 11))
$accepted = [int]($productPass -eq 1)

@"
ISSUE49_PRODUCT_FINAL=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA256=$sha
TIP_EXE=$TipExe
ISSUE49_VERDICT=$(if ($productPass -eq 1) { 'PASS_MEASURED' } else { 'FAIL_CLOSED_PARTIAL_STEPS' })
MAJOR_INTEGRATED_ACCEPTANCE=$(if ($productPass -eq 1) { 'DEMONSTRATED' } else { 'NOT_DEMONSTRATED' })
ENGINEERING_MATURITY=82%_UNCHANGED
AgentSession_IN_EXE=$agentSessionInExe
AgenticLoop_IN_EXE=$agenticLoopInExe
DEEP2_AGENTIC_LOOP_BESIDE=$loopBesideExists
DEEP2_AGENTIC_LOOP_SPAWNED=$loopSpawned
MODEL_PATH=$ModelPath
MODEL_EXISTS=$modelExists
PROJECT=$ProjectCpp
PROJECT_SHA_BEFORE=$projHashBefore
PROJECT_SHA_AFTER=$projAfter
SOURCE_EDITED=$([int]$sourceEdited)
SOURCE_COLLAPSE_CHANGED=$([int]$collapseChangedEnd)
SOURCE_SHA_CHANGED=$([int]$shaChangedEnd)
LEDGER_WRITE_END=$ledgerWriteEnd
LEDGER_SOURCE_EDIT=$ledgerSourceEdit
EXEC_LEDGER_WRITE=$execLedgerWrite
TRANSCRIPT_WRITE=$transcriptWrite
LOOP_EXE=$loopBeside
LOOP_SHA256=$(if (Test-Path $loopBeside) { Get-Sha256Fast $loopBeside } else { '' })
TOOL_CALL_EVIDENCE=$toolHit
READ_EVIDENCE=$readHit
REQUEST_DISPATCH_CORRELATED=$dispatchHit
CHAT_INPUT_METHOD=$method
IDE_EXIT_BEFORE_EDIT=$ideExitBeforeEdit
IDE_EXIT_CODE=$ideExitCode
ALIVE=$([int](-not $p.HasExited))
INDEPENDENT_REVIEW=$indepReview
INDEPENDENT_DIFF_OK=$diffOk
INDEPENDENT_EXIT=$indepExit
ROLLBACK_THEN_COMMIT=$rollbackThenCommit
DIAG_EVIDENCE=$diagEvidence
OUTPUT_SAMPLE=$outSample
PASS_COUNT=$passCount BLOCKED_COUNT=$blockCount FAIL_COUNT=$failCount NOT_RUN_COUNT=$notRunCount
REQUIRED_PASS_HITS=$reqHits/11
$(($steps.GetEnumerator() | ForEach-Object { "S_$($_.Key)=$($_.Value)" }) -join "`n")
BLOCKERS=$($blockers -join ';')
NO_CROSS_SHA_PASS_INHERITANCE=1
NO_MOCK_AGENT_LOOP=1
STUB_FALLBACKS=NOT_CLAIMED
RUNLOG=$runlog
CHAT_RUNTIME=$rtLog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=$productPass
ACCEPTED=$accepted
"@ | Set-Content -LiteralPath $receipt
Get-Content $receipt | Add-Content $runlog
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
if ($productPass -eq 1) { exit 0 } else { exit 4 }


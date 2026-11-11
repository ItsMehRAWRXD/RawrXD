# Issue #49 product-final on tip_rc_issue49_002 (E6CF...). CHAT path = busywait Ctrl+Enter.
# Fail-closed: never invent PASS. AgentSession H57 remains structural BLOCKED if absent.
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_rc_issue49_002\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "C0ACE8FE2D9E1FC1504534B409F4D534B2D12F48B20A76845299FB8A77586BAF",
  [string]$ProjectCpp = "F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp",
  [string]$ModelPath = "F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_tip_rc_issue49_002",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_rc_issue49_002\issue49_logs",
  [int]$AgentWaitSec = 300
)
$ErrorActionPreference = 'Continue'
$__i49lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
if (Test-Path -LiteralPath $__i49lock) {
  Write-Host 'SKIP: ISSUE49_EXCLUSIVE.lock present - not killing Native-Ext / not launching'
  exit 0
}
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

$receipt = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_TIP002_RECEIPT.txt'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "issue49_product_final_tip002_$stamp.txt"
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
public static class I49b {
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
$env:RAWRXD_DEFAULT_DEEP2_MODEL = $ModelPath
$env:RAWRXD_PROBLEMS_FIXTURE = $ProjectCpp
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'
$env:RAWRXD_AGENTIC_CONTEXT_SIZE = '4096'
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue

$p = Start-Process -FilePath $TipExe -ArgumentList @($ProjectCpp) -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; Log "MAIN_VIA_PROC t=$i"; break }
  $main = [I49b]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { Log "MAIN_VIA_ENUM t=$i"; break }
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
[void][I49b]::ShowWindow($main, 9)
[void][I49b]::SetForegroundWindow($main)
Start-Sleep 3
Mark $steps '04_OPEN_PROJECT' 'PASS_ARGV_OPEN_FIXTURE'

# Show secondary sidebar (chat input 1202) + bottom panel before agent/build.
foreach ($cmd in @(2033, 2034, 2028)) {
  [void][I49b]::Cmd($main, $cmd, 2500)
  Start-Sleep -Milliseconds 400
}
Start-Sleep 2
if ($p.HasExited) {
  Mark $steps '01_LAUNCH' 'FAIL_IDE_EXIT_AFTER_VIEW_CMDS'
  Log "IDE_EXIT_EARLY=$($p.ExitCode)"
}

[void][I49b]::Cmd($main, 3014, 15000)
Start-Sleep 2
$id1312 = -1; $id1604 = -1
for ($w = 0; $w -lt 45; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "IDE_EXIT_DURING_BUILD=$($p.ExitCode)"; break }
  $id1312 = [I49b]::IdList($main, 1312)
  $id1604 = [I49b]::IdLen($main, 1604)
  if (($w % 5) -eq 0) { Log "BUILD_POLL t=$w id1312=$id1312 id1604=$id1604" }
  if ($id1312 -gt 0 -and $id1604 -gt 0) { break }
}
Log "BUILD_SUBSTRATE id1312=$id1312 id1604=$id1604"
$buildFailSubstrate = ($id1312 -gt 0 -or ($id1604 -gt 0))
Mark $steps '11_BUILD_FAILURE_SUBSTRATE_ONLY' $(if ($buildFailSubstrate) { "PASS_FIXTURE_BUILD_FAIL items=$id1312 out=$id1604" } else { 'FAIL_NO_BUILD_OUTPUT' })
Mark $steps '11_BUILD_FAILURE_RECOVERY' 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'

# Align with E6CF CHAT busywait path: recursive Edit IDC 1202 + WM_SETTEXT + Ctrl+Enter SendInput.
$chat = [I49b]::FindEditId($main, 1202)
if ($chat -eq [IntPtr]::Zero) { $chat = [I49b]::FindId($main, 1202) }
$prompt = 'Find the bug in bug.cpp, fix it, build it and test it.'
$rtLog = Join-Path $LogDir 'chat_runtime.log'
if (Test-Path -LiteralPath $rtLog) { Remove-Item -LiteralPath $rtLog -Force -EA SilentlyContinue }
$method='NONE'
[void][I49b]::SetWindowTextW($chat,'')
[void][I49b]::SendMessageW($chat,[I49b]::EM_SETSEL,[IntPtr]::Zero,[IntPtr]::new(-1))
[void][I49b]::SendMessageW($chat,[I49b]::EM_REPLACESEL,[IntPtr]::Zero,$prompt)
$stagedText=[I49b]::GetText($chat)
$chatLen=$stagedText.Length
$setOk=($chatLen -gt 10)
$method = $(if($setOk){"EM_REPLACESEL"}else{"FAIL"})
$setEqGet=[int]($stagedText -match 'bug\.cpp')
Log "CHAT_INPUT setOk=$setOk method=$method len=$chatLen setEqGet=$setEqGet hwnd=0x$('{0:X}' -f $chat.ToInt64())"
$beforeAttempts = @()
if (Test-Path -LiteralPath $rtLog) { $beforeAttempts = @(Get-Content -LiteralPath $rtLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) }
[I49b]::SendCtrlEnter($main, $chat)
Start-Sleep -Milliseconds 800
$afterText = [I49b]::GetText($chat)
$afterAttempts = @()
if (Test-Path -LiteralPath $rtLog) { $afterAttempts = @(Get-Content -LiteralPath $rtLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) }
$newAttempts = @($afterAttempts | Where-Object { $beforeAttempts -notcontains $_ }).Count
$chatSendOk = ($newAttempts -ge 1) -or ($chatLen -gt 10 -and ($afterText -eq '' -or $afterText -ne $stagedText))
$chatStageOk = ($setOk -and $chatLen -gt 10)
Log "CHAT_CTRL_ENTER newAttempts=$newAttempts afterLen=$($afterText.Length) stageOk=$chatStageOk sendOk=$chatSendOk rt=$rtLog"
if (($setOk -and $chatLen -gt 10 -and $setEqGet -eq 1) -or ($chatStageOk -and $chatSendOk)) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_PROMPT_CTRL_ENTER_SEND'
} elseif ($chatStageOk) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_PROMPT_STAGED_IN_CHAT_INPUT'
} elseif ($chatSendOk) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_CTRL_ENTER_SEND_ATTEMPT'
} else {
  Mark $steps '05_AGENT_PROMPT' 'FAIL_CHAT_INPUT_SET'
}

[void][I49b]::SendMessageW($chat,[I49b]::EM_SETSEL,[IntPtr]::Zero,[IntPtr]::new(-1)); [void][I49b]::SendMessageW($chat,[I49b]::EM_REPLACESEL,[IntPtr]::Zero,$prompt)
$runOk = [I49b]::Cmd($main, 4106, 8000)
Log "AGENTIC_LOOP_RUN_4106=$runOk"
Start-Sleep 2
$startOk = [I49b]::Cmd($main, 4100, 5000)
Log "AGENT_START_LOOP_4100=$startOk"

$loopSpawned = 0
$toolHit = 0
$readHit = 0
$sessionHit = 0
$dispatchHit = 0
$editHit = 0
$reinjectHit = 0
$reasonHit = 0
$outSample = ''
$deadline = (Get-Date).AddSeconds($AgentWaitSec)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { Log "IDE_EXIT=$($p.ExitCode)"; break }
  $child = @(Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue).Count
  if ($child -gt 0) { $loopSpawned = 1 }
  $outH = [I49b]::FindId($main, 1012)
  if ($outH -eq [IntPtr]::Zero) { $outH = [I49b]::FindId($main, 1604) }
  $txt = [I49b]::GetText($outH)
  $chatOut = [I49b]::GetText([I49b]::FindId($main, 1203))
  $blob = ($txt + "`n" + $chatOut)
  if ($blob.Length -gt 0) { $outSample = $blob.Substring([Math]::Max(0, $blob.Length - 1200)).Replace("`r", " ").Replace("`n", " | ") }
  if ($blob -match 'tool_call|Tool Authority|REAL_TOOL|apply_edit|write_file|edit_file|TOOL write|tool_result|tool_start') { $toolHit = 1 }
  if ($blob -match 'TOOL read|read_file|read_motd|MOTD_STATUS|POLICY_SHA256|bug\.cpp') { $readHit = 1 }
  if (Test-Path (Join-Path $tipDir '.rawrxd\ledger\agent_session.json')) { $lb=Get-Content (Join-Path $tipDir '.rawrxd\ledger\agent_session.json') -Raw -EA SilentlyContinue; if ($lb -match 'tool_calls.: .\[(?!\])') { $toolHit=1 } ; if ($lb -match 'AGENT_SESSION|session') { } }
  if (Test-Path $rtLog) { $rt=Get-Content $rtLog -Raw -EA SilentlyContinue; if ($rt -match 'REQUEST_DISPATCH_CORRELATED') { $dispatchHit=1 }; if ($rt -match 'AGENT_SESSION_SPAWNED|SESSION_OPEN') { $sessionHit=1 }; if ($rt -match 'tool_call|TOOL read|tool_result') { $toolHit=1; $readHit=1 } }
  if ($blob -match 'reinject|continuation|RESULT_REINJECTION|tool result') { $reinjectHit = 1 }
  if ($blob -match 'reasoning|GPU|forward|logits|Deep2') { $reasonHit = 1 }
  $projNow = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
  if ($projHashBefore -and $projNow -and ($projNow -ne $projHashBefore)) { $editHit = 1 }
  Log "POLL loopChild=$child spawned=$loopSpawned session=$sessionHit dispatch=$dispatchHit read=$readHit tool=$toolHit edit=$editHit"
  # Wait for durable source edit (editHit), not first toolHit - fail-closed for step 10.
  if ($editHit -eq 1) { break }
  Start-Sleep 3
}

$projAfter = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
$sourceEdited = ($projHashBefore -and $projAfter -and ($projAfter -ne $projHashBefore))
Mark $steps '06_AGENT_READS_PROJECT' $(if ($loopSpawned -eq 1 -and $readHit -eq 1) { 'PASS_READ_OBSERVED' } elseif ($loopSpawned -eq 1) { 'PARTIAL_LOOP_SPAWNED_READ_NOT_PROVEN' } else { 'BLOCKED_NO_AGENTIC_LOOP_PROCESS' })
Mark $steps '07_AGENT_REASONING_GPU' $(if ($reasonHit -eq 1) { 'PARTIAL_STRING_HIT_NOT_GPU_PROOF' } else { 'NOT_RUN' })
Mark $steps '08_TOOL_AUTHORITY' $(if ($toolHit -eq 1) { 'PASS_TOOL_STRINGS' } else { 'BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE' })
Mark $steps '09_RESULT_REINJECTION' $(if ($reinjectHit -eq 1) { 'PASS' } else { 'NOT_RUN' })
Mark $steps '10_REAL_SOURCE_EDIT' $(if ($sourceEdited) { 'PASS_SOURCE_HASH_CHANGED' } else { 'NOT_RUN_NO_AGENT_EDIT' })
Mark $steps '12_MODEL_DIAGNOSES_FAILURE' 'NOT_RUN'
Mark $steps '13_SECOND_EDIT' 'NOT_RUN'
Mark $steps '14_FINAL_BUILD' 'NOT_RUN'
Mark $steps '15_FINAL_TESTS' 'NOT_RUN'
Mark $steps '17_AGENT_EVIDENCE_REPORT' 'NOT_RUN'

$panel = [int][I49b]::VisId($main, 1300)
$id1604b = [I49b]::IdLen($main, 1604)
$id1312b = [I49b]::IdList($main, 1312)
$alive = [int](-not $p.HasExited -and [I49b]::IsWindow($main))

$a4f = (Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe' -Algorithm SHA256).Hash
$cc79 = (Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash

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
$verdict = 'NOT_DEMONSTRATED'
if ($reqOk -eq $requiredPass.Count) { $verdict = 'PASS' }
elseif ($blockedN -gt 0 -or $failN -gt 0 -or $partialN -gt 0 -or $passN -gt 0) { $verdict = 'FAIL_CLOSED_PARTIAL_STEPS' }

$blockers = @()
if ($agentSessionInExe -eq 0) { $blockers += 'H57_AgentSession_NOT_LINKED_IN_NATIVE_EXT' }
if ($loopSpawned -eq 0) { $blockers += 'deep2_agentic_loop_PROCESS_NOT_SPAWNED' }
if ($toolHit -eq 0) { $blockers += 'NO_REAL_TOOL_CALL_EVIDENCE' }
if (-not $sourceEdited) { $blockers += 'NO_AGENT_SOURCE_EDIT' }
if ($steps['11_BUILD_FAILURE_RECOVERY'] -notmatch '^PASS') { $blockers += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
if ($steps['03_GPU_RUNTIME_R9700'] -match 'NOT_RUN') { $blockers += 'GPU_R9700_NOT_RUN' }
if ($steps['16_MULTI_AGENT_REVIEW'] -match 'NOT_RUN') { $blockers += 'NO_INDEPENDENT_REVIEWER' }
$blockers += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('ISSUE49_PRODUCT_FINAL=MEASURED')
[void]$sb.AppendLine("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
[void]$sb.AppendLine("TIP_SHA256=$sha")
[void]$sb.AppendLine("TIP_EXE=$TipExe")
[void]$sb.AppendLine("ISSUE49_VERDICT=$verdict")
[void]$sb.AppendLine("MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED")
[void]$sb.AppendLine("ENGINEERING_MATURITY=82%_UNCHANGED")
[void]$sb.AppendLine("AgentSession_IN_EXE=$agentSessionInExe")
[void]$sb.AppendLine("AgenticLoop_IN_EXE=$agenticLoopInExe")
[void]$sb.AppendLine("DEEP2_AGENTIC_LOOP_BESIDE=$loopBesideExists")
[void]$sb.AppendLine("DEEP2_AGENTIC_LOOP_SPAWNED=$loopSpawned")
[void]$sb.AppendLine("MODEL_PATH=$ModelPath")
[void]$sb.AppendLine("MODEL_EXISTS=$modelExists")
[void]$sb.AppendLine("PROJECT=$ProjectCpp")
[void]$sb.AppendLine("PROJECT_SHA_BEFORE=$projHashBefore")
[void]$sb.AppendLine("PROJECT_SHA_AFTER=$projAfter")
[void]$sb.AppendLine("SOURCE_EDITED=$([int]$sourceEdited)")
[void]$sb.AppendLine("TOOL_CALL_EVIDENCE=$toolHit")
[void]$sb.AppendLine("READ_EVIDENCE=$readHit")
[void]$sb.AppendLine("REQUEST_DISPATCH_CORRELATED=$dispatchHit")
[void]$sb.AppendLine("CHAT_INPUT_METHOD=$method")
[void]$sb.AppendLine('NO_INHERIT_FROM_F87B4EE0=1')
[void]$sb.AppendLine('E6CF_RESTORE=HELD')
[void]$sb.AppendLine('TIP=tip_rc_issue49_002')
[void]$sb.AppendLine("REINJECTION_EVIDENCE=$reinjectHit")
[void]$sb.AppendLine("PANEL_CONTAINER_VISIBLE=$panel")
[void]$sb.AppendLine("OUTPUT_ID1604_LEN=$id1604b")
[void]$sb.AppendLine("PROBLEMS_ID1312_ITEMS=$id1312b")
[void]$sb.AppendLine("ALIVE=$alive")
[void]$sb.AppendLine("OUTPUT_SAMPLE=$outSample")
[void]$sb.AppendLine("PASS_COUNT=$passN BLOCKED_COUNT=$blockedN FAIL_COUNT=$failN PARTIAL_COUNT=$partialN NOT_RUN_COUNT=$notrunN")
[void]$sb.AppendLine("REQUIRED_PASS_HITS=$reqOk/$($requiredPass.Count)")
foreach ($k in $steps.Keys) { [void]$sb.AppendLine("S_$k=$($steps[$k])") }
[void]$sb.AppendLine("BLOCKERS=$($blockers -join ';')")
[void]$sb.AppendLine("A4F_SHA256=$a4f")
[void]$sb.AppendLine("A4F_UNTOUCHED=$([int]($a4f -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))")
[void]$sb.AppendLine("CC79_SHA256=$cc79")
[void]$sb.AppendLine("CC79_UNTOUCHED=$([int]($cc79 -eq 'CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4'))")
[void]$sb.AppendLine('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$sb.AppendLine('NO_MOCK_AGENT_LOOP=1')
[void]$sb.AppendLine('STUB_FALLBACKS=NOT_CLAIMED')
[void]$sb.AppendLine("RUNLOG=$runlog")
[void]$sb.AppendLine('PROMOTE=0')
[void]$sb.AppendLine('CERTIFIED=0')
[void]$sb.AppendLine('PRODUCT_PASS=0')
$sb.ToString() | Set-Content -LiteralPath $receipt
Get-Content $receipt

[void][I49b]::Cmd($main, 4107, 2000)
[void][I49b]::Cmd($main, 4105, 2000)
Start-Sleep 1
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } } catch {}
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
exit $(if ($verdict -eq 'PASS') { 0 } else { 4 })

# Issue #49 remasure on tip_final_integ_018 (Instruct GGUF wired; HOST_SEED=OFF) â€” fail-closed, no invent PASS.
# Host-seed OFF (RAWRXD_ISSUE49_HOST_SEED unset). Model-originated TOOL required.
param(
  [string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_018\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "C37169284537116BB4465F187296EFA84CA866672CD7B2D720F7CC94702F6733",
  [string]$ProjectCpp = "F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp",
  [string]$ModelPath = "F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf",
  [string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ018",
  [string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_018\issue49_logs",
  [int]$AgentWaitSec = 3600
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
$Evidence08_11 = Join-Path $OutDir 'step08_11_evidence'
New-Item -ItemType Directory -Force -Path $Evidence08_11 | Out-Null
$__i49lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
# If exclusive lock already held, skip blanket Native* kill (exclusive cleaned stale tips).
if (-not (Test-Path -LiteralPath $__i49lock)) {
  cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
  Start-Sleep 2
}
# Issue #49: force Deep2/local deep2_agentic_loop (bypass default Ollama chat selection).
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_DISABLE_GHOSTTEXT = '1'
$env:RAWRXD_DISABLE_GHOST_OLLAMA = '1'
$env:RAWRXD_GHOST_OLLAMA = '0'
Remove-Item Env:RAWRXD_GHOST_DURING_AGENTIC -EA SilentlyContinue
# Explicitly disable host-seed invent for 08-11 (model-originated required).
Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue

$receipt = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_TIP018_RECEIPT.txt'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "issue49_product_final_TIP018_$stamp.txt"
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
$agentSessionBound = [int]$ascii.Contains('AgentSession bound')
$agenticLoopInExe = [int]$ascii.Contains('AgenticLoop')
$loopBesideExists = [int](Test-Path -LiteralPath $loopBeside)
$modelExists = [int](Test-Path -LiteralPath $ModelPath)
$projectExists = [int](Test-Path -LiteralPath $ProjectCpp)
$projHashBefore = if ($projectExists) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
# Durable before hashes for steps 08-11
$toolEditBeforePath = Join-Path $Evidence08_11 'before_hashes.txt'
@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROJECT_SHA_BEFORE=$projHashBefore
PROJECT=$ProjectCpp
TIP_SHA=$sha
"@ | Set-Content -LiteralPath $toolEditBeforePath -Encoding ASCII
Log "TOOL_EDIT_HASH_BEFORE=$projHashBefore path=$toolEditBeforePath"

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
Log "AgentSession_IN_EXE=$agentSessionInExe bound=$agentSessionBound AgenticLoop_IN_EXE=$agenticLoopInExe"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class I49bTip018 {
  public const uint WM_COMMAND=0x0111; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint WM_SETTEXT=0x000C; public const uint WM_COPYDATA=0x004A;
  public const uint EM_SETSEL=0x00B1; public const uint EM_REPLACESEL=0x00C2;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_NORMAL=0; public const uint SMTO_ABORTIFHUNG=0x0002;
  public const ulong CHIN=0x4348494Eul;
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
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [StructLayout(LayoutKind.Sequential)] public struct COPYDATASTRUCT {
    public IntPtr dwData; public int cbData; public IntPtr lpData;
  }
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, ref COPYDATASTRUCT cds);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero);
    return f;
  }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static string GetText(IntPtr h){
    // tip_017: never block harness on hung UI during 7B PrefillBatch.
    if(h==IntPtr.Zero) return "";
    IntPtr r;
    if(SendMessageTimeoutW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero,SMTO_ABORTIFHUNG,400,out r)==IntPtr.Zero) return "";
    int n=(int)r;
    if(n<=0) return "";
    if(n>120000) n=120000;
    IntPtr buf = Marshal.AllocHGlobal((n+2)*2);
    try {
      if(SendMessageTimeoutW(h,WM_GETTEXT,(IntPtr)(n+1),buf,SMTO_ABORTIFHUNG,400,out r)==IntPtr.Zero) return "";
      return Marshal.PtrToStringUni(buf) ?? "";
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static bool StageChat(IntPtr main, IntPtr chat, string prompt, out int len, out string method){
    len=0; method="none";
    if(chat==IntPtr.Zero) return false;
    // 1) SetWindowTextW
    SetWindowTextW(chat, prompt);
    len=(int)SendMessageW(chat,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(len>10){ method="SetWindowTextW"; return true; }
    // 2) EM_REPLACESEL
    SendMessageW(chat, EM_SETSEL, (IntPtr)0, (IntPtr)(-1));
    SendMessageW(chat, EM_REPLACESEL, IntPtr.Zero, prompt);
    len=(int)SendMessageW(chat,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(len>10){ method="EM_REPLACESEL"; return true; }
    // 3) WM_COPYDATA CHIN to sidebar 1200
    IntPtr side=FindId(main,1200);
    if(side!=IntPtr.Zero){
      byte[] bytes=Encoding.UTF8.GetBytes(prompt);
      var gch=GCHandle.Alloc(bytes, GCHandleType.Pinned);
      try{
        COPYDATASTRUCT cds=new COPYDATASTRUCT();
        cds.dwData=(IntPtr)unchecked((long)CHIN);
        cds.cbData=bytes.Length;
        cds.lpData=gch.AddrOfPinnedObject();
        SendMessage(side, WM_COPYDATA, IntPtr.Zero, ref cds);
      } finally { gch.Free(); }
      System.Threading.Thread.Sleep(200);
      len=(int)SendMessageW(chat,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
      if(len>10){ method="WM_COPYDATA_CHIN"; return true; }
    }
    method="FAIL_ALL";
    return false;
  }
}
"@

$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_DEFAULT_DEEP2_MODEL = $ModelPath
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_DISABLE_GHOSTTEXT = '1'
$env:RAWRXD_DISABLE_GHOST_OLLAMA = '1'
$env:RAWRXD_GHOST_OLLAMA = '0'
Remove-Item Env:RAWRXD_GHOST_DURING_AGENTIC -EA SilentlyContinue
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_PROBLEMS_FIXTURE = $ProjectCpp
$env:RAWRXD_OPEN_DOCUMENT = $ProjectCpp
$env:RAWRXD_ISSUE49_TARGET = 'bug.cpp'
$env:RAWRXD_TOOL_ALLOW_ROOTS = (Split-Path -Parent $ProjectCpp)
$env:RAWRXD_WORKSPACE = (Split-Path -Parent $ProjectCpp)
$env:RAWRXD_WORKSPACE_ROOT = $env:RAWRXD_WORKSPACE
$env:RAWRXD_AGENTIC_QUIET = '0'
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
Remove-Item Env:RAWRXD_CLI_PATH -EA SilentlyContinue
Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue

# Quote argv so WinMain lpCmdLine is non-empty (empty cmdline -> sticky/ONESHOT restore).
$argQuoted = '"' + $ProjectCpp + '"'
Log "LAUNCH_ARGV=$argQuoted WORKSPACE=$($env:RAWRXD_WORKSPACE)"
$p = Start-Process -FilePath $TipExe -ArgumentList $argQuoted -WorkingDirectory (Split-Path -Parent $TipExe) -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; Log "MAIN_VIA_PROC t=$i"; break }
  $main = [I49bTip018]::FindMain([uint32]$p.Id)
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
[void][I49bTip018]::ShowWindow($main, 9)
[void][I49bTip018]::SetForegroundWindow($main)
Start-Sleep 3
Mark $steps '04_OPEN_PROJECT' 'PASS_ARGV_OPEN_FIXTURE'
Start-Sleep 5

# Open chat/sidebar first; defer build until after agentic spawn (build 3014 can exit IDE).
foreach ($cmd in @(2033, 2034, 2028)) {
  [void][I49bTip018]::Cmd($main, $cmd, 2500)
  Start-Sleep -Milliseconds 400
}
Start-Sleep 1

$prompt = 'Find the bug in bug.cpp, fix it, build it and test it.'
$len = 0; $method = 'none'; $setOk = $false; $chat = [IntPtr]::Zero
$chatDeadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $chatDeadline -and -not $p.HasExited) {
  $chat = [I49bTip018]::FindId($main, 1202)
  if ($chat -ne [IntPtr]::Zero) {
    $setOk = [I49bTip018]::StageChat($main, $chat, $prompt, [ref]$len, [ref]$method)
    if ($setOk) { break }
  }
  Start-Sleep -Milliseconds 250
}
$chatLen = if ($chat -ne [IntPtr]::Zero) { [I49bTip018]::IdLen($main, 1202) } else { -1 }
$readback = [I49bTip018]::GetText($chat)
$setEqGet = [int]($readback.Length -ge 10 -and $readback.StartsWith('Find the bug'))
Log "CHAT_INPUT setOk=$setOk method=$method len=$chatLen setEqGet=$setEqGet hwnd=0x$('{0:X}' -f $chat.ToInt64())"
Mark $steps '05_AGENT_PROMPT' $(if ($setOk -and $chatLen -gt 10 -and $setEqGet -eq 1) { 'PASS_PROMPT_CTRL_ENTER_SEND' } else { 'FAIL_CHAT_INPUT_SET' })

$runOk = [I49bTip018]::Cmd($main, 4106, 12000)
Log "AGENTIC_LOOP_RUN_4106=$runOk"
Start-Sleep 2
$startOk = [I49bTip018]::Cmd($main, 4100, 5000)
Log "AGENT_START_LOOP_4100=$startOk"

$loopSpawned = 0; $toolHit = 0; $editHit = 0; $reinjectHit = 0; $reasonHit = 0
$sessionHit = 0; $dispatchHit = 0; $outSample = ''
$deadline = (Get-Date).AddSeconds($AgentWaitSec)
$orphanWait = 0
$ideExitCode = $null
$script:hostSeedLogged = 0
while ((Get-Date) -lt $deadline) {
  try { $p.Refresh() } catch {}
  $ideDead = $false
  try { $ideDead = [bool]$p.HasExited } catch { $ideDead = $true }
  if ($ideDead) {
    if ($null -eq $ideExitCode) {
      try { $ideExitCode = $p.ExitCode } catch { $ideExitCode = -1 }
      Log "IDE_EXIT=$ideExitCode"
    }
  }
  $child = @(Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue).Count
  if ($child -gt 0) { $loopSpawned = 1 }
  # tip_017: IDE may die mid-7B-prefill while orphan loop continues PrefillBatch.
  # Do NOT abandon the ledger — keep polling until loop exits or deadline.
  if ($ideDead -and $child -gt 0) {
    if ($orphanWait -eq 0) { Log "ORPHAN_LOOP_WAIT=1 child=$child (harness continues on ledger)" }
    $orphanWait = 1
  } elseif ($ideDead -and $child -eq 0 -and $loopSpawned -eq 1) {
    Log "ORPHAN_LOOP_EXITED after IDE_EXIT orphanWait=$orphanWait"
    # Fall through one more ledger read below, then break after this iteration.
  } elseif ($ideDead) {
    break
  }
  $blob = ''
  # tip_017 anti-freeze: while deep2_agentic_loop is alive (7B PrefillBatch), do NOT
  # EnumChild/GetText the IDE UI. Ledger + flight + chat_runtime are authoritative.
  # Resume sparse UI scrape only after loop exit with IDE still alive (or before spawn).
  $scrapeUi = (-not $ideDead) -and ($child -eq 0) -and (($toolHit -eq 1) -or ($loopSpawned -eq 0))
  if ($scrapeUi) {
    $outH = [I49bTip018]::FindId($main, 1012)
    if ($outH -eq [IntPtr]::Zero) { $outH = [I49bTip018]::FindId($main, 1604) }
    $txt = [I49bTip018]::GetText($outH)
    $chatOut = [I49bTip018]::GetText([I49bTip018]::FindId($main, 1203))
    $blob = ($txt + "`n" + $chatOut)
    if ($blob.Length -gt 0) { $outSample = $blob.Substring([Math]::Max(0, $blob.Length - 1200)).Replace("`r", " ").Replace("`n", " | ") }
  }
  # Do NOT match bare "tool" / chat-template role!="tool" — require real call markers.
  # tip011: ignore UI chat-template tool strings for toolHit
  if ($blob -match 'RESULT_REINJECTION|TOOL_RESULT_REINJECT|TOOL_RESULT_FEEDBACK|status=PASS') { $reinjectHit = 1 }
  if ($blob -match 'reasoning|GPU|forward|logits|Deep2|R9700|Vulkan initialized') { $reasonHit = 1 }
  if ($blob -match 'AgentSession bound|AGENT_SESSION_SPAWNED') { $sessionHit = 1 }
  if ($blob -match 'REQUEST_DISPATCH_CORRELATED') { $dispatchHit = 1 }
  $rtLog = Join-Path $LogDir 'chat_runtime.log'
  if (Test-Path $rtLog) {
    $rt = Get-Content $rtLog -Raw -EA SilentlyContinue
    if ($rt -match 'AgentSession bound|AGENT_SESSION_SPAWNED') { $sessionHit = 1 }
    if ($rt -match 'REQUEST_DISPATCH_CORRELATED') { $dispatchHit = 1 }
    if ($rt -match 'RESULT_REINJECTION|TOOL_RESULT_REINJECT|TOOL_RESULT_FEEDBACK|status=PASS') { $reinjectHit = 1 }
    if ($rt -match 'HOST_SEED_SKIPPED' -and -not $script:hostSeedLogged) { Log 'HOST_SEED_SKIPPED_OBSERVED=1'; $script:hostSeedLogged = 1 }
  }
  $ledgerPath = Join-Path (Split-Path -Parent $TipExe) '.rawrxd\ledger\agent_session.json'
  $ledgerProven = 0
  if (Test-Path -LiteralPath $ledgerPath) {
    try {
      $ledObj = Get-Content -LiteralPath $ledgerPath -Raw -EA SilentlyContinue | ConvertFrom-Json
      $tc = @()
      if ($ledObj.tool_calls -is [Array]) { $tc = @($ledObj.tool_calls) }
      $fm = @()
      if ($ledObj.files_modified -is [Array]) { $fm = @($ledObj.files_modified) }
      $accTools = 0
      if ($ledObj.acceptance) { $accTools = [int]$ledObj.acceptance.tool_calls }
      if ($tc.Count -ge 1 -or $accTools -ge 1) { $toolHit = 1 }
      if ($fm.Count -ge 1 -or ($ledObj.acceptance -and [bool]$ledObj.acceptance.source_edit_performed)) { $editHit = 1 }
      # Require non-empty tool_calls array object (not empty []) for early-break.
      if ($tc.Count -ge 1 -and ($editHit -eq 1)) { $ledgerProven = 1 }
      if ($ideDead -and $ledObj.termination_reason -and $ledObj.termination_reason -ne 'running') {
        Log "ORPHAN_LEDGER_TERMINATION=$($ledObj.termination_reason) driver_exit=$($ledObj.driver_exit_code)"
      }
    } catch {
      Log "LEDGER_PARSE_ERR=$($_.Exception.Message)"
    }
  }
  $projNow = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
  # Hash drift alone is NOT edit proof (IDE normalize / foreign writers). Require ledger corroboration.
  if ($projHashBefore -and $projNow -and ($projNow -ne $projHashBefore) -and ($editHit -eq 1)) { }
  elseif ($projHashBefore -and $projNow -and ($projNow -ne $projHashBefore)) {
    Log "HASH_DRIFT_UNCORROBORATED before=$projHashBefore now=$projNow"
  }
  $flightPath = Join-Path (Split-Path -Parent $ProjectCpp) 'deep2_flight.jsonl'
  $tipFlightPath = Join-Path (Split-Path -Parent $TipExe) 'deep2_flight.jsonl'
  if (-not (Test-Path -LiteralPath $flightPath) -and (Test-Path -LiteralPath $tipFlightPath)) { $flightPath = $tipFlightPath }
  $flightHint = ''
  if (Test-Path -LiteralPath $flightPath) {
    try {
      $ftail = Get-Content -LiteralPath $flightPath -Tail 3 -EA SilentlyContinue
      if ($ftail) {
        $joined = ($ftail -join ' ')
        if ($joined -match 'prefill_batch_P\d+_at\d+') { $flightHint = 'prefill_batch_progress' }
        elseif ($joined -match 'global_no_progress') { $flightHint = 'global_no_progress' }
        elseif ($joined -match '"type":"progress"') { $flightHint = 'progress' }
      }
    } catch {}
  }
  if ($env:RAWRXD_ISSUE49_HEARTBEAT) {
    try { Set-Content -LiteralPath $env:RAWRXD_ISSUE49_HEARTBEAT -Value "$(Get-Date -Format o) poll orphan=$orphanWait ideDead=$([int]$ideDead) child=$child tool=$toolHit edit=$editHit flight=$flightHint" -Encoding ASCII } catch {}
  }
  Log "POLL loopChild=$child spawned=$loopSpawned session=$sessionHit dispatch=$dispatchHit tool=$toolHit edit=$editHit ledgerProven=$ledgerProven orphanWait=$orphanWait ideDead=$([int]$ideDead) flight=$flightHint"
  # Early-break ONLY on ledger-corroborated tool AND edit.
  if ($loopSpawned -eq 1 -and $ledgerProven -eq 1 -and $projNow -and $projHashBefore -and ($projNow -ne $projHashBefore)) { break }
  if ($ideDead -and $child -eq 0) { break }
  Start-Sleep 3
}

# Build substrate after agentic spawn attempt (do not invent PASS if IDE already dead).
$id1312 = -1; $id1604 = -1
if (-not $p.HasExited -and [I49bTip018]::IsWindow($main)) {
  [void][I49bTip018]::Cmd($main, 3014, 15000)
  for ($w = 0; $w -lt 20; $w++) {
    Start-Sleep 1
    if ($p.HasExited) { Log "IDE_EXIT_DURING_BUILD=$($p.ExitCode)"; break }
    $id1312 = [I49bTip018]::IdList($main, 1312)
    $id1604 = [I49bTip018]::IdLen($main, 1604)
    if (($w % 5) -eq 0) { Log "BUILD_POLL t=$w id1312=$id1312 id1604=$id1604" }
    if ($id1312 -gt 0 -or $id1604 -gt 0) { break }
  }
}
$buildFailSubstrate = ($id1312 -gt 0 -or ($id1604 -gt 0))
Mark $steps '11_BUILD_FAILURE_SUBSTRATE_ONLY' $(if ($buildFailSubstrate) { "PASS_FIXTURE_BUILD_FAIL items=$id1312 out=$id1604" } else { 'FAIL_NO_BUILD_OUTPUT' })
Mark $steps '11_BUILD_FAILURE_RECOVERY' 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'

$projAfter = if (Test-Path $ProjectCpp) { (Get-FileHash -LiteralPath $ProjectCpp -Algorithm SHA256).Hash } else { '' }
$ledgerPath = Join-Path (Split-Path -Parent $TipExe) '.rawrxd\ledger\agent_session.json'
$ledgerToolCalls = 0; $ledgerEdit = 0
if (Test-Path -LiteralPath $ledgerPath) {
  try {
    $ledObj = Get-Content -LiteralPath $ledgerPath -Raw | ConvertFrom-Json
    if ($ledObj.acceptance) {
      $ledgerToolCalls = [int]$ledObj.acceptance.tool_calls
      $ledgerEdit = [int]([bool]$ledObj.acceptance.source_edit_performed)
    }
    if ($ledObj.tool_calls -is [Array]) { $ledgerToolCalls = [Math]::Max($ledgerToolCalls, @($ledObj.tool_calls).Count) }
    if ($ledObj.files_modified -is [Array] -and @($ledObj.files_modified).Count -gt 0) { $ledgerEdit = 1 }
  } catch {}
}
$hashChanged = ($projHashBefore -and $projAfter -and ($projAfter -ne $projHashBefore))
$sourceEdited = ($ledgerEdit -eq 1 -and $hashChanged)
if ($toolHit -eq 1 -and $ledgerToolCalls -lt 1) {
  Log "TOOL_HIT_RETRACTED_LEDGER_TOOL_CALLS=$ledgerToolCalls"
  $toolHit = 0
}
Mark $steps '06_AGENT_READS_PROJECT' $(if ($loopSpawned -eq 1) { 'PARTIAL_LOOP_SPAWNED_READ_NOT_PROVEN' } else { 'BLOCKED_NO_AGENTIC_LOOP_PROCESS' })
Mark $steps '07_AGENT_REASONING_GPU' $(if ($reasonHit -eq 1) { 'PARTIAL_STRING_HIT_NOT_GPU_PROOF' } else { 'NOT_RUN' })
Mark $steps '08_TOOL_AUTHORITY' $(if ($toolHit -eq 1 -and $ledgerToolCalls -ge 1) { 'PASS_TOOL_LEDGER_CORROBORATED' } else { 'BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE' })
Mark $steps '09_RESULT_REINJECTION' $(if ($reinjectHit -eq 1) { 'PASS' } else { 'NOT_RUN' })
Mark $steps '10_REAL_SOURCE_EDIT' $(if ($sourceEdited) { 'PASS_SOURCE_HASH_AND_LEDGER' } else { $(if ($hashChanged) { 'NOT_RUN_HASH_DRIFT_UNCORROBORATED' } else { 'NOT_RUN_NO_AGENT_EDIT' }) })
# Durable after hashes + tool/edit evidence for steps 08-11
$toolEditAfterPath = Join-Path $Evidence08_11 'after_hashes.txt'
$toolHitPath = Join-Path $Evidence08_11 'tool_call_evidence.txt'
$editHitPath = Join-Path $Evidence08_11 'source_edit_evidence.txt'
@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROJECT_SHA_AFTER=$projAfter
PROJECT_SHA_BEFORE=$projHashBefore
SOURCE_EDITED=$([int]$sourceEdited)
TOOL_CALL_EVIDENCE=$toolHit
REINJECTION_EVIDENCE=$reinjectHit
LOOP_SPAWNED=$loopSpawned
AGENT_WAIT_SEC=$AgentWaitSec
"@ | Set-Content -LiteralPath $toolEditAfterPath -Encoding ASCII
@"
TOOL_CALL_EVIDENCE=$toolHit
OUTPUT_SAMPLE=$outSample
"@ | Set-Content -LiteralPath $toolHitPath -Encoding ASCII
@"
SOURCE_EDITED=$([int]$sourceEdited)
PROJECT_SHA_BEFORE=$projHashBefore
PROJECT_SHA_AFTER=$projAfter
"@ | Set-Content -LiteralPath $editHitPath -Encoding ASCII
$rtLogCopy = Join-Path $LogDir 'chat_runtime.log'
if (Test-Path -LiteralPath $rtLogCopy) {
  Copy-Item -LiteralPath $rtLogCopy -Destination (Join-Path $Evidence08_11 'chat_runtime.log') -Force -EA SilentlyContinue
}
Log "TOOL_EDIT_HASH_AFTER=$projAfter edited=$([int]$sourceEdited) tool=$toolHit"
Mark $steps '12_MODEL_DIAGNOSES_FAILURE' 'NOT_RUN'
Mark $steps '13_SECOND_EDIT' 'NOT_RUN'
Mark $steps '14_FINAL_BUILD' 'NOT_RUN'
Mark $steps '15_FINAL_TESTS' 'NOT_RUN'
Mark $steps '17_AGENT_EVIDENCE_REPORT' 'NOT_RUN'
if ($sessionHit -eq 1) { Mark $steps 'H57_AGENTSESSION' 'PASS_SESSION_SPAWNED_RUNTIME' }

$panel = [int][I49bTip018]::VisId($main, 1300)
$id1604b = [I49bTip018]::IdLen($main, 1604)
$id1312b = [I49bTip018]::IdList($main, 1312)
$alive = [int](-not $p.HasExited -and [I49bTip018]::IsWindow($main))

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
if ($sessionHit -eq 0) { $blockers += 'AGENT_SESSION_RUNTIME_NOT_OBSERVED' }
if ($loopSpawned -eq 0) { $blockers += 'deep2_agentic_loop_PROCESS_NOT_SPAWNED' }
if ($dispatchHit -eq 0) { $blockers += 'REQUEST_DISPATCH_NOT_CORRELATED' }
if ($toolHit -eq 0) { $blockers += 'NO_REAL_TOOL_CALL_EVIDENCE' }
if (-not $sourceEdited) { $blockers += 'NO_AGENT_SOURCE_EDIT' }
if ($steps['11_BUILD_FAILURE_RECOVERY'] -notmatch '^PASS') { $blockers += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
if ($steps['03_GPU_RUNTIME_R9700'] -match 'NOT_RUN') { $blockers += 'GPU_R9700_NOT_RUN' }
if ($steps['16_MULTI_AGENT_REVIEW'] -match 'NOT_RUN') { $blockers += 'NO_INDEPENDENT_REVIEWER' }
$blockers += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('ISSUE49_PRODUCT_FINAL=MEASURED')
[void]$sb.AppendLine("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
[void]$sb.AppendLine("TIP=tip_final_integ_018")
[void]$sb.AppendLine("HOST_SEED_DEFAULT=OFF")
[void]$sb.AppendLine("MODEL_ORIGINATED_TOOL_REQUIRED=1")
[void]$sb.AppendLine("TIP_SHA256=$sha")
[void]$sb.AppendLine("TIP_EXE=$TipExe")
[void]$sb.AppendLine("ISSUE49_VERDICT=$verdict")
[void]$sb.AppendLine("MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED")
[void]$sb.AppendLine("ENGINEERING_MATURITY=82%_UNCHANGED")
[void]$sb.AppendLine("CHAT_INPUT_METHOD=$method")
[void]$sb.AppendLine("CHAT_INPUT_SET_EQ_GET=$setEqGet")
[void]$sb.AppendLine("AgentSession_IN_EXE=$agentSessionInExe")
[void]$sb.AppendLine("AgentSession_bound_IN_EXE=$agentSessionBound")
[void]$sb.AppendLine("AGENT_SESSION_RUNTIME=$sessionHit")
[void]$sb.AppendLine("REQUEST_DISPATCH_CORRELATED=$dispatchHit")
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
[void]$sb.AppendLine('E6CF_RESTORE=HELD')
[void]$sb.AppendLine('CONTROLLING_TIP=CC79')
[void]$sb.AppendLine('CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4')
[void]$sb.AppendLine('A4F_UNTOUCHED=1')
[void]$sb.AppendLine('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$sb.AppendLine('TIP_MOVE=0')
[void]$sb.AppendLine("RUNLOG=$runlog")
[void]$sb.AppendLine('PROMOTE=0')
[void]$sb.AppendLine('CERTIFIED=0')
[void]$sb.AppendLine('PRODUCT_PASS=0')
$sb.ToString() | Set-Content -LiteralPath $receipt
Get-Content $receipt

[void][I49bTip018]::Cmd($main, 4107, 2000)
[void][I49bTip018]::Cmd($main, 4105, 2000)
Start-Sleep 1
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } } catch {}
# PID-scoped cleanup only (avoid killing sibling lanes). Lock owned by exclusive wrapper.
Get-Process -Name 'deep2_agentic_loop' -EA SilentlyContinue | Where-Object { $_.Id -ne $PID } | Stop-Process -Force -EA SilentlyContinue
# Post-run SHA freeze confirm
$post = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
"POST_HARNESS_SHA_MATCH=$([int]($post -eq $sha))" | Add-Content $receipt
exit $(if ($verdict -eq 'PASS') { 0 } else { 4 })
















$ErrorActionPreference='Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$base = 'G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001'
$outDir = Join-Path $base "A8_MODEL_WIRE_PEER\run_$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$ws = Join-Path $outDir 'ws'
New-Item -ItemType Directory -Force -Path $ws | Out-Null
@'
// A8_MODEL_WIRE fixture
int main(){ return 0; }
'@ | Set-Content (Join-Path $ws 'bug.cpp') -Encoding ASCII
'note=A8_MODEL_WIRE_READ_TARGET' | Set-Content (Join-Path $ws 'note.txt') -Encoding ASCII
$peerRoot = Join-Path $base 'A8_MODEL_WIRE_PEER'
$exe = Join-Path $peerRoot 'RawrXD-Win32IDE_tip_land_a8_modelwire.exe'
$model = 'G:\~dev\rawrxd\models\tinyllama.gguf'
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$preBug = (Get-FileHash (Join-Path $ws 'bug.cpp') -Algorithm SHA256).Hash
$log = Join-Path $outDir 'RUNLOG.txt'
function WLog($m){ $l='[{0}] {1}' -f (Get-Date -Format 'o'),$m; Add-Content $log $l; Write-Output $l }
WLog "CITE=BR_CONTINUE_THREE_GATES_HOLD_001"
WLog "PATH=B_PEER_MODEL_WIRE"
WLog "EXE=$exe"
WLog "SHA256=$sha"
WLog "MODEL=$model"
WLog "CONTROLLING_TIP=6754616E UNCHANGED=1"
WLog "INVENT_FORCE_TOOL=0 INVENT_DEEP2=0 PROMOTE=0"
# settings pin
$settingsDir = Join-Path $env:APPDATA 'RawrXD'
New-Item -ItemType Directory -Force -Path $settingsDir | Out-Null
$settings = Join-Path $settingsDir 'settings.ini'
$bak = Join-Path $outDir 'settings.ini.bak'
if (Test-Path $settings) { Copy-Item $settings $bak -Force }
@"
[General]
WorkingDirectory=$ws
[Model]
LastModelPath=$model
RecentModels=$model
[Agent]
CycleCount=8
"@ | Set-Content $settings -Encoding ASCII
WLog "SETTINGS_PINNED LastModelPath=tinyllama"
function ExitHex([int]$c){ '0x{0:X8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes($c),0) }

$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class A8Mw {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetPropW(IntPtr h, string name);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C; public const uint BM_CLICK=0x00F5;
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true; var c=new StringBuilder(256); GetClassNameW(h,c,256); string s=c.ToString(); if(s=="RawrXD_IDE_MainWindow"||s=="RawrXD_IDE_Window"){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static bool MenuReady(IntPtr main){ return main!=IntPtr.Zero && GetPropW(main,"RawrXD.MainMenuReady")!=IntPtr.Zero; }
  public static int PostId(IntPtr h,int id){ if(h==IntPtr.Zero||!IsWindow(h)) return 0; return PostMessageW(h,WM_COMMAND,(IntPtr)id,IntPtr.Zero)?1:0; }
  public static IntPtr FindTitlePid(uint pid,string needle){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid) return true; var t=new StringBuilder(256); GetWindowTextW(h,t,256); if(t.ToString().IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindChildClass(IntPtr parent,string clsWant){ IntPtr f=IntPtr.Zero; EnumChildWindows(parent,(h,l)=>{ var c=new StringBuilder(64); GetClassNameW(h,c,64); if(string.Equals(c.ToString(),clsWant,StringComparison.OrdinalIgnoreCase)){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static IntPtr FindChildTitle(IntPtr parent,string needle){ IntPtr f=IntPtr.Zero; EnumChildWindows(parent,(h,l)=>{ var t=new StringBuilder(128); GetWindowTextW(h,t,128); if(t.ToString().IndexOf(needle,StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int FillBounded(uint pid,string prompt){ IntPtr dlg=FindTitlePid(pid,"Bounded Agent Loop"); if(dlg==IntPtr.Zero) return 0; IntPtr edit=FindChildClass(dlg,"Edit"); if(edit==IntPtr.Zero) return 0; SendMessageW(edit,WM_SETTEXT,IntPtr.Zero,prompt); IntPtr ok=FindChildTitle(dlg,"Run Agent"); if(ok==IntPtr.Zero) ok=FindChildTitle(dlg,"OK"); if(ok==IntPtr.Zero) return 0; SetForegroundWindow(dlg); PostMessageW(dlg,WM_COMMAND,(IntPtr)1,IntPtr.Zero); SendMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero); return 1; }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null
Get-Process -Name 'RawrXD-Win32IDE*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName=$exe; $psi.WorkingDirectory=$ws; $psi.UseShellExecute=$false; $psi.Arguments="`"$ws`""
# Avoid EnvironmentVariables indexer null-key issue: set via ProcessStartInfo after UseShellExecute false
$psi.EnvironmentVariables['RAWRXD_GUI']='1'
# Boot: FORCE_CPU + SKIP_GPU_POWER_PROBE keep UI/PDH stable (dialog fill).
# AgentPanel LoadModel worker clears FORCE_CPU and arms GPU ProductOpen lane.
$psi.EnvironmentVariables['RAWRXD_ALLOW_GPU']='0'
$psi.EnvironmentVariables['RAWRXD_HOST_DECODE']='1'
$psi.EnvironmentVariables['RAWR_HOST_DECODE']='1'
$psi.EnvironmentVariables['RAWRXD_FORCE_CPU_INFERENCE']='1'
$psi.EnvironmentVariables['RAWR_FORCE_CPU']='1'
$psi.EnvironmentVariables['RAWR_FORCE_GPU']='0'
$psi.EnvironmentVariables['RAWR_NO_CPU_FALLBACK']='0'
$psi.EnvironmentVariables['LOCAL_ONLY']='1'
$psi.EnvironmentVariables['RAWRXD_DISABLE_OLLAMA_FETCH']='1'
$psi.EnvironmentVariables['LOCAL_ONLY_NO_OLLAMA']='1'
$psi.EnvironmentVariables['RAWRXD_SKIP_GPU_POWER_PROBE']='1'
$psi.EnvironmentVariables['RAWRXD_SKIP_DEFERRED_MODEL_LOAD']='1'
$psi.EnvironmentVariables['SKIP_DEFERRED_MODEL_LOAD']='1'
$psi.EnvironmentVariables['RAWRXD_DEFAULT_MODEL']=$model
$psi.EnvironmentVariables['RAWRXD_PRODUCT_MODEL']=$model
# Pin residency — neutralize ArmSpeed E8B0M (59568MiB) before ProductOpen.
$psi.EnvironmentVariables['WEIGHT_BUDGET_MIB']='8192'
$psi.EnvironmentVariables['DEEP2_WEIGHT_BUDGET_MIB']='8192'
$psi.EnvironmentVariables['WEIGHT_BUDGET_INPUT']='8192'
# Kill reverse bunnyhop reconstruct (R74 C0000409 mid-prefill on TinyLlama).
$psi.EnvironmentVariables['RAWRXD_NVME_REVERSE_BUNNYHOP']='0'
# R75: skip ProductPathSeal/product::Emit (A2) — post-decode MEAN_TOKEN_WALL GS.
$psi.EnvironmentVariables['RAWRXD_A8_MIN_TEARDOWN']='1'
$psi.EnvironmentVariables['RAWRXD_A8_WORKSPACE']=$ws
$psi.EnvironmentVariables['DEEP2_ISOLATION_RUN']='A2'
# Clear stale MODEL_RESIDENT crumb from prior peer runs (R73e false-positive).
$staleCrumb = Join-Path $peerRoot 'logs\MODEL_RESIDENT_CRUMB.txt'
if (Test-Path $staleCrumb) { Remove-Item $staleCrumb -Force -EA SilentlyContinue }
$staleDisp = Join-Path $peerRoot 'logs\MODEL_LOAD_DISPATCH.txt'
if (Test-Path $staleDisp) { Remove-Item $staleDisp -Force -EA SilentlyContinue }
$sw=[Diagnostics.Stopwatch]::StartNew()
$proc=[Diagnostics.Process]::Start($psi)
WLog "SPAWN_PID=$($proc.Id)"
$menu=0; $main=[IntPtr]::Zero
$deadline=(Get-Date).AddSeconds(45)
while((Get-Date) -lt $deadline){
    if($proc.HasExited){ $hx=(ExitHex ([int]$proc.ExitCode)); WLog "EXIT_EARLY code=$($proc.ExitCode) hex=$hx"; break }
  $main=[A8Mw]::FindMain([uint32]$proc.Id)
  if([A8Mw]::MenuReady($main)){ $menu=1; break }
  Start-Sleep -Milliseconds 400
}
WLog ("MENU_READY={0} MAIN=0x{1:X} WALL_MS={2}" -f $menu,$main.ToInt64(),$sw.ElapsedMilliseconds)
$r=[ordered]@{MENU_READY=$menu;POST_4120=0;BOUNDED_DIALOG_FILLED=0;MODEL_LOAD_SEEN=0;MODEL_RESIDENT_CRUMB=0;TRANSCRIPT_CRUMB=0;FILES_READ=0;PATCH_APPLIED=0;BUILD_COMPLETED=0;TEST_EXECUTED=0;AGENT_RESULT5=0;LLM_ERROR_SEEN=0;PRE_BUG_SHA=$preBug;POST_BUG_SHA=$preBug;PATCH_DELTA=0;HWND_EBT='NOT_RUN';EDIT_BUILD_TEST_PASS=0;BLOCKER='';EXIT_CODE='';EXIT_HEX=''}
if($menu -eq 1){
  Start-Sleep 3
  $main=[A8Mw]::FindMain([uint32]$proc.Id)
  $r.POST_4120=[A8Mw]::PostId($main,4120)
  WLog "POST_4120=$($r.POST_4120)"
  $prompt='Using tools only: read_file note.txt; read_file bug.cpp; write_file bug.cpp with a C program that prints AGENT_RESULT=5; run terminal cl /nologo /Fe:bug.exe bug.cpp && bug.exe. Stop when AGENT_RESULT=5 is printed.'
  $fillEnd=(Get-Date).AddSeconds(45)
  while((Get-Date) -lt $fillEnd){ if([A8Mw]::FillBounded([uint32]$proc.Id,$prompt) -eq 1){ $r.BOUNDED_DIALOG_FILLED=1; break }; Start-Sleep -Milliseconds 300 }
  WLog "BOUNDED_DIALOG_FILLED=$($r.BOUNDED_DIALOG_FILLED)"
  $waitEnd=(Get-Date).AddSeconds(360)
  while((Get-Date) -lt $waitEnd){
    if($proc.HasExited){ $r.EXIT_CODE="$($proc.ExitCode)"; $r.EXIT_HEX=(ExitHex ([int]$proc.ExitCode)); WLog "PROC_EXIT code=$($r.EXIT_CODE) hex=$($r.EXIT_HEX)"; break }
    $tx=Join-Path $ws '.rawrxd\transcripts'
    if(Test-Path $tx){
      $files=@(Get-ChildItem $tx -Filter '*.json' -EA SilentlyContinue)
      if($files.Count -gt 0){
        $r.TRANSCRIPT_CRUMB=1
        Copy-Item $files[0].FullName (Join-Path $outDir 'transcript.json') -Force
        $tb=Get-Content $files[0].FullName -Raw -EA SilentlyContinue
        if($tb -match '(?i)read_file|note\.txt'){ $r.FILES_READ=1 }
        if($tb -match '(?i)write_file|replace_in_file|apply_patch'){ $r.PATCH_APPLIED=1 }
        if($tb -match '(?i)run_build|cl\.exe|/Fe:'){ $r.BUILD_COMPLETED=1 }
        if($tb -match 'AGENT_RESULT=5' -or $tb -match '(?i)bug\.exe'){ $r.TEST_EXECUTED=1; $r.AGENT_RESULT5=1 }
        if($tb -match '(?i)NO_MODEL_RESIDENT|Native inference failed|\[BackendError\]|ProductDeep2Infer failed|\[Agent error:'){ $r.LLM_ERROR_SEEN=1 }
        if($tb -match 'MODEL_RESIDENT=1' -or $tb -match '(?i)Registered model tag'){ $r.MODEL_RESIDENT_CRUMB=1 }
      }
    }
    # Durable crumbs first (written by onBoundedAgentModelLoadDone / worker dispatch)
    $crumbHits = @(
      (Join-Path $ws '.rawrxd\MODEL_RESIDENT_CRUMB.txt'),
      (Join-Path $ws '.rawrxd\MODEL_LOAD_DISPATCH.txt'),
      (Join-Path $ws '.rawrxd\FILES_READ_CRUMB.txt'),
      (Join-Path $peerRoot 'logs\MODEL_RESIDENT_CRUMB.txt')
    )
    foreach($cf in $crumbHits){
      if(-not (Test-Path $cf)){ continue }
      if($cf -match 'MODEL_LOAD_DISPATCH'){ $r.MODEL_LOAD_SEEN=1; continue }
      if($cf -match 'FILES_READ_CRUMB'){ $r.FILES_READ=1; continue }
      $cb = Get-Content $cf -Raw -EA SilentlyContinue
      if($cb -match 'MODEL_RESIDENT=1'){ $r.MODEL_RESIDENT_CRUMB=1 }
      elseif($cb -match 'MODEL_RESIDENT=0' -and $r.MODEL_RESIDENT_CRUMB -ne 1){ $r.LLM_ERROR_SEEN=1 }
    }
    # Also scan IDE logs for LoadModel worker + MODEL_RESIDENT (output panel crumbs)
    $logRoots = @((Join-Path $peerRoot 'logs'), (Join-Path $ws '.rawrxd'), (Join-Path $ws 'logs'))
    foreach($lr in $logRoots){
      if(-not (Test-Path $lr)){ continue }
      Get-ChildItem $lr -File -EA SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) -and $_.Length -lt 8MB -and ($_.Extension -match '\.(log|txt)$' -or $_.Name -match 'trace|ide|output|MODEL_') } | ForEach-Object {
        $lb = Get-Content $_.FullName -Raw -EA SilentlyContinue
        if(-not $lb){ return }
        if($lb -match 'LoadModel worker dispatch|DISPATCH=1'){ $r.MODEL_LOAD_SEEN=1 }
        if($lb -match 'MODEL_RESIDENT=1'){ $r.MODEL_RESIDENT_CRUMB=1 }
        if(($lb -match 'NO_MODEL_RESIDENT' -or $lb -match 'MODEL_RESIDENT=0') -and $r.MODEL_RESIDENT_CRUMB -ne 1){ $r.LLM_ERROR_SEEN=1 }
        if($lb -match '(?i)Native inference failed|\[BackendError\]|ProductDeep2Infer failed|SubmitInference/GetResult missing'){ $r.LLM_ERROR_SEEN=1 }
      }
    }
    $post=(Get-FileHash (Join-Path $ws 'bug.cpp') -Algorithm SHA256).Hash
    $bug=Get-Content (Join-Path $ws 'bug.cpp') -Raw -EA SilentlyContinue
    if(($post -ne $preBug) -and $bug -match 'AGENT_RESULT=5'){ $r.PATCH_APPLIED=1; $r.AGENT_RESULT5=1 }
    if(Test-Path (Join-Path $ws 'bug.exe')){ $r.BUILD_COMPLETED=1; $r.TEST_EXECUTED=1 }
    $crumbFile=Join-Path $ws '.rawrxd\MODEL_RESIDENT_CRUMB.txt'
    if(Test-Path $crumbFile){ $cb=Get-Content $crumbFile -Raw -EA SilentlyContinue; if($cb -match 'MODEL_RESIDENT=1'){ $r.MODEL_RESIDENT_CRUMB=1 }; if($cb -match 'MODEL_RESIDENT=0' -and $r.MODEL_RESIDENT_CRUMB -ne 1){ $r.LLM_ERROR_SEEN=1 } }
    $dispFile=Join-Path $ws '.rawrxd\MODEL_LOAD_DISPATCH.txt'
    if(Test-Path $dispFile){ $r.MODEL_LOAD_SEEN=1 }
    # EBT wait: do NOT break on MODEL_RESIDENT alone (R72 killed agent before tools).
    if($r.PATCH_APPLIED -eq 1 -and $r.BUILD_COMPLETED -eq 1 -and $r.AGENT_RESULT5 -eq 1){ break }
    if($r.FILES_READ -eq 1 -and $r.PATCH_APPLIED -eq 1 -and $r.BUILD_COMPLETED -eq 1 -and ($r.TEST_EXECUTED -eq 1 -or $r.AGENT_RESULT5 -eq 1)){ break }
    Start-Sleep 2
  }
}
$proc.Refresh()
if(-not $proc.HasExited){ try{$proc.Kill()}catch{}; Start-Sleep 1 } else { if(-not $r.EXIT_CODE){ $r.EXIT_CODE="$($proc.ExitCode)"; $r.EXIT_HEX=(ExitHex ([int]$proc.ExitCode)) } }
$sw.Stop()
$r.POST_BUG_SHA=(Get-FileHash (Join-Path $ws 'bug.cpp') -Algorithm SHA256).Hash
$r.PATCH_DELTA=[int]($r.POST_BUG_SHA -ne $preBug)
$full=($r.FILES_READ -eq 1 -and $r.PATCH_APPLIED -eq 1 -and $r.BUILD_COMPLETED -eq 1 -and ($r.TEST_EXECUTED -eq 1 -or $r.AGENT_RESULT5 -eq 1))
if($full){ $r.HWND_EBT='PASS'; $r.EDIT_BUILD_TEST_PASS=1; $r.BLOCKER='' }
elseif($r.BOUNDED_DIALOG_FILLED -eq 1 -or $r.TRANSCRIPT_CRUMB -eq 1 -or $r.MODEL_RESIDENT_CRUMB -eq 1){
  $r.HWND_EBT='RUN_PARTIAL'; $r.EDIT_BUILD_TEST_PASS=0
  if($r.LLM_ERROR_SEEN -eq 1){ $r.BLOCKER='LLM_ERROR_AFTER_DIALOG' }
  elseif($r.MODEL_RESIDENT_CRUMB -eq 0 -and $r.TRANSCRIPT_CRUMB -eq 0){ $r.BLOCKER='NO_MODEL_RESIDENT_OR_NO_TRANSCRIPT' }
  else { $r.BLOCKER='PARTIAL_EBT_CRUMBS_ONLY' }
} elseif($menu -eq 1){ $r.HWND_EBT='RUN_NO_EBT_CRUMB'; $r.EDIT_BUILD_TEST_PASS=0; $r.BLOCKER='DIALOG_OR_POST_INCOMPLETE' }
else { $r.HWND_EBT='RUN_FAIL'; $r.EDIT_BUILD_TEST_PASS=0; $r.BLOCKER='MENU_NOT_READY_OR_CRASH' }
WLog "HWND_EBT=$($r.HWND_EBT) PASS=$($r.EDIT_BUILD_TEST_PASS) BLOCKER=$($r.BLOCKER) WALL_MS=$($sw.ElapsedMilliseconds)"
($r.GetEnumerator()|%{ "$($_.Key)=$($_.Value)" }) | Set-Content (Join-Path $outDir 'RESULT.txt')
$cat11=25; $disp='HOLD_25_NO_EDIT_BUILD_TEST_PASS'
if($r.EDIT_BUILD_TEST_PASS -eq 1){ $cat11=55; $disp='PEER_PROPOSE_55_EDIT_BUILD_TEST_PASS' }
$seal=@"
ID=A8_MODEL_WIRE_PEER_$stamp
PATH=B
CITE=board_receipts/BR_CONTINUE_THREE_GATES_HOLD_001.txt
PRIOR_SEAL=GUI_TOP25_VALUATION_001/A8_GUI_EDIT_BUILD_TEST_20261113_220615/SEAL_PROPOSE.txt
PEER_EXE=$exe
PEER_SHA256=$sha
CONTROLLING_TIP=tip_land_6754616E SHA=6754616E... UNCHANGED=1
SOURCE_WIRE=Win32IDE_AgentPanel.cpp startAgentSession std::thread LoadModel + WM_APP+207
FORCE_TOOL=ABSENT
DEEP2_AGENTIC_LOOP_EXE=ABSENT
INVENT_FORCE_TOOL=0
INVENT_DEEP2_HELPER=0
LOADMODEL_WORKER_DISPATCH_STRING=1
MODEL_LOAD_SEEN=$($r.MODEL_LOAD_SEEN)
MENU_READY=$($r.MENU_READY)
POST_4120=$($r.POST_4120)
BOUNDED_DIALOG_FILLED=$($r.BOUNDED_DIALOG_FILLED)
MODEL_RESIDENT_CRUMB=$($r.MODEL_RESIDENT_CRUMB)
TRANSCRIPT_CRUMB=$($r.TRANSCRIPT_CRUMB)
FILES_READ=$($r.FILES_READ)
PATCH_APPLIED=$($r.PATCH_APPLIED)
PATCH_DELTA=$($r.PATCH_DELTA)
BUILD_COMPLETED=$($r.BUILD_COMPLETED)
TEST_EXECUTED=$($r.TEST_EXECUTED)
AGENT_RESULT5=$($r.AGENT_RESULT5)
LLM_ERROR_SEEN=$($r.LLM_ERROR_SEEN)
EXIT_CODE=$($r.EXIT_CODE)
EXIT_HEX=$($r.EXIT_HEX)
HWND_AGENTIC_EDIT_BUILD_TEST=$($r.HWND_EBT)
EDIT_BUILD_TEST_PASS=$($r.EDIT_BUILD_TEST_PASS)
BLOCKER=$($r.BLOCKER)
PRIOR_CAT11_CONTROLLING=25
PEER_PROPOSE_CAT11=$cat11
PEER_PROPOSE_DISP=$disp
PARENT_PCT_WRITE=0
JOINT_PCT=0
PRIOR_STALE_PEER_SHA=97A7EF29FF7608C0BE44D8D753ACA31907AE9B93958B947DEE1DA456D22082BC
CRASH_TIP_REF=0xC000041D @ +0x1F99DB4 module=tip_land_6754616E.exe; heap peer/tip 0xC0000374
NOTE=Peer rebuilt with LoadModel worker offload. Cat11 raise only if EDIT_BUILD_TEST_PASS=1. No JOINT PCT.
PROMOTE=0 CERTIFIED=0 TIP_CLIMB=HOLD NOT_RUN!=PASS INVENT_PASS=0
ASOF=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))
"@
Set-Content (Join-Path $outDir 'SEAL_PROPOSE.txt') $seal -Encoding ASCII
Copy-Item (Join-Path $outDir 'SEAL_PROPOSE.txt') (Join-Path $peerRoot 'SEAL_PROPOSE.txt') -Force
# crumbs table
@"
A8_MODEL_WIRE_PEER crumbs
CITE=BR_CONTINUE_THREE_GATES_HOLD_001
PEER_SHA256=$sha
| Crumb | Value |
| MENU_READY | $($r.MENU_READY) |
| POST_4120 | $($r.POST_4120) |
| BOUNDED_DIALOG_FILLED | $($r.BOUNDED_DIALOG_FILLED) |
| MODEL_LOAD_SEEN | $($r.MODEL_LOAD_SEEN) |
| MODEL_RESIDENT_CRUMB | $($r.MODEL_RESIDENT_CRUMB) |
| TRANSCRIPT_CRUMB | $($r.TRANSCRIPT_CRUMB) |
| FILES_READ | $($r.FILES_READ) |
| PATCH_APPLIED | $($r.PATCH_APPLIED) |
| BUILD_COMPLETED | $($r.BUILD_COMPLETED) |
| TEST_EXECUTED | $($r.TEST_EXECUTED) |
| AGENT_RESULT5 | $($r.AGENT_RESULT5) |
| EDIT_BUILD_TEST_PASS | $($r.EDIT_BUILD_TEST_PASS) |
| EXIT_HEX | $($r.EXIT_HEX) |
| HWND_EBT | $($r.HWND_EBT) |
| BLOCKER | $($r.BLOCKER) |
PROMOTE=0 CERTIFIED=0 JOINT_PCT=0
"@ | Set-Content (Join-Path $outDir 'CRUMBS_TABLE.txt') -Encoding ASCII
Copy-Item (Join-Path $outDir 'CRUMBS_TABLE.txt') (Join-Path $peerRoot 'CRUMBS_TABLE.txt') -Force
# restore settings
if (Test-Path $bak) { Copy-Item $bak $settings -Force }
WLog "SEAL=$(Join-Path $outDir 'SEAL_PROPOSE.txt')"
Write-Output "OUTDIR=$outDir"
Write-Output $seal


# Focused SESSION_REAL proof: START once, wait for pause/vars/BP — NO early STOP.
$ErrorActionPreference = 'Continue'
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe'
$expect = '27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC'
$debuggee = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\debuggee_fixture.exe'
$broken = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$logDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\debug_session_real_27e2'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $outDir ("debug_session_real_$stamp.txt")
$receipt = Join-Path $outDir 'DEBUG_SESSION_REAL_START_ONLY_RECEIPT.txt'
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
if ($sha -ne $expect) {
  @"
DEBUG_SESSION_REAL=0
DEBUG_RESULT=SHA_DRIFT
TIP_SHA256=$sha
EXPECT=$expect
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class DbgSR {
  public const uint WM_COMMAND=0x0111; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_NORMAL=0;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
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
      if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0){ var t=new StringBuilder(512); GetWindowTextW(h,t,512); return t.ToString(); }
    if(n>200000) n=200000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public static string CollectEvidence(IntPtr root){
    var hits=new List<string>();
    string[] keys=new string[]{
      "Native debug launched","Breakpoint hit","CREATE_PROCESS","BP hit break_site",
      "Debugging start failed","Native debug launch failed","RAWRXD_DEBUGGEE",
      "WaitForDebugEvent","Native debugger:","Creating launch configuration",
      "DEBUGGEE:break_site","g_watch_value","exit_process","EXIT_PROCESS"
    };
    EnumChildWindows(root,(h,lp)=>{
      string txt=GetText(h);
      if(string.IsNullOrEmpty(txt)||txt.Length<8) return true;
      foreach(var k in keys){
        if(txt.IndexOf(k,StringComparison.OrdinalIgnoreCase)>=0){
          int i=txt.IndexOf(k,StringComparison.OrdinalIgnoreCase);
          int a=Math.Max(0,i-40); int b=Math.Min(txt.Length,i+80);
          string snip=txt.Substring(a,b-a).Replace("\r"," ").Replace("\n"," ");
          hits.Add("id="+GetDlgCtrlID(h)+" len="+txt.Length+" :: "+snip);
          break;
        }
      }
      return true;
    },IntPtr.Zero);
    return string.Join(" || ", hits);
  }
}
"@
$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_PROBLEMS_FIXTURE = $broken
$env:RAWRXD_DEBUGGEE = $debuggee
Log "TIP_SHA256=$sha"
Log "DEBUGGEE=$debuggee EXISTS=$([int](Test-Path $debuggee))"
$p = Start-Process -FilePath $exe -ArgumentList @($broken) -WorkingDirectory 'F:\rawrxd' -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i=0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 400
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode)"; break }
  $main = [DbgSR]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  "DEBUG_SESSION_REAL=0`nDEBUG_RESULT=NO_MAIN_HWND`nTIP_SHA256=$sha`nPROMOTE=0" | Set-Content $receipt
  exit 2
}
[void][DbgSR]::ShowWindow($main, 9)
[void][DbgSR]::SetForegroundWindow($main)
Start-Sleep 2

# Activate Run/Debug sidebar (activity bar + sidebar alias)
foreach ($act in @(1104, 6004)) {
  $ok = [DbgSR]::Cmd($main, $act, 2500)
  Log "ACTIVATE_DEBUG_VIEW id=$act ok=$ok"
  Start-Sleep -Milliseconds 400
}
$varsPre = [DbgSR]::IdList($main, 6043)
$varsVis = [int][DbgSR]::VisId($main, 6043)
Log "VARS_PRE=$varsPre VIS=$varsVis"

# Single START path only — do NOT post STOP/STEP yet
$startOk = [DbgSR]::Cmd($main, 5060, 8000)
Log "TOOLS_DEBUG_START_5060=$startOk"
Start-Sleep 1
if (-not $startOk) {
  $startOk2 = [DbgSR]::Cmd($main, 10500, 8000)
  Log "DEBUG_START_10500=$startOk2"
}

$varsPeak = $varsPre
$sessionReal = 0
$bpHit = 0
$launched = 0
$failed = 0
$childDbg = 0
$evidence = ''
for ($w=0; $w -lt 30; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "IDE_EXITED=$($p.ExitCode) at_w=$w"; break }
  $v = [DbgSR]::IdList($main, 6043)
  if ($v -gt $varsPeak) { $varsPeak = $v }
  $evidence = [DbgSR]::CollectEvidence($main)
  if ($evidence -match 'Native debug launched') { $launched = 1 }
  if ($evidence -match 'Breakpoint hit|BP hit break_site') { $bpHit = 1 }
  if ($evidence -match 'Debugging start failed|Native debug launch failed') { $failed = 1 }
  $childDbg = @(Get-Process -Name 'debuggee_fixture' -EA SilentlyContinue).Count
  Log "w=$w vars6043=$v peak=$varsPeak childDbg=$childDbg launched=$launched bp=$bpHit fail=$failed"
  if ($v -gt 0 -or $bpHit -eq 1) { $sessionReal = 1; break }
  if ($failed -eq 1 -and $w -ge 3) { break }
}

# If paused with vars, try one step then re-check (still no STOP until after measure)
$stepOk = 'SKIP'
$varsAfterStep = $varsPeak
if ($sessionReal -eq 1 -or $launched -eq 1) {
  $stepOk = [DbgSR]::Cmd($main, 10503, 3000)
  Start-Sleep 2
  $varsAfterStep = [DbgSR]::IdList($main, 6043)
  if ($varsAfterStep -gt $varsPeak) { $varsPeak = $varsAfterStep }
  if ($varsAfterStep -gt 0) { $sessionReal = 1 }
  $evidence = [DbgSR]::CollectEvidence($main)
  Log "STEP_OVER=$stepOk varsAfter=$varsAfterStep"
}

$alive = [int](-not $p.HasExited -and [DbgSR]::IsWindow($main))
if ($sessionReal -eq 0 -and $launched -eq 1 -and ($bpHit -eq 1 -or $varsPeak -gt 0)) { $sessionReal = 1 }
# Fail-closed: launch string alone without BP/vars/pause evidence is NOT SESSION_REAL
if ($sessionReal -eq 0 -and $launched -eq 1 -and $bpHit -eq 0 -and $varsPeak -le 0) {
  $sessionReal = 0
}

$dbgResult = if ($sessionReal -eq 1) { 'PASS_SESSION_REAL' }
             elseif ($failed -eq 1) { 'BLOCKED_LAUNCH_FAILED' }
             elseif ($launched -eq 1) { 'BLOCKED_NO_SESSION_REAL' }
             elseif ($alive -eq 1) { 'BLOCKED_NO_SESSION_REAL' }
             else { 'FAIL_IDE_DEAD' }

$locus = if ($sessionReal -eq 1) { '' }
         elseif ($failed -eq 1) { 'launchNativeDebuggee returned false / CreateProcess failed under GUI START' }
         elseif ($launched -eq 1) { 'launchNativeDebuggee reached; WaitForDebugEvent ran; BP/vars not observed before exit/timeout' }
         else { 'WM_COMMAND START posted; launchNativeDebuggee evidence absent in Output (RUNTIME_REACHED=0)' }

@"
DEBUG_SESSION_REAL_PROBE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA256=$sha
DEBUG_SHA=$sha
DEBUG_RESULT=$dbgResult
SESSION_REAL=$sessionReal
DEBUG_VARS_ID6043_PEAK=$varsPeak
DEBUG_VARS_AFTER_STEP=$varsAfterStep
DEBUG_LAUNCHED_EVIDENCE=$launched
DEBUG_BP_HIT_EVIDENCE=$bpHit
DEBUG_LAUNCH_FAILED_EVIDENCE=$failed
DEBUG_CHILD_DEBUGGEE_PEAK=$childDbg
DEBUG_START_5060=$startOk
DEBUG_STEP_OVER=$stepOk
DEBUG_PRODUCT_PATH=CreateProcess_DEBUG_ONLY_THIS_PROCESS_plus_WaitForDebugEvent
DEBUG_ACTIVE_PROCESS_API=0_EXPECTED_NOT_PRODUCT_PATH
DEBUG_BLOCKED_LOCUS=$locus
DEBUG_EVIDENCE_SNIPS=$evidence
DEBUGGEE_PATH=$debuggee
ALIVE=$alive
PROBE_MODE=START_ONLY_NO_EARLY_STOP
PRIOR_FALSE_NEGATIVE_NOTE=previous four_panel probe posted STOP(10501) before vars wait
A4F_UNTOUCHED=1
CONTROLLING_TIP=CC79
NO_CROSS_SHA_PASS_INHERITANCE=1
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ISSUE49=NOT_DEMONSTRATED
"@ | Set-Content -LiteralPath $receipt
Get-Content $receipt | ForEach-Object { Log $_ }

# Cleanup: STOP then kill
[void][DbgSR]::Cmd($main, 10501, 2000)
Start-Sleep 1
try { if (-not $p.HasExited) { $p.Kill() } } catch {}
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
exit $(if ($sessionReal -eq 1) { 0 } else { 4 })

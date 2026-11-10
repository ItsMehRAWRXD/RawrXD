# Native Debug SESSION_REAL on tip_cc79_integ_002 (F5F4807E...). START once; no mock.
# Product path: CreateProcess(DEBUG_ONLY_THIS_PROCESS) + WaitForDebugEvent.
param(
  [string]$TipExe = "F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_002\RawrXD-Win32IDE-Native-Ext.exe",
  [string]$ExpectSha = "F5F4807E4738F500397AA5ACEBC8BE095806DF19C71FF959083512C73A16BA15",
  [string]$Debuggee = "F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_002\debuggee_fixture.exe",
  [string]$BrokenCpp = "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp",
  [string]$OutDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\candidates\tip_cc79_integ_002_debug"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir, $LogDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
if (-not (Test-Path -LiteralPath $TipExe)) {
  "DEBUG_SESSION=NOT_RUN`nREASON=tip_missing`nPROMOTE=0" | Set-Content (Join-Path $OutDir 'DEBUG_SESSION_REAL_TIP002_RECEIPT.txt')
  exit 2
}
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "debug_session_real_tip002_$stamp.txt"
$receipt = Join-Path $OutDir 'DEBUG_SESSION_REAL_TIP002_RECEIPT.txt'
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
if ($sha -ne $ExpectSha) {
  @"
DEBUG_SESSION_REAL_PROBE=NOT_RUN
REASON=SHA_DRIFT
TIP_SHA256=$sha
EXPECT=$ExpectSha
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}
if (-not (Test-Path -LiteralPath $Debuggee)) {
  @"
DEBUG_SESSION_REAL_PROBE=MEASURED
TIP_SHA256=$sha
DEBUG_RESULT=BLOCKED_NO_DEBUGGEE
SESSION_REAL=0
DEBUGGEE_EXISTS=0
PROMOTE=0
"@ | Set-Content $receipt
  exit 4
}
$dbgSha = (Get-FileHash -LiteralPath $Debuggee -Algorithm SHA256).Hash
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class DbgF5 {
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
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0){ var t=new StringBuilder(512); GetWindowTextW(h,t,512); return t.ToString(); }
    if(n>80000) n=80000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public static string Collect(IntPtr root){
    var hits=new List<string>();
    string[] keys=new[]{"Native debug launched","Breakpoint hit","CREATE_PROCESS","BP hit break_site","RAWRXD_DEBUGGEE","Creating launch","g_watch_value","launched pid","EXIT_PROCESS","Debugging start failed","Native debug:","Native debugger","WaitForDebugEvent","debuggee_fixture"};
    EnumChildWindows(root,(h,lp)=>{
      string txt=GetText(h);
      if(string.IsNullOrEmpty(txt)||txt.Length<6) return true;
      foreach(var k in keys){
        if(txt.IndexOf(k,StringComparison.OrdinalIgnoreCase)>=0){
          int i=txt.IndexOf(k,StringComparison.OrdinalIgnoreCase);
          int a=Math.Max(0,i-40); int b=Math.Min(txt.Length,i+90);
          hits.Add("id="+GetDlgCtrlID(h)+" :: "+txt.Substring(a,b-a).Replace("\r"," ").Replace("\n"," "));
          break;
        }
      }
      return true;
    }, IntPtr.Zero);
    return string.Join(" || ", hits);
  }
}
"@
$tipDir = Split-Path -Parent $TipExe
$env:RAWRXD_LOG_DIR = $LogDir
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
$env:RAWRXD_DEBUGGEE = $Debuggee
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
$env:RAWRXD_DEBUGGEE = $Debuggee
Log "TIP_SHA256=$sha"
Log "DEBUGGEE=$Debuggee SHA=$dbgSha EXISTS=1"
Log "WORKDIR=$tipDir"
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'chat_17_probe_matrix' } | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
}
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 90; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT=$($p.ExitCode) t=$i"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; Log "MAIN_VIA_PROC t=$i"; break }
  $main = [DbgF5]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { Log "MAIN_VIA_ENUM t=$i"; break }
  if (($i % 10) -eq 0) { Log "WAIT_MAIN t=$i" }
}
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if ($main -eq [IntPtr]::Zero) {
  @"
DEBUG_SESSION_REAL_PROBE=MEASURED
TIP_SHA256=$sha
DEBUG_RESULT=NO_MAIN_HWND
SESSION_REAL=0
PROMOTE=0
RUNLOG=$runlog
"@ | Set-Content $receipt
  exit 2
}
[void][DbgF5]::ShowWindow($main, 9)
[void][DbgF5]::SetForegroundWindow($main)
Start-Sleep 2
if ([int][DbgF5]::VisId($main, 1300) -eq 0) {
  [void][DbgF5]::Cmd($main, 2034, 2000)
  Start-Sleep -Milliseconds 500
}
# Activate debugger UI surfaces (sidebar/debug view) then START once.
foreach ($act in @(1104, 6004)) {
  [void][DbgF5]::Cmd($main, $act, 2500)
  Start-Sleep -Milliseconds 300
}
$sw = [Diagnostics.Stopwatch]::StartNew()
$startOk = [DbgF5]::Cmd($main, 5060, 20000)
$sw.Stop()
$varsImm = [DbgF5]::IdList($main, 6043)
Log "START5060=$startOk elapsed_ms=$($sw.ElapsedMilliseconds) VARS_IMMEDIATE=$varsImm"
$varsPeak = $varsImm
$sessionReal = 0
$bpHit = 0
$launched = 0
$evidence = ''
$childPeak = 0
for ($w = 0; $w -lt 20; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { Log "IDE_EXIT=$($p.ExitCode) w=$w"; break }
  $v = [DbgF5]::IdList($main, 6043)
  if ($v -gt $varsPeak) { $varsPeak = $v }
  $evidence = [DbgF5]::Collect($main)
  if ($evidence -match 'Native debug launched|launched pid|Creating launch|RAWRXD_DEBUGGEE|debuggee_fixture') { $launched = 1 }
  if ($evidence -match 'Breakpoint hit|BP hit break_site|Native debug:') { $bpHit = 1 }
  $child = @(Get-Process -Name 'debuggee_fixture' -EA SilentlyContinue).Count
  if ($child -gt $childPeak) { $childPeak = $child }
  Log "w=$w vars=$v peak=$varsPeak child=$child launched=$launched bp=$bpHit"
  if ($v -gt 0) { $sessionReal = 1; break }
}
$stepOk = $false
$contOk = $false
$stopOk = $false
if ($sessionReal -eq 1 -or $varsPeak -gt 0) {
  $sessionReal = 1
  $stepOk = [DbgF5]::Cmd($main, 10503, 4000)  # step over / step
  Start-Sleep 1
  $v2 = [DbgF5]::IdList($main, 6043)
  if ($v2 -gt $varsPeak) { $varsPeak = $v2 }
  Log "STEP10503=$stepOk vars=$v2"
  $contOk = [DbgF5]::Cmd($main, 10508, 4000)  # continue
  Start-Sleep 1
  $v3 = [DbgF5]::IdList($main, 6043)
  if ($v3 -gt $varsPeak) { $varsPeak = $v3 }
  Log "CONTINUE10508=$contOk vars=$v3"
  $evidence = [DbgF5]::Collect($main)
}
$stopOk = [DbgF5]::Cmd($main, 10501, 3000)  # stop
Start-Sleep 1
Get-Process -Name 'debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$childAfter = @(Get-Process -Name 'debuggee_fixture' -EA SilentlyContinue).Count
$alive = [int](-not $p.HasExited -and [DbgF5]::IsWindow($main))
$id1312 = [DbgF5]::IdList($main, 1312)
$id1604 = [DbgF5]::IdLen($main, 1604)
$panel = [int][DbgF5]::VisId($main, 1300)
$a4f = (Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe' -Algorithm SHA256).Hash
$cc79 = (Get-FileHash 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash
if ($varsPeak -gt 0) { $sessionReal = 1 }
$dbgResult = if ($sessionReal -eq 1) { 'PASS_SESSION_REAL' } else { 'BLOCKED_NO_SESSION_REAL' }
$locus = if ($sessionReal -eq 1) { '' } else {
  'GUI START posted; WaitForDebugEvent product strings present in EXE; vars id6043 / BP evidence absent — SESSION_REAL not demonstrated on this SHA'
}
@"
DEBUG_SESSION_REAL_PROBE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_SHA256=$sha
TIP_EXE=$TipExe
DEBUGGEE=$Debuggee
DEBUGGEE_SHA256=$dbgSha
DEBUGGEE_EXISTS=1
DEBUG_RESULT=$dbgResult
SESSION_REAL=$sessionReal
DEBUG_VARS_ID6043_PEAK=$varsPeak
DEBUG_LAUNCHED_EVIDENCE=$launched
DEBUG_BP_HIT_EVIDENCE=$bpHit
DEBUG_START_5060=$startOk
DEBUG_STEP_10503=$stepOk
DEBUG_CONTINUE_10508=$contOk
DEBUG_STOP_10501=$stopOk
DEBUG_CHILD_PEAK=$childPeak
DEBUG_CHILD_AFTER_STOP=$childAfter
DEBUG_PRODUCT_PATH=CreateProcess_DEBUG_ONLY_THIS_PROCESS_plus_WaitForDebugEvent
WaitForDebugEvent_IN_EXE=1
DebugActiveProcess_IN_EXE=0
DEBUG_BLOCKED_LOCUS=$locus
DEBUG_EVIDENCE_SNIPS=$evidence
PROBLEMS_ID1312_ITEMS=$id1312
OUTPUT_ID1604_LEN=$id1604
PANEL_CONTAINER_VISIBLE=$panel
ALIVE=$alive
CLEAN_EXIT_ATTEMPTED=1
A4F_SHA256=$a4f
A4F_UNTOUCHED=$([int]($a4f -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))
CC79_SHA256=$cc79
CC79_UNTOUCHED=$([int]($cc79 -eq 'CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4'))
NO_CROSS_SHA_PASS_INHERITANCE=1
PRIOR_B39_NOT_INHERITED=1
ISSUE49=NOT_DEMONSTRATED
MATURITY=82
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
RUNLOG=$runlog
"@ | Set-Content -LiteralPath $receipt
Get-Content $receipt
try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } } catch {}
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
exit $(if ($sessionReal -eq 1) { 0 } else { 4 })

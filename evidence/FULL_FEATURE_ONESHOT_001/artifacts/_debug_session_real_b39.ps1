# SESSION_REAL probe on tip_session_real_001 (B39). START once; no early STOP.
$ErrorActionPreference = 'Continue'
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001\RawrXD-Win32IDE-Native-Ext.exe'
$debuggee = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001\debuggee_fixture.exe'
$broken = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$logDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\debug_session_real_b39'
New-Item -ItemType Directory -Force -Path $outDir, $logDir | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $outDir ("debug_session_real_b39_$stamp.txt")
$receipt = Join-Path $outDir 'DEBUG_SESSION_REAL_B39_RECEIPT.txt'
function Log([string]$m) { $line = "$(Get-Date -Format o) $m"; Add-Content $runlog $line; Write-Host $line }
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class DbgB39 {
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
  public static IntPtr FindMain(uint pid){ IntPtr f=IntPtr.Zero; EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true; var sb=new StringBuilder(256); GetClassNameW(h,sb,256); if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero); return f; }
  public static IntPtr FindId(IntPtr root,int id){ IntPtr f=IntPtr.Zero; EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero); return f; }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static string GetText(IntPtr h){ if(h==IntPtr.Zero) return ""; int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); if(n<=0){ var t=new StringBuilder(512); GetWindowTextW(h,t,512); return t.ToString(); } if(n>80000) n=80000; var sb=new StringBuilder(n+2); SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb); return sb.ToString(); }
  public static string Collect(IntPtr root){ var hits=new List<string>(); string[] keys=new[]{"Native debug launched","Breakpoint hit","CREATE_PROCESS","BP hit break_site","RAWRXD_DEBUGGEE","Creating launch","g_watch_value","launched pid","EXIT_PROCESS","Debugging start failed","Native debug:"}; EnumChildWindows(root,(h,lp)=>{ string txt=GetText(h); if(string.IsNullOrEmpty(txt)||txt.Length<6) return true; foreach(var k in keys){ if(txt.IndexOf(k,StringComparison.OrdinalIgnoreCase)>=0){ int i=txt.IndexOf(k,StringComparison.OrdinalIgnoreCase); int a=Math.Max(0,i-40); int b=Math.Min(txt.Length,i+90); hits.Add("id="+GetDlgCtrlID(h)+" :: "+txt.Substring(a,b-a).Replace("\r"," ").Replace("\n"," ")); break;} } return true; },IntPtr.Zero); return string.Join(" || ", hits); }
}
"@
$env:RAWRXD_LOG_DIR=$logDir; $env:RAWRXD_PROBLEMS_FIXTURE=$broken; $env:RAWRXD_DEBUGGEE=$debuggee
Log "TIP_SHA256=$sha DEBUGGEE_EXISTS=$([int](Test-Path $debuggee))"
$p=Start-Process $exe -ArgumentList @($broken) -WorkingDirectory 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_session_real_001' -PassThru -WindowStyle Normal
$main=[IntPtr]::Zero
for($i=0;$i -lt 60;$i++){ Start-Sleep -Milliseconds 400; if($p.HasExited){Log "EARLY_EXIT=$($p.ExitCode)"; break}; $main=[DbgB39]::FindMain([uint32]$p.Id); if($main -ne [IntPtr]::Zero){break} }
Log "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if($main -eq [IntPtr]::Zero){ "DEBUG_SHA=$sha`nDEBUG_RESULT=NO_MAIN_HWND`nSESSION_REAL=0`nPROMOTE=0" | Set-Content $receipt; exit 2 }
[void][DbgB39]::ShowWindow($main,9); [void][DbgB39]::SetForegroundWindow($main); Start-Sleep 2
if([int][DbgB39]::VisId($main,1300) -eq 0){ [void][DbgB39]::Cmd($main,2034,2000); Start-Sleep -Milliseconds 400 }
foreach($act in @(1104,6004)){ [void][DbgB39]::Cmd($main,$act,2500); Start-Sleep -Milliseconds 300 }
$sw=[Diagnostics.Stopwatch]::StartNew()
$startOk=[DbgB39]::Cmd($main,5060,15000)
$sw.Stop()
$varsImm=[DbgB39]::IdList($main,6043)
Log "START5060=$startOk elapsed_ms=$($sw.ElapsedMilliseconds) VARS_IMMEDIATE=$varsImm"
$varsPeak=$varsImm; $sessionReal=0; $bpHit=0; $launched=0; $evidence=''
for($w=0;$w -lt 12;$w++){
  Start-Sleep 1
  if($p.HasExited){ Log "IDE_EXIT=$($p.ExitCode) w=$w"; break }
  $v=[DbgB39]::IdList($main,6043); if($v -gt $varsPeak){$varsPeak=$v}
  $evidence=[DbgB39]::Collect($main)
  if($evidence -match 'Native debug launched|launched pid|Creating launch|RAWRXD_DEBUGGEE'){ $launched=1 }
  if($evidence -match 'Breakpoint hit|BP hit break_site|Native debug:'){ $bpHit=1 }
  $child=@(Get-Process debuggee_fixture -EA SilentlyContinue).Count
  Log "w=$w vars=$v peak=$varsPeak child=$child launched=$launched bp=$bpHit"
  if($v -gt 0){ $sessionReal=1; break }
}
if($sessionReal -eq 1 -or $varsPeak -gt 0){
  $step=[DbgB39]::Cmd($main,10503,3000); Start-Sleep 1
  $v2=[DbgB39]::IdList($main,6043); if($v2 -gt $varsPeak){$varsPeak=$v2}; if($v2 -gt 0){$sessionReal=1}
  Log "STEP=$step vars=$v2"; $evidence=[DbgB39]::Collect($main)
}
$id1312=[DbgB39]::IdList($main,1312); $id1604=[DbgB39]::IdLen($main,1604); $panel=[int][DbgB39]::VisId($main,1300)
$alive=[int](-not $p.HasExited -and [DbgB39]::IsWindow($main))
if($varsPeak -gt 0){ $sessionReal=1 }
$dbgResult=if($sessionReal -eq 1){'PASS_SESSION_REAL'}else{'BLOCKED_NO_SESSION_REAL'}
$locus=if($sessionReal -eq 1){''}else{'launchNativeDebuggee CreateProcess_DEBUG_ONLY_THIS_PROCESS+WaitForDebugEvent; GUI START posted; vars/BP SESSION_REAL witness absent after tip drain/poll'}
@"
DEBUG_SESSION_REAL_PROBE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
DEBUG_SHA=$sha
TIP_SHA256=$sha
DEBUG_RESULT=$dbgResult
SESSION_REAL=$sessionReal
DEBUG_VARS_ID6043_PEAK=$varsPeak
DEBUG_LAUNCHED_EVIDENCE=$launched
DEBUG_BP_HIT_EVIDENCE=$bpHit
DEBUG_START_5060=$startOk
DEBUG_PRODUCT_PATH=CreateProcess_DEBUG_ONLY_THIS_PROCESS_plus_WaitForDebugEvent
DEBUG_BLOCKED_LOCUS=$locus
DEBUG_EVIDENCE_SNIPS=$evidence
PROBLEMS_ID1312_ITEMS=$id1312
OUTPUT_ID1604_LEN=$id1604
PANEL_CONTAINER_VISIBLE=$panel
ALIVE=$alive
NO_CROSS_SHA_PASS_INHERITANCE=1
PRIOR_27E226_NOT_INHERITED=1
A4F_UNTOUCHED=1
CONTROLLING_TIP=CC79
EXACTLY_ONCE=NOT_VERIFIED
ISSUE49=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82
RUNLOG=$runlog
"@ | Set-Content -LiteralPath $receipt
Get-Content $receipt | ForEach-Object { Log $_ }
[void][DbgB39]::Cmd($main,10501,2000); Start-Sleep 1
try{if(-not $p.HasExited){$p.Kill()}}catch{}
Get-Process -Name 'RawrXD-Win32IDE-Native*','debuggee_fixture' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
exit $(if($sessionReal -eq 1){0}else{4})

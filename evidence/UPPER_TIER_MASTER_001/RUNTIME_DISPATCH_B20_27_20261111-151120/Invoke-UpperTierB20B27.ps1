# B20-B27 LIVE tip runtime. CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD. No invent PASS.
param(
  [string]$ExePath = 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe',
  [string]$ExpectedTipSha = 'A1A04779DCEB25B83ED0F4771EC120538560F0D9CEB5FE82588FA3B16760AD64',
  [string]$OutDir = 'F:\\rawrxd\\evidence\\UPPER_TIER_MASTER_001\\RUNTIME_DISPATCH_B20_27_20261111-151120'
)
$ErrorActionPreference = 'Continue'
$R = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runLog = Join-Path $OutDir "runtime_dispatch_run_$stamp.txt"
function Log([string]$m){ $l="$(Get-Date -Format o) $m"; Add-Content $runLog $l -Encoding UTF8; Write-Output $l }
function ED([string]$p){ New-Item -ItemType Directory -Force -Path $p | Out-Null }
function WStatus([int]$n,[string]$b){
  $d1=Join-Path $R ("BATCH_{0}" -f $n); $d2=Join-Path $R ("BATCH_{0}_AUDIT" -f $n)
  ED $d1; ED $d2
  Set-Content (Join-Path $d1 'STATUS.txt') $b -Encoding UTF8
  Set-Content (Join-Path $d2 'STATUS.txt') $b -Encoding UTF8
}
function WDisp([int]$n,[string]$body){
  $d=Join-Path $R ("BATCH_{0}_AUDIT\RUNTIME_DISPATCH" -f $n); ED $d
  Set-Content (Join-Path $d 'RUNTIME_DISPATCH_RECEIPT.txt') $body -Encoding UTF8
}

if(-not (Test-Path $ExePath)){ Log "EXE_ABSENT=$ExePath"; exit 2 }
$sha=(Get-FileHash -Algorithm SHA256 $ExePath).Hash.ToUpperInvariant()
$bytes=(Get-Item $ExePath).Length
$mtime=(Get-Item $ExePath).LastWriteTime.ToString('o')
$tipMatch=[int]($sha -eq $ExpectedTipSha.ToUpperInvariant())
$extHost=Test-Path 'F:\rawrxd\build_win32ide\bin\Release\RawrXD-ExtensionHost.exe'
Log "EXE_PATH=$ExePath TIP_SHA=$sha TIP_MATCH=$tipMatch BYTES=$bytes EXT_HOST=$extHost"
if($tipMatch -ne 1){ Log "WARN_TIP_DRIFT expected=$ExpectedTipSha live=$sha — using LIVE" }

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class UTB27 {
  public const uint WM_COMMAND=0x0111, WM_CLOSE=0x0010, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, BM_CLICK=0x00F5;
  public const int IDOK=1;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public static IntPtr FindMain(uint pid){
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      if(sb.ToString().IndexOf("RawrXD",StringComparison.OrdinalIgnoreCase)>=0){ found=h; return false; }
      if(found==IntPtr.Zero) found=h; return true; }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindById(IntPtr root,int id){ IntPtr found=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){ found=h; return false;} return true;}, IntPtr.Zero); return found; }
  public static string GetText(IntPtr h){ if(h==IntPtr.Zero) return "";
    int len=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); if(len<=0) return "";
    if(len>262144) len=262144; var sb=new StringBuilder(len+2); SendMessageW(h,WM_GETTEXT,(IntPtr)(len+1),sb); return sb.ToString(); }
  public static int DismissDialogs(uint pid){ int n=0;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid||!IsWindowVisible(h)) return true;
      var cls=new StringBuilder(64); GetClassNameW(h,cls,cls.Capacity);
      if(cls.ToString()!="#32770") return true;
      IntPtr ok=FindById(h,IDOK);
      if(ok!=IntPtr.Zero) PostMessageW(ok,BM_CLICK,IntPtr.Zero,IntPtr.Zero); else PostMessageW(h,WM_CLOSE,IntPtr.Zero,IntPtr.Zero);
      n++; return true; }, IntPtr.Zero); return n; }
}
"@

Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$env:RAWRXD_LOG_DIR=$OutDir
$sw=[Diagnostics.Stopwatch]::StartNew()
$proc=Start-Process -FilePath $ExePath -WorkingDirectory (Split-Path $ExePath) -PassThru -WindowStyle Normal
Log "PID=$($proc.Id)"
$main=[IntPtr]::Zero; $early=$false; $exitCode=''
for($i=0;$i -lt 100;$i++){
  Start-Sleep -Milliseconds 250; try{$proc.Refresh()}catch{}
  if($proc.HasExited){ $early=$true; $exitCode="$($proc.ExitCode)"; Log "EARLY_EXIT=$exitCode"; break }
  if($proc.MainWindowHandle -ne 0){ $main=[IntPtr]$proc.MainWindowHandle; break }
  $main=[UTB27]::FindMain([uint32]$proc.Id); if($main -ne [IntPtr]::Zero){ break }
}
Log ("MAIN_HWND=0x{0:X} ms={1}" -f $main.ToInt64(),$sw.ElapsedMilliseconds)
$cold= if($early){'FAIL_EARLY_EXIT'} elseif($main -eq [IntPtr]::Zero){'HELD_NO_MAIN_HWND'} else {'RUNTIME_REACHED_COLD_START_HWND'}

function Alive(){ try{$proc.Refresh()}catch{}; return -not $proc.HasExited }
function PostCmd([int]$id,[string]$name){
  if($main -eq [IntPtr]::Zero -or -not (Alive)){ Log "SKIP $name"; return $false }
  [void][UTB27]::SetForegroundWindow($main)
  [void][UTB27]::PostMessageW($main,[UTB27]::WM_COMMAND,[IntPtr]$id,[IntPtr]::Zero)
  Log "POST $id $name"; Start-Sleep -Milliseconds 550
  $d=[UTB27]::DismissDialogs([uint32]$proc.Id); if($d -gt 0){ Log "DISMISS=$d"; Start-Sleep -Milliseconds 350 }
  [void][UTB27]::DismissDialogs([uint32]$proc.Id)
  if(-not (Alive)){ $script:early=$true; $script:exitCode="$($proc.ExitCode)"; Log "EXIT_AFTER $name"; return $false }
  return $true
}
function ReadOut(){
  $p=@(); foreach($id in @(1011,1012,1013,1014,1303)){
    $h=[UTB27]::FindById($main,$id); $t=[UTB27]::GetText($h)
    if($t -and $t.Trim().Length -gt 0){ $p+="CTRL_$id`n$t"; Log ("OUT id=$id len={0}" -f $t.Length) }
  }; return ($p -join "`n====`n")
}

$raw=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($ExePath))
$S=@{
  ExtensionHost=[int]$raw.Contains('ExtensionHost')
  ProductExtension=[int]$raw.Contains('ProductExtensionRuntime')
  GhostText=[int]$raw.Contains('GhostText')
  PeekOverlay=[int]$raw.Contains('PeekOverlay')
  setOllama=[int]$raw.Contains('setOllamaModelOverride')
  ConPTY=[int]$raw.Contains('ConPTY')
}
Log ("STR ExtHost=$($S.ExtensionHost) ProdExt=$($S.ProductExtension) Ghost=$($S.GhostText) Peek=$($S.PeekOverlay) setOllama=$($S.setOllama) ConPTY=$($S.ConPTY)")

# B20
$b20=@{tools='NOT_RUN';status='NOT_RUN';cancel='NOT_RUN';loopst='NOT_RUN';fall='NOT_RUN'}
if($main -ne [IntPtr]::Zero -and -not $early){
  if(PostCmd 4103 'VIEW_TOOLS'){ $o=ReadOut; if($o -match 'Available Agent Tools|Agent Tools'){ $b20.tools='RUNTIME_REACHED_TOOLS_LISTED' } elseif(Alive){ $b20.tools='RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED' } }
  if(PostCmd 4104 'VIEW_STATUS'){ Start-Sleep -Milliseconds 400; [void][UTB27]::DismissDialogs([uint32]$proc.Id); $o=ReadOut; if($o -match 'Agent Status|Agentic'){ $b20.status='RUNTIME_REACHED_STATUS_OBSERVED' } elseif(Alive){ $b20.status='RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED' } }
  if(PostCmd 4107 'LOOP_CANCEL'){ $o=ReadOut; if($o -match 'cancelled|Cancel'){ $b20.cancel='RUNTIME_REACHED_CANCEL_OBSERVED' } elseif(Alive){ $b20.cancel='RUNTIME_REACHED_CANCEL_POSTED' } }
  if(PostCmd 4108 'LOOP_STATUS'){ Start-Sleep -Milliseconds 400; [void][UTB27]::DismissDialogs([uint32]$proc.Id); $o=ReadOut; if($o -match 'Loop Status|Agentic Loop'){ $b20.loopst='RUNTIME_REACHED_STATUS_OBSERVED' } elseif(Alive){ $b20.loopst='RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED' } }
  if($b20.tools -like 'RUNTIME_REACHED*'){ $b20.fall='RUNTIME_REACHED_REGISTRY_SURFACE_ONLY_FALLTHROUGH_NOT_PROVEN' }
}
$b20Dim=@($b20.fall,$b20.cancel,'NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN')
$b20R=@($b20Dim|?{$_ -like 'RUNTIME_REACHED*'}).Count

# B21
$b21=@{lspS='NOT_RUN';lspSt='NOT_RUN';lspD='NOT_RUN';dapV='NOT_RUN';dapC='NOT_RUN';dapA='NOT_RUN';peek='NOT_RUN'}
if($main -ne [IntPtr]::Zero -and -not $early){
  $tabs=[UTB27]::FindById($main,1301); if($tabs -ne [IntPtr]::Zero){ [void][UTB27]::SendMessageW($tabs,0x130C,[IntPtr]1,[IntPtr]::Zero) }
  if(PostCmd 9200 'LSP_START'){ Start-Sleep -Milliseconds 700; $o=ReadOut; if($o -match 'LSP Server'){ $b21.lspS='RUNTIME_REACHED_LSP_START_OUTPUT' } elseif(Alive){ $b21.lspS='RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED' } }
  if(PostCmd 9202 'LSP_STATUS'){ $o=ReadOut; if($o -match 'LSP Server'){ $b21.lspSt='RUNTIME_REACHED_LSP_STATUS_OUTPUT' } elseif(Alive){ $b21.lspSt='RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED' } }
  if(PostCmd 9205 'LSP_PUBDIAG'){ $o=ReadOut; if($o -match 'Published|diagnostic|not running'){ $b21.lspD='RUNTIME_REACHED_PUBLISH_DIAG_OUTPUT' } elseif(Alive){ $b21.lspD='RUNTIME_REACHED_CMD_POSTED_OUTPUT_UNCONFIRMED' } }
  if(PostCmd 10508 'DAP_VARS'){ if(Alive){ $b21.dapV='RUNTIME_REACHED_CMD_POSTED_NO_CRASH' } }
  if(PostCmd 10507 'DAP_STACK'){ if(Alive){ $b21.dapC='RUNTIME_REACHED_CMD_POSTED_NO_CRASH' } }
  if(PostCmd 10510 'DAP_ATTACH'){ Start-Sleep -Milliseconds 500; [void][UTB27]::DismissDialogs([uint32]$proc.Id); if(Alive){ $b21.dapA='RUNTIME_REACHED_CMD_POSTED_TRUE_ATTACH_UNPROVEN' } }
  $b21.peek= if($S.PeekOverlay -eq 1){'SOURCE_HINT_PEEK_PRESENT_E2E_NOT_RUN'} else {'NOT_REACHED_PEEK_STRING_ABSENT_IN_EXE'}
}
$b21Dim=@('NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN',$b21.lspD,$b21.peek,'NOT_RUN',$b21.dapA,'NOT_RUN','NOT_RUN',$b21.dapV)
$b21R=@($b21Dim|?{$_ -like 'RUNTIME_REACHED*'}).Count

# B22
$b22R=0
$b22Res= if($extHost){'RUNTIME_REACHED_EXT_HOST_PRESENT_UNEXERCISED'} else {'RUNTIME_FAILCLOSED_NO_EXTENSIONHOST_EXE'}

# B23
$b23=@{cfg='NOT_RUN';load='NOT_RUN'}
if($main -ne [IntPtr]::Zero -and -not $early){
  if(PostCmd 4102 'CFG_MODEL'){ [void][UTB27]::DismissDialogs([uint32]$proc.Id); if(Alive){ $b23.cfg='RUNTIME_REACHED_CMD_POSTED_DIALOG_DISMISSED' } }
  if(PostCmd 2006 'LOAD_MODEL'){ [void][UTB27]::DismissDialogs([uint32]$proc.Id); if(Alive){ $b23.load='RUNTIME_REACHED_CMD_POSTED_DIALOG_DISMISSED' } }
}
$b23Dim=@($b23.cfg,'NOT_RUN',$(if($S.GhostText){'SOURCE_HINT_GhostText_IN_EXE'}else{'ABSENT'}),'NOT_RUN',$b23.load,'NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN','NOT_CERTIFIED')
$b23R=@($b23Dim|?{$_ -like 'RUNTIME_REACHED*'}).Count
$b23Res= if($b23R -gt 0){'PARTIAL_RUNTIME_REACHED_UNPROMOTED'} else {'FAIL_CLOSED_ROUTING_E2E_NOT_CERTIFIED'}

# B24
$b24=@{sb='NOT_RUN';term='NOT_RUN';theme='NOT_RUN';outp='NOT_RUN'}
if($main -ne [IntPtr]::Zero -and -not $early){
  if(PostCmd 2028 'SIDEBAR'){ if(Alive){ $b24.sb='RUNTIME_REACHED_CMD_POSTED_NO_CRASH' } }
  if(PostCmd 2029 'TERMINAL'){ if(Alive){ $b24.term='RUNTIME_REACHED_CMD_POSTED_NO_CRASH' } }
  if(PostCmd 2023 'THEME_ED'){ [void][UTB27]::DismissDialogs([uint32]$proc.Id); if(Alive){ $b24.theme='RUNTIME_REACHED_CMD_POSTED_NO_CRASH' } }
  if(PostCmd 2025 'OUTPUT'){ if(Alive){ $b24.outp='RUNTIME_REACHED_CMD_POSTED_NO_CRASH' } }
}
$b24Dim=@($cold,$b24.sb,$b24.term,$b24.theme,$b24.outp,'NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN','NOT_RUN')
$b24R=@($b24Dim|?{$_ -like 'RUNTIME_REACHED*'}).Count

# B25 owners
$inst=@(
  'F:\rawrxd\dist\RawrXD-Setup.exe','F:\rawrxd\release\RawrXD-Setup.exe','F:\rawrxd\installer\RawrXD-Setup.exe'
)|?{ Test-Path $_ }|Select-Object -First 1
$aliveMid= if(Alive){'RUNTIME_REACHED_PROCESS_ALIVE'} else {'FAIL_PROCESS_DEAD'}
$b25R= if($aliveMid -like 'RUNTIME_REACHED*'){1} else {0}
$b25Res= if(-not $inst){'FAIL_CLOSED_INSTALLER_ABSENT_PARTIAL_LAUNCH_ONLY'} else {'PARTIAL_RUNTIME_REACHED_UNPROMOTED'}

$surv= if(Alive){1} else {0}
Log "SURVIVED=$surv EARLY=$early EXIT=$exitCode"
if($main -ne [IntPtr]::Zero -and (Alive)){ Set-Content (Join-Path $OutDir 'output_panel_capture.txt') (ReadOut) -Encoding UTF8 }
try{ if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force } }catch{}
Start-Sleep -Milliseconds 400
$asof=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$b20Res= if($b20R -gt 0){'PARTIAL_RUNTIME_REACHED_UNPROMOTED'} else {'NOT_RUN_OR_FAIL_CLOSED'}
$b21Res= if($b21R -gt 0){'PARTIAL_RUNTIME_REACHED_UNPROMOTED'} else {'NOT_RUN_OR_FAIL_CLOSED'}
$b24Res= if($b24R -gt 0){'PARTIAL_RUNTIME_REACHED_UNPROMOTED'} else {'NOT_RUN_OR_FAIL_CLOSED'}
$b26Res='FAIL_CLOSED_SHA_BOUND_LIVE_NOT_CERTIFICATION_READY'
$b27Res='NOT_RUN_FAIL_CLOSED_PENDING_B18_26'

WDisp 20 @"
BATCH_20_RUNTIME_DISPATCH=EXERCISED_UNPROMOTED
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch BYTES=$bytes
COLD_START=$cold VIEW_TOOLS=$($b20.tools) VIEW_STATUS=$($b20.status)
LOOP_CANCEL=$($b20.cancel) LOOP_STATUS=$($b20.loopst) FALLTHROUGH=$($b20.fall)
RUNTIME_REACHED_DIMS=$b20R/6 PRODUCT_RUNTIME_PASS=0/6
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b20Res RUNLOG=$runLog
"@
WDisp 21 @"
BATCH_21_RUNTIME_DISPATCH=EXERCISED_UNPROMOTED
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
LSP_START=$($b21.lspS) LSP_STATUS=$($b21.lspSt) LSP_PUBDIAG=$($b21.lspD)
DAP_VARS=$($b21.dapV) DAP_STACK=$($b21.dapC) DAP_ATTACH=$($b21.dapA) PEEK=$($b21.peek)
RUNTIME_REACHED_CAPS=$b21R/13 PRODUCT_RUNTIME_PASS=0/13
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b21Res
MISSING_OWNER_PEEK=Win32IDE_PeekOverlay.cpp_or_string_absent RUNLOG=$runLog
"@
WDisp 22 @"
BATCH_22_RUNTIME_DISPATCH=FAILCLOSED
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
EXTENSION_HOST_BINARY=$(if($extHost){'PRESENT'}else{'ABSENT'})
MISSING_OWNER=F:\rawrxd\build_win32ide\bin\Release\RawrXD-ExtensionHost.exe
STR_ExtensionHost=$($S.ExtensionHost) STR_ProductExtensionRuntime=$($S.ProductExtension)
RUNTIME_REACHED_CAPS=$b22R/10 PRODUCT_RUNTIME_PASS=0/10
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b22Res RUNLOG=$runLog
"@
WDisp 23 @"
BATCH_23_RUNTIME_DISPATCH=EXERCISED_UNPROMOTED
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
CFG_MODEL=$($b23.cfg) LOAD_MODEL=$($b23.load) GHOSTTEXT_STR=$($S.GhostText) SETOLLAMA_STR=$($S.setOllama)
ROUTING_E2E=NOT_CERTIFIED RUNTIME_REACHED_CAPS=$b23R/10 PRODUCT_RUNTIME_PASS=0/10
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b23Res
MISSING_OWNER_ROUTING_EPOCH=Win32IDE::setOllamaModelOverride RUNLOG=$runLog
"@
WDisp 24 @"
BATCH_24_RUNTIME_DISPATCH=EXERCISED_UNPROMOTED
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
SIDEBAR=$($b24.sb) TERMINAL=$($b24.term) THEME=$($b24.theme) OUTPUT=$($b24.outp) CONPTY=$($S.ConPTY)
RUNTIME_REACHED_CAPS=$b24R/13 PRODUCT_RUNTIME_PASS=0/13
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b24Res
MISSING_OWNER_A11Y=IAccessible/UIA MISSING_OWNER_TIER3=Win32IDE_Tier3Cosmetics.cpp RUNLOG=$runLog
"@
WDisp 25 @"
BATCH_25_RUNTIME_DISPATCH=EXERCISED_FAILCLOSED_PARTIAL
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
COLD_START=$cold PROCESS_ALIVE=$aliveMid
INSTALLER=$(if($inst){"PRESENT_$inst"}else{'ABSENT_NO_PRODUCT_INSTALLER'})
CLEAN_MACHINE=NOT_RUN_DISTINCT_VM_0 SOAK=NOT_RUN FI=NOT_RUN SECURITY=NOT_RUN
RUNTIME_REACHED_DIMS=$b25R/5 PRODUCT_RUNTIME_PASS=0/5
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b25Res
MISSING_OWNER_INSTALLER=product_NSIS_Setup.exe MISSING_OWNER_CLEAN_MACHINE=DISTINCT_VM=1
FINISH25_REMAINING=T05,T07,T08,T18,T19,T25 RUNLOG=$runLog
"@
WDisp 26 @"
BATCH_26_RUNTIME_DISPATCH=SHA_BIND_LIVE_FAILCLOSED
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch AUTHORITATIVE_SHA=$sha
VERDICT=NOT_CERTIFICATION_READY T25=HELD FINISH25_REMAINING=T05,T07,T08,T18,T19,T25
INDEPENDENT_E2E=NOT_ESTABLISHED REPRODUCIBILITY=NOT_ESTABLISHED
PRODUCT_RUNTIME_PASS=0 CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b26Res
MISSING_OWNER=Finish25_remaining+installer+independent_E2E RUNLOG=$runLog
"@
WDisp 27 @"
BATCH_27_RUNTIME_DISPATCH=NOT_RUN_FAILCLOSED
ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
ROWS_MEASURED=0/10 BENCHMARK_SUITE=NOT_EXECUTED
PRODUCT_RUNTIME_PASS=0/10 CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD RESULT=$b27Res
MISSING_OWNER=BATCHES_18_26_PRODUCT_RUNTIME_ACCEPTANCE RUNLOG=$runLog
"@

WStatus 20 @"
BATCH=20 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=$ExePath
RESULT=$b20Res RUNTIME_REACHED=$b20R/6 PRODUCT_RUNTIME_PASS=0/6
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
NOTE=tools/status/cancel exercised; atomic/exactly-once/bounds/rates NOT_RUN
EVIDENCE=$OutDir
"@
WStatus 21 @"
BATCH=21 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=$ExePath
RESULT=$b21Res RUNTIME_REACHED=$b21R/13 PRODUCT_RUNTIME_PASS=0/13
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
MISSING_OWNER_PEEK=Win32IDE_PeekOverlay.cpp_or_string_absent
NOTE=LSP/DAP cmds posted; live LS JSON-RPC + DebugActiveProcess unproven
EVIDENCE=$OutDir
"@
WStatus 22 @"
BATCH=22 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=ABSENT
RESULT=$b22Res RUNTIME_REACHED=$b22R/10 PRODUCT_RUNTIME_PASS=0/10
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
MISSING_OWNER=F:\rawrxd\build_win32ide\bin\Release\RawrXD-ExtensionHost.exe
EVIDENCE=$OutDir
"@
WStatus 23 @"
BATCH=23 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=$ExePath
RESULT=$b23Res RUNTIME_REACHED=$b23R/10 PRODUCT_RUNTIME_PASS=0/10 ROUTING_E2E=NOT_CERTIFIED
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
MISSING_OWNER_ROUTING_EPOCH=Win32IDE::setOllamaModelOverride
EVIDENCE=$OutDir
"@
WStatus 24 @"
BATCH=24 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=$ExePath
RESULT=$b24Res RUNTIME_REACHED=$b24R/13 PRODUCT_RUNTIME_PASS=0/13
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
MISSING_OWNER_A11Y=IAccessible/UIA MISSING_OWNER_TIER3=Win32IDE_Tier3Cosmetics.cpp
EVIDENCE=$OutDir
"@
WStatus 25 @"
BATCH=25 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=$ExePath
RESULT=$b25Res RUNTIME_REACHED=$b25R/5 PRODUCT_RUNTIME_PASS=0/5
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
MISSING_OWNER_INSTALLER=product_NSIS_Setup.exe MISSING_OWNER_CLEAN_MACHINE=DISTINCT_VM=1
FINISH25_REMAINING=T05,T07,T08,T18,T19,T25
EVIDENCE=$OutDir
"@
WStatus 26 @"
BATCH=26 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=$ExePath
RESULT=$b26Res RUNTIME_REACHED=0/FINISH25 PRODUCT_RUNTIME_PASS=0 VERDICT=NOT_CERTIFICATION_READY
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
MISSING_OWNER=Finish25_remaining+installer+independent_E2E
EVIDENCE=$OutDir
"@
WStatus 27 @"
BATCH=27 ASOF_UTC=$asof TIP_SHA=$sha TIP_MATCH=$tipMatch
BINARY_ENTRY=N/A_PLAN_ONLY
RESULT=$b27Res RUNTIME_REACHED=0/10 PRODUCT_RUNTIME_PASS=0/10 ROWS_MEASURED=0/10
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
MISSING_OWNER=BATCHES_18_26_PRODUCT_RUNTIME_ACCEPTANCE
EVIDENCE=$OutDir
"@

$master=@"
UPPER_TIER_B20_27_RUNTIME_DISPATCH=COMPLETE_UNPROMOTED
ASOF_UTC=$asof EXE_PATH=$ExePath TIP_SHA=$sha TIP_MATCH=$tipMatch BYTES=$bytes MTIME=$mtime
PROCESS_SURVIVED=$surv EARLY_EXIT=$early COLD_START=$cold
B20_RESULT=$b20Res REACHED=$b20R/6 PASS=0/6
B21_RESULT=$b21Res REACHED=$b21R/13 PASS=0/13
B22_RESULT=$b22Res REACHED=$b22R/10 PASS=0/10 MISSING=RawrXD-ExtensionHost.exe
B23_RESULT=$b23Res REACHED=$b23R/10 PASS=0/10 ROUTING_E2E=NOT_CERTIFIED
B24_RESULT=$b24Res REACHED=$b24R/13 PASS=0/13
B25_RESULT=$b25Res REACHED=$b25R/5 PASS=0/5 MISSING=installer+DISTINCT_VM
B26_RESULT=$b26Res VERDICT=NOT_CERTIFICATION_READY
B27_RESULT=$b27Res MISSING=BATCHES_18_26_PRODUCT_RUNTIME_ACCEPTANCE
CERTIFIED=0 PROMOTE=0 TIP_CLIMB=HOLD NO_INVENT_PASS=1
RUNLOG=$runLog
"@
Set-Content (Join-Path $OutDir 'RUNTIME_DISPATCH_RECEIPT.txt') $master -Encoding UTF8
Get-Content (Join-Path $OutDir 'RUNTIME_DISPATCH_RECEIPT.txt')
exit 0


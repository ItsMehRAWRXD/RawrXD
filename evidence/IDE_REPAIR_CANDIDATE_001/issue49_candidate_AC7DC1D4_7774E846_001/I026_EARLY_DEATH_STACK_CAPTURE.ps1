param()
$ErrorActionPreference='Continue'
$cand='F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_AC7DC1D4_7774E846_001'
$tipExe=Join-Path $cand 'bin\RawrXD-Win32IDE-Native-Ext.exe'
$tipDir=Join-Path $cand 'bin'
$expect='AC7DC1D44F699FBCA19D4948CCE7EA1C17A4C941627CB229583DE4C570C2DF9A'
$loopExpect='7774E846CE748DA97590FE63E859DFDDA82756546C5F32F588BBACB69BDC2563'
$project='F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\fixtures\bug.cpp'
$model='F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
$outDir=Join-Path $cand 'issue49_gui_ollama_qwen3_027_STACK'
$logDir=Join-Path $outDir 'logs_live'
$userData=Join-Path $outDir 'userdata'
$dumpDir=Join-Path $outDir 'dumps'
$cdb='C:\Users\Garrett\AppData\Local\Microsoft\WindowsApps\cdbX64.exe'
$evidence=Join-Path $cand 'I026_EARLY_DEATH_STACK_001.txt'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force -Path $outDir,$logDir,$userData,$dumpDir | Out-Null
"REPRO_FOR_STACK_ONLY`nASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))`nLABEL=issue49_gui_ollama_qwen3_027_STACK`nREGIME=746_ASCII_STEP_A_B`nNOT_ACCEPTANCE=1`nCONTROLLING=D015`nPROMOTE=0" | Set-Content (Join-Path $outDir 'REPRO_LABEL.txt') -Encoding ASCII

function Get-Sha256Fast([string]$path) {
  $line = (certutil -hashfile $path SHA256 2>$null | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -First 1)
  if ($line) { return $line.Trim().ToUpperInvariant() }
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
}
$ideSha=Get-Sha256Fast $tipExe
$loopSha=Get-Sha256Fast (Join-Path $tipDir 'deep2_agentic_loop.exe')
if($ideSha -ne $expect){ throw "IDE_SHA_DRIFT actual=$ideSha expect=$expect" }
if($loopSha -ne $loopExpect){ throw "LOOP_SHA_DRIFT actual=$loopSha expect=$loopExpect" }

# LocalDumps (HKCU) backup for exception deaths
$ldKey='HKCU:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\RawrXD-Win32IDE-Native-Ext.exe'
New-Item -Path $ldKey -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpFolder -Value $dumpDir -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpCount -Value 10 -PropertyType DWord -Force | Out-Null

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','cdb*','cdbX64*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

# Reset fixture to baseline (same as harness)
$fixtureBaseline = @"
#include <cstdio>

// Issue #49 Wave2 fixture: two defects for fail-then-fix second edit.
// 1) undeclared_fn(1, 2) is a C2660 arity error (must fix call or signature).
// 2) add() returns a - b so AGENT_RESULT is wrong until changed to a + b.
// Do not leave unused parameters (C4100 under /WX).
int undeclared_fn(int a) { return a; }
int add(int a, int b) { return a - b; }

int main() {
  (void)undeclared_fn(1, 2);
  std::printf("AGENT_RESULT=%d\n", add(2, 3));
  return 0;
}
"@
[IO.File]::WriteAllText($project, $fixtureBaseline.TrimStart("`r","`n"), [Text.UTF8Encoding]::new($false))

$env:RAWRXD_LOG_DIR = $logDir
$env:RAWRXD_USERDATA = $userData
$env:RAWRXD_DEFAULT_DEEP2_MODEL = $model
$env:RAWRXD_PROBLEMS_FIXTURE = $project
$env:RAWRXD_OPEN_DOCUMENT = $project
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '0'
$env:RAWRXD_FORCE_OLLAMA_AGENTIC = '1'
$env:RAWRXD_OLLAMA_AGENT_MODEL = 'qwen3:8b'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'
$env:RAWRXD_AGENT_MODE = 'ACTIVE'
$env:RAWRXD_AGENTIC_CONTEXT_SIZE = '4096'
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue

if(-not ('I49_74_STACK' -as [type])){
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class I49_74_STACK {
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint EM_SETSEL=0x00B1; public const uint EM_REPLACESEL=0x00C2;
  public const uint SMTO_NORMAL=0; public const uint KEYEVENTF_KEYUP=0x0002;
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
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
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
}

$runLog=Join-Path $outDir ("stack_capture_$stamp.txt")
function SLog([string]$m){ $line="$(Get-Date -Format o) $m"; Add-Content $runLog $line; Write-Host $line }

$liveDump=Join-Path $dumpDir ("i026_early_death_$stamp.dmp")
$cdbLog=Join-Path $outDir ("cdb_$stamp.log")
$cmdFile=Join-Path $outDir 'cdb_cmds.txt'
# Break on ExitProcess / TerminateProcess to capture silent -1; also catch exceptions.
# HIT_* markers are only emitted by .echo on real break (not substring of bp source alone for wait).
# Attempt3: drop sxe eh (attempt2 stalled at KiUserCallbackDispatch); add epr; bl verify.
$cmdLines = @(
  ".logopen $cdbLog"
  '.sympath srv*'
  '.reload /f ntdll.dll'
  ("bp ntdll!RtlExitUserProcess `".echo ===HIT_EXITPROCESS===; r rcx; kL 80; lm m RawrXD*; .dump /ma /u $liveDump; .logclose; qd`"")
  ("bp ntdll!NtTerminateProcess `".echo ===HIT_NTTERMINATE===; r rcx; r rdx; kL 80; lm m RawrXD*; .dump /ma /u $liveDump; .logclose; qd`"")
  ("sxe -c `".echo ===HIT_EXCEPTION===; .exr -1; kL 80; lm m RawrXD*; .dump /ma /u $liveDump; .logclose; qd`" av")
  ("sxe -c `".echo ===HIT_EXCEPTION===; .exr -1; kL 80; lm m RawrXD*; .dump /ma /u $liveDump; .logclose; qd`" c0000409")
  ("sxe -c `".echo ===HIT_EXCEPTION===; .exr -1; kL 80; lm m RawrXD*; .dump /ma /u $liveDump; .logclose; qd`" c0000005")
  ("sxe -c `".echo ===HIT_EPR===; .lastevent; kL 40; lm m RawrXD*; .dump /ma /u $liveDump; .logclose; qd`" epr")
  'sxd eh'
  'sxi ibp'
  'bl'
  'g'
)
$cmdLines | Set-Content $cmdFile -Encoding ASCII
$procdump = 'F:\rawrxd\scripts\procdump_tools\procdump64.exe'
$procDumpOut = Join-Path $dumpDir ("i026_procdump_term_$stamp.dmp")

$p=Start-Process -FilePath $tipExe -ArgumentList @("--user-data-dir=$userData", $project) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
SLog "SPAWN_PID=$($p.Id)"
Start-Sleep -Milliseconds 900
if($p.HasExited){ SLog "EARLY_EXIT_BEFORE_ATTACH exit=$($p.ExitCode)"; throw 'EARLY_EXIT_BEFORE_ATTACH' }

$cdbProc=Start-Process -FilePath $cdb -ArgumentList @('-p',"$($p.Id)",'-cf',$cmdFile) -PassThru -WindowStyle Minimized
SLog "CDB_PID=$($cdbProc.Id) attached to $($p.Id)"
$pdProc=$null
if(Test-Path $procdump){
  # -t: dump on process terminate (covers silent ExitProcess(-1) without exception)
  $pdProc=Start-Process -FilePath $procdump -ArgumentList @('-accepteula','-t','-ma','-n','1',"$($p.Id)",$procDumpOut) -PassThru -WindowStyle Minimized
  SLog "PROCDUMP_PID=$($pdProc.Id) OUT=$procDumpOut"
} else {
  SLog "PROCDUMP_MISSING path=$procdump"
}
Start-Sleep 4

$main=[IntPtr]::Zero
for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 500
  try{$p.Refresh()}catch{}
  if($p.HasExited){ SLog "EXIT_BEFORE_MAIN exit=$($p.ExitCode)"; break }
  if($p.MainWindowHandle -ne 0){ $main=[IntPtr]$p.MainWindowHandle; break }
  $main=[I49_74_STACK]::FindMain([uint32]$p.Id)
  if($main -ne [IntPtr]::Zero){ break }
}
SLog "MAIN=0x$('{0:X}' -f $main.ToInt64())"
if($main -eq [IntPtr]::Zero){ throw 'NO_MAIN_HWND' }
[void][I49_74_STACK]::ShowWindow($main,9)
[void][I49_74_STACK]::SetForegroundWindow($main)
Start-Sleep 3

$prompt='bug.cpp has TWO separate defects. Follow this exact order - do not fix both in one write: STEP A: Fix ONLY the compile error around undeclared_fn. Keep add() exactly as "return a - b;". Do not rewrite the whole file to a simplified version. Then build/test. STEP B: After the tool result shows compile success but AGENT_RESULT is not 5 (or the write was rolled back for wrong output), issue a SECOND write that changes add() to "return a + b;" while keeping undeclared_fn fixed. Then build/test until AGENT_RESULT=5. Rules: /WX - no unused parameters. Two writes required. Final independent result must be AGENT_RESULT=5. After a write rolled back, you MUST issue another TOOL write with a different body until write committed and AGENT_RESULT=5.'
SLog "PROMPT_LEN=$($prompt.Length)"
$rtLog=Join-Path $logDir 'chat_runtime.log'
if(Test-Path $rtLog){ Remove-Item $rtLog -Force -EA SilentlyContinue }
$chat=[I49_74_STACK]::FindEditId($main,1202)
if($chat -eq [IntPtr]::Zero){ $chat=[I49_74_STACK]::FindId($main,1202) }
[void][I49_74_STACK]::SetWindowTextW($chat,'')
[void][I49_74_STACK]::SendMessageW($chat,[I49_74_STACK]::EM_SETSEL,[IntPtr]::Zero,[IntPtr]::new(-1))
[void][I49_74_STACK]::SendMessageW($chat,[I49_74_STACK]::EM_REPLACESEL,[IntPtr]::Zero,$prompt)
$staged=[I49_74_STACK]::GetText($chat)
SLog "CHAT_INPUT len=$($staged.Length) hwnd=0x$('{0:X}' -f $chat.ToInt64())"
[I49_74_STACK]::SendCtrlEnter($main,$chat)
SLog "CTRL_ENTER_SENT"
$sendAt=Get-Date

# Wait up to 150s for real death / HIT echo (not bp-source false positive)
$gotDeath=$false
$hitSeen=$false
$exitCode=''
# Whole-line HIT only (bp command echo also contains the string inline).
$hitPattern='^===HIT_(EXITPROCESS|EXITPROCESS_KB|NTTERMINATE|EXCEPTION)===$'
for($w=0;$w -lt 150;$w++){
  Start-Sleep 1
  try{$p.Refresh()}catch{}
  if((Test-Path $cdbLog) -and -not $hitSeen){
    if(Select-String -Path $cdbLog -Pattern $hitPattern -Quiet){
      $hitSeen=$true
      SLog "CDB_HIT_MARKER_SEEN t=$w"
    }
  }
  if($p.HasExited){
    $exitCode=[string]$p.ExitCode
    $gotDeath=$true
    SLog "IDE_EXIT=$exitCode after_sec=$([int]((Get-Date)-$sendAt).TotalSeconds)"
    break
  }
  if($hitSeen -and (Test-Path $liveDump)){
    SLog "DUMP_AFTER_HIT"
    Start-Sleep 3
    try{$p.Refresh()}catch{}
    if($p.HasExited){ $exitCode=[string]$p.ExitCode; $gotDeath=$true }
    break
  }
}
for($w=0;$w -lt 45;$w++){
  if(-not (Get-Process -Id $cdbProc.Id -EA SilentlyContinue)){ break }
  Start-Sleep 1
}

# Collect artifacts
$pmStack=''
$dumps=@(Get-ChildItem $dumpDir -Filter '*.dmp' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending)
$cdbText=''
if(Test-Path $cdbLog){ $cdbText=Get-Content $cdbLog -Raw -EA SilentlyContinue }
$rtTail=''
if(Test-Path $rtLog){ $rtTail=((Get-Content $rtLog -EA SilentlyContinue) | Select-Object -Last 60) -join "`n" }
$marker='NONE'
if($cdbText -match '(?m)^===HIT_EXITPROCESS===$'){ $marker='EXITPROCESS' }
elseif($cdbText -match '(?m)^===HIT_EXITPROCESS_KB===$'){ $marker='EXITPROCESS_KERNELBASE' }
elseif($cdbText -match '(?m)^===HIT_NTTERMINATE===$'){ $marker='NTTERMINATEPROCESS' }
elseif($cdbText -match '(?m)^===HIT_EXCEPTION===$'){ $marker='EXCEPTION' }
$stackGot=0
if($marker -ne 'NONE' -and $cdbText -match '(?ms)^===HIT_(?:EXITPROCESS|EXITPROCESS_KB|NTTERMINATE|EXCEPTION)===\s*$.*?(?:Child-SP|RetAddr)'){ $stackGot=1 }
$dumpPath=''
if(Test-Path $liveDump){ $dumpPath=$liveDump }
elseif(Test-Path $procDumpOut){ $dumpPath=$procDumpOut }
elseif($dumps.Count -gt 0){ $dumpPath=$dumps[0].FullName }

# Post-mortem stack from dump if live HIT missed
$pmLog=Join-Path $outDir ("cdb_postmortem_$stamp.log")
$pmStack=''
if($dumpPath -and (Test-Path $dumpPath) -and $stackGot -eq 0){
  $pmCmds=Join-Path $outDir 'cdb_postmortem_cmds.txt'
  @(
    ".logopen $pmLog"
    '.sympath srv*'
    'kL 80'
    'lm m RawrXD*'
    '.ecxr'
    'kL 40'
    '!peb'
    '.lastevent'
    '.logclose'
    'q'
  ) | Set-Content $pmCmds -Encoding ASCII
  $pm=Start-Process -FilePath $cdb -ArgumentList @('-z',$dumpPath,'-cf',$pmCmds) -PassThru -WindowStyle Minimized -Wait
  SLog "POSTMORTEM_CDB_EXIT=$($pm.ExitCode)"
  if(Test-Path $pmLog){
    $pmStack=Get-Content $pmLog -Raw -EA SilentlyContinue
    if($pmStack -match 'Child-SP|RetAddr'){ $stackGot=1; $marker= if($marker -eq 'NONE'){'POSTMORTEM_DUMP'} else {$marker} }
  }
}

# Extract exit code from cdb rcx if present
$cdbExit=''
if($cdbText -match '(?s)===HIT_EXITPROCESS(?:_KB)?===\s*\r?\n.*?rcx=([0-9A-Fa-f`]+)'){ $cdbExit=$Matches[1] }
if(-not $exitCode){
  try{$p.Refresh()}catch{}
  if($p.HasExited){ $exitCode=[string]$p.ExitCode; $gotDeath=$true }
}

# Kill leftovers
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','cdb*','cdbX64*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue

$excCode='NONE'
if($cdbText -match 'ExceptionCode:\s*([0-9A-Fa-fx]+)'){ $excCode=$Matches[1] }
elseif($marker -eq 'EXCEPTION' -and $cdbText -match 'c0000409|C0000409'){ $excCode='0xC0000409' }
elseif($marker -eq 'EXCEPTION' -and $cdbText -match 'c0000005|C0000005'){ $excCode='0xC0000005' }

$class='UNKNOWN'
if($marker -eq 'EXITPROCESS' -or $marker -eq 'EXITPROCESS_KERNELBASE'){ $class='SILENT_EXITPROCESS_PATH' }
elseif($marker -eq 'NTTERMINATEPROCESS'){ $class='TERMINATEPROCESS_PATH' }
elseif($marker -eq 'EXCEPTION'){ $class='EXCEPTION_PATH' }
elseif($gotDeath -and $stackGot -eq 0){ $class='SILENT_EXIT_NO_CDB_STACK' }
elseif(-not $gotDeath -and $marker -eq 'NONE'){ $class='NO_DEATH_IN_WINDOW' }

$excerpt='CDB_LOG_MISSING'
if($cdbText){
  $ls=$cdbText -split "`r?`n"
  $idx=-1
  for($i=0;$i -lt $ls.Count;$i++){ if($ls[$i] -match '^===HIT_'){ $idx=$i; break } }
  if($idx -lt 0){
    $excerpt=($ls | Where-Object { $_ -match 'bp |Malformed|Could not|Unable|error|Error|Breakpoint|Quit' } | Select-Object -First 80) -join "`n"
  } else {
    $end=[Math]::Min($ls.Count-1, $idx+100)
    $excerpt=($ls[$idx..$end] -join "`n")
  }
}
$deathInt=0; if($gotDeath){ $deathInt=1 }
$hitInt=0; if($hitSeen){ $hitInt=1 }
$missInt=0; if($stackGot -eq 0){ $missInt=1 }

$ev=@(
'I026_EARLY_DEATH_STACK_001'
"ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
'CANDIDATE=I'
'CANDIDATE_DIR=issue49_candidate_AC7DC1D4_7774E846_001'
'RECEIPT_LABEL=issue49_gui_ollama_qwen3_027_STACK'
'REPRO_FOR_STACK_ONLY=1'
'ATTEMPT=3'
'NOT_ACCEPTANCE_REMEASURE=1'
'NO_ALIVE_PASS_CLAIM=1'
'NO_SOURCE_EDITED_PASS_CLAIM=1'
"REPAIR_SHA=$expect"
"LOOP_SHA=$loopExpect"
"IDE_SHA_VERIFIED=$ideSha"
"LOOP_SHA_VERIFIED=$loopSha"
"PROMPT_LEN=$($prompt.Length)"
'PROMPT_REGIME=ASCII_staged_dual_fault_STEP_A_B'
'OllamaAgentModel=qwen3:8b'
'STRING_VERIFY_PASS=1'
'CONTROLLING=D015'
'H_022_SUPERSEDES_D015=0'
'T05_LANE_SEPARATE=1'
'PROMOTE=0'
'CERTIFIED=0'
'TIP_CLIMB=HOLD'
''
'========================================================================'
'CAPTURE METHOD'
'========================================================================'
"TIP_EXE=$tipExe"
"OUTDIR=$outDir"
"CDB=$cdb"
'ATTACH=cdb -p <pid> -cf cdb_cmds.txt (post-spawn ~900ms)'
'BPS=ntdll!RtlExitUserProcess ; ntdll!NtTerminateProcess'
'SXE=av,c0000409,c0000005,epr (eh disabled; attempt2 stalled)'
"PROCDUMP=$procdump"
"PROCDUMP_OUT=$procDumpOut"
"LOCALDUMPS_HKCU=$ldKey -> $dumpDir"
"SPAWN_PID=$($p.Id)"
"CDB_PID=$($cdbProc.Id)"
"RUNLOG=$runLog"
"CDB_LOG=$cdbLog"
"CDB_CMDS=$cmdFile"
''
'========================================================================'
'RESULT'
'========================================================================'
"GOT_STACK=$stackGot"
"MISSING_STACK=$missInt"
"CDB_MARKER=$marker"
"DEATH_CLASS=$class"
"PROCESS_EXIT_CODE=$exitCode"
"CDB_RCX_AT_EXIT=$cdbExit"
"EXCEPTION_CODE=$excCode"
"DUMP_PATH=$dumpPath"
"DUMP_COUNT=$($dumps.Count)"
"GOT_DEATH=$deathInt"
"HIT_SEEN=$hitInt"
''
'========================================================================'
'CDB LOG EXCERPT (HIT + stack)'
'========================================================================'
$excerpt
''
'========================================================================'
'LAST chat_runtime LINES'
'========================================================================'
$rtTail
''
'========================================================================'
'AUTHORITY'
'========================================================================'
'CONTROLLING=D015'
'PROMOTE=0'
'NO_SUPERSEDE=1'
'NO_BLIND_027_ACCEPTANCE=1'
'LoadTensorSlice_REOPENED=0'
'ATTEMPT1_INVALID=1'
'ATTEMPT1_NOTE=false_positive_marker_from_bp_command_text; RtlExitUserProcess_bp_malformed_quotes'
'ATTEMPT2_NOTE=IDE_EXIT=-1 reproduced under cdb; no HIT; cdb stalled at KiUserCallbackDispatch (sxe eh); no dump'
'ATTEMPT3_NOTE=procdump -t + lean cdb (no eh) + epr + postmortem'
''
'========================================================================'
'POSTMORTEM / PROCDUMP NOTES'
'========================================================================'
$(if($pmStack){ ($pmStack -split "`r?`n" | Where-Object { $_ -match 'Child-SP|RetAddr|RawrXD|Exception|Quit|error|Error|lastevent|PEB' } | Select-Object -First 100) -join "`n" } else { 'NO_POSTMORTEM_STACK' })
)
[IO.File]::WriteAllText($evidence, (($ev -join "`r`n") + "`r`n"), [Text.UTF8Encoding]::new($false))

SLog "EVIDENCE_WRITTEN=$evidence GOT_STACK=$stackGot EXIT=$exitCode MARKER=$marker DUMP=$dumpPath DEATH=$gotDeath"
Write-Host "DONE GOT_STACK=$stackGot EXIT=$exitCode MARKER=$marker DEATH=$gotDeath"
if($stackGot -eq 1){ exit 0 } else { exit 2 }

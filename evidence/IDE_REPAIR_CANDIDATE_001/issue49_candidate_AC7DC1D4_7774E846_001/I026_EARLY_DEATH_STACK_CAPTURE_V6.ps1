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
function Get-Sha256Fast([string]$path){
  $line=(certutil -hashfile $path SHA256 2>$null | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -First 1)
  if($line){ return $line.Trim().ToUpperInvariant() }
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
}
function To-Hex32([int64]$v){ $b=[BitConverter]::GetBytes([int]$v); return ('{0:X2}{1:X2}{2:X2}{3:X2}' -f $b[3],$b[2],$b[1],$b[0]) }
$ideSha=Get-Sha256Fast $tipExe
$loopSha=Get-Sha256Fast (Join-Path $tipDir 'deep2_agentic_loop.exe')
if($ideSha -ne $expect){ throw "IDE_SHA_DRIFT $ideSha" }
if($loopSha -ne $loopExpect){ throw "LOOP_SHA_DRIFT $loopSha" }
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','cdb*','cdbX64*','procdump*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
# Full harness fixture
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
[IO.File]::WriteAllText($project,$fixtureBaseline.TrimStart("`r","`n"),[Text.UTF8Encoding]::new($false))
$env:RAWRXD_LOG_DIR=$logDir
$env:RAWRXD_USERDATA=$userData
$env:RAWRXD_DEFAULT_DEEP2_MODEL=$model
$env:RAWRXD_PROBLEMS_FIXTURE=$project
$env:RAWRXD_OPEN_DOCUMENT=$project
$env:RAWRXD_FORCE_LOCAL_AGENTIC='0'
$env:RAWRXD_FORCE_OLLAMA_AGENTIC='1'
$env:RAWRXD_OLLAMA_AGENT_MODEL='qwen3:8b'
$env:RAWRXD_GUI_APPROVE_MUTATIONS='YES'
$env:RAWRXD_AGENTIC_QUIET='0'
$env:RAWRXD_AGENT_MODE='ACTIVE'
$env:RAWRXD_AGENTIC_CONTEXT_SIZE='4096'
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
. (Join-Path $cand 'I026_STACK_HELPERS.ps1')
$runLog=Join-Path $outDir ("stack_capture_v6_$stamp.txt")
function SLog([string]$m){ $line="$(Get-Date -Format o) $m"; Add-Content $runLog $line; Write-Host $line }
$liveDump=Join-Path $dumpDir ("i026_early_death_$stamp.dmp")
$liveDumpCdb=($liveDump -replace [char]92, [char]47)
$cdbLog=Join-Path $outDir ("cdb_v6_$stamp.log")
$cmdFile=Join-Path $outDir 'cdb_v6_cmds.txt'
# Minimal: only ExitProcess/NtTerminate/av/c0000409. No eh. stdin watchdog will send g if stalled.
@(
  ".logopen $cdbLog"
  '.sympath srv*'
  '.reload /f ntdll.dll'
  ("bp ntdll!RtlExitUserProcess `".echo ===HIT_EXITPROCESS===; r rcx; kL 80; lm m RawrXD*; .dump /ma /u $liveDumpCdb; .logclose; qd`"")
  ("bp ntdll!NtTerminateProcess `".echo ===HIT_NTTERMINATE===; r rcx; r rdx; kL 80; lm m RawrXD*; .dump /ma /u $liveDumpCdb; .logclose; qd`"")
  ("sxe -c `".echo ===HIT_EXCEPTION===; .exr -1; kL 80; lm m RawrXD*; .dump /ma /u $liveDumpCdb; .logclose; qd`" av")
  ("sxe -c `".echo ===HIT_EXCEPTION===; .exr -1; kL 80; lm m RawrXD*; .dump /ma /u $liveDumpCdb; .logclose; qd`" c0000409")
  'sxd eh'
  'sxi ibp'
  'bl'
  'g'
) | Set-Content $cmdFile -Encoding ASCII

$p=Start-Process -FilePath $tipExe -ArgumentList @("--user-data-dir=$userData",$project) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
SLog "SPAWN_PID=$($p.Id)"
$main=[IntPtr]::Zero
for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 500
  try{$p.Refresh()}catch{}
  if($p.HasExited){ throw ("EXIT_BEFORE_MAIN=$($p.ExitCode) hex="+(To-Hex32 $p.ExitCode)) }
  if($p.MainWindowHandle -ne 0){ $main=[IntPtr]$p.MainWindowHandle; break }
  $main=[I49_74_STACK]::FindMain([uint32]$p.Id)
  if($main -ne [IntPtr]::Zero){ break }
}
SLog ("MAIN=0x{0:X}" -f $main.ToInt64())
if($main -eq [IntPtr]::Zero){ throw 'NO_MAIN_HWND' }
[void][I49_74_STACK]::ShowWindow($main,9)
[void][I49_74_STACK]::SetForegroundWindow($main)
Start-Sleep 2

# Attach cdb AFTER main with redirected stdin for g-watchdog
$psi=New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName=$cdb
$psi.Arguments=("-p $($p.Id) -cf `"$cmdFile`"")
$psi.UseShellExecute=$false
$psi.RedirectStandardInput=$true
$psi.RedirectStandardOutput=$false
$psi.RedirectStandardError=$false
$psi.CreateNoWindow=$true
$cdbProc=[Diagnostics.Process]::Start($psi)
SLog "CDB_PID=$($cdbProc.Id) ATTACH_AFTER_MAIN=1"
Start-Sleep 5

$prompt='bug.cpp has TWO separate defects. Follow this exact order - do not fix both in one write: STEP A: Fix ONLY the compile error around undeclared_fn. Keep add() exactly as "return a - b;". Do not rewrite the whole file to a simplified version. Then build/test. STEP B: After the tool result shows compile success but AGENT_RESULT is not 5 (or the write was rolled back for wrong output), issue a SECOND write that changes add() to "return a + b;" while keeping undeclared_fn fixed. Then build/test until AGENT_RESULT=5. Rules: /WX - no unused parameters. Two writes required. Final independent result must be AGENT_RESULT=5. After a write rolled back, you MUST issue another TOOL write with a different body until write committed and AGENT_RESULT=5.'
SLog "PROMPT_LEN=$($prompt.Length)"
$rtLog=Join-Path $logDir 'chat_runtime.log'
if(Test-Path $rtLog){ Remove-Item $rtLog -Force -EA SilentlyContinue }
$chat=[I49_74_STACK]::FindEditId($main,1202)
if($chat -eq [IntPtr]::Zero){ $chat=[I49_74_STACK]::FindId($main,1202) }
[void][I49_74_STACK]::SetWindowTextW($chat,'')
[void][I49_74_STACK]::SendMessageW($chat,[I49_74_STACK]::EM_SETSEL,[IntPtr]::Zero,[IntPtr]::new(-1))
[void][I49_74_STACK]::SendMessageW($chat,[I49_74_STACK]::EM_REPLACESEL,[IntPtr]::Zero,$prompt)
SLog ("CHAT_INPUT len=$([I49_74_STACK]::GetText($chat).Length)")
[I49_74_STACK]::SendCtrlEnter($main,$chat)
SLog 'CTRL_ENTER_SENT'
$sendAt=Get-Date

$gotDeath=$false; $exitCode=''; $hitSeen=$false
$hitPattern='^===HIT_(EXITPROCESS|NTTERMINATE|EXCEPTION)===$'
$lastLogLen=0; $stallG=0
for($w=0;$w -lt 150;$w++){
  Start-Sleep 1
  try{$p.Refresh()}catch{}
  # stdin g watchdog: if cdb log grew with a break that is not HIT and then stalled, send g
  if(Test-Path $cdbLog){
    $len=(Get-Item $cdbLog).Length
    if(-not $hitSeen -and (Select-String -Path $cdbLog -Pattern $hitPattern -Quiet)){ $hitSeen=$true; SLog "CDB_HIT_MARKER_SEEN t=$w" }
    if(-not $hitSeen -and $len -eq $lastLogLen -and $len -gt 200 -and $w -gt 8){
      try{ $cdbProc.StandardInput.WriteLine('g'); $cdbProc.StandardInput.Flush(); $stallG++; SLog "CDB_STDIN_G t=$w count=$stallG" } catch { SLog "CDB_STDIN_G_FAIL $($_.Exception.Message)" }
      Start-Sleep 1
    }
    $lastLogLen=$len
  }
  $alive=Get-Process -Id $p.Id -EA SilentlyContinue
  if(-not $alive){
    try{$p.Refresh()}catch{}
    $exitCode='-1'
    try{ if($p.HasExited){ $exitCode=[string]$p.ExitCode } }catch{}
    $gotDeath=$true
    $hx='UNKNOWN'; try{ $hx=To-Hex32 ([int64]$exitCode) }catch{}
    SLog ("IDE_EXIT=$exitCode hex=$hx after_sec=$([int]((Get-Date)-$sendAt).TotalSeconds) via=Get-Process-missing")
    break
  }
  if($hitSeen -and (Test-Path $liveDump)){ SLog 'DUMP_AFTER_HIT'; Start-Sleep 3; try{$p.Refresh()}catch{}; if($p.HasExited){$exitCode=[string]$p.ExitCode;$gotDeath=$true}; break }
}
for($w=0;$w -lt 40;$w++){ if(-not (Get-Process -Id $cdbProc.Id -EA SilentlyContinue)){ break }; Start-Sleep 1 }

$cdbText=''; if(Test-Path $cdbLog){ $cdbText=Get-Content $cdbLog -Raw -EA SilentlyContinue }
$rtTail=''; if(Test-Path $rtLog){ $rtTail=((Get-Content $rtLog -EA SilentlyContinue)|Select-Object -Last 60) -join "`n" }
$marker='NONE'
if($cdbText -match '(?m)^===HIT_EXITPROCESS===$'){ $marker='EXITPROCESS' }
elseif($cdbText -match '(?m)^===HIT_NTTERMINATE===$'){ $marker='NTTERMINATEPROCESS' }
elseif($cdbText -match '(?m)^===HIT_EXCEPTION===$'){ $marker='EXCEPTION' }
$stackGot=0
if($marker -ne 'NONE' -and $cdbText -match '(?ms)^===HIT_(?:EXITPROCESS|NTTERMINATE|EXCEPTION)===\s*$.*?(?:Child-SP|RetAddr)'){ $stackGot=1 }
$dumps=@(Get-ChildItem $dumpDir -Filter '*.dmp' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending)
$dumpPath=''; if(Test-Path $liveDump){$dumpPath=$liveDump} elseif($dumps.Count -gt 0){$dumpPath=$dumps[0].FullName}
$cdbExit=''; if($cdbText -match '(?s)===HIT_EXITPROCESS===\s*\r?\n.*?rcx=([0-9A-Fa-f`]+)'){ $cdbExit=$Matches[1] }
$excCode='NONE'; if($cdbText -match 'ExceptionCode:\s*([0-9A-Fa-fx]+)'){ $excCode=$Matches[1] }
if(-not $exitCode){ try{$p.Refresh()}catch{}; if($p.HasExited){$exitCode=[string]$p.ExitCode;$gotDeath=$true} }
$class='UNKNOWN'
if($marker -eq 'EXITPROCESS'){ $class='SILENT_EXITPROCESS_PATH' }
elseif($marker -eq 'NTTERMINATEPROCESS'){ $class='TERMINATEPROCESS_PATH' }
elseif($marker -eq 'EXCEPTION'){ $class='EXCEPTION_PATH' }
elseif($gotDeath -and $exitCode -eq '-1'){ $class='SILENT_EXIT_CODE_MINUS_1_NO_CDB_STACK' }
elseif($gotDeath){ $class='EXIT_NO_CDB_HIT' }
elseif(-not $gotDeath){ $class='NO_DEATH_IN_WINDOW' }
$exitHex=''; if($exitCode -match '^-?\d+$'){ $exitHex=To-Hex32 ([int64]$exitCode) }
$excerpt='CDB_LOG_MISSING'
if($cdbText){
  $ls=$cdbText -split "`r?`n"; $idx=-1
  for($i=0;$i -lt $ls.Count;$i++){ if($ls[$i] -match '^===HIT_'){ $idx=$i; break } }
  if($idx -lt 0){ $excerpt=($ls | Where-Object { $_ -match 'bp |bl|Malformed|Could not|Unable|error|Error|Breakpoint|KiUser|Quit|ntdll!' } | Select-Object -First 100) -join "`n" }
  else { $end=[Math]::Min($ls.Count-1,$idx+100); $excerpt=($ls[$idx..$end] -join "`n") }
}
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','cdb*','cdbX64*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
$deathInt=0; if($gotDeath){$deathInt=1}
$missInt=0; if($stackGot -eq 0){$missInt=1}
$hitInt=0; if($hitSeen){$hitInt=1}
$ev=@(
'I026_EARLY_DEATH_STACK_001'
"ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
'CANDIDATE=I'
'CANDIDATE_DIR=issue49_candidate_AC7DC1D4_7774E846_001'
'RECEIPT_LABEL=issue49_gui_ollama_qwen3_027_STACK'
'REPRO_FOR_STACK_ONLY=1'
'ATTEMPT=6'
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
'METHOD=attach_cdb_after_MAIN; lean bps (no eh); stdin g-watchdog'
"SPAWN_PID=$($p.Id)"
"CDB_PID=$($cdbProc.Id)"
"RUNLOG=$runLog"
"CDB_LOG=$cdbLog"
"STDIN_G_COUNT=$stallG"
''
'========================================================================'
'RESULT'
'========================================================================'
"GOT_STACK=$stackGot"
"MISSING_STACK=$missInt"
"CDB_MARKER=$marker"
"DEATH_CLASS=$class"
"PROCESS_EXIT_CODE=$exitCode"
"PROCESS_EXIT_HEX=$exitHex"
"CDB_RCX_AT_EXIT=$cdbExit"
"EXCEPTION_CODE=$excCode"
"DUMP_PATH=$dumpPath"
"DUMP_COUNT=$($dumps.Count)"
"GOT_DEATH=$deathInt"
"HIT_SEEN=$hitInt"
''
'========================================================================'
'CDB LOG EXCERPT'
'========================================================================'
$excerpt
''
'========================================================================'
'LAST chat_runtime LINES'
'========================================================================'
$rtTail
''
'========================================================================'
'PRIOR ATTEMPTS'
'========================================================================'
'ATTEMPT1_INVALID=false_positive HIT'
'ATTEMPT2=IDE_EXIT=-1 ~97s; cdb stalled KiUserCallbackDispatch (sxe eh); no dump'
'ATTEMPT3=dual attach early death before MAIN'
'ATTEMPT4=procdump -t after MAIN caused IDE_EXIT=-1073740972 (0xC0000354) ~1s post-send; no dump'
'ATTEMPT5=false HasExited under cdb; ATTEMPT6=Get-Process death + forward-slash dump path'
''
'========================================================================'
'AUTHORITY'
'========================================================================'
'CONTROLLING=D015'
'PROMOTE=0'
'NO_SUPERSEDE=1'
'NO_BLIND_027_ACCEPTANCE=1'
'LoadTensorSlice_REOPENED=0'
)
[IO.File]::WriteAllText($evidence,(($ev -join "`r`n")+"`r`n"),[Text.UTF8Encoding]::new($false))
SLog "EVIDENCE_WRITTEN=$evidence GOT_STACK=$stackGot EXIT=$exitCode MARKER=$marker DUMP=$dumpPath DEATH=$gotDeath"
Write-Host "DONE GOT_STACK=$stackGot EXIT=$exitCode MARKER=$marker DEATH=$gotDeath"
if($stackGot -eq 1){ exit 0 } else { exit 2 }

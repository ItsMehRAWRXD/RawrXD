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
$procdump='F:\rawrxd\scripts\procdump_tools\procdump64.exe'
$evidence=Join-Path $cand 'I026_EARLY_DEATH_STACK_001.txt'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force -Path $outDir,$logDir,$userData,$dumpDir | Out-Null
function Get-Sha256Fast([string]$path){
  $line=(certutil -hashfile $path SHA256 2>$null | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -First 1)
  if($line){ return $line.Trim().ToUpperInvariant() }
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
}
function To-Hex32([int64]$v){ '{0:X8}' -f [uint32]($v -band 0xffffffff) }
$ideSha=Get-Sha256Fast $tipExe
$loopSha=Get-Sha256Fast (Join-Path $tipDir 'deep2_agentic_loop.exe')
if($ideSha -ne $expect){ throw "IDE_SHA_DRIFT $ideSha" }
if($loopSha -ne $loopExpect){ throw "LOOP_SHA_DRIFT $loopSha" }
$ldKey='HKCU:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\RawrXD-Win32IDE-Native-Ext.exe'
New-Item -Path $ldKey -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpFolder -Value $dumpDir -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpType -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $ldKey -Name DumpCount -Value 10 -PropertyType DWord -Force | Out-Null
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','cdb*','cdbX64*','procdump*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
$fixture=@"
#include <cstdio>
int undeclared_fn(int a) { return a; }
int add(int a, int b) { return a - b; }
int main() {
  (void)undeclared_fn(1, 2);
  std::printf("AGENT_RESULT=%d\n", add(2, 3));
  return 0;
}
"@
[IO.File]::WriteAllText($project,$fixture.TrimStart("`r","`n"),[Text.UTF8Encoding]::new($false))
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
$runLog=Join-Path $outDir ("stack_capture_v3_$stamp.txt")
function SLog([string]$m){ $line="$(Get-Date -Format o) $m"; Add-Content $runLog $line; Write-Host $line }
$procDumpOut=Join-Path $dumpDir ("i026_procdump_term_$stamp.dmp")
$p=Start-Process -FilePath $tipExe -ArgumentList @("--user-data-dir=$userData",$project) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
SLog "SPAWN_PID=$($p.Id)"
$main=[IntPtr]::Zero
for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 500
  try{$p.Refresh()}catch{}
  if($p.HasExited){ throw ("EXIT_BEFORE_MAIN=$($p.ExitCode) hex=" + (To-Hex32 $p.ExitCode)) }
  if($p.MainWindowHandle -ne 0){ $main=[IntPtr]$p.MainWindowHandle; break }
  $main=[I49_74_STACK]::FindMain([uint32]$p.Id)
  if($main -ne [IntPtr]::Zero){ break }
}
SLog ("MAIN=0x{0:X}" -f $main.ToInt64())
if($main -eq [IntPtr]::Zero){ throw 'NO_MAIN_HWND' }
$pdProc=Start-Process -FilePath $procdump -ArgumentList @('-accepteula','-t','-ma','-n','1',"$($p.Id)",$procDumpOut) -PassThru -WindowStyle Minimized
SLog "PROCDUMP_PID=$($pdProc.Id) OUT=$procDumpOut"
Start-Sleep 1
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
SLog ("CHAT_INPUT len=$($staged.Length)")
[I49_74_STACK]::SendCtrlEnter($main,$chat)
SLog 'CTRL_ENTER_SENT'
$sendAt=Get-Date
$gotDeath=$false; $exitCode=''
for($w=0;$w -lt 150;$w++){
  Start-Sleep 1
  try{$p.Refresh()}catch{}
  if($p.HasExited){
    $exitCode=[string]$p.ExitCode; $gotDeath=$true
    SLog ("IDE_EXIT=$exitCode hex=" + (To-Hex32 $p.ExitCode) + " after_sec=$([int]((Get-Date)-$sendAt).TotalSeconds)")
    break
  }
  if(Test-Path $procDumpOut){ SLog "PROCDUMP_FILE_SEEN t=$w"; Start-Sleep 2; try{$p.Refresh()}catch{}; if($p.HasExited){$exitCode=[string]$p.ExitCode;$gotDeath=$true}; break }
}
for($w=0;$w -lt 60;$w++){
  if((Test-Path $procDumpOut) -and ((Get-Item $procDumpOut).Length -gt 1000000)){ Start-Sleep 2; break }
  if($pdProc -and -not (Get-Process -Id $pdProc.Id -EA SilentlyContinue) -and (Test-Path $procDumpOut)){ break }
  Start-Sleep 1
}
$dumps=@(Get-ChildItem $dumpDir -Filter '*.dmp' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending)
$dumpPath=''; if(Test-Path $procDumpOut){$dumpPath=$procDumpOut} elseif($dumps.Count -gt 0){$dumpPath=$dumps[0].FullName}
$rtTail=''; if(Test-Path $rtLog){ $rtTail=((Get-Content $rtLog -EA SilentlyContinue)|Select-Object -Last 60) -join "`n" }
$pmLog=Join-Path $outDir ("cdb_postmortem_$stamp.log")
$pmStack=''; $stackGot=0; $marker='NONE'; $excCode='NONE'
if($dumpPath -and (Test-Path $dumpPath)){
  $marker='PROCDUMP_TERMINATE'
  $pmCmds=Join-Path $outDir 'cdb_postmortem_cmds.txt'
  @(".logopen $pmLog",'.sympath srv*','.echo ===HIT_POSTMORTEM===','kL 80','lm m RawrXD*','lm m deep2*','.lastevent','!peb','.ecxr','kL 40','.logclose','q') | Set-Content $pmCmds -Encoding ASCII
  SLog "POSTMORTEM_START dump=$dumpPath"
  $pm=Start-Process -FilePath $cdb -ArgumentList @('-z',$dumpPath,'-cf',$pmCmds) -PassThru -WindowStyle Minimized -Wait
  SLog "POSTMORTEM_DONE exit=$($pm.ExitCode)"
  if(Test-Path $pmLog){
    $pmStack=Get-Content $pmLog -Raw -EA SilentlyContinue
    if($pmStack -match '(?m)^===HIT_POSTMORTEM===$' -and $pmStack -match 'Child-SP|RetAddr'){ $stackGot=1 }
    if($pmStack -match 'ExceptionCode:\s*([0-9A-Fa-fx]+)'){ $excCode=$Matches[1] }
  }
}
if(-not $exitCode){ try{$p.Refresh()}catch{}; if($p.HasExited){ $exitCode=[string]$p.ExitCode; $gotDeath=$true } }
$class='UNKNOWN'
if($gotDeath -and $exitCode -eq '-1'){ $class='SILENT_EXIT_CODE_MINUS_1' }
elseif($gotDeath -and $excCode -ne 'NONE'){ $class='EXCEPTION_IN_DUMP' }
elseif($gotDeath){ $class='EXIT_WITH_CODE' }
elseif(-not $gotDeath){ $class='NO_DEATH_IN_WINDOW' }
$exitHex=''; if($exitCode -match '^-?\d+$'){ $exitHex=To-Hex32 ([int64]$exitCode) }
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','cdb*','cdbX64*','procdump*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
$pmExcerpt='NO_POSTMORTEM'
if($pmStack){ $pmExcerpt=($pmStack -split "`r?`n" | Where-Object { $_ -match '===HIT_|Child-SP|RetAddr|RawrXD|Exception|Quit|error|Error|lastevent|PEB|WARNING|Unable' } | Select-Object -First 120) -join "`n" }
$deathInt=0; if($gotDeath){$deathInt=1}
$missInt=0; if($stackGot -eq 0){$missInt=1}
$ev=@(
'I026_EARLY_DEATH_STACK_001'
"ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
'CANDIDATE=I'
'CANDIDATE_DIR=issue49_candidate_AC7DC1D4_7774E846_001'
'RECEIPT_LABEL=issue49_gui_ollama_qwen3_027_STACK'
'REPRO_FOR_STACK_ONLY=1'
'ATTEMPT=4'
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
'METHOD=launch_no_debugger; procdump -t -ma after MAIN; cdb -z postmortem'
"PROCDUMP=$procdump"
"SPAWN_PID=$($p.Id)"
"PROCDUMP_PID=$($pdProc.Id)"
"RUNLOG=$runLog"
"POSTMORTEM_LOG=$pmLog"
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
"EXCEPTION_CODE=$excCode"
"DUMP_PATH=$dumpPath"
"DUMP_COUNT=$($dumps.Count)"
"GOT_DEATH=$deathInt"
''
'========================================================================'
'POSTMORTEM STACK EXCERPT'
'========================================================================'
$pmExcerpt
''
'========================================================================'
'LAST chat_runtime LINES'
'========================================================================'
$rtTail
''
'========================================================================'
'PRIOR ATTEMPTS'
'========================================================================'
'ATTEMPT1_INVALID=1 NOTE=false_positive HIT from bp command text'
'ATTEMPT2=IDE_EXIT=-1 ~97s under cdb; stalled KiUserCallbackDispatch; no dump'
'ATTEMPT3=early EXIT_BEFORE_MAIN=-1073740972 (0xC0000404-class) dual attach'
'ATTEMPT4=procdump -t after MAIN + cdb postmortem'
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
SLog "EVIDENCE_WRITTEN=$evidence GOT_STACK=$stackGot EXIT=$exitCode DUMP=$dumpPath DEATH=$gotDeath"
Write-Host "DONE GOT_STACK=$stackGot EXIT=$exitCode DUMP=$dumpPath DEATH=$gotDeath"
if($stackGot -eq 1){ exit 0 } else { exit 2 }

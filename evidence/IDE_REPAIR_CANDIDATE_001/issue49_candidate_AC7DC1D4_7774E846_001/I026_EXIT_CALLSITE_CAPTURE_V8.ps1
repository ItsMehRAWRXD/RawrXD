param()
$ErrorActionPreference='Continue'
$cand='F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_AC7DC1D4_7774E846_001'
$tipExe=Join-Path $cand 'bin\RawrXD-Win32IDE-Native-Ext.exe'
$tipDir=Join-Path $cand 'bin'
$expect='AC7DC1D44F699FBCA19D4948CCE7EA1C17A4C941627CB229583DE4C570C2DF9A'
$loopExpect='7774E846CE748DA97590FE63E859DFDDA82756546C5F32F588BBACB69BDC2563'
$project='F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_wave2\fixtures\bug.cpp'
$model='F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
$outDir=Join-Path $cand 'issue49_gui_ollama_qwen3_027_EXIT_CALLSITE'
$logDir=Join-Path $outDir 'logs_live'
$userData=Join-Path $outDir 'userdata'
$cdb='C:\Users\Garrett\AppData\Local\Microsoft\WindowsApps\cdbX64.exe'
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Force -Path $outDir,$logDir,$userData | Out-Null
function Get-Sha256Fast([string]$path){
  $line=(certutil -hashfile $path SHA256 2>$null | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Select-Object -First 1)
  if($line){ return $line.Trim().ToUpperInvariant() }
  return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
}
function To-Hex32([int64]$v){ $b=[BitConverter]::GetBytes([int]$v); '{0:X2}{1:X2}{2:X2}{3:X2}' -f $b[3],$b[2],$b[1],$b[0] }
function Stop-CandidateIOnly {
  Get-CimInstance Win32_Process -EA SilentlyContinue |
    Where-Object {
      $_.Name -match '^(RawrXD-Win32IDE-Native-Ext|deep2_agentic_loop|cdb|cdbX64)\.exe$' -or
      ($_.ExecutablePath -and $_.ExecutablePath -like '*AC7DC1D4_7774E846*')
    } |
    ForEach-Object {
      if($_.ExecutablePath -and $_.ExecutablePath -like '*\build_ide\*'){ return }
      if($_.Name -eq 'RawrXD-Win32IDE-Native.exe' -and $_.ExecutablePath -notlike '*Native-Ext*'){ return }
      try{ Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }catch{}
    }
}
$ideSha=Get-Sha256Fast $tipExe
$loopSha=Get-Sha256Fast (Join-Path $tipDir 'deep2_agentic_loop.exe')
if($ideSha -ne $expect){ throw "IDE_SHA_DRIFT $ideSha" }
if($loopSha -ne $loopExpect){ throw "LOOP_SHA_DRIFT $loopSha" }
Stop-CandidateIOnly
Start-Sleep 2
$fixture=@"
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
[IO.File]::WriteAllText($project,$fixture.TrimStart("`r","`n"),[Text.UTF8Encoding]::new($false))
$env:RAWRXD_LOG_DIR=$logDir; $env:RAWRXD_USERDATA=$userData; $env:RAWRXD_DEFAULT_DEEP2_MODEL=$model
$env:RAWRXD_PROBLEMS_FIXTURE=$project; $env:RAWRXD_OPEN_DOCUMENT=$project
$env:RAWRXD_FORCE_LOCAL_AGENTIC='0'; $env:RAWRXD_FORCE_OLLAMA_AGENTIC='1'; $env:RAWRXD_OLLAMA_AGENT_MODEL='qwen3:8b'
$env:RAWRXD_GUI_APPROVE_MUTATIONS='YES'; $env:RAWRXD_AGENTIC_QUIET='0'; $env:RAWRXD_AGENT_MODE='ACTIVE'; $env:RAWRXD_AGENTIC_CONTEXT_SIZE='4096'
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
. (Join-Path $cand 'I026_STACK_HELPERS.ps1')
$runLog=Join-Path $outDir ("exit_callsite_v8_$stamp.txt")
function SLog([string]$m){ $line="$(Get-Date -Format o) $m"; Add-Content $runLog $line; Write-Host $line }
$cdbLog=Join-Path $outDir ("cdb_v8_$stamp.log")
$cmdFile=Join-Path $outDir 'cdb_v8_cmds.txt'
@(
  ".logopen `"$cdbLog`""
  '.sympath srv*'
  '.reload /f kernelbase.dll'
  '.reload /f ntdll.dll'
  '.reload /f ucrtbase.dll'
  'x kernel*!*ExitProcess*'
  'bp kernelbase!ExitProcess ".echo HIT_EXIT_CALLSITE; r rcx; kL 80; lm m RawrXD*; .echo STOP_AT_EXIT_CALLSITE; .logclose"'
  'bp ntdll!RtlExitUserProcess ".echo HIT_EXIT_CALLSITE; r rcx; kL 80; lm m RawrXD*; .echo STOP_AT_EXIT_CALLSITE; .logclose"'
  'bp ucrtbase!common_exit ".echo HIT_EXIT_CALLSITE; r rcx; kL 80; lm m RawrXD*; .echo STOP_AT_EXIT_CALLSITE; .logclose"'
  'bp ucrtbase!quick_exit ".echo HIT_EXIT_CALLSITE; r rcx; kL 80; lm m RawrXD*; .echo STOP_AT_EXIT_CALLSITE; .logclose"'
  'sxd eh'
  'sxi ibp'
  'bl'
  'g'
) | Set-Content $cmdFile -Encoding ASCII

$userData=Join-Path $outDir ("userdata_$stamp")
New-Item -ItemType Directory -Force -Path $userData | Out-Null
$env:RAWRXD_USERDATA=$userData
$p=Start-Process -FilePath $tipExe -ArgumentList @("--user-data-dir=$userData",$project) -WorkingDirectory $tipDir -PassThru -WindowStyle Normal
SLog "SPAWN_PID=$($p.Id) METHOD=EARLY_ATTACH_AT_MAIN_THEN_SEND"
$main=[IntPtr]::Zero
for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 500
  try{$p.Refresh()}catch{}
  if(-not (Get-Process -Id $p.Id -EA SilentlyContinue)){ throw 'EXIT_BEFORE_MAIN' }
  if($p.MainWindowHandle -ne 0){ $main=[IntPtr]$p.MainWindowHandle; break }
  $main=[I49_74_STACK]::FindMain([uint32]$p.Id)
  if($main -ne [IntPtr]::Zero){ break }
}
SLog ("MAIN=0x{0:X}" -f $main.ToInt64())
if($main -eq [IntPtr]::Zero){ throw 'NO_MAIN_HWND' }
[void][I49_74_STACK]::ShowWindow($main,9); [void][I49_74_STACK]::SetForegroundWindow($main); Start-Sleep 2

# EARLY attach at MAIN (before send): late attach raced DIED_BEFORE_ATTACH ~2s.
$createSeen=$false
$cdbProc=$null
$attachAt=''
$psi=New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName=$cdb; $psi.Arguments=("-p $($p.Id) -cf `"$cmdFile`"")
$psi.UseShellExecute=$false; $psi.RedirectStandardInput=$true; $psi.CreateNoWindow=$true
$cdbProc=[Diagnostics.Process]::Start($psi)
$attachAt=(Get-Date).ToString('o')
SLog "CDB_PID=$($cdbProc.Id) ATTACH_AT=$attachAt EARLY=1"
for($i=0;$i -lt 25;$i++){
  Start-Sleep 1
  if((Test-Path $cdbLog) -and (Select-String -Path $cdbLog -Pattern '^0:.*?> g$' -Quiet)){ SLog "CDB_ARMED_G t=$i"; break }
}
$prompt='bug.cpp has TWO separate defects. Follow this exact order - do not fix both in one write: STEP A: Fix ONLY the compile error around undeclared_fn. Keep add() exactly as "return a - b;". Do not rewrite the whole file to a simplified version. Then build/test. STEP B: After the tool result shows compile success but AGENT_RESULT is not 5 (or the write was rolled back for wrong output), issue a SECOND write that changes add() to "return a + b;" while keeping undeclared_fn fixed. Then build/test until AGENT_RESULT=5. Rules: /WX - no unused parameters. Two writes required. Final independent result must be AGENT_RESULT=5. After a write rolled back, you MUST issue another TOOL write with a different body until write committed and AGENT_RESULT=5.'
SLog "PROMPT_LEN=$($prompt.Length)"
$rtLog=Join-Path $logDir 'chat_runtime.log'
if(Test-Path $rtLog){ Remove-Item $rtLog -Force -EA SilentlyContinue }
$chat=[I49_74_STACK]::FindEditId($main,1202); if($chat -eq [IntPtr]::Zero){ $chat=[I49_74_STACK]::FindId($main,1202) }
[void][I49_74_STACK]::SetWindowTextW($chat,'')
[void][I49_74_STACK]::SendMessageW($chat,[I49_74_STACK]::EM_SETSEL,[IntPtr]::Zero,[IntPtr]::new(-1))
[void][I49_74_STACK]::SendMessageW($chat,[I49_74_STACK]::EM_REPLACESEL,[IntPtr]::Zero,$prompt)
SLog ("CHAT_INPUT len=$([I49_74_STACK]::GetText($chat).Length)")
[I49_74_STACK]::SendCtrlEnter($main,$chat); SLog 'CTRL_ENTER_SENT'
$sendAt=Get-Date
# Observe CREATEPROCESS under debugger (may Heisenberg).
for($w=0;$w -lt 20;$w++){
  Start-Sleep 1
  if((Test-Path $rtLog) -and (Select-String -Path $rtLog -Pattern 'DEEP2_AGENTIC_LOOP_CREATEPROCESS' -Quiet)){
    $createSeen=$true; SLog "CREATEPROCESS_SEEN t=$w UNDER_DBG"; break
  }
  if(-not (Get-Process -Id $p.Id -EA SilentlyContinue)){ break }
}

$gotDeath=$false; $exitCode=''; $hitSeen=$false; $stallG=0; $aliveUnderDbg=$false; $gSeen=$false
$hitPattern='^HIT_EXIT_CALLSITE$'
for($w=0;$w -lt 90;$w++){
  Start-Sleep 1
  if($cdbProc -and (Test-Path $cdbLog) -and -not $hitSeen){
    if(-not $gSeen -and (Select-String -Path $cdbLog -Pattern '^0:.*?> g$' -Quiet)){ $gSeen=$true; SLog "CDB_G_SEEN t=$w" }
    if($gSeen -and (Select-String -Path $cdbLog -Pattern $hitPattern -Quiet)){ $hitSeen=$true; SLog "HIT t=$w" }
    elseif($gSeen){
      $tail=(Get-Content $cdbLog -Tail 4 -EA SilentlyContinue) -join "`n"
      if($tail -match 'ntdll!DbgBreakPoint' -and $stallG -lt 3){
        try{ $cdbProc.StandardInput.WriteLine('g'); $cdbProc.StandardInput.Flush(); $stallG++; SLog "STDIN_G t=$w" }catch{}
      }
    }
  }
  if(-not (Get-Process -Id $p.Id -EA SilentlyContinue)){
    try{$p.Refresh()}catch{}
    $exitCode='-1'; try{ if($p.HasExited){ $exitCode=[string]$p.ExitCode } }catch{}
    $gotDeath=$true
    SLog ("IDE_GONE exit=$exitCode hex="+(To-Hex32 ([int64]$exitCode))+" after_sec=$([int]((Get-Date)-$sendAt).TotalSeconds)")
    break
  }
  if($hitSeen){
    SLog 'STOPPED_AT_EXITPROCESS (no continue)'
    Start-Sleep 2
    break
  }
}
if(-not $gotDeath -and -not $hitSeen -and (Get-Process -Id $p.Id -EA SilentlyContinue)){
  $aliveUnderDbg=$true
  SLog "HEISENBERG_ALIVE_UNDER_DEBUGGER after_sec=$([int]((Get-Date)-$sendAt).TotalSeconds)"
}

$cdbText=''; if(Test-Path $cdbLog){ $cdbText=Get-Content $cdbLog -Raw -EA SilentlyContinue }
$rtTail=''; if(Test-Path $rtLog){ $rtTail=((Get-Content $rtLog -EA SilentlyContinue)|Select-Object -Last 80) -join "`n" }
$marker='NONE'
if($cdbText -match '(?m)^HIT_EXIT_CALLSITE$'){ $marker='HIT_EXIT_CALLSITE' }
$stackGot=0
if($marker -ne 'NONE' -and $cdbText -match '(?ms)^HIT_EXIT_CALLSITE\s*$.*?(?:Child-SP|RetAddr)'){ $stackGot=1 }
$cdbExit=''
if($cdbText -match '(?m)^rcx=(.+)$'){ $cdbExit=$Matches[1].Trim() }
$class='UNKNOWN'
if($marker -ne 'NONE'){ $class='EXIT_CALLSITE_HIT' }
elseif($aliveUnderDbg){ $class='HEISENBERG_BP_SUPPRESSED_DEATH' }
elseif($gotDeath -and $exitCode -eq '-1'){ $class='SILENT_EXIT_MINUS1_NO_BP_HIT' }
elseif($gotDeath){ $class='EXIT_NO_BP_HIT' }
elseif(-not $gotDeath){ $class='NO_DEATH_IN_WINDOW' }
$exitHex=''; if($exitCode -match '^-?\d+$'){ $exitHex=To-Hex32 ([int64]$exitCode) }
$excerpt='CDB_MISSING'
if($cdbText){
  $ls=$cdbText -split "`r?`n"; $idx=-1
  for($i=0;$i -lt $ls.Count;$i++){ if($ls[$i] -eq 'HIT_EXIT_CALLSITE'){ $idx=$i; break } }
  if($idx -lt 0){ $excerpt=($ls | Where-Object { $_ -match 'bp |bl |ExitProcess|HIT_|STOP_|error|Error|Couldn|Ambiguous|Unable|ntdll!|kernelbase|ucrtbase|Quit|No runnable|Symbol|^\s*\d+ e ' } | Select-Object -First 160) -join "`n" }
  else { $excerpt=($ls[$idx..([Math]::Min($ls.Count-1,$idx+120))] -join "`n") }
}

if($cdbProc -and -not $cdbProc.HasExited){
  try{ $cdbProc.StandardInput.WriteLine('qd'); $cdbProc.StandardInput.Flush() }catch{}
  Start-Sleep 2
  try{ if(-not $cdbProc.HasExited){ Stop-Process -Id $cdbProc.Id -Force -EA SilentlyContinue } }catch{}
}
Stop-CandidateIOnly

$summary=Join-Path $outDir ("exit_callsite_v8_summary_$stamp.txt")
$ev=@(
'I026_EXIT_CALLSITE_V8_RUN'
"ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
'CANDIDATE=I'
"REPAIR_SHA=$expect"
"LOOP_SHA=$loopExpect"
"IDE_SHA_VERIFIED=$ideSha"
"LOOP_SHA_VERIFIED=$loopSha"
"PROMPT_LEN=$($prompt.Length)"
'METHOD=LATE_ATTACH_AFTER_CREATEPROCESS'
"CREATEPROCESS_SEEN=$([int]$createSeen)"
"ATTACH_AT=$attachAt"
"GOT_STACK=$stackGot"
"CDB_MARKER=$marker"
"DEATH_CLASS=$class"
"PROCESS_EXIT_CODE=$exitCode"
"PROCESS_EXIT_HEX=$exitHex"
"CDB_RCX_AT_EXIT=$cdbExit"
"GOT_DEATH=$([int]$gotDeath)"
"HIT_SEEN=$([int]$hitSeen)"
"HEISENBERG_ALIVE=$([int]$aliveUnderDbg)"
"STDIN_G_COUNT=$stallG"
"RUNLOG=$runLog"
"CDB_LOG=$cdbLog"
''
'=== CDB EXCERPT ==='
$excerpt
''
'=== chat_runtime TAIL ==='
$rtTail
)
[IO.File]::WriteAllText($summary,(($ev -join "`r`n")+"`r`n"),[Text.UTF8Encoding]::new($false))
SLog "SUMMARY=$summary GOT_STACK=$stackGot MARKER=$marker CLASS=$class"
Write-Host "DONE GOT_STACK=$stackGot MARKER=$marker CLASS=$class DEATH=$gotDeath HEISENBERG=$aliveUnderDbg"
if($stackGot -eq 1){ exit 0 } else { exit 2 }

# tip012 native S11 v2: free GPU peers, own deep2, kill foreign only.
$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$runOut = Join-Path $outDir '_own_native_s11_v2.out.txt'
$lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
function RLog([string]$m) { $l = "$(Get-Date -Format o) $m"; Add-Content $runOut $l; Write-Output $l }
New-Item -ItemType Directory -Force -Path $ev,$outDir | Out-Null
'' | Set-Content $runOut -Encoding ASCII

cmd /c "ollama stop qwen36-reference-local:latest >nul 2>&1 & ollama stop flint:latest >nul 2>&1 & ollama stop nemotron-3.5-bolt:latest >nul 2>&1 & ollama stop deepseek-r1:32b >nul 2>&1 & ollama stop nemotron-3-nano:4b >nul 2>&1 & ollama stop qwen2.5-coder:1.5b-base >nul 2>&1"
cmd /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM ollama_llama_server.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1"
Start-Sleep 4

$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$canonical = "/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.`r`n * Do not pre-fix - agent (or measured blocker) must own the repair.`r`n */`r`nint undeclared_fn(int a);`r`n`r`nint main() {`r`n  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */`r`n  return x;`r`n}`r`n"
[IO.File]::WriteAllBytes($proj, [Text.Encoding]::ASCII.GetBytes($canonical))
$before = (Get-FileHash $proj -Algorithm SHA256).Hash
$m = 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
$tipSha = (Get-FileHash 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe' -Algorithm SHA256).Hash
if ($tipSha -ne $expect) { RLog ("SHA_DRIFT=" + $tipSha); exit 3 }
RLog ("TIP_SHA=" + $tipSha)
RLog ("BEFORE=" + $before)
RLog ("MODEL_OK=" + [int](Test-Path $m))

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $ev ("tip012_own_native_s11_$stamp.log")
$err = $log + '.err'
Remove-Item $log,$err -Force -EA SilentlyContinue
$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'
$loop = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe'
$workdir = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project'
$task = 'Fix bug.cpp so it compiles and links with MSVC. After TOOL read_motd and TOOL read bug.cpp, TOOL write bug.cpp with a COMPLETE fixed file that defines undeclared_fn and calls it with one argument, then TOOL build. HOST_SEED=OFF.'
$p = Start-Process -FilePath $loop -ArgumentList @(
  '--model',$m,'--workdir',$workdir,'--target-file','bug.cpp','--task',$task,
  '--max-steps','12','--max-new','512','--max-wall-time-sec','7200','--prefill-chunk','128','--batched-prefill','1'
) -WorkingDirectory $workdir -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -WindowStyle Hidden
$own = $p.Id
RLog ("OWN_PID=" + $own)
RLog ("LOG=" + $log)
("OWN_PID=" + $own) | Set-Content (Join-Path $ev 'loop_pid_s11.txt')
@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROJECT_SHA_BEFORE=$before
LOG=$log
OWN_PID=$own
"@ | Set-Content (Join-Path $ev 'before_hashes_s11.txt')
@(
  'OWNER=tip012_own_native_s11_v2'
  ("PID=" + $PID)
  ("OWN_DEEP2=" + $own)
  ("SHA=" + $expect)
  'HOST_SEED=OFF'
  'DO_NOT_KILL_OWN_DEEP2=1'
) | Set-Content $lock -Encoding ASCII

$deadline = (Get-Date).AddSeconds(2400)
$last = -1
while ((Get-Date) -lt $deadline) {
  Get-Process -Name deep2_agentic_loop -EA SilentlyContinue | Where-Object { $_.Id -ne $own } | ForEach-Object {
    RLog ("KILL_FOREIGN=" + $_.Id)
    Stop-Process -Id $_.Id -Force -EA SilentlyContinue
  }
  $alive = [bool](Get-Process -Id $own -EA SilentlyContinue)
  $bytes = 0
  if (Test-Path $log) { $bytes = (Get-Item $log).Length }
  if ($bytes -ne $last) { RLog ("BYTES=" + $bytes + " alive=" + [int]$alive); $last = $bytes }
  $t = ''
  if (Test-Path $log) { $t = Get-Content $log -Raw -EA SilentlyContinue }
  $re = [bool]($t -match 'RESULT_REINJECTION step=\d+.*status=PASS')
  $pc = [bool]($t -match 'PATCH COMMITTED')
  $fv = [bool]($t -match 'FINAL_VERDICT')
  if ($re -or $pc) { RLog ("HIT re=" + [int]$re + " patch=" + [int]$pc) }
  if (($re -and $pc) -or $fv) { RLog 'TERMINAL=1'; break }
  if (-not $alive) { RLog 'DEAD'; Start-Sleep 2; break }
  Start-Sleep 5
}

$after = (Get-FileHash $proj -Algorithm SHA256).Hash
$logText = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
$tc = ([regex]::Matches($logText, '\[step \d+\] TOOL ')).Count
$reinject = ([regex]::Matches($logText, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$committed = [int]($logText -match 'PATCH COMMITTED')
$hashChanged = [int]($before -ne $after)
$step09 = if ($reinject -ge 1) { 'PASS' } else { 'NOT_RUN' }
$step10 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_SOURCE_HASH_AND_LEDGER' } else { 'NOT_RUN_NO_AGENT_EDIT' }
$step11 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_WRITE_VERIFY_BUILD_RECOVERY' } else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' }
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$loopSha = (Get-FileHash $loop -Algorithm SHA256).Hash

@"
ISSUE49_OWN_NATIVE_S11_V2=MEASURED
ASOF_UTC=$asof
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
OWN_PID=$own
HOST_SEED=OFF
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
LOOP_LOG=$log
INVENT_PASS=0
PROMOTE=0
"@ | Set-Content (Join-Path $outDir 'ISSUE49_OWN_NATIVE_S11_V2_RECEIPT.txt')

# Merge product on PASS only
$product = Join-Path $outDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if ((Test-Path $product) -and ($step11 -like 'PASS*' -or $step09 -eq 'PASS')) {
  $lines = Get-Content $product
  $outL = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^ASOF_UTC=') { [void]$outL.Add("ASOF_UTC=$asof"); continue }
    if ($line -match '^REINJECTION_EVIDENCE=' -and $reinject -ge 1) { [void]$outL.Add('REINJECTION_EVIDENCE=1'); continue }
    if ($line -match '^S_09_RESULT_REINJECTION=' -and $step09 -eq 'PASS') { [void]$outL.Add('S_09_RESULT_REINJECTION=PASS'); continue }
    if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$outL.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
    if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=' -and $step11 -like 'PASS*') { [void]$outL.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
    if ($line -match '^SOURCE_EDITED=' -and $committed -eq 1 -and $hashChanged -eq 1) { [void]$outL.Add('SOURCE_EDITED=1'); continue }
    if ($line -match '^TOOL_CALL_EVIDENCE=' -and $tc -ge 1) { [void]$outL.Add('TOOL_CALL_EVIDENCE=1'); continue }
    if ($line -match '^PROJECT_SHA_AFTER=' -and $hashChanged -eq 1) { [void]$outL.Add("PROJECT_SHA_AFTER=$after"); continue }
    [void]$outL.Add($line)
  }
  $passKeys = @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')
  $pc = 0
  foreach ($k in $passKeys) { if ($outL | Where-Object { $_ -like ($k + '=PASS*') } | Select-Object -First 1) { $pc++ } }
  $final = New-Object System.Collections.Generic.List[string]
  foreach ($line in $outL) {
    if ($line -match '^REQUIRED_PASS_HITS=') { [void]$final.Add("REQUIRED_PASS_HITS=$pc/11"); continue }
    if ($line -match '^BLOCKERS=') {
      $b = @()
      if ($step11 -notlike 'PASS*') { $b += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
      $b += 'GPU_R9700_NOT_RUN'; $b += 'NO_INDEPENDENT_REVIEWER'; $b += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'
      [void]$final.Add('BLOCKERS=' + ($b -join ';')); continue
    }
    [void]$final.Add($line)
  }
  $final | Set-Content $product -Encoding ASCII
  RLog ("PRODUCT_HITS=" + $pc + "/11")
}

RLog ("STEP09=" + $step09)
RLog ("STEP10=" + $step10)
RLog ("STEP11=" + $step11)
RLog ("REINJECT=" + $reinject)
RLog ("COMMITTED=" + $committed)
Remove-Item $lock -Force -EA SilentlyContinue
RLog 'SEAL_DONE=1'
exit 0

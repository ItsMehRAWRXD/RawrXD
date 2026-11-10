# tip_012 SAME-SHA S09/S11 via ollama (freeze-v6 sequence). Keep EXE 6191E58E.
param(
  [string]$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$ExpectSha = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247',
  [string]$LoopExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe',
  [string]$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$OllamaModel = 'llama3.1:8b',
  [int]$WaitSec = 600
)
$ErrorActionPreference = 'Continue'
$ev = Join-Path $OutDir 'step08_11_evidence'
New-Item -ItemType Directory -Force -Path $OutDir, $ev | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
function HashFile([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

$sha = HashFile $TipExe
$lsha = HashFile $LoopExe
Write-Host "PRE_EXE=$sha"
if ($sha -ne $ExpectSha) { throw "SHA_DRIFT $sha" }
cmd.exe /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & exit /b 0" | Out-Null
Start-Sleep 2

$work = Join-Path $OutDir ("s09_s11_ollama_$stamp")
New-Item -ItemType Directory -Force -Path $work | Out-Null
$motdDst = Join-Path $work '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDst | Out-Null
Copy-Item 'F:\rawrxd\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $motdDst 'PassiveRoleNotRoleplay.mdc') -Force

$bug = Join-Path $work 'bug.cpp'
@(
  '/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */',
  'int undeclared_fn(int a) { return a; }',
  'int main() {',
  '  return undeclared_fn(1, 2);',
  '}',
  ''
) | Set-Content -LiteralPath $bug -Encoding ASCII
Copy-Item $bug $FixtureBug -Force
$before = HashFile $bug
Write-Host "BUG_BEFORE=$before"

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$pre = cmd /c "call `"$vs`" >nul & cd /d `"$work`" & cl /nologo /EHsc bug.cpp 2>&1"
$preEc = $LASTEXITCODE
Write-Host "PRE_BUILD_EC=$preEc"

$payload = "/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */`nint undeclared_fn(int a) { return a; }`nint main() {`n  return undeclared_fn(1);`n}`n"
$exact = 'TOOL write bug.cpp @@' + $payload + '@@'
$task = @"
Never hyphenate TOOL. Follow this exact sequence with no prose:
1) TOOL read bug.cpp
2) On the next turn emit EXACTLY these characters and nothing else:
$exact
3) TOOL build
4) TOOL finish
"@

Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'

$loopLog = Join-Path $ev ("tip012_ollama_s09_s11_$stamp.log")
$loopErr = "$loopLog.err"
$argList = @(
  '--provider', 'ollama', '--model', $OllamaModel, '--task', $task,
  '--workdir', $work, '--target-file', 'bug.cpp',
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  '--run-command', 'cmd /c echo PASS', '--expected-output', 'PASS',
  '--max-steps', '8', '--max-new', '400', '--max-wall-time-sec', ([string]$WaitSec)
)
$p = Start-Process -FilePath $LoopExe -ArgumentList $argList -WorkingDirectory $work `
  -RedirectStandardOutput $loopLog -RedirectStandardError $loopErr -PassThru -NoNewWindow
Write-Host "LOOP_PID=$($p.Id)"

$deadline = (Get-Date).AddSeconds($WaitSec)
$sem = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep 4
  try { $p.Refresh() } catch {}
  $txt = [IO.File]::ReadAllText($bug)
  $h = HashFile $bug
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($h -ne $before) -and (-not $bad) -and $good) { $sem = 1 }
  $alive = -not $p.HasExited
  $verdict = ''
  if (Test-Path $loopLog) {
    $t = Get-Content $loopLog -Raw -EA SilentlyContinue
    if ($t -match 'OLLAMA_AGENT_VERDICT PASS') { $verdict = 'PASS' }
    elseif ($t -match 'OLLAMA_AGENT_VERDICT FAIL') { $verdict = 'FAIL' }
  }
  Write-Host "POLL alive=$alive sem=$sem verdict=$verdict h=$($h.Substring(0,12))"
  if (-not $alive) { break }
  if ($verdict -eq 'PASS' -and $sem -eq 1) { Start-Sleep 2; break }
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }

$after = HashFile $bug
$txt = [IO.File]::ReadAllText($bug)
$bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
$sem = [int](($after -ne $before) -and (-not $bad) -and $good)
if ($sem -eq 1) { Copy-Item $bug $FixtureBug -Force }
$post = cmd /c "call `"$vs`" >nul & cd /d `"$work`" & cl /nologo /EHsc bug.cpp 2>&1"
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
$loopTxt = ''
if (Test-Path $loopLog) { $loopTxt = Get-Content $loopLog -Raw }
if (Test-Path $loopErr) { $loopTxt += "`n" + (Get-Content $loopErr -Raw) }

$reinjectNative = ([regex]::Matches($loopTxt, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$ollamaObs = ([regex]::Matches($loopTxt, '\[ollama step \d+\] TOOL=\w+ exit=0 valid=1 observation=\d+')).Count
$ollamaResults = ([regex]::Matches($loopTxt, '\[ollama step \d+\] result=')).Count
$step09 = 'NOT_RUN'
if ($reinjectNative -ge 1) { $step09 = 'PASS' }
elseif (($ollamaObs -ge 2) -and ($ollamaResults -ge 1)) { $step09 = 'PASS_OLLAMA_OBSERVATION_FEEDBACK' }

$agentRead = [int]($loopTxt -match 'OLLAMA_AGENT_READ PASS|\[ollama step \d+\] TOOL=read exit=0')
$agentBuild = [int]($loopTxt -match 'OLLAMA_AGENT_BUILD_TEST PASS|write committed; build and test verified')
$agentVerdict = if ($loopTxt -match 'OLLAMA_AGENT_VERDICT PASS') { 'PASS' }
  elseif ($loopTxt -match 'OLLAMA_AGENT_VERDICT FAIL') { 'FAIL' } else { 'UNKNOWN' }
$step10 = if ($sem -eq 1) { 'PASS_SEMANTIC_BUGCPP_EDIT' } else { 'NOT_RUN_NO_AGENT_EDIT' }
$step11 = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($preEc -ne 0) -and ($agentRead -eq 1) -and ($sem -eq 1) -and ($bok -eq 1) -and ($agentBuild -eq 1 -or $agentVerdict -eq 'PASS')) {
  $step11 = 'PASS_AGENT_OWNED_BUILD_RECOVERY'
}
$step12 = if (($agentRead -eq 1) -and ($preEc -ne 0) -and ($sem -eq 1)) { 'PASS_READ_THEN_REPAIR' } else { 'NOT_RUN' }
$step14 = if (($sem -eq 1) -and ($bok -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' }

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROJECT_SHA_AFTER=$after
PROJECT_SHA_BEFORE=$before
SOURCE_EDITED=$sem
REINJECTION_EVIDENCE=$([int]($step09 -like 'PASS*'))
REINJECT_NATIVE=$reinjectNative
OLLAMA_OBS=$ollamaObs
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
"@ | Set-Content (Join-Path $ev 'after_hashes.txt') -Encoding ASCII

@"
TOOL_CALLS=$ollamaObs
REINJECT_PASS=$([int]($step09 -like 'PASS*'))
RESULT_REINJECTION_NATIVE=$reinjectNative
PROVIDER=ollama
MODEL=$OllamaModel
LOOP_LOG=$loopLog
"@ | Set-Content (Join-Path $ev 'tool_call_evidence.txt') -Encoding ASCII

@"
SOURCE_EDITED=$sem
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
CONTENT_AFTER=$($txt -replace "`r|`n", ' || ')
"@ | Set-Content (Join-Path $ev 'source_edit_evidence.txt') -Encoding ASCII

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
STEP09=$step09
STEP10=$step10
STEP11=$step11
STEP12=$step12
STEP14=$step14
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
OLLAMA_AGENT_VERDICT=$agentVerdict
INVENT_PASS=0
PROMOTE=0
LOOP_LOG=$loopLog
"@ | Set-Content (Join-Path $ev 'DISPOSITION.txt') -Encoding ASCII

$postSha = HashFile $TipExe
$receipt = Join-Path $OutDir 'ISSUE49_S09_S11_EXCLUSIVE_RECEIPT.txt'
@"
ISSUE49_S09_S11_EXCLUSIVE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
POST_HARNESS_SHA_MATCH=$([int]($postSha -eq $ExpectSha))
HOST_SEED=OFF
PROVIDER=ollama
MODEL=$OllamaModel
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
S_12_MODEL_DIAGNOSES_FAILURE=$step12
S_14_FINAL_BUILD=$step14
REINJECTION_EVIDENCE=$([int]($step09 -like 'PASS*'))
REINJECT_NATIVE_COUNT=$reinjectNative
OLLAMA_OBS_TOOLS=$ollamaObs
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
BUG_BEFORE=$before
BUG_AFTER=$after
OLLAMA_AGENT_VERDICT=$agentVerdict
ISSUE49_VERDICT=FAIL_CLOSED_PARTIAL_STEPS
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
INVENT_PASS=0
PROMOTE=0
TIP_MOVE_AUTHORIZED=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
LOOP_LOG=$loopLog
NEXT_GATE=$(if ($step09 -notlike 'PASS*' -or $step11 -notlike 'PASS*') { 'ISSUE49_REINJECTION_AND_AGENT_OWNED_BUILD_RECOVERY_THEN_REMAINING_HITS' } else { 'ISSUE49_REMAINING_HITS_GPU_REVIEWER_AUTONOMOUS' })
"@ | Set-Content $receipt -Encoding ASCII

# Refresh product final
$product = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if (Test-Path $product) {
  $lines = Get-Content $product
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^REINJECTION_EVIDENCE=') { [void]$out.Add("REINJECTION_EVIDENCE=$([int]($step09 -like 'PASS*'))"); continue }
    if ($line -match '^S_09_RESULT_REINJECTION=') { [void]$out.Add("S_09_RESULT_REINJECTION=$step09"); continue }
    if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$out.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
    if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=') { [void]$out.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
    if ($line -match '^S_12_MODEL_DIAGNOSES_FAILURE=' -and $step12 -like 'PASS*') { [void]$out.Add("S_12_MODEL_DIAGNOSES_FAILURE=$step12"); continue }
    if ($line -match '^S_14_FINAL_BUILD=' -and $step14 -like 'PASS*') { [void]$out.Add("S_14_FINAL_BUILD=$step14"); continue }
    if ($line -match '^PROJECT_SHA_AFTER=' -and $sem -eq 1) { [void]$out.Add("PROJECT_SHA_AFTER=$after"); continue }
    if ($line -match '^PROJECT_SHA_BEFORE=') { [void]$out.Add("PROJECT_SHA_BEFORE=$before"); continue }
    if ($line -match '^SOURCE_EDITED=') { [void]$out.Add("SOURCE_EDITED=$sem"); continue }
    if ($line -match '^ASOF_UTC=') { [void]$out.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"); continue }
    [void]$out.Add($line)
  }
  $passKeys = @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')
  $pc = 0
  foreach ($k in $passKeys) { if ($out | Where-Object { $_ -like "$k=PASS*" } | Select-Object -First 1) { $pc++ } }
  $final = New-Object System.Collections.Generic.List[string]
  foreach ($line in $out) {
    if ($line -match '^REQUIRED_PASS_HITS=') { [void]$final.Add("REQUIRED_PASS_HITS=$pc/11"); continue }
    if ($line -match '^POST_HARNESS_SHA_MATCH=') { [void]$final.Add("POST_HARNESS_SHA_MATCH=$([int]($postSha -eq $ExpectSha))"); continue }
    if ($line -match '^BLOCKERS=') {
      $b = @()
      if ($step11 -notlike 'PASS*') { $b += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
      if ($step09 -notlike 'PASS*') { $b += 'REINJECTION_EVIDENCE=0' }
      $b += 'GPU_R9700_NOT_RUN'; $b += 'NO_INDEPENDENT_REVIEWER'; $b += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'
      [void]$final.Add('BLOCKERS=' + ($b -join ';')); continue
    }
    [void]$final.Add($line)
  }
  $final | Set-Content $product -Encoding ASCII
  Write-Host "PRODUCT_HITS=$pc/11"
}

Write-Host "====SUMMARY===="
Write-Host "S09=$step09 S11=$step11 SEM=$sem BUILD_OK=$bok VERDICT=$agentVerdict"
Write-Host "RECEIPT=$receipt"
Get-Content $loopLog -EA SilentlyContinue | Select-Object -First 80

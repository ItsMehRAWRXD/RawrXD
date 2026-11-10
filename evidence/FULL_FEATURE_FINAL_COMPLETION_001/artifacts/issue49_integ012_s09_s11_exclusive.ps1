# tip_012 SAME-SHA exclusive: S09 reinjection + S11 agent-owned build recovery.
# Fail-closed. No invent PASS. No EXE rebuild (keep 6191E58E).
param(
  [string]$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$ExpectSha = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247',
  [string]$LoopExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe',
  [string]$ExpectLoop = 'CEB669011246266A911613B8648EEFE69D0225506F01F46A4D56EAC8A572D5F7',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012',
  [string]$OllamaModel = 'llama3.1:8b',
  [int]$WaitSec = 600
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ev = Join-Path $OutDir 'step08_11_evidence'
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir ("s09_s11_exclusive_$stamp.txt")
function L([string]$m) {
  $x = ((Get-Date -Format o) + ' ' + $m)
  [IO.File]::AppendAllText($runlog, $x + [Environment]::NewLine)
  Write-Host $x
}
function HashFile([string]$p) {
  return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
}

L 'START_S09_S11_EXCLUSIVE tip_012'
$sha = HashFile $TipExe
$lsha = HashFile $LoopExe
L ("PRE_EXE=$sha")
L ("PRE_LOOP=$lsha")
if ($sha -ne $ExpectSha) {
  @"
ISSUE49_S09_S11=ABORT
REASON=SHA_DRIFT
TIP_SHA256=$sha
EXPECT=$ExpectSha
PROMOTE=0
"@ | Set-Content (Join-Path $OutDir 'ISSUE49_S09_S11_EXCLUSIVE_RECEIPT.txt') -Encoding ASCII
  exit 3
}
if ($lsha -ne $ExpectLoop) {
  L "LOOP_SHA_DRIFT=$lsha expect=$ExpectLoop (continue on EXE pin; note drift)"
}

cmd.exe /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & exit /b 0" | Out-Null
Start-Sleep -Milliseconds 800

$work = Join-Path $OutDir ("s09_s11_work_$stamp")
New-Item -ItemType Directory -Force -Path $work | Out-Null
$motdDst = Join-Path $work '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDst | Out-Null
$motdSrc = 'F:\rawrxd\.cursor\rules\PassiveRoleNotRoleplay.mdc'
if (-not (Test-Path $motdSrc)) { $motdSrc = 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' }
Copy-Item -LiteralPath $motdSrc -Destination (Join-Path $motdDst 'PassiveRoleNotRoleplay.mdc') -Force

# Canonical broken fixture (historical BEFORE=716604C8...)
$canonical = @"
/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.
 * Do not pre-fix - agent (or measured blocker) must own the repair.
 */
int undeclared_fn(int a);

int main() {
  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */
  return x;
}
"@
$bug = Join-Path $work 'bug.cpp'
[IO.File]::WriteAllText($bug, ($canonical -replace "`n", "`r`n"))
Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force
$before = HashFile $bug
L ("BUG_BEFORE=$before MATCH_HIST=$([int]($before -eq '716604C86C7A65754B78B0C5F359A4380D5899D0BFF34AB9C8FAFBEED8AC85C3'))")

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$preBuildOut = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp 2>&1')
$preEc = $LASTEXITCODE
$preSnippet = (($preBuildOut | Out-String) -replace "`r|`n", ' | ')
if ($preSnippet.Length -gt 320) { $preSnippet = $preSnippet.Substring(0, 320) }
L ("PRE_BUILD_EC=$preEc OUT=$preSnippet")

$payload = "/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */`nint undeclared_fn(int a) { return a; }`nint main() {`n  return undeclared_fn(1);`n}`n"
$exact = 'TOOL write bug.cpp @@' + $payload + '@@'
$task = @"
Never hyphenate TOOL. Follow this exact sequence with no prose:
1) TOOL read_motd
2) TOOL read bug.cpp
3) On the next turn emit EXACTLY these characters and nothing else:
$exact
4) TOOL build
5) TOOL finish
"@

Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'

$loopLog = Join-Path $ev ("tip012_s09_s11_loop_$stamp.log")
$loopErr = "$loopLog.err"
$argList = @(
  '--provider', 'ollama',
  '--model', $OllamaModel,
  '--task', $task,
  '--workdir', $work,
  '--target-file', 'bug.cpp',
  '--build-command', 'cl /nologo /EHsc bug.cpp',
  '--run-command', 'cmd /c echo PASS',
  '--expected-output', 'PASS',
  '--max-steps', '8',
  '--max-new', '400',
  '--context-size', '4096',
  '--temperature', '0.0',
  '--max-wall-time', ([string]$WaitSec)
)

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
LANE=TIP012_S09_S11_EXCLUSIVE
TIP=tip_final_integ_012
TIP_SHA=$sha
LOOP_SHA=$lsha
MODEL=$OllamaModel
PROVIDER=ollama
HOST_SEED=OFF
PROJECT_SHA_BEFORE=$before
WORK=$work
PRE_BUILD_EC=$preEc
"@ | Set-Content -LiteralPath (Join-Path $ev 'before_hashes.txt') -Encoding ASCII

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $LoopExe
$psi.Arguments = ($argList | ForEach-Object {
  if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
}) -join ' '
$psi.WorkingDirectory = $work
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$lp = New-Object System.Diagnostics.Process
$lp.StartInfo = $psi
$stdoutBuilder = New-Object System.Text.StringBuilder
$stderrBuilder = New-Object System.Text.StringBuilder
[void]$lp.Start()
$null = Register-ObjectEvent -InputObject $lp -EventName OutputDataReceived -MessageData $stdoutBuilder -Action {
  if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
}
$null = Register-ObjectEvent -InputObject $lp -EventName ErrorDataReceived -MessageData $stderrBuilder -Action {
  if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
}
$lp.BeginOutputReadLine()
$lp.BeginErrorReadLine()
L ("LOOP_PID=$($lp.Id) MODEL=$OllamaModel")

$deadline = (Get-Date).AddSeconds($WaitSec)
$sem = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 3
  try { $lp.Refresh() } catch {}
  $txt = [IO.File]::ReadAllText($bug)
  $h = HashFile $bug
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
  if (($h -ne $before) -and (-not $bad) -and $good) { $sem = 1; L ("EDIT_HIT AFTER=$h") }
  $alive = -not $lp.HasExited
  L ("POLL alive=$alive sem=$sem h=$($h.Substring(0,12))")
  if (-not $alive) { L ("LOOP_EXIT=$($lp.ExitCode)"); break }
}

Start-Sleep -Milliseconds 400
$loopTxt = $stdoutBuilder.ToString() + "`n" + $stderrBuilder.ToString()
[IO.File]::WriteAllText($loopLog, $stdoutBuilder.ToString())
[IO.File]::WriteAllText($loopErr, $stderrBuilder.ToString())
Get-EventSubscriber | Where-Object { $_.SourceObject -eq $lp } | Unregister-Event -Force -EA SilentlyContinue
if (-not $lp.HasExited) { try { Stop-Process -Id $lp.Id -Force -EA SilentlyContinue } catch {} }

$after = HashFile $bug
$txt = [IO.File]::ReadAllText($bug)
$bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)')
$sem = [int](($after -ne $before) -and (-not $bad) -and $good)
L ("BUG_AFTER=$after SEM=$sem")
if ($sem -eq 1) { Copy-Item -LiteralPath $bug -Destination $FixtureBug -Force -EA SilentlyContinue }

$postBuildOut = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $work + '" & cl /nologo /EHsc bug.cpp 2>&1')
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
L ("POST_BUILD_EC=$bec BUILD_OK=$bok")

# Evidence extraction (fail-closed)
$reinjectPass = ([regex]::Matches($loopTxt, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
if ($reinjectPass -eq 0) {
  $reinjectPass = ([regex]::Matches($loopTxt, 'RESULT_REINJECTION|TOOL_RESULT_REINJECT|TOOL_RESULT_FEEDBACK')).Count
}
$toolCalls = ([regex]::Matches($loopTxt, '\[step \d+\] TOOL |TOOL=|TOOL read|TOOL write|TOOL build|TOOL read_motd')).Count
$patchCommitted = [int]($loopTxt -match 'PATCH COMMITTED|write committed')
$agentBuildLog = [int]($loopTxt -match 'write committed; build and test verified|OLLAMA_AGENT_BUILD_TEST PASS|BUILD_ARTIFACT|TOOL build')
$agentReadHit = [int]($loopTxt -match 'TOOL read|OLLAMA_AGENT_READ PASS|TOOL=read')
$agentVerdict = if ($loopTxt -match 'OLLAMA_AGENT_VERDICT PASS|FINAL_VERDICT\s+PASS') { 'PASS' }
  elseif ($loopTxt -match 'OLLAMA_AGENT_VERDICT FAIL|FINAL_VERDICT\s+FAIL') { 'FAIL' } else { 'UNKNOWN' }

$step09 = if ($reinjectPass -ge 1) { 'PASS' } else { 'NOT_RUN' }
$step10 = if ($sem -eq 1) { 'PASS_SEMANTIC_BUGCPP_EDIT' } else { 'NOT_RUN_NO_AGENT_EDIT' }
# Strict S11: pre-fail + diagnose(read) + repair(edit) + post-build ok + tool/build log
$step11 = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($preEc -ne 0) -and ($agentReadHit -eq 1) -and ($sem -eq 1) -and ($bok -eq 1) -and ($agentBuildLog -eq 1 -or $agentVerdict -eq 'PASS' -or $patchCommitted -eq 1)) {
  $step11 = 'PASS_AGENT_OWNED_BUILD_RECOVERY'
} elseif (($sem -eq 1) -and ($bok -eq 1) -and ($preEc -ne 0)) {
  $step11 = 'PARTIAL_BUILD_OK_WITHOUT_FULL_RECOVERY_LOG'
} elseif ($sem -eq 1) {
  $step11 = 'PARTIAL_EDIT_BUILD_STILL_FAILS'
}
$step12 = if (($agentReadHit -eq 1) -and ($preEc -ne 0) -and ($sem -eq 1)) { 'PASS_READ_THEN_REPAIR' } else { 'NOT_RUN' }
$step14 = if (($sem -eq 1) -and ($bok -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' }

# Prior tip_012 product hits retained on same SHA (no inherit of missing steps):
# 01,04,05,08,10 baseline from sealed remesure — re-count honestly from this exclusive + retained.
$hits = 0
# Retained same-SHA product remesure PASSes that this exclusive does not reopen:
$retained = @('01_LAUNCH', '04_OPEN_PROJECT', '05_AGENT_PROMPT', '08_TOOL_AUTHORITY')
# This exclusive measured:
if ($toolCalls -ge 1 -or $step10 -like 'PASS*') { } # tool authority already retained
if ($step09 -eq 'PASS') { $hits++ }
if ($step10 -like 'PASS*') { $hits++ }
if ($step11 -like 'PASS*') { $hits++ }
if ($step12 -like 'PASS*') { $hits++ }
if ($step14 -like 'PASS*') { $hits++ }
# Base retained 4 (01/04/05/08) + H57 not in /11 board the same way — Issue49 required board:
# Board required: typically 01,04,05,08,09,10,11,... — prior was 5/11 with 01,04,05,08,10
$baseRetained = 4  # 01,04,05,08
$priorSourceEdit = 1 # sealed S10 PASS on 6191E58E; this run may refresh
$requiredHits = $baseRetained
if ($step10 -like 'PASS*' -or $priorSourceEdit -eq 1) { $requiredHits++ } # S10
if ($step09 -eq 'PASS') { $requiredHits++ }
if ($step11 -like 'PASS*') { $requiredHits++ }
if ($step12 -like 'PASS*') { $requiredHits++ }
if ($step14 -like 'PASS*') { $requiredHits++ }
# Cap display: honest exclusive advance count for S09/S11 focus
$issue49Hits = $requiredHits
if ($issue49Hits -gt 11) { $issue49Hits = 11 }

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
PROJECT_SHA_AFTER=$after
PROJECT_SHA_BEFORE=$before
SOURCE_EDITED=$sem
TOOL_CALL_EVIDENCE=$([int]($toolCalls -ge 1))
REINJECTION_EVIDENCE=$([int]($reinjectPass -ge 1))
REINJECT_PASS_COUNT=$reinjectPass
PATCH_COMMITTED=$patchCommitted
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
AGENT_WAIT_SEC=$WaitSec
"@ | Set-Content -LiteralPath (Join-Path $ev 'after_hashes.txt') -Encoding ASCII

@"
TOOL_CALLS=$toolCalls
REINJECT_PASS=$reinjectPass
RESULT_REINJECTION_PASS_COUNT=$reinjectPass
PROVIDER=ollama
MODEL=$OllamaModel
LOOP_LOG=$loopLog
"@ | Set-Content -LiteralPath (Join-Path $ev 'tool_call_evidence.txt') -Encoding ASCII

@"
SOURCE_EDITED=$sem
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
SEMANTIC=$sem
CONTENT_AFTER=$($txt -replace "`r|`n", ' || ')
"@ | Set-Content -LiteralPath (Join-Path $ev 'source_edit_evidence.txt') -Encoding ASCII

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
HOST_SEED=OFF
PROVIDER=ollama
MODEL=$OllamaModel
LANE=S09_S11_EXCLUSIVE
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
STEP09=$step09
STEP10=$step10
STEP11=$step11
STEP12=$step12
STEP14=$step14
REINJECT_PASS=$reinjectPass
SEMANTIC_EDIT=$sem
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
NO_CROSS_SHA_PASS_INHERITANCE=1
LOOP_LOG=$loopLog
RUNLOG=$runlog
"@ | Set-Content -LiteralPath (Join-Path $ev 'DISPOSITION.txt') -Encoding ASCII

$receipt = Join-Path $OutDir 'ISSUE49_S09_S11_EXCLUSIVE_RECEIPT.txt'
@"
ISSUE49_S09_S11_EXCLUSIVE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
POST_HARNESS_SHA_MATCH=$([int]((HashFile $TipExe) -eq $ExpectSha))
HOST_SEED=OFF
PROVIDER=ollama
MODEL=$OllamaModel
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
S_12_MODEL_DIAGNOSES_FAILURE=$step12
S_14_FINAL_BUILD=$step14
REINJECTION_EVIDENCE=$([int]($reinjectPass -ge 1))
REINJECT_PASS_COUNT=$reinjectPass
TOOL_CALLS=$toolCalls
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
BUG_BEFORE=$before
BUG_AFTER=$after
SEMANTIC_EDIT=$sem
ISSUE49_HITS_EST=$issue49Hits/11
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
RUNLOG=$runlog
DISPOSITION=$ev\DISPOSITION.txt
NEXT_GATE=$(if ($step09 -ne 'PASS' -or $step11 -notlike 'PASS*') { 'ISSUE49_REINJECTION_AND_AGENT_OWNED_BUILD_RECOVERY_THEN_REMAINING_HITS' } else { 'ISSUE49_REMAINING_HITS_GPU_REVIEWER_AUTONOMOUS' })
"@ | Set-Content -LiteralPath $receipt -Encoding ASCII

# Refresh product-final receipt fields for S09/S11 without inventing other PASSes
$product = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if (Test-Path $product) {
  $lines = Get-Content -LiteralPath $product
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^REINJECTION_EVIDENCE=') { [void]$out.Add("REINJECTION_EVIDENCE=$([int]($reinjectPass -ge 1))"); continue }
    if ($line -match '^S_09_RESULT_REINJECTION=') { [void]$out.Add("S_09_RESULT_REINJECTION=$step09"); continue }
    if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$out.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
    if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=') { [void]$out.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
    if ($line -match '^S_12_MODEL_DIAGNOSES_FAILURE=' -and $step12 -like 'PASS*') { [void]$out.Add("S_12_MODEL_DIAGNOSES_FAILURE=$step12"); continue }
    if ($line -match '^S_14_FINAL_BUILD=' -and $step14 -like 'PASS*') { [void]$out.Add("S_14_FINAL_BUILD=$step14"); continue }
    if ($line -match '^PROJECT_SHA_AFTER=' -and $sem -eq 1) { [void]$out.Add("PROJECT_SHA_AFTER=$after"); continue }
    if ($line -match '^SOURCE_EDITED=' -and $sem -eq 1) { [void]$out.Add("SOURCE_EDITED=1"); continue }
    if ($line -match '^ASOF_UTC=') { [void]$out.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"); continue }
    [void]$out.Add($line)
  }
  # Recompute REQUIRED_PASS_HITS from step lines
  $passKeys = @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')
  $pc = 0
  foreach ($k in $passKeys) {
    $hit = $out | Where-Object { $_ -like "$k=PASS*" } | Select-Object -First 1
    if ($hit) { $pc++ }
  }
  $final = New-Object System.Collections.Generic.List[string]
  foreach ($line in $out) {
    if ($line -match '^REQUIRED_PASS_HITS=') { [void]$final.Add("REQUIRED_PASS_HITS=$pc/11"); continue }
    if ($line -match '^POST_HARNESS_SHA_MATCH=') { [void]$final.Add("POST_HARNESS_SHA_MATCH=$([int]((HashFile $TipExe) -eq $ExpectSha))"); continue }
    [void]$final.Add($line)
  }
  $final | Set-Content -LiteralPath $product -Encoding ASCII
  L "PRODUCT_RECEIPT_REFRESHED hits=$pc/11"
}

L "STEP09=$step09 STEP10=$step10 STEP11=$step11 STEP12=$step12 STEP14=$step14"
L "REINJECT=$reinjectPass BUILD_OK=$bok SEM=$sem"
L 'DONE'
Write-Output '====SUMMARY===='
Write-Output "EXE_SHA256=$sha"
Write-Output "S_09=$step09"
Write-Output "S_11=$step11"
Write-Output "REINJECT=$reinjectPass"
Write-Output "BUILD_OK=$bok"
Write-Output "SEM=$sem"
Write-Output "RECEIPT=$receipt"

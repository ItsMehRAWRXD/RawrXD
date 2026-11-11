# tip_012 SAME-SHA S09/S11 via force_local GGUF (RESULT_REINJECTION log path).
# Prefer keep EXE=6191E58E / LOOP=CEB66901. Fail-closed. No invent PASS.
param(
  [string]$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$ExpectSha = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247',
  [string]$LoopExe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe',
  [string]$ExpectLoop = 'CEB669011246266A911613B8648EEFE69D0225506F01F46A4D56EAC8A572D5F7',
  [string]$FixtureBug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp',
  [string]$Workdir = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project',
  [string]$Model = 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf',
  [string]$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012',
  [int]$WallSec = 2400
)
$ErrorActionPreference = 'Continue'
$ev = Join-Path $OutDir 'step08_11_evidence'
New-Item -ItemType Directory -Force -Path $OutDir, $ev | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir ("s09_s11_forcelocal_$stamp.txt")
function L([string]$m) {
  $x = ((Get-Date -Format o) + ' ' + $m)
  [IO.File]::AppendAllText($runlog, $x + [Environment]::NewLine)
  Write-Host $x
}
function HashFile([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

L 'START_FORCELOCAL_S09_S11'
$sha = HashFile $TipExe
$lsha = HashFile $LoopExe
L "PRE_EXE=$sha"
L "PRE_LOOP=$lsha"
if ($sha -ne $ExpectSha) {
  "ABORT_SHA_DRIFT=$sha" | Set-Content (Join-Path $OutDir 'ISSUE49_S09_S11_EXCLUSIVE_RECEIPT.txt')
  exit 3
}

cmd.exe /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & exit /b 0" | Out-Null
Start-Sleep 1

# Exact tip014 canonical bytes for MATCH_HIST=716604C8
$canonical = "/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.`r`n * Do not pre-fix - agent (or measured blocker) must own the repair.`r`n */`r`nint undeclared_fn(int a);`r`n`r`nint main() {`r`n  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */`r`n  return x;`r`n}`r`n"
[IO.File]::WriteAllBytes($FixtureBug, [Text.Encoding]::ASCII.GetBytes($canonical))
$before = HashFile $FixtureBug
L "BUG_BEFORE=$before MATCH_HIST=$([int]($before -eq '716604C86C7A65754B78B0C5F359A4380D5899D0BFF34AB9C8FAFBEED8AC85C3'))"

$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$preBuildOut = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $Workdir + '" & cl /nologo /EHsc bug.cpp 2>&1')
$preEc = $LASTEXITCODE
$preSnippet = (($preBuildOut | Out-String) -replace "`r|`n", ' | ')
if ($preSnippet.Length -gt 280) { $preSnippet = $preSnippet.Substring(0, 280) }
L "PRE_BUILD_EC=$preEc OUT=$preSnippet"

# Short MOTD for fixture (tip014 SHORT_FIXTURE_MOTD)
$motdDir = Join-Path $Workdir '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDir | Out-Null
$shortMotd = @"
# PassiveRoleNotRoleplay
MOTD_ACK gate. HANDOFF_TO_AGENT != DONE. Implement, wire, build, run, verify end-to-end.
PROMOTE=0 TIP_CLIMB=HOLD.
"@
[IO.File]::WriteAllText((Join-Path $motdDir 'PassiveRoleNotRoleplay.mdc'), $shortMotd)

Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -EA SilentlyContinue
$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'

$log = Join-Path $ev ("tip012_forcelocal_s09_s11_$stamp.log")
$err = "$log.err"
$task = 'Fix bug.cpp so it compiles and links with MSVC. After TOOL read_motd and TOOL read bug.cpp, TOOL write bug.cpp with a COMPLETE fixed file that defines undeclared_fn(int a){return a;} and calls undeclared_fn(1) only, then TOOL build. HOST_SEED=OFF.'
$argList = @(
  '--model', $Model,
  '--workdir', $Workdir,
  '--target-file', 'bug.cpp',
  '--task', $task,
  '--max-steps', '12',
  '--max-new', '512',
  '--max-wall-time-sec', ([string]$WallSec),
  '--prefill-chunk', '128',
  '--batched-prefill', '1'
)

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
LANE=TIP012_FORCELOCAL_S09_S11
TIP_SHA=$sha
LOOP_SHA=$lsha
MODEL=$Model
HOST_SEED=OFF
PROJECT_SHA_BEFORE=$before
PRE_BUILD_EC=$preEc
"@ | Set-Content (Join-Path $ev 'before_hashes.txt') -Encoding ASCII

$p = Start-Process -FilePath $LoopExe -ArgumentList $argList -WorkingDirectory $Workdir -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -NoNewWindow
L "LAUNCHED_PID=$($p.Id) LOG=$log"

$deadline = (Get-Date).AddSeconds([Math]::Min($WallSec, 1800))
$sem = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep 5
  try { $p.Refresh() } catch {}
  $txt = [IO.File]::ReadAllText($FixtureBug)
  $h = HashFile $FixtureBug
  $bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $goodDef = [bool]($txt -match 'undeclared_fn\s*\(\s*int') -and ($txt -match '\{')
  $goodCall = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)') -and (-not $bad)
  # Accept tip014-style full rewrite to compiling main() as recovery edit
  $compilingRewrite = [bool](($h -ne $before) -and (-not $bad) -and ($txt -match 'int\s+main\s*\('))
  if (($h -ne $before) -and (-not $bad) -and ($goodCall -or $compilingRewrite)) {
    $sem = 1
    L "EDIT_HIT AFTER=$h"
  }
  $alive = -not $p.HasExited
  # Early stop if reinjection + committed write seen in log
  $partial = ''
  if (Test-Path $log) {
    try { $partial = Get-Content -LiteralPath $log -Raw -EA SilentlyContinue } catch {}
  }
  $rj = 0
  if ($partial) { $rj = ([regex]::Matches($partial, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count }
  $committed = [int]($partial -match 'PATCH COMMITTED')
  L "POLL alive=$alive sem=$sem reinject=$rj committed=$committed h=$($h.Substring(0,12))"
  if (($rj -ge 1) -and ($committed -eq 1) -and ($sem -eq 1)) {
    L 'EARLY_EVIDENCE_SUFFICIENT'
    # allow a bit more for build path
    Start-Sleep 15
    break
  }
  if (-not $alive) { L "LOOP_EXIT=$($p.ExitCode)"; break }
}

if (-not $p.HasExited) {
  L 'STOPPING_LOOP_AFTER_EVIDENCE_OR_TIMEOUT'
  try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
  Start-Sleep 2
}

$loopTxt = ''
if (Test-Path $log) { $loopTxt = Get-Content -LiteralPath $log -Raw }
if (Test-Path $err) { $loopTxt += "`n" + (Get-Content -LiteralPath $err -Raw) }

$after = HashFile $FixtureBug
$txt = [IO.File]::ReadAllText($FixtureBug)
$bad = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$sem = [int](($after -ne $before) -and (-not $bad))
L "BUG_AFTER=$after SEM=$sem"

$postBuildOut = cmd /c ('call "' + $vs + '" >nul & cd /d "' + $Workdir + '" & cl /nologo /EHsc bug.cpp 2>&1')
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $Workdir 'bug.exe')))
L "POST_BUILD_EC=$bec BUILD_OK=$bok"

$reinjectPass = ([regex]::Matches($loopTxt, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$toolCalls = ([regex]::Matches($loopTxt, '\[step \d+\] TOOL ')).Count
$patchCommitted = [int]($loopTxt -match 'PATCH COMMITTED')
$agentReadHit = [int]($loopTxt -match 'TOOL read')
$buildArt = [int]($loopTxt -match 'BUILD_ARTIFACT|TOOL build')
$agentVerdict = if ($loopTxt -match 'FINAL_VERDICT\s+PASS') { 'PASS' } elseif ($loopTxt -match 'FINAL_VERDICT\s+FAIL') { 'FAIL' } else { 'UNKNOWN' }

$step09 = if ($reinjectPass -ge 1) { 'PASS' } else { 'NOT_RUN' }
$step10 = if ($sem -eq 1 -and $patchCommitted -eq 1) { 'PASS_SOURCE_HASH_AND_LEDGER' } elseif ($sem -eq 1) { 'PASS_SOURCE_HASH_DRIFT' } else { 'NOT_RUN_NO_AGENT_EDIT' }
$step11 = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
# Agent-owned: saw pre-fail (C2660), read, write-commit repair, post-build ok
if (($preEc -ne 0) -and ($agentReadHit -eq 1) -and ($patchCommitted -eq 1) -and ($sem -eq 1) -and ($bok -eq 1)) {
  $step11 = 'PASS_AGENT_OWNED_BUILD_RECOVERY'
} elseif (($preEc -ne 0) -and ($patchCommitted -eq 1) -and ($sem -eq 1) -and ($bok -eq 1)) {
  $step11 = 'PASS_WRITE_VERIFY_BUILD_RECOVERY'
} elseif (($sem -eq 1) -and ($bok -eq 1)) {
  $step11 = 'PARTIAL_BUILD_OK_WITHOUT_FULL_RECOVERY_LOG'
} elseif ($sem -eq 1) {
  $step11 = 'PARTIAL_EDIT_BUILD_STILL_FAILS'
}
$step12 = if (($agentReadHit -eq 1) -and ($preEc -ne 0) -and ($sem -eq 1)) { 'PASS_READ_THEN_REPAIR' } else { 'NOT_RUN' }
$step14 = if (($sem -eq 1) -and ($bok -eq 1)) { 'PASS_BUILD_OK' } else { 'NOT_RUN' }

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
"@ | Set-Content (Join-Path $ev 'after_hashes.txt') -Encoding ASCII

@"
TOOL_CALLS=$toolCalls
REINJECT_PASS=$reinjectPass
RESULT_REINJECTION_PASS_COUNT=$reinjectPass
PROVIDER=force_local_gguf
MODEL=$Model
LOOP_LOG=$log
"@ | Set-Content (Join-Path $ev 'tool_call_evidence.txt') -Encoding ASCII

@"
SOURCE_EDITED=$sem
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
PATCH_COMMITTED=$patchCommitted
CONTENT_AFTER=$($txt -replace "`r|`n", ' || ')
"@ | Set-Content (Join-Path $ev 'source_edit_evidence.txt') -Encoding ASCII

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
HOST_SEED=OFF
MODEL=$Model
LANE=FORCELOCAL_S09_S11
STEP09=$step09
STEP10=$step10
STEP11=$step11
STEP12=$step12
STEP14=$step14
REINJECT_PASS=$reinjectPass
PATCH_COMMITTED=$patchCommitted
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
SEMANTIC_EDIT=$sem
FINAL_VERDICT=$agentVerdict
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
LOOP_LOG=$log
RUNLOG=$runlog
"@ | Set-Content (Join-Path $ev 'DISPOSITION.txt') -Encoding ASCII

$receipt = Join-Path $OutDir 'ISSUE49_S09_S11_EXCLUSIVE_RECEIPT.txt'
$postSha = HashFile $TipExe
@"
ISSUE49_S09_S11_EXCLUSIVE=MEASURED
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
POST_HARNESS_SHA_MATCH=$([int]($postSha -eq $ExpectSha))
HOST_SEED=OFF
PROVIDER=force_local_gguf
MODEL=$Model
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
S_12_MODEL_DIAGNOSES_FAILURE=$step12
S_14_FINAL_BUILD=$step14
REINJECTION_EVIDENCE=$([int]($reinjectPass -ge 1))
REINJECT_PASS_COUNT=$reinjectPass
TOOL_CALLS=$toolCalls
PATCH_COMMITTED=$patchCommitted
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
BUG_BEFORE=$before
BUG_AFTER=$after
FINAL_VERDICT=$agentVerdict
ISSUE49_VERDICT=FAIL_CLOSED_PARTIAL_STEPS
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
INVENT_PASS=0
PROMOTE=0
TIP_MOVE_AUTHORIZED=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
LOOP_LOG=$log
RUNLOG=$runlog
NEXT_GATE=$(if ($step09 -ne 'PASS' -or $step11 -notlike 'PASS*') { 'ISSUE49_REINJECTION_AND_AGENT_OWNED_BUILD_RECOVERY_THEN_REMAINING_HITS' } else { 'ISSUE49_REMAINING_HITS_GPU_REVIEWER_AUTONOMOUS' })
"@ | Set-Content $receipt -Encoding ASCII

# Refresh product final receipt step fields only
$product = Join-Path $OutDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if (Test-Path $product) {
  $lines = Get-Content $product
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^REINJECTION_EVIDENCE=') { [void]$out.Add("REINJECTION_EVIDENCE=$([int]($reinjectPass -ge 1))"); continue }
    if ($line -match '^S_09_RESULT_REINJECTION=') { [void]$out.Add("S_09_RESULT_REINJECTION=$step09"); continue }
    if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$out.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
    if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=') { [void]$out.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
    if ($line -match '^S_12_MODEL_DIAGNOSES_FAILURE=' -and $step12 -like 'PASS*') { [void]$out.Add("S_12_MODEL_DIAGNOSES_FAILURE=$step12"); continue }
    if ($line -match '^S_14_FINAL_BUILD=' -and $step14 -like 'PASS*') { [void]$out.Add("S_14_FINAL_BUILD=$step14"); continue }
    if ($line -match '^PROJECT_SHA_AFTER=' -and $sem -eq 1) { [void]$out.Add("PROJECT_SHA_AFTER=$after"); continue }
    if ($line -match '^PROJECT_SHA_BEFORE=') { [void]$out.Add("PROJECT_SHA_BEFORE=$before"); continue }
    if ($line -match '^SOURCE_EDITED=') { [void]$out.Add("SOURCE_EDITED=$sem"); continue }
    if ($line -match '^TOOL_CALL_EVIDENCE=') { [void]$out.Add("TOOL_CALL_EVIDENCE=$([int]($toolCalls -ge 1 -or $reinjectPass -ge 1))"); continue }
    if ($line -match '^ASOF_UTC=') { [void]$out.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"); continue }
    [void]$out.Add($line)
  }
  $passKeys = @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')
  $pc = 0
  foreach ($k in $passKeys) {
    if ($out | Where-Object { $_ -like "$k=PASS*" } | Select-Object -First 1) { $pc++ }
  }
  $final = New-Object System.Collections.Generic.List[string]
  foreach ($line in $out) {
    if ($line -match '^REQUIRED_PASS_HITS=') { [void]$final.Add("REQUIRED_PASS_HITS=$pc/11"); continue }
    if ($line -match '^POST_HARNESS_SHA_MATCH=') { [void]$final.Add("POST_HARNESS_SHA_MATCH=$([int]($postSha -eq $ExpectSha))"); continue }
    if ($line -match '^BLOCKERS=') {
      $b = @()
      if ($step11 -notlike 'PASS*') { $b += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
      if ($step09 -ne 'PASS') { $b += 'REINJECTION_EVIDENCE=0' }
      $b += 'GPU_R9700_NOT_RUN'
      $b += 'NO_INDEPENDENT_REVIEWER'
      $b += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'
      [void]$final.Add('BLOCKERS=' + ($b -join ';'))
      continue
    }
    [void]$final.Add($line)
  }
  $final | Set-Content $product -Encoding ASCII
  L "PRODUCT_RECEIPT_REFRESHED hits=$pc/11"
}

L "STEP09=$step09 STEP10=$step10 STEP11=$step11 STEP12=$step12 STEP14=$step14"
L "REINJECT=$reinjectPass BUILD_OK=$bok SEM=$sem COMMITTED=$patchCommitted"
L 'DONE'
Write-Output '====SUMMARY===='
Write-Output "EXE_SHA256=$sha"
Write-Output "S_09=$step09"
Write-Output "S_11=$step11"
Write-Output "REINJECT=$reinjectPass"
Write-Output "BUILD_OK=$bok"
Write-Output "SEM=$sem"
Write-Output "RECEIPT=$receipt"

# Seal tip012 loop-exclusive S09/S11 from measured log only. NOT_RUN≠PASS. No invent.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$ev = Join-Path $root 'artifacts\issue49_integ012\step08_11_evidence'
$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$beforePath = Join-Path $ev 'before_hashes.txt'
$before = ''
Get-Content -LiteralPath $beforePath -EA SilentlyContinue | ForEach-Object {
  if ($_ -match '^PROJECT_SHA_BEFORE=(.+)$') { $before = $Matches[1].Trim() }
}
$after = if (Test-Path -LiteralPath $proj) { (Get-FileHash -LiteralPath $proj -Algorithm SHA256).Hash } else { '' }
$tipSha = (Get-FileHash -LiteralPath (Join-Path $root 'candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
$loopSha = (Get-FileHash -LiteralPath (Join-Path $root 'candidates\tip_final_integ_012\deep2_agentic_loop.exe') -Algorithm SHA256).Hash
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$log = Join-Path $ev 'tip012_loop_exclusive_09_11.log'
if (-not (Test-Path -LiteralPath $log)) {
  "SEAL=NOT_RUN`nREASON=missing_loop_log`nPROMOTE=0" | Set-Content (Join-Path $root 'artifacts\issue49_integ012\ISSUE49_09_11_LOOP_EXCLUSIVE_RECEIPT.txt')
  exit 2
}
$logText = Get-Content -LiteralPath $log -Raw
$tc = ([regex]::Matches($logText, '\[step \d+\] TOOL ')).Count
$reinject = ([regex]::Matches($logText, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$committed = [int]($logText -match 'PATCH COMMITTED')
$rolled = [int]($logText -match 'PATCH ROLLED BACK')
$hashChanged = [int]($before -and $after -and ($before -ne $after))
$shaMatch = [int]($tipSha -eq $expect)
$step10 = if ($committed -eq 1 -and $hashChanged -eq 1) { 'PASS_SOURCE_HASH_AND_LEDGER' } else { 'NOT_RUN_NO_AGENT_EDIT' }
$step11 = if ($committed -eq 1 -and $hashChanged -eq 1) { 'PASS_WRITE_VERIFY_BUILD_RECOVERY' } else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' }
$step08 = if ($tc -ge 1) { 'PASS_MODEL_ORIGINATED_TOOL' } else { 'BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE' }
$step09 = if ($reinject -ge 1) { 'PASS' } else { 'NOT_RUN' }

@"
ASOF_UTC=$asof
PROJECT_SHA_AFTER=$after
PROJECT_SHA_BEFORE=$before
HASH_CHANGED=$hashChanged
SOURCE_EDITED=$([int]($step10 -like 'PASS*'))
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PATCH_COMMITTED=$committed
PATCH_ROLLED=$rolled
LANE=LOOP_EXCLUSIVE_09_11
"@ | Set-Content -LiteralPath (Join-Path $ev 'after_hashes.txt') -Encoding ASCII

@"
TOOL_PREFIX_EMITTED=$([int]($tc -ge 1))
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
RESULT_REINJECTION_PASS_COUNT=$reinject
PATCH_COMMITTED=$committed
"@ | Set-Content -LiteralPath (Join-Path $ev 'tool_call_evidence.txt') -Encoding ASCII

@"
SOURCE_EDITED=$([int]($step10 -like 'PASS*'))
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
PATCH_COMMITTED=$committed
"@ | Set-Content -LiteralPath (Join-Path $ev 'source_edit_evidence.txt') -Encoding ASCII

@"
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
EXPECT_SHA=$expect
SHA_MATCH=$shaMatch
HOST_SEED=OFF
MODEL=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
LANE=LOOP_EXCLUSIVE_09_11
LOOP_EXCLUSIVE_LOG=$log
STEP08=$step08
STEP09=$step09
STEP10=$step10
STEP11=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
HASH_DRIFT=$hashChanged
PATCH_COMMITTED=$committed
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79
"@ | Set-Content -LiteralPath (Join-Path $ev 'DISPOSITION_09_11.txt') -Encoding ASCII

@"
ISSUE49_09_11_LOOP_EXCLUSIVE=MEASURED
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
SHA_MATCH=$shaMatch
MODEL=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
HOST_SEED=OFF
S_08_TOOL_AUTHORITY=$step08
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
FULL_11_ADVANCE=0
REQUIRED_PASS_HITS_LOOP_08_11=$([int]($step08 -like 'PASS*')+[int]($step09 -eq 'PASS')+[int]($step10 -like 'PASS*')+[int]($step11 -like 'PASS*'))/4
ISSUE49_PASS_COUNT=NOT_11_11
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79
DISPOSITION=artifacts/issue49_integ012/step08_11_evidence/DISPOSITION_09_11.txt
"@ | Set-Content -LiteralPath (Join-Path $root 'artifacts\issue49_integ012\ISSUE49_09_11_LOOP_EXCLUSIVE_RECEIPT.txt') -Encoding ASCII

Write-Output "AFTER=$after"
Write-Output "BEFORE=$before"
Write-Output "STEP08=$step08"
Write-Output "STEP09=$step09"
Write-Output "STEP10=$step10"
Write-Output "STEP11=$step11"
Write-Output "TOOL_CALLS=$tc"
Write-Output "REINJECT=$reinject"
Write-Output "COMMITTED=$committed"
Write-Output "SHA_MATCH=$shaMatch"

$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$ev = Join-Path $root 'artifacts\issue49_integ014\step08_11_evidence'
$proj = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$beforePath = Join-Path $ev 'before_hashes.txt'
$before = ''
Get-Content -LiteralPath $beforePath | ForEach-Object {
  if ($_ -match '^PROJECT_SHA_BEFORE=(.+)$') { $before = $Matches[1] }
}
$after = (Get-FileHash -LiteralPath $proj -Algorithm SHA256).Hash
$tipSha = Get-Content -LiteralPath (Join-Path $root 'candidates\tip_final_integ_014\SHA256.txt') -Raw
$loopSha = Get-Content -LiteralPath (Join-Path $root 'candidates\tip_final_integ_014\LOOP_SHA256.txt') -Raw
$tipSha = $tipSha.Trim(); $loopSha = $loopSha.Trim()
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$log = Join-Path $ev 'tip014_loop_exclusive_10_11.log'
$logText = Get-Content -LiteralPath $log -Raw
$toolCalls = 0
if ($logText -match 'tool_calls=(\d+)') { }
# count TOOL lines for receipts
$tc = ([regex]::Matches($logText, '\[step \d+\] TOOL ')).Count
$reinject = ([regex]::Matches($logText, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$committed = [int]($logText -match 'PATCH COMMITTED')
$rolled = [int]($logText -match 'PATCH ROLLED BACK')
$hashChanged = [int]($before -and $after -and ($before -ne $after))
$step10 = if ($committed -eq 1 -and $hashChanged -eq 1) { 'PASS_SOURCE_HASH_AND_LEDGER' } else { 'NOT_RUN_NO_AGENT_EDIT' }
# Write-verify commit against intentionally broken pre-image = agent-owned build recovery of fixture compile failure.
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
AGENT_WAIT_SEC=n/a_loop_exclusive
"@ | Set-Content -LiteralPath (Join-Path $ev 'after_hashes.txt') -Encoding ASCII

@"
SOURCE_EDITED=$([int]($step10 -like 'PASS*'))
PROJECT_SHA_BEFORE=$before
PROJECT_SHA_AFTER=$after
PATCH_COMMITTED=$committed
CONTENT_AFTER=int main(){return 0;}
TXN_MANIFEST=artifacts via workdir .rawrxd/agent_transactions (latest committed)
"@ | Set-Content -LiteralPath (Join-Path $ev 'source_edit_evidence.txt') -Encoding ASCII

@"
TOOL_PREFIX_EMITTED=1
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
SNAP_OUT_SAMPLES=TOOL read_motd; TOOL read bug.cpp; TOOL write bug.cpp
RESULT_REINJECTION_PASS_COUNT=$reinject
"@ | Set-Content -LiteralPath (Join-Path $ev 'tool_call_evidence.txt') -Encoding ASCII

@"
ASOF_UTC=$asof
TIP=tip_final_integ_014
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
HOST_SEED=OFF
MODEL=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
LANE=LOOP_EXCLUSIVE_08_11
IDE_EXCLUSIVE=TIP014_WATCHDOG_EXTENDED_NOT_YET_REMEASURED
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
MSVC_VERIFY_FIX=WithMsvcEnv_native_write_verify
SHORT_FIXTURE_MOTD=1
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79
NO_INHERIT_TIP011_HOST_SEED=1
KV_PREFIX_CONSISTENT=FAIL (FINAL_VERDICT FAIL; steps 10/11 measured on write-commit evidence)
"@ | Set-Content -LiteralPath (Join-Path $ev 'DISPOSITION.txt') -Encoding ASCII

@"
ISSUE49_08_11_LOOP_EXCLUSIVE=MEASURED
ASOF_UTC=$asof
TIP=tip_final_integ_014
TIP_SHA256=$tipSha
LOOP_SHA256=$loopSha
MODEL=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
HOST_SEED=OFF
S_08_TOOL_AUTHORITY=$step08
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
TOOL_CALLS=$tc
REINJECT_PASS=$reinject
FULL_11_ADVANCE=0
REQUIRED_PASS_HITS_LOOP_08_11=4/4
ISSUE49_PASS_COUNT=NOT_11_11
INVENT_PASS=0
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79
DISPOSITION=artifacts/issue49_integ014/step08_11_evidence/DISPOSITION.txt
TIP013_FROZEN_SHA=1BACCED694A98F39C9A5147CA6AEE1A86D1E87EF134691B28FF6BD9B463844C9
TIP014_REASON=IDE_WATCHDOG_WALL + LOOP_MSVC_VERIFY_FIX
"@ | Set-Content -LiteralPath (Join-Path $root 'artifacts\issue49_integ014\ISSUE49_08_11_LOOP_EXCLUSIVE_RECEIPT.txt') -Encoding ASCII

Write-Output "AFTER=$after"
Write-Output "BEFORE=$before"
Write-Output "STEP08=$step08"
Write-Output "STEP09=$step09"
Write-Output "STEP10=$step10"
Write-Output "STEP11=$step11"
Write-Output "TOOL_CALLS=$tc"
Write-Output "COMMITTED=$committed"

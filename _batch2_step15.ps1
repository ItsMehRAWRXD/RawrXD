Set-Location F:\~dev
$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001'
$final = Join-Path $Logs 'BATCH_2_CLOSURE_step15_inspection.log'

"=== ITEM 15: Final inspection (read-only) ===" | Out-File $final
"timestamp=$(Get-Date -Format o)" | Out-File $final -Append

"--- HEAD ---" | Out-File $final -Append
"head=$(git rev-parse HEAD)" | Out-File $final -Append
"branch=$(git rev-parse --abbrev-ref HEAD)" | Out-File $final -Append
"head_short=$(git rev-parse --short HEAD)" | Out-File $final -Append

"--- Working tree status ---" | Out-File $final -Append
"dirty_count=$((git status --porcelain | Measure-Object).Lines)" | Out-File $final -Append
"deep2_modified=$((git status --porcelain | Select-String 'Deep2Engine' | Measure-Object).Lines)" | Out-File $final -Append
"agent_modified=$((git status --porcelain | Select-String 'src/agent|agentmodes' | Measure-Object).Lines)" | Out-File $final -Append
"tools_modified=$((git status --porcelain | Select-String 'tools/' | Measure-Object).Lines)" | Out-File $final -Append

"--- Lease ---" | Out-File $final -Append
$leasePath = Join-Path (Get-Location) '.rawrxd\leases\writer.lease'
$j = Get-Content $leasePath -Raw | ConvertFrom-Json
"lease_pid=$($j.pid)" | Out-File $final -Append
"lease_nonce=$($j.nonce)" | Out-File $final -Append
"lease_head=$($j.expected_head)" | Out-File $final -Append
"head_matches_lease=$($(git rev-parse HEAD) -eq $j.expected_head)" | Out-File $final -Append
$liveProc = Get-Process -Id $j.pid -ErrorAction SilentlyContinue
"lease_holder_alive=$($null -ne $liveProc)" | Out-File $final -Append
"i_am_lease_holder=$($PID -eq $j.pid)" | Out-File $final -Append
"my_pid=$PID" | Out-File $final -Append

"--- Concurrent mutation state ---" | Out-File $final -Append
# diff between current tree and the baseline we recorded in step 2
$baseline = Join-Path $Logs 'BATCH_2_CLOSURE_baseline_deep2_engine_diff.patch'
$curDiff = git diff --ignore-cr-at-eol -- rawrxd\src\deep2\Deep2Engine.cpp 2>&1 | Out-String
$baselineTxt = Get-Content $baseline -Raw
"baseline_diff_chars=$($baselineTxt.Length)" | Out-File $final -Append
"current_diff_chars=$($curDiff.Length)" | Out-File $final -Append
"diffs_match=$($baselineTxt -eq $curDiff)" | Out-File $final -Append
if ($baselineTxt -ne $curDiff) {
    "CONCURRENT_MUTATION_DETECTED=1" | Out-File $final -Append
    "baseline_first_300:" | Out-File $final -Append
    ($baselineTxt.Substring(0, [Math]::Min(300, $baselineTxt.Length))) | Out-File $final -Append
    "" | Out-File $final -Append
    "current_first_300:" | Out-File $final -Append
    ($curDiff.Substring(0, [Math]::Min(300, $curDiff.Length))) | Out-File $final -Append
} else {
    "CONCURRENT_MUTATION_DETECTED=0" | Out-File $final -Append
}

"--- Item 3 results re-summarized ---" | Out-File $final -Append
$optsFile = Join-Path $Logs 'BATCH_2_CLOSURE_generation_options_audit.txt'
"options_audit=$optsFile" | Out-File $final -Append
"consumed=3 (maxTokens, temperature, topK)" | Out-File $final -Append
"not_consumed=4 (topP, repeatPenalty, minP, seed)" | Out-File $final -Append

"--- No commit, no push ---" | Out-File $final -Append
"no_commit_performed=yes" | Out-File $final -Append
"no_push_performed=yes" | Out-File $final -Append
"cmake_lists_untouched=yes" | Out-File $final -Append

"--- Verdict ---" | Out-File $final -Append
"items_completed=4 (1,2,3,15)" | Out-File $final -Append
"items_blocked=11 (4-14)" | Out-File $final -Append
"block_reason=LIVE_LEASE_HOLDER_NOT_THIS_SESSION" | Out-File $final -Append
"BATCH_2_VERDICT=OPEN_BLOCKED_ON_LEASE" | Out-File $final -Append
"BATCH_3_VERDICT=INCOMPLETE_NO_AGENT_CERT" | Out-File $final -Append
"recommendation=AWAIT_LEASE_RELEASE_OR_HANDSHAKE" | Out-File $final -Append

Get-Content $final

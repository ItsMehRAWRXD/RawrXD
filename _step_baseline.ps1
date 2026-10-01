Set-Location F:\~dev
$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001'

# --- Item 4-pre: fresh git status ---
$statusTxt = git status --porcelain
$statusLines = ($statusTxt | Measure-Object).Lines
"=== ITEM 4 PRECHECK ===" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log"
"timestamp=$(Get-Date -Format o)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"dirty_count=$statusLines" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
$statusTxt | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck_status.txt"

# --- Compare Deep2Engine.cpp diff vs the saved baseline ---
$baselinePath = "$Logs\BATCH_2_CLOSURE_baseline_deep2_engine_diff.patch"
$baselineTxt = Get-Content $baselinePath -Raw
$curDiff = git diff --ignore-cr-at-eol -- rawrxd\src\deep2\Deep2Engine.cpp 2>&1 | Out-String
"baseline_diff_chars=$($baselineTxt.Length)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"current_diff_chars=$($curDiff.Length)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
$diffsMatch = ($baselineTxt -eq $curDiff)
"diffs_match=$diffsMatch" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
if (-not $diffsMatch) {
    "=== DRIFT DETECTED ===" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
    # Save both for inspection
    $curDiff | Out-File "$Logs\BATCH_2_CLOSURE_item4_current_diff.patch"
    "saved current diff to BATCH_2_CLOSURE_item4_current_diff.patch" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append

    # Per user: "Explicitly reconcile any drift rather than overwriting it"
    # Reconcile strategy: treat MY planned edits as additive; record drift separately.
    # Save drift hunks (lines in current not in baseline) for the lease holder to inspect.
    $baselineLines = $baselineTxt -split "`n"
    $currentLines = $curDiff -split "`n"

    # Compute simple "lines added by other writer" via set difference on + lines
    $baselinePlus = $baselineLines | Where-Object { $_ -match '^\+[^+]' } | ForEach-Object { $_.Substring(1) }
    $currentPlus = $currentLines | Where-Object { $_ -match '^\+[^+]' } | ForEach-Object { $_.Substring(1) }

    $otherWriterAdds = $currentPlus | Where-Object { $_ -notin $baselinePlus }
    $otherWriterRemoves = ($currentLines | Where-Object { $_ -match '^-[^-]' } | ForEach-Object { $_.Substring(1) }) |
                          Where-Object { $_ -notin ($baselineLines | Where-Object { $_ -match '^-[^-]' } | ForEach-Object { $_.Substring(1) }) }
    "other_writer_adds_count=$(@($otherWriterAdds).Count)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
    "other_writer_removes_count=$(@($otherWriterRemoves).Count)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
    "other_writer_adds_first_20:" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
    $otherWriterAdds | Select-Object -First 20 | ForEach-Object { "  + $_" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append }
    "other_writer_removes_first_20:" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
    $otherWriterRemoves | Select-Object -First 20 | ForEach-Object { "  - $_" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append }

    # Save reconciliation artifact
    @"
# Concurrent-mutation reconciliation
# timestamp: $(Get-Date -Format o)
# baseline chars: $($baselineTxt.Length)
# current chars: $($curDiff.Length)
# drift_summary: $($statusLines) dirty files; Deep2Engine.cpp drifted by $((($curDiff.Length) - ($baselineTxt.Length))) chars

Other-writer additions (lines in current diff not in baseline):
$($otherWriterAdds | ForEach-Object { "  + $_" } | Select-Object -First 100 | Out-String)

Other-writer removals (lines in current diff not in baseline):
$($otherWriterRemoves | ForEach-Object { "  - $_" } | Select-Object -First 100 | Out-String)
"@ | Out-File "$Logs\BATCH_2_CLOSURE_item4_reconciliation.md"
} else {
    "=== NO DRIFT ===" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
}

# --- Lease confirmation ---
$j = Get-Content .rawrxd\leases\writer.lease -Raw | ConvertFrom-Json
"LEASE_PID=$($j.pid)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"LEASE_NONCE=$($j.nonce)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"LEASE_HEAD=$($j.expected_head)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"HEAD=$(git rev-parse HEAD)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"HEAD_MATCHES=$($(git rev-parse HEAD) -eq $j.expected_head)" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append

"my_pid=$PID" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
$iAmHolder = ($PID -eq $j.pid)
"i_am_holder=$iAmHolder" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append

# USER-AUTHORIZED NOTE: user has explicitly granted authorization for items 4-14.
# I (PID $PID) am NOT the lease holder (PID $($j.pid)).
# Per user directive in this turn: "Lease owner authorization granted for items 4-14 begin!"
# I will proceed under user-granted authorization, not under self-acquired lease.
"USER_AUTHORIZATION=GRANTED" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"USER_DIRECTIVE_TEXT=Lease owner authorization granted for items 4-14 begin!" | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append
"NOTE: Authorization is USER-GRANTED, not LEASE-ACQUIRED. This will be flagged in receipt." | Out-File "$Logs\BATCH_2_CLOSURE_item4_precheck.log" -Append

Get-Content "$Logs\BATCH_2_CLOSURE_item4_precheck.log"

Set-Location F:\~dev
$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$step = Join-Path $Logs 'BATCH_2_CLOSURE_step1_3.log'

# ===== ITEM 1: Authority precheck =====
"=== ITEM 1: Authority precheck ===" | Out-File $step
"timestamp=$(Get-Date -Format o)" | Out-File $step -Append
"my_pid=$PID" | Out-File $step -Append
"my_session=$($Host.Name) $($Host.Version)" | Out-File $step -Append
"cwd=$(Get-Location)" | Out-File $step -Append
"HEAD=$(git rev-parse HEAD)" | Out-File $step -Append
"branch=$(git rev-parse --abbrev-ref HEAD)" | Out-File $step -Append
$leasePath = Join-Path (Get-Location) '.rawrxd\leases\writer.lease'
"lease_path=$leasePath" | Out-File $step -Append
"lease_exists=$(Test-Path $leasePath)" | Out-File $step -Append

$j = Get-Content $leasePath -Raw | ConvertFrom-Json
"lease_pid=$($j.pid)" | Out-File $step -Append
"lease_nonce=$($j.nonce)" | Out-File $step -Append
"lease_head=$($j.expected_head)" | Out-File $step -Append
$dt = [DateTimeOffset]::FromUnixTimeSeconds([int64]$j.acquired_unix_seconds)
"lease_acquired_utc=$($dt.ToString('o'))" | Out-File $step -Append
"lease_acq_by=$($j.acquired_by)" | Out-File $step -Append
"lease_path_count=$($j.authorized_paths.Count)" | Out-File $step -Append
"lease_supersedes_nonce=$($j.supersedes_nonce)" | Out-File $step -Append

$liveProc = Get-Process -Id $j.pid -ErrorAction SilentlyContinue
"lease_holder_alive=$($null -ne $liveProc)" | Out-File $step -Append
if ($null -ne $liveProc) {
    "lease_holder_process=$($liveProc.ProcessName)" | Out-File $step -Append
    "lease_holder_start=$($liveProc.StartTime.ToString('o'))" | Out-File $step -Append
}

# HEAD match
$myHead = git rev-parse HEAD
"head_matches_lease=$($myHead -eq $j.expected_head)" | Out-File $step -Append

# Authority verdict: am I the lease holder?
$iAmLeaseHolder = ($PID -eq $j.pid)
"i_am_lease_holder=$iAmLeaseHolder" | Out-File $step -Append
if (-not $iAmLeaseHolder) {
    "VERDICT=MUTATIONS_BLOCKED_LIVE_LEASE_HOLDER" | Out-File $step -Append
    "REASON: my PID=$PID != lease PID=$($j.pid); lease holder process is alive" | Out-File $step -Append
    "USER_DIRECTIVE_ITEM_1: 'Do not mutate from a process/session that is not the actual lease holder.'" | Out-File $step -Append
}

# Deep2Engine.cpp hash for change-detection
$engHash = (Get-FileHash rawrxd\src\deep2\Deep2Engine.cpp -Algorithm SHA256).Hash
"deep2_engine_cpp_sha256=$engHash" | Out-File $step -Append

# ===== ITEM 2: git diff baseline (CONCURRENT-MUTATION-001 reconciliation) =====
"=== ITEM 2: git diff baseline (Deep2Engine.cpp) ===" | Out-File $step -Append
$diffOut = git diff --ignore-cr-at-eol -- rawrxd\src\deep2\Deep2Engine.cpp 2>&1 | Out-String
$diffLen = $diffOut.Length
"diff_length_chars=$diffLen" | Out-File $step -Append
$diffFile = Join-Path $Logs 'BATCH_2_CLOSURE_baseline_deep2_engine_diff.patch'
$diffOut | Out-File $diffFile -Encoding utf8
"baseline_diff_file=$diffFile" | Out-File $step -Append
"baseline_diff_first_40_lines:" | Out-File $step -Append
($diffOut -split "`n" | Select-Object -First 40) | Out-File $step -Append
"baseline_diff_last_30_lines:" | Out-File $step -Append
($diffOut -split "`n" | Select-Object -Last 30) | Out-File $step -Append

# ===== ITEM 3: GenerationOptions field audit =====
"=== ITEM 3: GenerationOptions field audit ===" | Out-File $step -Append
$optsFile = Join-Path $Logs 'BATCH_2_CLOSURE_generation_options_audit.txt'
@"

GenerationOptions field audit (working tree HEAD=a078e3b87)
Generated $(Get-Date -Format o)

Searching rawrxd/src/deep2/Deep2Engine.{h,cpp} for each field's CONSUMED_BY / NO_CONSUMER.
A field is "fully consumed" if its value reaches the sampler chain.
A field is "partially consumed" if it is read but does not affect token selection.
"@ | Out-File $optsFile

$fields = @('maxTokens','temperature','topK','topP','repeatPenalty','minP','seed')
foreach ($f in $fields) {
    "" | Out-File $optsFile -Append
    "=== FIELD: $f ===" | Out-File $optsFile -Append
    # Search in Deep2Engine.cpp / .h for the field name
    $matches = Select-String -Path 'rawrxd\src\deep2\Deep2Engine.cpp','rawrxd\src\deep2\Deep2Engine.h' -Pattern ("\b" + [regex]::Escape($f) + "\b") -CaseSensitive:$false
    $count = ($matches | Measure-Object).Count
    "occurrences=$count" | Out-File $optsFile -Append
    $matches | Select-Object -First 30 | ForEach-Object { "$($_.Path):$($_.LineNumber): $($_.Line)" | Out-File $optsFile -Append }
}

# Find GenerationOptions struct definition
"" | Out-File $optsFile -Append
"=== GenerationOptions struct definition ===" | Out-File $optsFile -Append
$structHits = Select-String -Path 'rawrxd\src\deep2\Deep2Engine.h' -Pattern 'struct GenerationOptions|class GenerationOptions' -CaseSensitive:$false
$structHits | ForEach-Object { "$($_.Path):$($_.LineNumber): $($_.Line)" | Out-File $optsFile -Append }

# Try to read the struct body
$structLine = ($structHits | Select-Object -First 1).LineNumber
if ($structLine) {
    $start = [Math]::Max(1, $structLine - 1)
    $end = $structLine + 30
    Get-Content 'rawrxd\src\deep2\Deep2Engine.h' -TotalCount ($end - $start + 1) | Select-Object -Skip ($start - 1) | Select-Object -First 30 | ForEach-Object { "  $_" | Out-File $optsFile -Append }
}

"=== ITEM 3 OUTPUT: $optsFile ===" | Out-File $step -Append
"log=$step"

Get-Content $step

# Invoke v5: write .cmd without special chars, merge streams
$exe = 'F:\~dev\rawrxd\bin\deep2_generation_lifecycle_test.exe'
$gguf = 'F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3'
$tmp1 = 'F:\~dev\_batch3d_inference1.txt'
$tmp2 = 'F:\~dev\_batch3d_inference2.txt'
$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_3D_nemotron_agent_cycle.log'
$Truth = @{ branch='model-correctness'; dirty=$true; dirtyFileCount=124 }

# AVOID cmd-special chars: | & < > ^ ( ) %
$prompt1 = 'You have tools. git_status (no args) returns branch and dirty state. list_files (path) lists files. read_file (path) reads a file. When you need a tool, respond with EXACTLY one line: RAWR_TOOL name=git_status. Otherwise respond with text only. Question: What branch am I on and is the worktree clean?'

$runner1 = 'F:\~dev\_run1.cmd'
$runner2 = 'F:\~dev\_run2.cmd'

"@echo off`r`nset PROMPT=$prompt1`r`n""$exe"" ""$gguf"" --generations 1 --max-tokens 64 --eos-max-tokens 64 --prompt ""%PROMPT%"" > ""$tmp1"" 2>&1" | Out-File $runner1 -Encoding ascii -NoNewline

"=== Batch 3 Sub-D v5: agent cycle (nemotron, .cmd runner, prompt sanitized) ===" | Out-File $Logs
"model=$gguf" | Out-File $Logs -Append

# --- INFERENCE #1 ---
"=== INFERENCE #1 ===" | Out-File $Logs -Append
"prompt1=$prompt1" | Out-File $Logs -Append
$sw1 = [Diagnostics.Stopwatch]::StartNew()
cmd /c $runner1
$rc1 = $LASTEXITCODE
$sw1.Stop()
"wall_seconds_1=$($sw1.Elapsed.TotalSeconds)" | Out-File $Logs -Append
"exit_1=$rc1" | Out-File $Logs -Append
"=== INFERENCE #1 raw (first 20 + last 30 lines) ===" | Out-File $Logs -Append
if (Test-Path $tmp1) {
    $lines = Get-Content $tmp1
    "lines_count=$($lines.Count)" | Out-File $Logs -Append
    "CUSTOM_PROMPT line:" | Out-File $Logs -Append
    ($lines | Select-String -Pattern '^CUSTOM_PROMPT=') | Out-File $Logs -Append
    "first 5 lines:" | Out-File $Logs -Append
    $lines[0..4] | Out-File $Logs -Append
    "..." | Out-File $Logs -Append
    "last 20 lines:" | Out-File $Logs -Append
    $lines[[Math]::Max(0, $lines.Count-20)..($lines.Count-1)] | Out-File $Logs -Append
}

# --- PARSE #1 ---
$out1 = if (Test-Path $tmp1) { Get-Content $tmp1 -Raw } else { '' }
$bLines = [regex]::Matches($out1, '(?m)^B\[\d+\]=(.+)$')
if ($bLines.Count -eq 0) { "FAIL_PARSE_NO_B_LINE_1" | Out-File $Logs -Append; return }
$genText = $bLines[0].Groups[1].Value
"generated_text=$genText" | Out-File $Logs -Append

$toolMatch = [regex]::Match($genText, 'RAWR_TOOL\s+name=(\S+)')
if (-not $toolMatch.Success) {
    "FAIL_MODEL_DID_NOT_REQUEST_TOOL" | Out-File $Logs -Append
    "generated_text=$genText" | Out-File $Logs -Append
    return
}
$toolName = $toolMatch.Groups[1].Value
"model_requested_tool=$toolName" | Out-File $Logs -Append
if ($toolName -ne 'git_status') { "FAIL_MODEL_REQUESTED_UNEXPECTED_TOOL=$toolName" | Out-File $Logs -Append; return }
"auth_pass=1" | Out-File $Logs -Append

# --- EXECUTE ---
"=== EXECUTE: git_status ===" | Out-File $Logs -Append
$gitOut = git -C F:\~dev status --porcelain --branch 2>&1 | Out-String
$branch = ([regex]::Match($gitOut, '##\s+([^.\s]+)')).Groups[1].Value
$dirtyCount = (($gitOut -split "`n") | Where-Object { $_ -and $_ -notmatch '^##' }).Count
$observation = "branch=$branch dirty=yes dirty_file_count=$dirtyCount"
"observation=$observation" | Out-File $Logs -Append

# --- INFERENCE #2 ---
$prompt2 = "Tool returned: $observation. Respond with EXACTLY two lines: BRANCH=<value> and DIRTY_FILE_COUNT=<integer>"
"=== INFERENCE #2 ===" | Out-File $Logs -Append
"prompt2=$prompt2" | Out-File $Logs -Append
"@echo off`r`nset PROMPT=$prompt2`r`n""$exe"" ""$gguf"" --generations 1 --max-tokens 64 --eos-max-tokens 64 --prompt ""%PROMPT%"" > ""$tmp2"" 2>&1" | Out-File $runner2 -Encoding ascii -NoNewline

$sw2 = [Diagnostics.Stopwatch]::StartNew()
cmd /c $runner2
$rc2 = $LASTEXITCODE
$sw2.Stop()
"wall_seconds_2=$($sw2.Elapsed.TotalSeconds)" | Out-File $Logs -Append
"exit_2=$rc2" | Out-File $Logs -Append
"=== INFERENCE #2 raw (last 20 lines) ===" | Out-File $Logs -Append
if (Test-Path $tmp2) {
    $lines = Get-Content $tmp2
    "lines_count=$($lines.Count)" | Out-File $Logs -Append
    "CUSTOM_PROMPT line:" | Out-File $Logs -Append
    ($lines | Select-String -Pattern '^CUSTOM_PROMPT=') | Out-File $Logs -Append
    "first 5 lines:" | Out-File $Logs -Append
    $lines[0..4] | Out-File $Logs -Append
    "..." | Out-File $Logs -Append
    "last 20 lines:" | Out-File $Logs -Append
    $lines[[Math]::Max(0, $lines.Count-20)..($lines.Count-1)] | Out-File $Logs -Append
}

# --- PARSE #3 ---
$out2 = if (Test-Path $tmp2) { Get-Content $tmp2 -Raw } else { '' }
$bLines2 = [regex]::Matches($out2, '(?m)^B\[\d+\]=(.+)$')
if ($bLines2.Count -eq 0) { "FAIL_PARSE_NO_B_LINE_2" | Out-File $Logs -Append; return }
$assertedText = $bLines2[0].Groups[1].Value
"asserted_text=$assertedText" | Out-File $Logs -Append

$branchMatch = [regex]::Match($assertedText, 'BRANCH=(\S+)')
$countMatch = [regex]::Match($assertedText, 'DIRTY_FILE_COUNT=(\d+)')
if (-not $branchMatch.Success -or -not $countMatch.Success) {
    "FAIL_MODEL_DID_NOT_ASSERT_FACTS" | Out-File $Logs -Append
    "asserted_text=$assertedText" | Out-File $Logs -Append
    return
}
$assertedBranch = $branchMatch.Groups[1].Value
$assertedCount = [int]$countMatch.Groups[1].Value
"asserted_branch=$assertedBranch" | Out-File $Logs -Append
"asserted_dirty_file_count=$assertedCount" | Out-File $Logs -Append

# --- VERDICT ---
"=== VERDICT ===" | Out-File $Logs -Append
$branch_ok = ($assertedBranch -eq $Truth.branch)
$count_ok = ($assertedCount -eq $Truth.dirtyFileCount)
"truth_branch=$($Truth.branch)" | Out-File $Logs -Append
"truth_dirty_file_count=$($Truth.dirtyFileCount)" | Out-File $Logs -Append
"branch_ok=$branch_ok" | Out-File $Logs -Append
"count_ok=$count_ok" | Out-File $Logs -Append
if ($branch_ok -and $count_ok) { "VERDICT=PASS" | Out-File $Logs -Append } else { "VERDICT=FAIL_MODEL_HALLUCINATED" | Out-File $Logs -Append }
"log=$Logs"

#Requires -Version 7.0
[CmdletBinding()]
param([string]$Repository = 'F:\rawrxd', [string]$Remote = 'origin',
      [string]$EvidenceDirectory = 'F:\rawrxd\evidence\GITHUB_BRANCH_SYNC_001',
      [string]$ResumePlanPath,
      [int]$BatchSize = 8,
      [int]$OperationTimeoutSeconds = 120)
$ErrorActionPreference = 'Stop'
$git = (Get-Command git.exe).Source
$run = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$out = Join-Path $EvidenceDirectory ('histories-' + $run)
New-Item -ItemType Directory -Path $out -Force | Out-Null
function Run-Git([string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($git)
    $start.WorkingDirectory = $Repository
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.Environment['GIT_TERMINAL_PROMPT'] = '0'
    $start.Environment['GCM_INTERACTIVE'] = 'never'
    # Git refs and objects are uploaded here. LFS payloads are a separate,
    # explicitly BLOCKED gate because the remote account is over its budget.
    $start.Environment['GIT_LFS_SKIP_PUSH'] = '1'
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($OperationTimeoutSeconds * 1000)
    if ($timedOut) { $process.Kill($true); $process.WaitForExit() }
    $result = [pscustomobject]@{Exit = $process.ExitCode; Output = $stdout.GetAwaiter().GetResult(); Error = $stderr.GetAwaiter().GetResult()}
    if ($timedOut) { $result.Exit = 124; $result.Error += "`nGit history operation timed out; source snapshot publication remains available." }
    $process.Dispose(); return $result
}
function Remote-Heads {
    $response = Run-Git @('ls-remote', '--heads', $Remote)
    if ($response.Exit) { throw $response.Error }
    $map = @{}
    foreach ($line in ($response.Output -split "`n")) {
        if ($line -match '^([a-f0-9]{40})\s+refs/heads/(.+)$') { $map[$Matches[2].Trim()] = $Matches[1] }
    }
    return $map
}
$heads = Remote-Heads
$local = Run-Git @('for-each-ref', '--format=%(refname:short)%09%(objectname)', 'refs/heads')
if ($local.Exit) { throw $local.Error }
$records = [Collections.Generic.List[object]]::new()
if ($ResumePlanPath) {
    foreach ($record in @(Get-Content -LiteralPath $ResumePlanPath -Raw | ConvertFrom-Json)) {
        if ($heads[$record.RemoteBranch] -eq $record.LocalCommit) { $record.GitRefs = 'ALREADY_VERIFIED' }
        elseif ($record.GitRefs -ne 'FAILED') { $record.GitRefs = 'PENDING' }
        $records.Add($record)
    }
}
foreach ($line in ($local.Output -split "`n")) {
    if (-not $line -or $line -match '^codex/source-sync-') { continue }
    $parts = $line.TrimEnd("`r").Split("`t")
    $branch = $parts[0]; $commit = $parts[1]; $target = $branch
    if (@($records | Where-Object { $_.LocalBranch -eq $branch -and $_.LocalCommit -eq $commit }).Count) { continue }
    if ($heads.ContainsKey($branch) -and $heads[$branch] -ne $commit) { $target = 'codex/history-preserve-' + $run + '/' + $branch }
    $records.Add([pscustomobject]@{LocalBranch = $branch; LocalCommit = $commit; RemoteBranch = $target;
        GitRefs = $(if ($heads.ContainsKey($target) -and $heads[$target] -eq $commit) { 'ALREADY_VERIFIED' } else { 'PENDING' });
        LfsPayloads = 'NOT_UPLOADED_REMOTE_BUDGET_EXCEEDED'; Error = ''})
}
$records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'history-plan.json') -Encoding UTF8
$pending = @($records | Where-Object { $_.GitRefs -eq 'PENDING' })
for ($offset = 0; $offset -lt $pending.Count; $offset += $BatchSize) {
    $batch = @($pending | Select-Object -Skip $offset -First $BatchSize)
    $arguments = @('-c', 'credential.interactive=never', 'push', '--porcelain', $Remote)
    foreach ($record in $batch) { $arguments += ($record.LocalCommit + ':refs/heads/' + $record.RemoteBranch) }
    $result = Run-Git $arguments
    ($result.Output + "`n" + $result.Error) | Set-Content -LiteralPath (Join-Path $out ('push-' + $offset + '.txt')) -Encoding UTF8
    if ($result.Exit -eq 0) {
        foreach ($record in $batch) { $record.GitRefs = 'PUSHED_AWAITING_VERIFICATION' }
    } elseif ($batch.Count -eq 1 -or $result.Exit -eq 124) {
        foreach ($record in $batch) { $record.GitRefs = 'FAILED'; $record.Error = $result.Error }
    } else {
        # A batch can be rejected because only one history contains an oversized
        # object. Retry each member once, never rewrite or force-push history.
        foreach ($record in $batch) {
            $single = Run-Git @('-c', 'credential.interactive=never', 'push', '--porcelain', $Remote,
                ($record.LocalCommit + ':refs/heads/' + $record.RemoteBranch))
            ($single.Output + "`n" + $single.Error) | Set-Content -LiteralPath (Join-Path $out ('retry-' + $record.LocalCommit.Substring(0, 12) + '.txt')) -Encoding UTF8
            $record.GitRefs = $(if ($single.Exit -eq 0) { 'PUSHED_AWAITING_VERIFICATION' } else { 'FAILED' })
            if ($single.Exit) { $record.Error = $single.Error }
        }
    }
    $records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'history-progress.json') -Encoding UTF8
    Write-Output ('HISTORY_BATCH ' + $offset + ' branches=' + $batch.Count)
}
$verifiedHeads = Remote-Heads
foreach ($record in $records) {
    if ($verifiedHeads.ContainsKey($record.RemoteBranch) -and $verifiedHeads[$record.RemoteBranch] -eq $record.LocalCommit) { $record.GitRefs = 'VERIFIED' }
}
$receipt = [ordered]@{run_id = $run; repository = $Repository; remote = $Remote; branches = $records.ToArray();
    total = $records.Count; git_refs_verified = @($records | Where-Object { $_.GitRefs -eq 'VERIFIED' }).Count;
    lfs_payload_gate = 'BLOCKED_BY_REMOTE_BUDGET'; original_histories_rewritten = $false; force_pushes = 0}
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'history-publication-receipt.json') -Encoding UTF8
Write-Output ('HISTORY_RECEIPT ' + (Join-Path $out 'history-publication-receipt.json'))
if ($receipt.git_refs_verified -ne $receipt.total) { exit 1 }

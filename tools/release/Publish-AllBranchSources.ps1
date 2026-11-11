#Requires -Version 7.0
[CmdletBinding()]
param([string]$Repository = 'F:\rawrxd',
      [string]$Remote = 'origin',
      [string]$EvidenceDirectory = 'F:\rawrxd\evidence\GITHUB_BRANCH_SYNC_001',
      [switch]$Push,
      [switch]$SkipBranches,
      [switch]$RootWorktreeOnly,
      [switch]$IncludeIgnoredSources,
      [string]$ResumePlanPath,
      [string[]]$CompletedLabels = @())
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $Repository).Path
$run = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$prefix = 'codex/source-sync-' + $run + '/'
$out = Join-Path $EvidenceDirectory $run
New-Item -ItemType Directory -Path $out -Force | Out-Null
$git = (Get-Command git.exe -ErrorAction Stop).Source
$utf8 = [Text.UTF8Encoding]::new($false)
function Start-Git([string]$Directory, [string[]]$Arguments, [string]$Index = '') {
    $start = [Diagnostics.ProcessStartInfo]::new($git)
    $start.WorkingDirectory = $Directory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
    $start.Environment['GIT_TERMINAL_PROMPT'] = '0'
    $start.Environment['GCM_INTERACTIVE'] = 'never'
    if ($Index) { $start.Environment['GIT_INDEX_FILE'] = $Index }
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $null = $process.Start()
    return $process
}
function Invoke-Git([string]$Directory, [string[]]$Arguments, [byte[]]$InputBytes = $null, [string]$Index = '') {
    $process = Start-Git $Directory $Arguments $Index
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if ($InputBytes) { $process.StandardInput.BaseStream.Write($InputBytes) }
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(600000)) { $process.Kill($true); throw 'Git operation timed out.' }
    $result = [pscustomobject]@{Exit = $process.ExitCode; Output = $stdout.GetAwaiter().GetResult(); Error = $stderr.GetAwaiter().GetResult()}
    $process.Dispose()
    if ($result.Exit -ne 0) {
        ($result.Output + "`n" + $result.Error) | Set-Content -LiteralPath (Join-Path $out ('git-failure-' + [Guid]::NewGuid().ToString('N') + '.log')) -Encoding UTF8
        throw ('git ' + ($Arguments -join ' ') + ': ' + $result.Error)
    }
    return $result.Output
}
$common = (Invoke-Git $root @('rev-parse', '--path-format=absolute', '--git-common-dir')).Trim()
$identity = (Invoke-Git $root @('var', 'GIT_COMMITTER_IDENT')).Trim()
$branches = @((Invoke-Git $root @('for-each-ref', '--format=%(refname:short)%09%(objectname)', 'refs/heads')) -split "`n" |
    Where-Object { $_ -and $_ -notmatch '^codex/source-sync-' } | ForEach-Object {
        $parts = $_.TrimEnd("`r").Split("`t")
        [pscustomobject]@{Name = $parts[0]; Commit = $parts[1]}
    })
$worktreeBlocks = (Invoke-Git $root @('worktree', 'list', '--porcelain')) -split "`n`n"
$plans = [Collections.Generic.List[object]]::new()
$exclusions = [Collections.Generic.List[object]]::new()
$failures = [Collections.Generic.List[object]]::new()
$snapshots = [Collections.Generic.List[object]]::new()
$script:excludedFileCount = 0L
function Flush-Exclusions {
    if (-not $exclusions.Count) { return }
    # Each line is one complete JSON array. Flush only new entries so a large
    # all-branch audit does not repeatedly serialize every prior checkpoint.
    $batchJson = ConvertTo-Json -InputObject $exclusions.ToArray() -Depth 5 -Compress
    [IO.File]::AppendAllText((Join-Path $out 'exclusions-batches.jsonl'), $batchJson + "`n", $utf8)
    $script:excludedFileCount += $exclusions.Count
    $exclusions.Clear()
}
function Exclusion-Reason([string]$Path) {
    if ($Path -match '(?i)(^|/)(\.git|node_modules|CMakeFiles|build(?:[-_][^/]*)?|_build[^/]*|\.rawr|\.rawrxd|\.swarm_runs|\.venv|ggml_env|\.cache|\.vs|\.backups)(/|$)' -or
        $Path -match '(?i)^(build[-_][^/]*|_build[^/]*|\.worktrees|\.kilo/worktrees|\.tmp_[^/]*|models|models-mnt)/' -or
        $Path -match '(?i)^(external/strata/engines|evidence/IDE_REPAIR_CANDIDATE_001/_strata_rx9070_stage|evidence/GITHUB_BRANCH_SYNC_001)/') { return 'generated-or-machine-local' }
    if ($Path -match '(?i)(^|/)(\.env(?:\.(?!example|sample)[^/]*)?|auth\.json|credentials[^/]*|id_rsa[^/]*|id_ed25519[^/]*)(/|$)' -or
        $Path -match '(?i)\.(pfx|p12|pem|key)$') { return 'credential-or-private-key-file' }
    if ($Path -match '(?i)\.(exe|dll|obj|o|lib|pdb|ilk|iobj|ipdb|spv|f32|dmp|tlog|gguf|bin|zip|tar\.gz|bundle|pack|co|zlib)(\..*)?$') { return 'binary-artifact-preserved-locally' }
    if ($Path -match '(?i)(^|/)(?:_e2e|_cert_clean\w*|_final_build|_cmake_recovery)(/|$)' -or
        $Path -match '(?i)/ggml-vulkan/[^/]+\.comp\.cpp$') { return 'generated-build-source' }
    return ''
}
if ($ResumePlanPath) {
    foreach ($savedPlan in @(Get-Content -LiteralPath $ResumePlanPath -Raw | ConvertFrom-Json)) { $plans.Add($savedPlan) }
}
foreach ($branch in $(if ($SkipBranches -or $ResumePlanPath) { @() } else { $branches })) {
    $plans.Add([pscustomobject]@{Label = $branch.Name; Tree = $branch.Commit; OriginalCommit = $branch.Commit; Worktree = $null; Kind = 'branch-tip'})
}
foreach ($block in $worktreeBlocks) {
    if ($ResumePlanPath) { break }
    if ($block -notmatch '(?m)^worktree (.+)\r?$') { continue }
    $directory = $Matches[1].TrimEnd("`r")
    if ($RootWorktreeOnly -and [IO.Path]::GetFullPath($directory) -ne $root) { continue }
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        $failures.Add([pscustomobject]@{Worktree = $directory; Error = 'registered worktree directory absent'}); continue
    }
    try {
        $head = (Invoke-Git $directory @('rev-parse', 'HEAD')).Trim()
        $label = 'detached-' + $head.Substring(0, 12)
        if ($block -match '(?m)^branch refs/heads/(.+)\r?$') { $label = $Matches[1].TrimEnd("`r") }
        $changed = (Invoke-Git $directory @('diff', '--name-only', '--no-renames', '-z', 'HEAD')) +
                   (Invoke-Git $directory @('ls-files', '--others', '--exclude-standard', '-z'))
        if ($IncludeIgnoredSources) {
            $changed += Invoke-Git $directory @('ls-files', '--others', '--ignored', '--exclude-standard', '-z', '--',
                ':(glob)**/*.bat', ':(glob)**/*.cmd', ':(glob)**/*.cpp', ':(glob)**/*.c',
                ':(glob)**/*.h', ':(glob)**/*.hpp', ':(glob)**/*.ps1', ':(glob)**/*.py',
                ':(glob)**/*.md', ':(glob)**/*.asm', ':(glob)**/*.cs', ':(glob)**/*.rs',
                ':(glob)**/*.ts', ':(glob)**/*.js', ':(glob)evidence/**/*.log')
        }
        $paths = @($changed.Split([char]0, [StringSplitOptions]::RemoveEmptyEntries) | Sort-Object -Unique)
        $eligible = [Collections.Generic.List[string]]::new()
        foreach ($path in $paths) {
            $reason = Exclusion-Reason $path
            if ($reason) { $exclusions.Add([pscustomobject]@{Scope = $label; Path = $path; Reason = $reason}); continue }
            $absolute = Join-Path $directory $path
            if ([IO.File]::Exists($absolute) -and [IO.FileInfo]::new($absolute).Length -ge 100MB) {
                $exclusions.Add([pscustomobject]@{Scope = $label; Path = $path; Reason = 'exceeds-GitHub-blob-limit'}); continue
            }
            $eligible.Add($path)
        }
        $staged = Invoke-Git $directory @('diff', '--cached', '--name-only', '-z')
        if ($staged) {
            $stagedTree = (Invoke-Git $directory @('write-tree')).Trim()
            $plans.Add([pscustomobject]@{Label = 'staged/' + $label; Tree = $stagedTree; OriginalCommit = $head; Worktree = $directory; Kind = 'staged-index'})
        }
        if ($eligible.Count) {
            $index = Join-Path $out ('index-' + [Guid]::NewGuid().ToString('N'))
            $null = Invoke-Git $directory @('read-tree', $head) $null $index
            $pathBytes = $utf8.GetBytes(($eligible -join [char]0) + [char]0)
            $addArguments = @('--literal-pathspecs', '-c', 'filter.lfs.process=', '-c', 'filter.lfs.clean=', '-c', 'filter.lfs.required=false', 'add', '-A')
            if ($IncludeIgnoredSources) { $addArguments += '-f' }
            $addArguments += @('--pathspec-from-file=-', '--pathspec-file-nul')
            $null = Invoke-Git $directory $addArguments $pathBytes $index
            $tree = (Invoke-Git $directory @('write-tree') $null $index).Trim()
            $plans.Add([pscustomobject]@{Label = 'worktree/' + $label; Tree = $tree; OriginalCommit = $head; Worktree = $directory; Kind = 'working-files'; ChangedPaths = $eligible.Count})
        }
        Write-Output ('INVENTORIED ' + $label + ' changed=' + $paths.Count + ' publishable=' + $eligible.Count)
    } catch { $failures.Add([pscustomobject]@{Worktree = $directory; Error = $_.Exception.Message}) }
}
$plans | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'plans.json') -Encoding UTF8
$cat = Start-Git $root @('cat-file', '--batch')
$catErrors = $cat.StandardError.ReadToEndAsync()
$import = Start-Git $root @('fast-import', '--quiet', '--done')
$importErrors = $import.StandardError.ReadToEndAsync()
$script:mark = 0
$cache = @{}
if (-not ('RawrXDGitBlobReader' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;
public static class RawrXDGitBlobReader {
    public static byte[] Read(Process process, string oid) {
        process.StandardInput.WriteLine(oid);
        process.StandardInput.Flush();
        return ReadNext(process);
    }
    public static Dictionary<string, byte[]> ReadMany(Process process, string[] oids) {
        var writer = Task.Run(() => {
            foreach (string oid in oids) process.StandardInput.WriteLine(oid);
            process.StandardInput.Flush();
        });
        var result = new Dictionary<string, byte[]>();
        foreach (string oid in oids) result.Add(oid, ReadNext(process));
        writer.GetAwaiter().GetResult();
        return result;
    }
    private static byte[] ReadNext(Process process) {
        Stream stream = process.StandardOutput.BaseStream;
        var header = new StringBuilder(96);
        for (;;) {
            int next = stream.ReadByte();
            if (next < 0) throw new EndOfStreamException("cat-file closed");
            if (next == 10) break;
            header.Append((char)next);
        }
        string[] fields = header.ToString().Split(' ');
        if (fields.Length != 3 || fields[1] != "blob") throw new InvalidDataException(header.ToString());
        byte[] data = new byte[int.Parse(fields[2])];
        stream.ReadExactly(data);
        if (stream.ReadByte() != 10) throw new InvalidDataException("cat-file boundary");
        return data;
    }
}
'@
}
$secret = [regex]::new('gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{70,}|sk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{32,}|AKIA[0-9A-Z]{16}|-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{64,}', [Text.RegularExpressions.RegexOptions]::CultureInvariant, [TimeSpan]::FromSeconds(2))
function Write-Import([string]$Value) { $bytes = $utf8.GetBytes($Value); $import.StandardInput.BaseStream.Write($bytes) }
function Read-Blob([string]$Oid) {
    return ,([RawrXDGitBlobReader]::Read($cat, $Oid))
}
function Add-Blob([byte[]]$Bytes) {
    $script:mark++
    Write-Import ("blob`nmark :" + $script:mark + "`ndata " + $Bytes.Length + "`n")
    $import.StandardInput.BaseStream.Write($Bytes)
    Write-Import "`n"
    return ':' + $script:mark
}
function Quote-Path([string]$Path) { return '"' + $Path.Replace('\', '\\').Replace('"', '\"').Replace("`n", '\n').Replace("`r", '\r').Replace("`t", '\t') + '"' }
try {
    foreach ($plan in $plans) {
        if ($plan.Label -in $CompletedLabels) { continue }
        $files = [Collections.Generic.List[object]]::new()
        $entries = (Invoke-Git $root @('ls-tree', '-r', '-l', '-z', $plan.Tree)).Split([char]0, [StringSplitOptions]::RemoveEmptyEntries)
        $candidates = [Collections.Generic.List[object]]::new()
        foreach ($entry in $entries) {
            $tab = $entry.IndexOf("`t"); $path = $entry.Substring($tab + 1)
            $metadata = $entry.Substring(0, $tab).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
            $reason = Exclusion-Reason $path
            if ($metadata[1] -ne 'blob') { $reason = 'nested-repository-reference-preserved-in-original-history' }
            if (-not $reason -and [long]$metadata[3] -ge 100MB) { $reason = 'exceeds-GitHub-blob-limit' }
            if ($reason) { $exclusions.Add([pscustomobject]@{Scope = $plan.Label; Path = $path; Reason = $reason}); continue }
            $candidates.Add([pscustomobject]@{Path = $path; Metadata = $metadata})
        }
        $prefetched = $null
        for ($entryIndex = 0; $entryIndex -lt $candidates.Count; $entryIndex++) {
            $path = $candidates[$entryIndex].Path
            $metadata = $candidates[$entryIndex].Metadata
            $oid = $metadata[2]
            if (-not $cache.ContainsKey($oid)) {
                if ($null -eq $prefetched -or -not $prefetched.ContainsKey($oid)) {
                    $nextOids = [Collections.Generic.List[string]]::new()
                    $nextBytes = 0L
                    for ($nextIndex = $entryIndex; $nextIndex -lt $candidates.Count -and $nextOids.Count -lt 128; $nextIndex++) {
                        $nextMetadata = $candidates[$nextIndex].Metadata
                        if ($cache.ContainsKey($nextMetadata[2]) -or $nextOids.Contains($nextMetadata[2])) { continue }
                        if ($nextOids.Count -and $nextBytes + [long]$nextMetadata[3] -gt 16MB) { break }
                        $nextOids.Add($nextMetadata[2]); $nextBytes += [long]$nextMetadata[3]
                    }
                    $prefetched = [RawrXDGitBlobReader]::ReadMany($cat, $nextOids.ToArray())
                }
                $bytes = $prefetched[$oid]
                $text = $utf8.GetString($bytes)
                $replacement = $oid; $reason = ''
                if ($bytes.Length -lt 1024 -and $text.StartsWith('version https://git-lfs.github.com/spec/v1')) {
                    if ($text -notmatch '(?m)^oid sha256:([a-f0-9]{64})\r?$') { $reason = 'invalid-lfs-pointer' }
                    else {
                        $lfsOid = $Matches[1]
                        $objectPath = Join-Path $common ('lfs/objects/' + $lfsOid.Substring(0, 2) + '/' + $lfsOid.Substring(2, 2) + '/' + $lfsOid)
                        if (-not [IO.File]::Exists($objectPath)) { $reason = 'LFS-payload-missing-locally-and-remote-budget-blocked' }
                        elseif ([IO.FileInfo]::new($objectPath).Length -ge 100MB) { $reason = 'LFS-payload-exceeds-GitHub-blob-limit' }
                        else {
                            $bytes = [IO.File]::ReadAllBytes($objectPath)
                            $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                            if ($actual -ne $lfsOid) { $reason = 'LFS-payload-hash-mismatch' }
                            else { $text = $utf8.GetString($bytes); $replacement = 'materialize' }
                        }
                    }
                }
                if (-not $reason -and [Array]::IndexOf($bytes, [byte]0) -eq -1) {
                    try { if ($secret.IsMatch($text)) { $reason = 'possible-credential-content' } }
                    catch { $reason = 'credential-scan-timeout' }
                }
                if (-not $reason -and $replacement -eq 'materialize') { $replacement = Add-Blob $bytes }
                $cache[$oid] = [pscustomobject]@{Ref = $replacement; Reason = $reason}
            }
            $decision = $cache[$oid]
            if ($decision.Reason) { $exclusions.Add([pscustomobject]@{Scope = $plan.Label; Path = $path; Reason = $decision.Reason}); continue }
            $blob = $decision.Ref
            if ($path -match '(^|/)\.gitattributes$') {
                $attributeBytes = Read-Blob $oid
                $attributes = (($utf8.GetString($attributeBytes) -split '\r?\n') | Where-Object { $_ -notmatch '\b(filter|diff|merge)=lfs\b' }) -join "`n"
                $blob = Add-Blob ($utf8.GetBytes($attributes + "`n# Source snapshot: payloads are regular Git blobs, not LFS dependencies.`n* -filter`n"))
            }
            $files.Add([pscustomobject]@{Mode = $metadata[0]; Ref = $blob; Path = $path})
        }
        $metadataText = [ordered]@{schema_version = 1; kind = $plan.Kind; original_branch = $plan.Label;
            original_commit = $plan.OriginalCommit; worktree = $plan.Worktree;
            publication = 'Source snapshot on a new branch; original history is preserved locally.';
            lfs_status = 'Remote account budget exceeded; locally available text payloads materialized as regular Git blobs.';
            exclusions_receipt = 'Local evidence/GITHUB_BRANCH_SYNC_001/' + $run + '/exclusions-batches.jsonl';
            release_certification = 'NOT_CLAIMED'} | ConvertTo-Json -Depth 5
        $metadataBlob = Add-Blob ($utf8.GetBytes($metadataText))
        $branchName = $prefix + $plan.Label
        $message = 'Preserve source snapshot: ' + $plan.Label + "`nOriginal commit: " + $plan.OriginalCommit + "`nNo release acceptance is claimed.`n"
        $script:mark++; $commitMark = $script:mark
        Write-Import ("commit refs/heads/" + $branchName + "`nmark :" + $commitMark + "`ncommitter " + $identity + "`ndata " + $utf8.GetByteCount($message) + "`n" + $message + "`ndeleteall`n")
        foreach ($file in $files) { Write-Import ('M ' + $file.Mode + ' ' + $file.Ref + ' ' + (Quote-Path $file.Path) + "`n") }
        Write-Import ('M 100644 ' + $metadataBlob + ' PUBLISH_SNAPSHOT.json' + "`n`n")
        Write-Import ("checkpoint`nget-mark :" + $commitMark + "`n")
        $import.StandardInput.BaseStream.Flush()
        $publishedCommit = $import.StandardOutput.ReadLine()
        if ($publishedCommit -notmatch '^[a-f0-9]{40}$') { throw ('Missing durable snapshot commit: ' + $publishedCommit) }
        $snapshots.Add([pscustomobject]@{OriginalBranch = $plan.Label; OriginalCommit = $plan.OriginalCommit;
            PublishedBranch = $branchName; PublishedCommit = $publishedCommit; Kind = $plan.Kind; Files = $files.Count; RemoteVerified = $false})
        $snapshots | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'snapshots-before-push.json') -Encoding UTF8
        Flush-Exclusions
        Write-Output ('SNAPSHOT ' + $plan.Label + ' files=' + $files.Count)
        if ($Push) {
            $pushOutput = Invoke-Git $root @('-c', 'credential.interactive=never', 'push', '--porcelain', $Remote,
                ($publishedCommit + ':refs/heads/' + $branchName))
            $pushOutput | Add-Content -LiteralPath (Join-Path $out 'incremental-push.log') -Encoding UTF8
            Write-Output ('PUSHED ' + $branchName)
        }
    }
    Write-Import "done`n"; $import.StandardInput.Close()
    if (-not $import.WaitForExit(600000)) { throw 'fast-import timed out' }
    if ($import.ExitCode -ne 0) { throw $importErrors.GetAwaiter().GetResult() }
} finally {
    $cat.StandardInput.Close()
    if (-not $cat.WaitForExit(5000)) { $cat.Kill() }
    if (-not $import.HasExited) { $import.StandardInput.Close(); if (-not $import.WaitForExit(5000)) { $import.Kill() } }
}
Flush-Exclusions
$failures | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'failures.json') -Encoding UTF8
$snapshots | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $out 'snapshots-before-push.json') -Encoding UTF8
if ($Push) {
    for ($offset = 0; $offset -lt $snapshots.Count; $offset += 8) {
        $batch = @($snapshots | Select-Object -Skip $offset -First 8)
        $arguments = @('-c', 'credential.interactive=never', 'push', '--porcelain', $Remote)
        foreach ($snapshot in $batch) { $arguments += ('refs/heads/' + $snapshot.PublishedBranch + ':refs/heads/' + $snapshot.PublishedBranch) }
        $pushOutput = Invoke-Git $root $arguments
        $pushOutput | Set-Content -LiteralPath (Join-Path $out ('push-' + $offset + '.txt')) -Encoding UTF8
        Write-Output ('PUSHED_BATCH ' + $offset + ' branches=' + $batch.Count)
    }
    $remoteRefs = Invoke-Git $root @('ls-remote', '--heads', $Remote, ('refs/heads/' + $prefix + '*'))
    $remoteMap = @{}
    foreach ($line in ($remoteRefs -split "`n")) { if ($line -match '^([a-f0-9]{40})\s+refs/heads/(.+)$') { $remoteMap[$Matches[2].Trim()] = $Matches[1] } }
    foreach ($snapshot in $snapshots) {
        $commit = (Invoke-Git $root @('rev-parse', ('refs/heads/' + $snapshot.PublishedBranch))).Trim()
        $snapshot.PublishedCommit = $commit
        $snapshot.RemoteVerified = $remoteMap.ContainsKey($snapshot.PublishedBranch) -and $remoteMap[$snapshot.PublishedBranch] -eq $commit
    }
}
$receipt = [ordered]@{run_id = $run; repository = $root; remote = $Remote; original_branch_count = $branches.Count;
    snapshots = $snapshots.ToArray(); excluded_file_count = $script:excludedFileCount;
    exclusions_format = 'One JSON array per line in exclusions-batches.jsonl'; worktree_failures = $failures.ToArray();
    push_requested = [bool]$Push; original_history_push = 'BLOCKED_BY_GITHUB_LFS_BUDGET';
    all_created_source_branches_verified = [bool]($Push -and @($snapshots | Where-Object { -not $_.RemoteVerified }).Count -eq 0)}
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'publication-receipt.json') -Encoding UTF8
Write-Output ('RECEIPT ' + (Join-Path $out 'publication-receipt.json'))
if ($Push -and -not $receipt.all_created_source_branches_verified) { exit 1 }

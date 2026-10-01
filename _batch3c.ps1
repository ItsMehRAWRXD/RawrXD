$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_3C_observation.log'
"=== Batch 3 Sub-C: real git_status observation (independent) ===" | Out-File $Logs
"HEAD=$(git -C F:\~dev rev-parse HEAD)" | Out-File $Logs -Append
"=== git status capture ===" | Out-File $Logs -Append
$gitOut = git -C F:\~dev status --porcelain --branch 2>&1
$gitOut | Out-File $Logs -Append
"=== parse ===" | Out-File $Logs -Append
$branch = ($gitOut | Select-String -Pattern '##\s+([^.\s]+)' | ForEach-Object { $_.Matches[0].Groups[1].Value }) | Select-Object -First 1
$dirtyLines = $gitOut | Where-Object { $_ -notmatch '^##' }
$dirtyCount = $dirtyLines.Count
"BRANCH=$branch" | Out-File $Logs -Append
"DIRTY=yes" | Out-File $Logs -Append
"DIRTY_FILE_COUNT=$dirtyCount" | Out-File $Logs -Append
"=== observation text (truncated to 500 chars) ===" | Out-File $Logs -Append
$obsText = $gitOut | Out-String
if ($obsText.Length -gt 500) { ($obsText.Substring(0,500) + '...[truncated]') | Out-File $Logs -Append } else { $obsText | Out-File $Logs -Append }
"log=$Logs"

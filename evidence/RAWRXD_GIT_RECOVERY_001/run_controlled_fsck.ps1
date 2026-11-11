$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$stdout = Join-Path $ev "fsck_${stamp}_stdout.txt"
$stderr = Join-Path $ev "fsck_${stamp}_stderr.txt"
$meta   = Join-Path $ev "fsck_${stamp}_meta.txt"
$latestOut = Join-Path $ev 'fsck_latest_stdout.txt'
$latestErr = Join-Path $ev 'fsck_latest_stderr.txt'
$latestMeta = Join-Path $ev 'fsck_latest_meta.txt'

# Also produce a no-reflogs companion after the primary scan completes.
$argsPrimary = @('-C', $repo, 'fsck', '--full', '--no-dangling', '--connectivity-only')
# Prefer full integrity first (user asked for complete integrity scan).
$gitArgs = @('-C', $repo, 'fsck', '--full')

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'git'
$psi.Arguments = ($gitArgs -join ' ')
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.WorkingDirectory = $repo

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$p = [System.Diagnostics.Process]::Start($psi)
$pidVal = $p.Id
"START=$(Get-Date -Format o)" | Set-Content -LiteralPath $meta -Encoding UTF8
"PID=$pidVal" | Add-Content -LiteralPath $meta -Encoding UTF8
"CMD=git $($gitArgs -join ' ')" | Add-Content -LiteralPath $meta -Encoding UTF8
"SCOPE=reachable_refs_and_objects_via_git_fsck_full_canonical_F_rawrxd" | Add-Content -LiteralPath $meta -Encoding UTF8
"NOTE=clean_fsck_does_not_prove_every_historical_object_ever_created_still_exists" | Add-Content -LiteralPath $meta -Encoding UTF8

$outTask = $p.StandardOutput.ReadToEndAsync()
$errTask = $p.StandardError.ReadToEndAsync()
$p.WaitForExit()
$sw.Stop()
$outText = $outTask.Result
$errText = $errTask.Result
$outText | Set-Content -LiteralPath $stdout -Encoding UTF8
$errText | Set-Content -LiteralPath $stderr -Encoding UTF8
Copy-Item -LiteralPath $stdout -Destination $latestOut -Force
Copy-Item -LiteralPath $stderr -Destination $latestErr -Force

"EXIT=$($p.ExitCode)" | Add-Content -LiteralPath $meta -Encoding UTF8
"ELAPSED_MS=$($sw.ElapsedMilliseconds)" | Add-Content -LiteralPath $meta -Encoding UTF8
"END=$(Get-Date -Format o)" | Add-Content -LiteralPath $meta -Encoding UTF8
"STDOUT_BYTES=$($outText.Length)" | Add-Content -LiteralPath $meta -Encoding UTF8
"STDERR_BYTES=$($errText.Length)" | Add-Content -LiteralPath $meta -Encoding UTF8
Copy-Item -LiteralPath $meta -Destination $latestMeta -Force

Write-Output "FSCK_PID=$pidVal"
Write-Output "FSCK_EXIT=$($p.ExitCode)"
Write-Output "FSCK_ELAPSED_MS=$($sw.ElapsedMilliseconds)"
Write-Output "STDOUT=$stdout"
Write-Output "STDERR=$stderr"
Write-Output "META=$meta"

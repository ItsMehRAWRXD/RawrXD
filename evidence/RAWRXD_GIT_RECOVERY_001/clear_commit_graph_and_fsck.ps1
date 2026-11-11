$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$info = Join-Path $repo '.git\objects\info'
$log = New-Object 'System.Collections.Generic.List[string]'
function L([string]$s) { [void]$log.Add($s); Write-Output $s }

L('=== commit-graph remediation ' + (Get-Date -Format o))

# Identify the three overflow commits before clearing cache.
$overflow = @(
  '1393940bf8206f638057bc5d90a5102b43f614a5',
  '45057c45c51ad6f27cf73697042e786494e47642',
  'b57a9880825e81dd44c218da23f920629afeafc3'
)
foreach ($oid in $overflow) {
  $type = (& git -C $repo cat-file -t $oid 2>&1 | Out-String).Trim()
  $parents = @(& git -C $repo rev-list --parents -n 1 $oid 2>&1)
  $refs = @(& git -C $repo for-each-ref --contains $oid --format='%(refname)' 2>&1 | Select-Object -First 12)
  L('OVERFLOW_OID=' + $oid)
  L('  type=' + $type)
  L('  rev-list-parents=' + (($parents | Select-Object -First 1) -join ' '))
  L('  parent_token_count=' + (($parents | Select-Object -First 1) -split '\s+').Count)
  L('  contains_refs=' + ($refs -join ';'))
}

# 1. Remove corrupted commit-graph file and/or directory.
$targets = @(
  (Join-Path $info 'commit-graph'),
  (Join-Path $info 'commit-graphs')
)
foreach ($t in $targets) {
  if (Test-Path -LiteralPath $t) {
    $item = Get-Item -LiteralPath $t -Force
    L('REMOVE_TARGET=' + $t + ' IsContainer=' + $item.PSIsContainer)
    if ($item.PSIsContainer) {
      Remove-Item -LiteralPath $t -Recurse -Force
    } else {
      Remove-Item -LiteralPath $t -Force
    }
    L('REMOVED_EXISTS_AFTER=' + (Test-Path -LiteralPath $t))
  } else {
    L('ABSENT=' + $t)
  }
}

# 2. fsck without commit-graph cache.
$stdout = Join-Path $ev 'fsck_nocg_stdout.txt'
$stderr = Join-Path $ev 'fsck_nocg_stderr.txt'
$meta = Join-Path $ev 'fsck_nocg_meta.txt'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'git'
$psi.Arguments = '-C "' + $repo + '" -c core.commitGraph=false fsck --full --no-commit-graph'
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = [Diagnostics.Process]::Start($psi)
$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()
$p.WaitForExit()
$sw.Stop()
$out | Set-Content -LiteralPath $stdout -Encoding UTF8
$err | Set-Content -LiteralPath $stderr -Encoding UTF8
@(
  'START_SCOPE=raw_object_db_without_commit_graph_cache',
  'PID=' + $p.Id,
  'EXIT=' + $p.ExitCode,
  'ELAPSED_MS=' + $sw.ElapsedMilliseconds,
  'STDOUT_BYTES=' + $out.Length,
  'STDERR_BYTES=' + $err.Length,
  'CMD=git -c core.commitGraph=false fsck --full --no-commit-graph',
  'CERT_NOTE=fsck_scope_limited_to_scanned_reachable_graph_not_every_historical_object_ever_created'
) | Set-Content -LiteralPath $meta -Encoding UTF8

$missing = ([regex]::Matches($out, 'missing\s+(?:blob|tree|commit|tag)\s+([0-9a-f]{40})')).Count
$dangling = ([regex]::Matches($out, '^dangling\s+', 'Multiline')).Count
$corrupt = ([regex]::Matches($out + "`n" + $err, '(?i)corrupt|sha1 mismatch|badObject')).Count
$graphErr = ([regex]::Matches($err, 'commit-graph parent list')).Count
L('FSCK_NOCG_EXIT=' + $p.ExitCode)
L('FSCK_NOCG_ELAPSED_MS=' + $sw.ElapsedMilliseconds)
L('FSCK_NOCG_MISSING_LINES=' + $missing)
L('FSCK_NOCG_DANGLING_LINES=' + $dangling)
L('FSCK_NOCG_CORRUPT_HITS=' + $corrupt)
L('FSCK_NOCG_COMMIT_GRAPH_ERRS=' + $graphErr)
L('FSCK_NOCG_STDERR=' + $err.Trim())

# Extract unique missing OIDs for next recovery pass.
$oids = New-Object 'System.Collections.Generic.List[string]'
foreach ($m in [regex]::Matches($out, 'missing\s+(?:blob|tree|commit|tag)\s+([0-9a-f]{40})')) {
  [void]$oids.Add($m.Groups[1].Value)
}
$unique = @($oids | Sort-Object -Unique)
$unique | Set-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') -Encoding UTF8
L('MISSING_UNIQUE_COUNT=' + $unique.Count)

$log | Set-Content -LiteralPath (Join-Path $ev 'commit_graph_remediation.txt') -Encoding UTF8

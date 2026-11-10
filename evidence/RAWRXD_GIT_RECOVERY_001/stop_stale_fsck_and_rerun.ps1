$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$log = New-Object 'System.Collections.Generic.List[string]'
function L([string]$s) { [void]$log.Add($s); Write-Output $s }

L('=== stop stale fsck + nocg rerun ' + (Get-Date -Format o))

Get-CimInstance Win32_Process -Filter "Name = 'git.exe'" | ForEach-Object {
  $cmd = [string]$_.CommandLine
  L('SEEN_PID=' + $_.ProcessId + ' CMD=' + $cmd)
  if ($cmd -match 'fsck' -and $cmd -notmatch 'fsmonitor') {
    try {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
      L('STOPPED_PID=' + $_.ProcessId)
    } catch {
      L('STOP_FAIL_PID=' + $_.ProcessId + ' ERR=' + $_.Exception.Message)
    }
  }
}
Start-Sleep -Seconds 2

# Confirm commit-graph cache remains absent.
$cg = Join-Path $repo '.git\objects\info\commit-graph'
$cgs = Join-Path $repo '.git\objects\info\commit-graphs'
L('commit-graph_exists=' + (Test-Path -LiteralPath $cg))
L('commit-graphs_exists=' + (Test-Path -LiteralPath $cgs))

$stdout = Join-Path $ev 'fsck_nocg_stdout.txt'
$stderr = Join-Path $ev 'fsck_nocg_stderr.txt'
$meta = Join-Path $ev 'fsck_nocg_meta.txt'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'git'
# This Git rejects --no-commit-graph; disable via config only.
$psi.Arguments = '-C "' + $repo + '" -c core.commitGraph=false fsck --full'
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = [Diagnostics.Process]::Start($psi)
L('FSCK_PID=' + $p.Id)
$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()
$p.WaitForExit()
$sw.Stop()
$out | Set-Content -LiteralPath $stdout -Encoding UTF8
$err | Set-Content -LiteralPath $stderr -Encoding UTF8

$missingMatches = [regex]::Matches($out, 'missing\s+(?:blob|tree|commit|tag)\s+([0-9a-f]{40})')
$oids = @($missingMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$dangling = ([regex]::Matches($out, '^dangling\s+', 'Multiline')).Count
$corrupt = ([regex]::Matches(($out + "`n" + $err), '(?i)corrupt|sha1 mismatch|badObject')).Count
$graphErr = ([regex]::Matches($err, 'commit-graph parent list')).Count

@(
  'SCOPE=reachable_refs_via_git_fsck_full_with_core.commitGraph=false',
  'PID=' + $p.Id,
  'EXIT=' + $p.ExitCode,
  'ELAPSED_MS=' + $sw.ElapsedMilliseconds,
  'STDOUT_BYTES=' + $out.Length,
  'STDERR_BYTES=' + $err.Length,
  'MISSING_UNIQUE=' + $oids.Count,
  'DANGLING_LINES=' + $dangling,
  'CORRUPT_HITS=' + $corrupt,
  'COMMIT_GRAPH_ERRS=' + $graphErr,
  'CERT_NOTE=fsck_scope_limited_to_scanned_reachable_graph_not_every_historical_object_ever_created'
) | Set-Content -LiteralPath $meta -Encoding UTF8

$oids | Set-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') -Encoding UTF8
L('FSCK_NOCG_EXIT=' + $p.ExitCode)
L('FSCK_NOCG_ELAPSED_MS=' + $sw.ElapsedMilliseconds)
L('FSCK_NOCG_MISSING_UNIQUE=' + $oids.Count)
L('FSCK_NOCG_DANGLING_LINES=' + $dangling)
L('FSCK_NOCG_CORRUPT_HITS=' + $corrupt)
L('FSCK_NOCG_COMMIT_GRAPH_ERRS=' + $graphErr)
L('FSCK_NOCG_STDERR=' + $err.Trim())
$log | Set-Content -LiteralPath (Join-Path $ev 'fsck_nocg_runlog.txt') -Encoding UTF8

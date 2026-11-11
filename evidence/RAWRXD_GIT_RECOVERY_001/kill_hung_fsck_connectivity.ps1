$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$log = New-Object 'System.Collections.Generic.List[string]'
function L([string]$s) { [void]$log.Add($s); Write-Output $s }

L('=== kill hung fsck; connectivity-only ' + (Get-Date -Format o))

Get-CimInstance Win32_Process -Filter "Name = 'git.exe'" | ForEach-Object {
  $cmd = [string]$_.CommandLine
  L('SEEN_PID=' + $_.ProcessId + ' CMD=' + $cmd)
  if ($cmd -match 'fsck' -and $cmd -notmatch 'fsmonitor') {
    try {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
      L('STOPPED_GIT_PID=' + $_.ProcessId)
    } catch {
      L('STOP_FAIL=' + $_.ProcessId)
    }
  }
}

# Also stop the parent recover_until_stable powershell if still running and stuck.
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | ForEach-Object {
  $cmd = [string]$_.CommandLine
  if ($cmd -match 'recover_until_stable\.ps1') {
    try {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
      L('STOPPED_PS_PID=' + $_.ProcessId)
    } catch {
      L('STOP_PS_FAIL=' + $_.ProcessId)
    }
  }
}

Start-Sleep -Seconds 3

# Fast missing detection: connectivity-only, no dangling enumeration.
$stdout = Join-Path $ev 'fsck_connectivity_stdout.txt'
$stderr = Join-Path $ev 'fsck_connectivity_stderr.txt'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'git'
$psi.Arguments = '-C "' + $repo + '" -c core.commitGraph=false fsck --connectivity-only --no-dangling'
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = [Diagnostics.Process]::Start($psi)
L('CONN_FSCK_PID=' + $p.Id)
$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()
$p.WaitForExit()
$sw.Stop()
$out | Set-Content -LiteralPath $stdout -Encoding UTF8
$err | Set-Content -LiteralPath $stderr -Encoding UTF8
$oids = @([regex]::Matches($out + "`n" + $err, 'missing\s+(?:blob|tree|commit|tag)\s+([0-9a-f]{40})') |
  ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
$oids | Set-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') -Encoding UTF8
L('CONN_FSCK_EXIT=' + $p.ExitCode)
L('CONN_FSCK_ELAPSED_MS=' + $sw.ElapsedMilliseconds)
L('CONN_FSCK_MISSING_UNIQUE=' + $oids.Count)
L('CONN_FSCK_STDERR=' + $err.Trim())
L('COMMIT_GRAPH_ERRS=' + ([regex]::Matches($err, 'commit-graph parent list')).Count)

# Confirm cache still absent.
L('commit-graph_exists=' + (Test-Path (Join-Path $repo '.git\objects\info\commit-graph')))
L('commit-graphs_exists=' + (Test-Path (Join-Path $repo '.git\objects\info\commit-graphs')))

$log | Set-Content -LiteralPath (Join-Path $ev 'connectivity_fsck_log.txt') -Encoding UTF8

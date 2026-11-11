$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$donors = @('G:\~dev\rawrxd', 'F:\~dev\rawrxd', 'G:\VSC0de\rawrxd')
$maxRounds = 8
$summary = New-Object 'System.Collections.Generic.List[string]'
function L([string]$s) { [void]$summary.Add($s); Write-Output $s }

function Invoke-FsckMissing {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'git'
  $psi.Arguments = '-C "' + $repo + '" -c core.commitGraph=false fsck --full --no-dangling'
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
  $oids = @([regex]::Matches($out, 'missing\s+(?:blob|tree|commit|tag)\s+([0-9a-f]{40})') |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
  return [pscustomobject]@{
    Exit = $p.ExitCode
    ElapsedMs = $sw.ElapsedMilliseconds
    Missing = $oids
    Stderr = $err.Trim()
    Stdout = $out
  }
}

function Recover-Oids($oids) {
  $need = New-Object 'System.Collections.Generic.List[string]'
  foreach ($oid in $oids) {
    & git -C $repo cat-file -e $oid 2>$null
    if ($LASTEXITCODE -ne 0) { [void]$need.Add($oid) }
  }
  $still = New-Object 'System.Collections.Generic.List[string]'
  foreach ($oid in $need) { [void]$still.Add($oid) }
  $recovered = 0
  foreach ($donor in $donors) {
    if ($still.Count -eq 0) { break }
    if (-not (Test-Path -LiteralPath $donor)) { continue }
    $have = New-Object 'System.Collections.Generic.List[string]'
    $remain = New-Object 'System.Collections.Generic.List[string]'
    foreach ($oid in $still) {
      & git -C $donor cat-file -e $oid 2>$null
      if ($LASTEXITCODE -eq 0) { [void]$have.Add($oid) } else { [void]$remain.Add($oid) }
    }
    L('DONOR=' + $donor + ' HAVE=' + $have.Count + ' LACK=' + $remain.Count)
    if ($have.Count -eq 0) { $still = $remain; continue }
    $safe = ($donor -replace '[^a-zA-Z0-9]', '_')
    $packFile = Join-Path $ev ('round_pack_' + $safe + '_' + [DateTime]::UtcNow.ToString('HHmmss') + '.pack')
    $packPsi = New-Object System.Diagnostics.ProcessStartInfo
    $packPsi.FileName = 'git'
    $packPsi.Arguments = '-C "' + $donor + '" pack-objects --stdout'
    $packPsi.RedirectStandardInput = $true
    $packPsi.RedirectStandardOutput = $true
    $packPsi.RedirectStandardError = $true
    $packPsi.UseShellExecute = $false
    $packPsi.CreateNoWindow = $true
    $packProc = [Diagnostics.Process]::Start($packPsi)
    foreach ($oid in $have) { $packProc.StandardInput.WriteLine($oid) }
    $packProc.StandardInput.Close()
    $fs = [IO.File]::Create($packFile)
    $packProc.StandardOutput.BaseStream.CopyTo($fs)
    $fs.Close()
    $packErr = $packProc.StandardError.ReadToEnd()
    $packProc.WaitForExit()
    $packLen = (Get-Item -LiteralPath $packFile).Length
    L('PACK_EXIT=' + $packProc.ExitCode + ' BYTES=' + $packLen + ' ERR=' + $packErr.Trim())
    if ($packLen -gt 32) {
      $unPsi = New-Object System.Diagnostics.ProcessStartInfo
      $unPsi.FileName = 'git'
      $unPsi.Arguments = '-C "' + $repo + '" unpack-objects -q'
      $unPsi.RedirectStandardInput = $true
      $unPsi.RedirectStandardOutput = $true
      $unPsi.RedirectStandardError = $true
      $unPsi.UseShellExecute = $false
      $unPsi.CreateNoWindow = $true
      $unProc = [Diagnostics.Process]::Start($unPsi)
      $inFs = [IO.File]::OpenRead($packFile)
      $inFs.CopyTo($unProc.StandardInput.BaseStream)
      $unProc.StandardInput.Close()
      $inFs.Close()
      [void]$unProc.StandardOutput.ReadToEnd()
      [void]$unProc.StandardError.ReadToEnd()
      $unProc.WaitForExit()
      L('UNPACK_EXIT=' + $unProc.ExitCode)
    }
    $still2 = New-Object 'System.Collections.Generic.List[string]'
    foreach ($oid in $still) {
      & git -C $repo cat-file -e $oid 2>$null
      if ($LASTEXITCODE -eq 0) { $recovered++ } else { [void]$still2.Add($oid) }
    }
    $still = $still2
  }
  return [pscustomobject]@{ Recovered = $recovered; Still = @($still) }
}

L('=== recover_until_stable ' + (Get-Date -Format o))
$oids = @(Get-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') | Where-Object { $_ -match '^[0-9a-f]{40}$' })
L('SEED_MISSING_COUNT=' + $oids.Count)

for ($round = 1; $round -le $maxRounds; $round++) {
  L('ROUND=' + $round + ' INPUT_MISSING=' + $oids.Count)
  if ($oids.Count -eq 0) { break }
  $rec = Recover-Oids $oids
  L('ROUND_RECOVERED=' + $rec.Recovered + ' STILL_UNAVAILABLE_IN_DONORS=' + $rec.Still.Count)
  $rec.Still | Set-Content -LiteralPath (Join-Path $ev 'still_missing.txt') -Encoding UTF8
  $fsck = Invoke-FsckMissing
  L('ROUND_FSCK_EXIT=' + $fsck.Exit + ' ELAPSED_MS=' + $fsck.ElapsedMs + ' MISSING=' + $fsck.Missing.Count)
  L('ROUND_FSCK_STDERR=' + $fsck.Stderr)
  $fsck.Missing | Set-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') -Encoding UTF8
  $oids = @($fsck.Missing)
  if ($oids.Count -eq 0) {
    L('STABLE_MISSING=0')
    break
  }
  # Stop if no progress against previous unique set size and donors exhausted.
  if ($rec.Recovered -eq 0 -and $rec.Still.Count -eq $oids.Count) {
    L('NO_PROGRESS_STOP')
    break
  }
}

# Rebuild commit-graph only when missing is zero OR explicitly after stable attempt.
$finalMissing = @(Get-Content (Join-Path $ev 'missing_objects.txt') -ErrorAction SilentlyContinue | Where-Object { $_ -match '^[0-9a-f]{40}$' })
if ($finalMissing.Count -eq 0) {
  L('COMMIT_GRAPH_WRITE_START')
  $cgOut = & git -C $repo -c core.commitGraph=true commit-graph write --reachable 2>&1 | Out-String
  L('COMMIT_GRAPH_WRITE_EXIT=' + $LASTEXITCODE)
  L('COMMIT_GRAPH_WRITE_OUT=' + $cgOut.Trim())
} else {
  L('COMMIT_GRAPH_WRITE_HELD missing=' + $finalMissing.Count)
}

L('FINAL_MISSING_COUNT=' + $finalMissing.Count)
L('PROMOTE=0')
$summary | Set-Content -LiteralPath (Join-Path $ev 'recover_until_stable_summary.txt') -Encoding UTF8

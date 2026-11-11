$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$donors = @(
  'G:\~dev\rawrxd',
  'F:\~dev\rawrxd',
  'G:\VSC0de\rawrxd'
)
$oids = @(Get-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') -ErrorAction SilentlyContinue)
$log = New-Object 'System.Collections.Generic.List[string]'
[void]$log.Add('=== missing object recovery ' + (Get-Date -Format o))
[void]$log.Add('MISSING_INPUT_COUNT=' + $oids.Count)

$recovered = 0
$stillMissing = New-Object 'System.Collections.Generic.List[string]'
$alreadyPresent = 0

foreach ($oid in $oids) {
  if (-not $oid) { continue }
  & git -C $repo cat-file -e ($oid + '^{object}') 2>$null
  if ($LASTEXITCODE -eq 0) {
    $alreadyPresent++
    [void]$log.Add('PRESENT ' + $oid)
    continue
  }
  $got = $false
  foreach ($donor in $donors) {
    if (-not (Test-Path -LiteralPath $donor)) { continue }
    & git -C $donor cat-file -e ($oid + '^{object}') 2>$null
    if ($LASTEXITCODE -ne 0) { continue }
    $bytes = & git -C $donor cat-file -p $oid 2>$null
    # Prefer git fetch object transfer via bundle-less stdin
    $tmp = Join-Path $ev ('obj_' + $oid + '.bin')
    & git -C $donor cat-file -s $oid 2>$null | Out-Null
    $type = (& git -C $donor cat-file -t $oid 2>$null | Out-String).Trim()
    if (-not $type) { continue }
    # Stream raw object into hash-object -w --stdin
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'git'
    $psi.Arguments = '-C "' + $donor + '" cat-file ' + $type + ' ' + $oid
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $ms = New-Object System.IO.MemoryStream
    $p.StandardOutput.BaseStream.CopyTo($ms)
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { continue }
    $rawBytes = $ms.ToArray()
    $psi2 = New-Object System.Diagnostics.ProcessStartInfo
    $psi2.FileName = 'git'
    $psi2.Arguments = '-C "' + $repo + '" hash-object -t ' + $type + ' -w --stdin'
    $psi2.RedirectStandardInput = $true
    $psi2.RedirectStandardOutput = $true
    $psi2.RedirectStandardError = $true
    $psi2.UseShellExecute = $false
    $psi2.CreateNoWindow = $true
    $p2 = [Diagnostics.Process]::Start($psi2)
    $p2.StandardInput.BaseStream.Write($rawBytes, 0, $rawBytes.Length)
    $p2.StandardInput.Close()
    $written = $p2.StandardOutput.ReadToEnd().Trim()
    $p2.WaitForExit()
    if ($p2.ExitCode -eq 0 -and $written -eq $oid) {
      $recovered++
      $got = $true
      [void]$log.Add('RECOVERED ' + $oid + ' type=' + $type + ' donor=' + $donor)
      break
    } else {
      [void]$log.Add('WRITE_FAIL ' + $oid + ' donor=' + $donor + ' wrote=' + $written + ' exit=' + $p2.ExitCode)
    }
  }
  if (-not $got) {
    [void]$stillMissing.Add($oid)
    [void]$log.Add('UNRECOVERED ' + $oid)
  }
}

[void]$log.Add('ALREADY_PRESENT=' + $alreadyPresent)
[void]$log.Add('RECOVERED_COUNT=' + $recovered)
[void]$log.Add('STILL_MISSING_COUNT=' + $stillMissing.Count)
$stillMissing | Set-Content -LiteralPath (Join-Path $ev 'still_missing.txt') -Encoding UTF8
$log | Set-Content -LiteralPath (Join-Path $ev 'recovery_log.txt') -Encoding UTF8
$log | Select-Object -Last 60

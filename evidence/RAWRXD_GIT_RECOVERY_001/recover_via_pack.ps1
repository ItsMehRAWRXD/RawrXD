$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$donors = @('G:\~dev\rawrxd', 'F:\~dev\rawrxd', 'G:\VSC0de\rawrxd')
$oids = @(Get-Content -LiteralPath (Join-Path $ev 'missing_objects.txt') | Where-Object { $_ -match '^[0-9a-f]{40}$' })
$logPath = Join-Path $ev 'recovery_log.txt'
$lines = New-Object 'System.Collections.Generic.List[string]'
[void]$lines.Add('=== pack recovery ' + (Get-Date -Format o))
[void]$lines.Add('MISSING_INPUT_COUNT=' + $oids.Count)

$seed = 'ae5bcf93cdf1504412826147509691ebc4689a77'
if ($oids -notcontains $seed) { $oids = @($seed) + $oids }

$present = 0
$need = New-Object 'System.Collections.Generic.List[string]'
foreach ($oid in $oids) {
  & git -C $repo cat-file -e $oid 2>$null
  if ($LASTEXITCODE -eq 0) { $present++; [void]$lines.Add('PRESENT ' + $oid) }
  else { [void]$need.Add($oid) }
}
[void]$lines.Add('ALREADY_PRESENT=' + $present)
[void]$lines.Add('NEED_COUNT=' + $need.Count)

$still = New-Object 'System.Collections.Generic.List[string]'
foreach ($oid in $need) { [void]$still.Add($oid) }

foreach ($donor in $donors) {
  if ($still.Count -eq 0) { break }
  if (-not (Test-Path -LiteralPath $donor)) {
    [void]$lines.Add('DONOR_MISSING ' + $donor)
    continue
  }
  $have = New-Object 'System.Collections.Generic.List[string]'
  $remain = New-Object 'System.Collections.Generic.List[string]'
  foreach ($oid in $still) {
    & git -C $donor cat-file -e $oid 2>$null
    if ($LASTEXITCODE -eq 0) { [void]$have.Add($oid) }
    else { [void]$remain.Add($oid) }
  }
  [void]$lines.Add('DONOR=' + $donor + ' HAVE=' + $have.Count + ' LACK=' + $remain.Count)
  if ($have.Count -eq 0) { $still = $remain; continue }

  $safe = ($donor -replace '[^a-zA-Z0-9]', '_')
  $listFile = Join-Path $ev ('pack_oids_' + $safe + '.txt')
  $have | Set-Content -LiteralPath $listFile -Encoding ASCII
  $packFile = Join-Path $ev ('recovery_' + $safe + '.pack')

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
  [void]$lines.Add('PACK_EXIT=' + $packProc.ExitCode + ' BYTES=' + $packLen + ' ERR=' + $packErr.Trim())

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
    $unOut = $unProc.StandardOutput.ReadToEnd()
    $unErr = $unProc.StandardError.ReadToEnd()
    $unProc.WaitForExit()
    [void]$lines.Add('UNPACK_EXIT=' + $unProc.ExitCode + ' OUT=' + $unOut.Trim() + ' ERR=' + $unErr.Trim())
  }

  $still2 = New-Object 'System.Collections.Generic.List[string]'
  foreach ($oid in $still) {
    & git -C $repo cat-file -e $oid 2>$null
    if ($LASTEXITCODE -eq 0) { [void]$lines.Add('RECOVERED ' + $oid) }
    else { [void]$still2.Add($oid) }
  }
  $still = $still2
  [void]$lines.Add('STILL_AFTER_' + $donor + '=' + $still.Count)
}

[void]$lines.Add('STILL_MISSING_COUNT=' + $still.Count)
$still | Set-Content -LiteralPath (Join-Path $ev 'still_missing.txt') -Encoding UTF8
$lines | Set-Content -LiteralPath $logPath -Encoding UTF8
'STILL_MISSING_COUNT=' + $still.Count
'ALREADY_PRESENT=' + $present
$lines | Select-Object -Last 50

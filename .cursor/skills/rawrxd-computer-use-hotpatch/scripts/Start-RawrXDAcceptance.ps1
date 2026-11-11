param(
  [Parameter(Mandatory=$true)][string]$ExePath,
  [Parameter(Mandatory=$true)][string]$ExpectedSha256,
  [string]$EvidenceRoot = "$env:USERPROFILE\RawrXD-Acceptance",
  [string]$WorkingDirectory = ""
)
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $ExePath -ErrorAction Stop).Path
if (!(Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Executable not found: $resolved" }
$actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToUpperInvariant()
$expected = $ExpectedSha256.ToUpperInvariant()
if ($actual -ne $expected) { throw "HASH MISMATCH expected=$expected actual=$actual" }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$dir = Join-Path $EvidenceRoot "routing_$stamp"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$wd = if ($WorkingDirectory) { (Resolve-Path -LiteralPath $WorkingDirectory).Path } else { Split-Path -Parent $resolved }
$proc = Start-Process -FilePath $resolved -WorkingDirectory $wd -PassThru
Start-Sleep -Seconds 3
$proc.Refresh(); $alive = -not $proc.HasExited
$receipt = [ordered]@{
  schema='RAWRXD_ROUTING_LAUNCH_001'; timestamp=(Get-Date).ToString('o');
  executable=$resolved; sha256=$actual; pid=$proc.Id; alive=$alive;
  working_directory=$wd; agent_model_routing='UNVERIFIED'; ghosttext_routing='UNVERIFIED';
  cancellation_recovery='UNVERIFIED'; PROMOTE=0; CERTIFIED=0; T25='HELD'
}
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $dir 'launch-receipt.json') -Encoding UTF8
Write-Output "Evidence: $dir"; Write-Output "PID: $($proc.Id) alive=$alive"
if (!$alive) { throw 'IDE exited before GUI acceptance' }

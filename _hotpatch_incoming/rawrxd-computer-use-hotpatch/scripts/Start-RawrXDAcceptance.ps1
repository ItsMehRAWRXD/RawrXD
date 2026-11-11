# Hash-locked IDE launcher. Rejects mismatched SHA-256. PROMOTE=0 CERTIFIED=0.
param(
  [Parameter(Mandatory = $true)][string]$ExePath,
  [Parameter(Mandatory = $true)][string]$ExpectedSha256,
  [string]$EvidenceRoot = "$env:USERPROFILE\RawrXD-Acceptance",
  [switch]$HashCheckOnly,
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $ExePath -PathType Leaf)) {
  throw "Executable not found: $ExePath"
}
$actual = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
if ($actual -ine $ExpectedSha256) {
  throw "HASH MISMATCH expected=$ExpectedSha256 actual=$actual"
}
Write-Host "HASH_OK sha256=$actual"
if ($HashCheckOnly -or $DryRun) {
  Write-Host 'HASH_CHECK_ONLY=1 launch skipped'
  exit 0
}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$dir = Join-Path $EvidenceRoot "routing_$stamp"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$proc = Start-Process -FilePath $ExePath -WorkingDirectory (Split-Path $ExePath -Parent) -PassThru
Start-Sleep -Seconds 3
$proc.Refresh()
$alive = -not $proc.HasExited
$receipt = [ordered]@{
  timestamp               = (Get-Date).ToString('o')
  executable              = $ExePath
  sha256                  = $actual
  pid                     = $proc.Id
  alive                   = $alive
  agent_model_routing     = 'UNVERIFIED'
  ghosttext_routing       = 'UNVERIFIED'
  cancellation_recovery   = 'UNVERIFIED'
  PROMOTE                 = 0
  CERTIFIED               = 0
  T25                     = 'HELD'
  ROUTING_E2E             = 'NOT_CERTIFIED'
}
$receipt | ConvertTo-Json -Depth 5 |
  Set-Content -LiteralPath (Join-Path $dir 'launch-receipt.json') -Encoding UTF8
Write-Host "Evidence: $dir"
Write-Host "PID: $($proc.Id) alive=$alive"
if (!$alive) { throw 'IDE exited before GUI acceptance' }
Write-Host 'GUI acceptance remains UNVERIFIED. Collect correlated outbound Ollama request identities.'

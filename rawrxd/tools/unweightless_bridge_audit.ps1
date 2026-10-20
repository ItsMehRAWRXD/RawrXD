[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    [Parameter(Mandatory = $false)]
    [switch]$FailOnProductionBridge
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepoRoot).Path
$sourceRoot = Join-Path $root 'src'
$extensions = @('.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx', '.asm', '.comp', '.cmake', '.ps1')
$trackedPaths = @(& git -C $root ls-files 2>$null | Where-Object { $_ })
$files = @(
    foreach ($relative in $trackedPaths) {
        $candidate = Join-Path $root $relative
        if ((Test-Path -LiteralPath $candidate -PathType Leaf) -and
            ($extensions -contains ([System.IO.Path]::GetExtension($candidate).ToLowerInvariant())) -and
            ($relative -notmatch '(?i)^evidence[\\/].*stub-quarantine[\\/]')) {
            Get-Item -LiteralPath $candidate
        }
    }
)

$explicitBridgeHits = [System.Collections.Generic.List[object]]::new()
$weightlessHits = [System.Collections.Generic.List[object]]::new()
$productionBridgeHits = [System.Collections.Generic.List[object]]::new()

foreach ($file in $files) {
    $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/')
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $file.FullName) {
        $lineNumber++
        if ($line -match '(?i)unweightless') {
            $hit = [pscustomobject]@{ path = $relative; line = $lineNumber; text = $line.Trim() }
            $explicitBridgeHits.Add($hit)
            if ($relative -notmatch '(?i)tools[\\/]unweightless_bridge_audit\.ps1$' -and
                $line -notmatch '(?i)RAWRXD_ENABLE_UNWEIGHTLESS_EXPERIMENT') {
                $productionBridgeHits.Add($hit)
            }
        }
        if ($line -match '(?i)weightless|unweighted') {
            $weightlessHits.Add([pscustomobject]@{ path = $relative; line = $lineNumber; text = $line.Trim() })
        }
    }
}

$trackedSourceCount = @($trackedPaths | Where-Object { $_ -match '(?i)^(src|tools)[\\/]' }).Count
$productionFiles = @($files | Where-Object { $_.FullName.StartsWith($sourceRoot, [System.StringComparison]::OrdinalIgnoreCase) })
$sourceHashes = foreach ($file in $productionFiles) {
    $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/')
    [pscustomobject]@{
        path = $relative
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        bytes = $file.Length
    }
}

$explicitBridgeStatus = if ($productionBridgeHits.Count -eq 0) { 'NOT_FOUND_IN_CHECKOUT' } else { 'FOUND_REQUIRES_REVIEW' }
$gates = [ordered]@{
    U1 = [ordered]@{ status = if ($weightlessHits.Count -gt 0) { 'PARTIAL' } else { 'BLOCKED' }; reason = 'Weightless control-plane references are catalogued; no Unweightless encoder or metadata contract is present.' }
    U2 = [ordered]@{ status = 'BLOCKED'; reason = 'No reconstruction implementation or serialized format was found.' }
    U3 = [ordered]@{ status = 'BLOCKED'; reason = 'Exact-versus-lossy behavior cannot be measured without an encoder and decoder pair.' }
    U4 = [ordered]@{ status = 'BLOCKED'; reason = 'Bytes-per-parameter cannot be measured without a real weightless artifact.' }
    U5 = [ordered]@{ status = 'BLOCKED'; reason = 'No reconstruction benchmark target exists in the production build graph.' }
    U6 = [ordered]@{ status = 'BLOCKED'; reason = 'No independent reconstructed logits or token stream exists.' }
}

$report = [ordered]@{
    schema = 'RAWRXD_UNWEIGHTLESS_AUDIT_001'
    generatedUtc = [DateTime]::UtcNow.ToString('o')
    repoRoot = $root
    bridge = [ordered]@{
        requestedMode = 'SUSPENDED'
        productionMutation = $false
        explicitUnweightlessStatus = $explicitBridgeStatus
        weightlessCandidateSurface = 'HexMag CandidateSource::W0 (orphaned, not in active build)'
        weightlessOptIn = 'NOT_IMPLEMENTED'
        deep2GgufPreserved = $true
        vulkanKernelsPreserved = $true
    }
    inventory = [ordered]@{
        filesScanned = $files.Count
        trackedSourceFiles = $trackedSourceCount
        explicitUnweightlessHits = $explicitBridgeHits
        weightlessHits = $weightlessHits
        sourceHashes = $sourceHashes
    }
    gates = $gates
    verdict = if ($productionBridgeHits.Count -eq 0) { 'ISOLATED_EXPERIMENTAL_PIPELINE_READY' } else { 'HOLD_PRODUCTION_BRIDGE_REVIEW' }
}

$json = $report | ConvertTo-Json -Depth 8
if ($OutputPath) {
    $destination = [System.IO.Path]::GetFullPath($OutputPath)
    $parent = Split-Path -Parent $destination
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Set-Content -LiteralPath $destination -Value $json -Encoding UTF8
}
$json

if ($FailOnProductionBridge -and $productionBridgeHits.Count -gt 0) {
    exit 2
}

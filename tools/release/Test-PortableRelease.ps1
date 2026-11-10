#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$PackageDirectory,
      [Parameter(Mandatory = $true)][string]$EvidenceDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseHash.ps1')
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Use a new evidence directory.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$fixture = Join-Path $EvidenceDirectory 'tamper-fixture'
New-Item -ItemType Directory -Path $fixture | Out-Null
$manifestPath = Join-Path $fixture 'manifest.json'
$original = Get-Content -LiteralPath (Join-Path $PackageDirectory 'manifest.json') -Raw
$manifest = $original | ConvertFrom-Json
$tests = @()
function Assert-Rejected([string]$Name, [scriptblock]$Test) {
    $rejected = $false
    try { & $Test | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "$Name was incorrectly accepted." }
    [pscustomobject]@{name = $Name; status = 'PASS'}
}
& (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $PackageDirectory | Out-Null
$tests += [pscustomobject]@{name = 'original-payload-integrity'; status = 'PASS'}
# All corruption is confined to a new fixture; no release payload is modified.
foreach ($entry in $manifest.files) {
    Copy-Item -LiteralPath (Join-Path $PackageDirectory $entry.path) -Destination $fixture
}
$original | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$readmePath = Join-Path $fixture 'README.md'
$readmeBytes = [IO.File]::ReadAllBytes($readmePath)
$changedBytes = [byte[]]$readmeBytes.Clone()
$changedBytes[0] = $changedBytes[0] -bxor 1
[IO.File]::WriteAllBytes($readmePath, $changedBytes)
$tests += Assert-Rejected 'same-length-payload-corruption' {
    & (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $fixture
}
[IO.File]::WriteAllBytes($readmePath, $readmeBytes)
$manifest.ide_sha256 = '0' * 64
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$tests += Assert-Rejected 'binary-identity-mismatch' {
    & (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $fixture
}
$manifest = $original | ConvertFrom-Json
$manifest.files = @($manifest.files | Where-Object { $_.path -ne 'deep2_agentic_loop.exe' })
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$tests += Assert-Rejected 'omitted-required-sidecar' {
    & (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $fixture
}
$manifest = $original | ConvertFrom-Json
$manifest.files[0].path = '..\outside-payload.exe'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$tests += Assert-Rejected 'manifest-path-escape' {
    & (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $fixture
}
$manifest = $original | ConvertFrom-Json
$manifest.files = @($manifest.files) + @($manifest.files[0])
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$tests += Assert-Rejected 'duplicate-manifest-entry' {
    & (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $fixture
}
$original | Set-Content -LiteralPath $manifestPath -Encoding UTF8
& (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $fixture | Out-Null
$tests += [pscustomobject]@{name = 'restored-fixture-integrity'; status = 'PASS'}
$receipt = [ordered]@{ tested_utc = [DateTime]::UtcNow.ToString('o');
    ide_sha256 = $manifest.ide_sha256; package = (Resolve-Path -LiteralPath $PackageDirectory).Path;
    tests = $tests; result = 'PASS'; test_count = $tests.Count }
$receipt | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'integrity-tests.json') -Encoding UTF8
$tests

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourcePackage,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$ExpectedIdeSha256 = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6',
    [string]$RuntimeDirectory = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Redist\MSVC\14.44.35112\x64\Microsoft.VC143.CRT'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseHash.ps1')
$source = (Resolve-Path -LiteralPath $SourcePackage).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw "Output already exists: $output" }
if ($ExpectedIdeSha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'A full SHA-256 is required.' }
$ideName = 'RawrXD-Win32IDE-Native-Ext.exe'
$ide = Join-Path $source $ideName
if ((Get-FileHash -LiteralPath $ide -Algorithm SHA256).Hash -ne $ExpectedIdeSha256) {
    throw 'Source IDE SHA does not match the requested release.'
}
$payload = @($ideName, 'deep2_agentic_loop.exe')
foreach ($name in $payload) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) {
        throw "Missing product binary: $name"
    }
}
$runtime = @('msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll')
foreach ($name in $runtime) {
    if (-not (Test-Path -LiteralPath (Join-Path $RuntimeDirectory $name) -PathType Leaf)) {
        throw "Missing redistributable runtime: $name"
    }
}
New-Item -ItemType Directory -Path $output | Out-Null
foreach ($name in $payload) { Copy-Item -LiteralPath (Join-Path $source $name) -Destination $output }
foreach ($name in $runtime) { Copy-Item -LiteralPath (Join-Path $RuntimeDirectory $name) -Destination $output }
foreach ($name in @('Start-RawrXD.ps1', 'Verify-PortableRelease.ps1', 'ReleaseHash.ps1', 'README.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $output
}
$revision = (& git -C (Join-Path $PSScriptRoot '..\..') rev-parse HEAD | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot record packaging checkout revision.' }
$entries = @(Get-ChildItem -LiteralPath $output -File | Sort-Object Name | ForEach-Object {
    [ordered]@{ path = $_.Name; size_bytes = $_.Length;
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
$manifest = [ordered]@{
    schema_version = 1
    package_status = 'RELEASE_CANDIDATE'
    created_utc = [DateTime]::UtcNow.ToString('o')
    ide_sha256 = $ExpectedIdeSha256.ToUpperInvariant()
    source_package = $source
    packaging_checkout_revision = $revision
    binary_source_revision = 'NOT_ESTABLISHED_BY_PACKAGING'
    freeze_control = 'DEFERRED_NON_BLOCKING'
    files = $entries
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'manifest.json') -Encoding UTF8
$checksumEntries = @($entries) + @([ordered]@{ path = 'manifest.json';
    sha256 = (Get-FileHash -LiteralPath (Join-Path $output 'manifest.json') -Algorithm SHA256).Hash })
$checksumEntries | ForEach-Object { '{0}  {1}' -f $_.sha256, $_.path } |
    Set-Content -LiteralPath (Join-Path $output 'checksums.sha256') -Encoding ASCII
& (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $output

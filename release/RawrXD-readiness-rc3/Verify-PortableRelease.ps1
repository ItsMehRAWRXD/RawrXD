#Requires -Version 5.1
[CmdletBinding()]
param([string]$PackageDirectory = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseHash.ps1')
$root = (Resolve-Path -LiteralPath $PackageDirectory).Path.TrimEnd('\')
$manifest = Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or @($manifest.files).Count -eq 0) {
    throw 'Missing or unsupported release manifest.'
}
$seen = @{}
foreach ($entry in $manifest.files) {
    $relative = [string]$entry.path
    $path = [IO.Path]::GetFullPath((Join-Path $root $relative))
    if ([IO.Path]::IsPathRooted($relative) -or
        -not $path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $seen.ContainsKey($relative)) { throw "Invalid manifest path: $relative" }
    $seen[$relative] = $true
    $file = Get-Item -LiteralPath $path
    if ($file.Length -ne $entry.size_bytes -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.sha256) {
        throw "Release integrity check failed: $relative"
    }
}
foreach ($required in @('RawrXD-Win32IDE-Native-Ext.exe', 'deep2_agentic_loop.exe',
                       'Start-RawrXD.ps1', 'Verify-PortableRelease.ps1', 'ReleaseHash.ps1', 'README.md',
                       'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll')) {
    if (-not $seen.ContainsKey($required)) { throw "Required file omitted: $required" }
}
$ideSha = (Get-FileHash -LiteralPath (Join-Path $root 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
if ($ideSha -ne $manifest.ide_sha256) { throw 'IDE identity does not match release metadata.' }
[pscustomobject]@{ Integrity = 'PASS'; IdeSha256 = $ideSha; FilesVerified = $seen.Count; Package = $root }

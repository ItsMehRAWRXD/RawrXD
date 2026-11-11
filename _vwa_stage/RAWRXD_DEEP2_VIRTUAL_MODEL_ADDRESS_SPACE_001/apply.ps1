# Fail-closed source overlay. Must be run from a Git working tree with the
# audited VWA file blobs present. No checkout/reset/force/commit/push/deletion.
param(
    [Parameter(Mandatory=$true)][string]$RepositoryRoot
)
$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $sourceRoot 'src/deep2/vwa'
$dst = Join-Path $RepositoryRoot 'src/deep2/vwa'
if (!(Test-Path (Join-Path $RepositoryRoot '.git'))) {
    throw 'Not a Git checkout root; refusing to copy anything.'
}
if (!(Test-Path $dst)) { throw 'Canonical VWA directory absent; refusing to create parallel implementation.' }
$expected = [ordered]@{
    'VwaTypes.hpp' = '1ebb26ad0433144b96d7638c393ca70addf36972'
    'VwaSpace.hpp' = '408e40b0d6d11063d9268aace288f135e48e6fa5'
    'VwaCoalesce.hpp' = '04ce573a4d3fc99a5a9ae473b7a57169501772eb'
    'VwaScheduler.hpp' = 'dd3e38e6c3062fc73f11022048529cb606150e26'
    'VwaScheduler_Lease.cpp' = '0dd27da962087d31f41d8354fd7407d80eacebfa'
    'VwaScheduler_Fulfill.cpp' = 'ed0b2e0c76cf9feabcc7234793ccd1428a4ae16b'
}
# Verify every target before a single write. Avoid touching concurrent edits.
foreach ($name in $expected.Keys) {
    $rel = "src/deep2/vwa/$name"
    if (!(Test-Path (Join-Path $dst $name))) { throw "Missing target: $rel" }
    if (!(Test-Path (Join-Path $src $name))) { throw "Missing source: $name" }
    $headBlob = (& git -C $RepositoryRoot rev-parse "HEAD:$rel" 2>$null | Select-Object -First 1).Trim()
    if ($LASTEXITCODE -ne 0 -or $headBlob -ne $expected[$name]) {
        throw "Changed source lineage for $rel (found $headBlob, expected $($expected[$name])). No files copied."
    }
    $dirty = & git -C $RepositoryRoot status --porcelain -- $rel
    if ($dirty) { throw "Dirty target: $rel. No files copied." }
}
foreach ($name in @('VwaIrResidency.hpp','VwaGeneratedBridge.hpp')) {
    if (Test-Path (Join-Path $dst $name)) { throw "Destination already exists: $name. No files copied." }
}
$backup = Join-Path $RepositoryRoot ("evidence/RAWRXD_DEEP2_VIRTUAL_MODEL_ADDRESS_SPACE_001/source_backup_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Force -Path $backup | Out-Null
foreach ($name in $expected.Keys) { Copy-Item (Join-Path $dst $name) (Join-Path $backup $name) }
foreach ($name in $expected.Keys) { Copy-Item (Join-Path $src $name) (Join-Path $dst $name) }
foreach ($name in @('VwaIrResidency.hpp','VwaGeneratedBridge.hpp')) { Copy-Item (Join-Path $src $name) (Join-Path $dst $name) }
Write-Output "SOURCE_OVERLAY=APPLIED"
Write-Output "BACKUP=$backup"
Write-Output "COMMITTED=0"
Write-Output 'NEXT=Copy the two tests into repo/tests, compile them, then integrate with live Deep2 op loop.'

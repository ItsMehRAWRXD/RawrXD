$ErrorActionPreference = 'Stop'
$src = 'F:\rawrxd\release\RawrXD-readiness-rc3'
$dst = 'F:\rawrxd\release\RawrXD-readiness-rc4'
$cand = 'F:\rawrxd\evidence\IDE_RELEASE_READINESS_001\candidate_source_004'
New-Item -ItemType Directory -Force -Path $dst, $cand | Out-Null
Copy-Item -Force (Join-Path $src '*') $dst
$exeSrc = 'F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe'
$loopSrc = 'F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe'
Copy-Item -Force $exeSrc (Join-Path $dst 'RawrXD-Win32IDE-Native-Ext.exe')
Copy-Item -Force $exeSrc (Join-Path $cand 'RawrXD-Win32IDE-Native-Ext.exe')
if (Test-Path $loopSrc) {
    Copy-Item -Force $loopSrc (Join-Path $dst 'deep2_agentic_loop.exe')
    Copy-Item -Force $loopSrc (Join-Path $cand 'deep2_agentic_loop.exe')
}
function Get-Sha256([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
$ide = Get-Sha256 (Join-Path $dst 'RawrXD-Win32IDE-Native-Ext.exe')
$loop = Get-Sha256 (Join-Path $dst 'deep2_agentic_loop.exe')
$certPath = 'F:\rawrxd\release\RawrXD-4DE06F9F-rc1\RawrXD-Win32IDE-Native-Ext.exe'
$cert = Get-Sha256 $certPath
$expected = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
Write-Output "IDE_SHA=$ide"
Write-Output "LOOP_SHA=$loop"
Write-Output "CERT_SHA=$cert"
Write-Output "CERT_MATCH=$($cert -eq $expected)"

# Refresh checksums.sha256 for all package files
$lines = @()
Get-ChildItem -LiteralPath $dst -File | Sort-Object Name | ForEach-Object {
    $lines += "$(Get-Sha256 $_.FullName)  $($_.Name)"
}
$lines | Set-Content -LiteralPath (Join-Path $dst 'checksums.sha256') -Encoding ascii

$files = @()
Get-ChildItem -LiteralPath $dst -File | Where-Object { $_.Name -ne 'manifest.json' } | Sort-Object Name | ForEach-Object {
    $files += [ordered]@{
        path = $_.Name
        size_bytes = $_.Length
        sha256 = (Get-Sha256 $_.FullName)
    }
}
$manifest = [ordered]@{
    schema_version = 1
    package_status = 'RELEASE_CANDIDATE'
    created_utc = (Get-Date).ToUniversalTime().ToString('o')
    ide_sha256 = $ide
    deep2_agentic_loop_sha256 = $loop
    source_package = $cand
    packaging_note = 'Computer Use integrated; Ctrl+S/O, --user-data-dir, Deep2 join included from tip lineage'
    freeze_control = 'DEFERRED_NON_BLOCKING'
    promote = 0
    tip_climb = 'HOLD'
    certified_4de0_untouched = ($cert -eq $expected)
    computer_use = 'SOURCE_WIRED'
    files = $files
}
($manifest | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $dst 'manifest.json') -Encoding utf8
# Re-hash after manifest write
$lines = @()
Get-ChildItem -LiteralPath $dst -File | Sort-Object Name | ForEach-Object {
    $lines += "$(Get-Sha256 $_.FullName)  $($_.Name)"
}
$lines | Set-Content -LiteralPath (Join-Path $dst 'checksums.sha256') -Encoding ascii
Write-Output "PACKAGE=$dst"
Write-Output "DONE"

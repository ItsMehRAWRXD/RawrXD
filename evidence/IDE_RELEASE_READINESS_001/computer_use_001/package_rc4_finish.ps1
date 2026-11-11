$ErrorActionPreference = 'Stop'
$dst = 'F:\rawrxd\release\RawrXD-readiness-rc4'
$cand = 'F:\rawrxd\evidence\IDE_RELEASE_READINESS_001\candidate_source_004'
$exeSrc = 'F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe'
$loopSrc = 'F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe'
New-Item -ItemType Directory -Force -Path $dst, $cand | Out-Null
Copy-Item -Force $exeSrc (Join-Path $dst 'RawrXD-Win32IDE-Native-Ext.exe')
Copy-Item -Force $exeSrc (Join-Path $cand 'RawrXD-Win32IDE-Native-Ext.exe')
Copy-Item -Force $loopSrc (Join-Path $dst 'deep2_agentic_loop.exe')
Copy-Item -Force $loopSrc (Join-Path $cand 'deep2_agentic_loop.exe')
foreach ($name in @('msvcp140.dll','vcruntime140.dll','vcruntime140_1.dll','README.md','ReleaseHash.ps1','Start-RawrXD.ps1','Verify-PortableRelease.ps1')) {
    $from = Join-Path 'F:\rawrxd\release\RawrXD-readiness-rc3' $name
    if (Test-Path -LiteralPath $from) { Copy-Item -Force $from (Join-Path $dst $name) }
}
$sha = [Security.Cryptography.SHA256]::Create()
function FileSha([string]$path) {
    $fs = [IO.File]::OpenRead($path)
    try {
        return ([BitConverter]::ToString($script:sha.ComputeHash($fs)).Replace('-',''))
    } finally { $fs.Dispose() }
}
$ide = FileSha (Join-Path $dst 'RawrXD-Win32IDE-Native-Ext.exe')
$loop = FileSha (Join-Path $dst 'deep2_agentic_loop.exe')
$cert = FileSha 'F:\rawrxd\release\RawrXD-4DE06F9F-rc1\RawrXD-Win32IDE-Native-Ext.exe'
"IDE_SHA=$ide" | Write-Output
"LOOP_SHA=$loop" | Write-Output
"CERT_SHA=$cert" | Write-Output
"CERT_MATCH=$($cert -eq '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6')" | Write-Output

$files = New-Object System.Collections.Generic.List[object]
Get-ChildItem -LiteralPath $dst -File | Where-Object { $_.Name -ne 'manifest.json' -and $_.Name -ne 'checksums.sha256' } | Sort-Object Name | ForEach-Object {
    $files.Add([ordered]@{ path=$_.Name; size_bytes=$_.Length; sha256=(FileSha $_.FullName) })
}
$manifestObj = [ordered]@{
    schema_version = 1
    package_status = 'RELEASE_CANDIDATE'
    created_utc = (Get-Date).ToUniversalTime().ToString('o')
    ide_sha256 = $ide
    deep2_agentic_loop_sha256 = $loop
    source_package = $cand
    packaging_note = 'Computer Use integrated into new candidate; 4DE0 package untouched'
    freeze_control = 'DEFERRED_NON_BLOCKING'
    promote = 0
    tip_climb = 'HOLD'
    certified_4de0_untouched = ($cert -eq '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6')
    computer_use = 'SOURCE_WIRED'
    files = $files
}
$json = $manifestObj | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText((Join-Path $dst 'manifest.json'), $json)
$check = New-Object System.Collections.Generic.List[string]
Get-ChildItem -LiteralPath $dst -File | Sort-Object Name | ForEach-Object {
    $check.Add("$(FileSha $_.FullName)  $($_.Name)")
}
[IO.File]::WriteAllLines((Join-Path $dst 'checksums.sha256'), $check)
"PACKAGE=$dst" | Write-Output
"DONE" | Write-Output
$sha.Dispose()

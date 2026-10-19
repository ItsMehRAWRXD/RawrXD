param(
    [string]$RepoRoot = 'G:\~dev\rawrxd',
    [string]$ZipPath = "$env:USERPROFILE\Downloads\DEEP2_DUAL_AGGREGATE_FABRIC_NODEP_20260912_BOUND.zip"
)

$ErrorActionPreference = 'Stop'
$Expected = 'c5a3810dd59840d2d9d5efdabda1e3f9bdaccd3cf4e139c68eef4cacb63cb5c8'
$Name = 'DEEP2_DUAL_AGGREGATE_FABRIC_NODEP_20260912'
$EvidenceRoot = Join-Path $RepoRoot 'evidence\RAWRXD_PERFORMANCE_001'
$Dest = Join-Path $EvidenceRoot $Name
$Tmp = Join-Path $env:TEMP ($Name + '.land.' + [guid]::NewGuid().ToString('N'))
$Safe = ($RepoRoot -replace '\\', '/')

if (!(Test-Path -LiteralPath $ZipPath)) { throw "ZIP_NOT_FOUND $ZipPath" }
$Actual = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw "HASH_MISMATCH actual=$Actual expected=$Expected" }

# Observe tracked state only. This side-drop must not modify tracked product/cert files.
$TrackedBefore = @(& git -c "safe.directory=$Safe" -C $RepoRoot status --porcelain --untracked-files=no 2>$null)

New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
try {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $Tmp -Force
    $Extracted = Join-Path $Tmp $Name
    if (!(Test-Path -LiteralPath $Extracted)) { throw "EXTRACT_ROOT_MISSING $Extracted" }

    $Required = @(
        'LAW.txt',
        'README.md',
        'RECEIPT_LAND.txt',
        'MANIFEST_SHA256.txt',
        'src\deep2_dual_fabric.h',
        'src\deep2_dual_fabric.cpp',
        'src\deep2_dual_fabric_map_bind.h',
        'src\deep2_dual_fabric_map_bind.cpp'
    )
    foreach ($Rel in $Required) {
        if (!(Test-Path -LiteralPath (Join-Path $Extracted $Rel))) { throw "REQUIRED_FILE_MISSING $Rel" }
    }

    $Manifest = Join-Path $Extracted 'MANIFEST_SHA256.txt'
    foreach ($Line in Get-Content -LiteralPath $Manifest) {
        if ($Line -notmatch '^([0-9a-fA-F]{64})\s+\./(.+)$') { continue }
        $Want = $Matches[1].ToLowerInvariant()
        $Rel = $Matches[2] -replace '/', '\\'
        $Path = Join-Path $Extracted $Rel
        if (!(Test-Path -LiteralPath $Path)) { throw "MANIFEST_FILE_MISSING $Rel" }
        $Got = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Got -ne $Want) { throw "MANIFEST_HASH_MISMATCH file=$Rel actual=$Got expected=$Want" }
    }

    $Law = Get-Content -LiteralPath (Join-Path $Extracted 'LAW.txt') -Raw
    $BindH = Get-Content -LiteralPath (Join-Path $Extracted 'src\deep2_dual_fabric_map_bind.h') -Raw
    $BindCpp = Get-Content -LiteralPath (Join-Path $Extracted 'src\deep2_dual_fabric_map_bind.cpp') -Raw

    $Checks = [ordered]@{
        EXISTING_DUAL_GPU_MAP_AUTHORITATIVE = $Law.Contains('EXISTING_DUAL_GPU_MAP_AUTHORITATIVE=1')
        ATTEMPT2_TOUCHED_ZERO              = $Law.Contains('ATTEMPT2_TOUCHED=0')
        CERT_BINARY_TOUCHED_ZERO           = $Law.Contains('CERT_BINARY_TOUCHED=0')
        PRODUCT_LINKED_INTO_CERT_ZERO      = $Law.Contains('PRODUCT_LINKED_INTO_CERT=0')
        RUNTIME_BIND_NOT_RUN               = $Law.Contains('RUNTIME_BIND_TEST=NOT_RUN')
        MAP_RESOLVE_CALLBACK_PRESENT       = $BindH.Contains('D2FabricMapResolveFn')
        LOCAL_RANGE_CALLBACK_PRESENT       = $BindH.Contains('D2FabricMapLocalFn')
        SAME_OWNER_REJECT_PRESENT          = $BindCpp.Contains('rejected_same_owner') -and $BindCpp.Contains('return -20')
        NONLOCAL_RANGE_REJECT_PRESENT      = $BindCpp.Contains('rejected_nonlocal_ranges') -and $BindCpp.Contains('return -12')
    }
    foreach ($K in $Checks.Keys) {
        if (-not $Checks[$K]) { throw "SOURCE_BIND_CHECK_FAIL $K" }
    }

    New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
    if (Test-Path -LiteralPath $Dest) {
        $Backup = $Dest + '.prebind.' + (Get-Date -Format 'yyyyMMdd_HHmmss')
        Move-Item -LiteralPath $Dest -Destination $Backup
    }
    Move-Item -LiteralPath $Extracted -Destination $Dest

    $TrackedAfter = @(& git -c "safe.directory=$Safe" -C $RepoRoot status --porcelain --untracked-files=no 2>$null)
    if (($TrackedBefore -join "`n") -ne ($TrackedAfter -join "`n")) {
        throw 'TRACKED_REPO_STATE_CHANGED_ABORT'
    }

    $Receipt = @(
        'GATE=DEEP2_DUAL_AGGREGATE_FABRIC_NODEP_20260912',
        'LAND=PASS',
        "BOUND_ZIP_SHA256=$Actual",
        'SOURCE_MANIFEST=PASS',
        'MAP_BIND_SOURCE=PASS',
        'BIND_TARGET=DEEP2_LOCALITY_STREAM_DUALGPU_NODEP_20260912:d2_dual_gpu',
        'EXISTING_DUAL_GPU_MAP_AUTHORITATIVE=1',
        'D2DEVICEIO_SSVK_BIND=DEFERRED',
        'RUNTIME_BIND_TEST=NOT_RUN',
        'ATTEMPT2_TOUCHED=0',
        'CERT_BINARY_TOUCHED=0',
        'PRODUCT_LINKED_INTO_CERT=0',
        'TPS_AUTHORITY=0',
        'PROMOTE=0',
        'GITHUB_PUSH=NOT_PERFORMED_BY_THIS_SCRIPT'
    )
    Set-Content -LiteralPath (Join-Path $Dest 'RECEIPT_LOCAL_LAND.txt') -Value $Receipt -Encoding ascii

    $Checks.GetEnumerator() | ForEach-Object { "{0}={1}" -f $_.Key, $(if ($_.Value) {'PASS'} else {'FAIL'}) }
    $Receipt
}
finally {
    if (Test-Path -LiteralPath $Tmp) { Remove-Item -LiteralPath $Tmp -Recurse -Force }
}

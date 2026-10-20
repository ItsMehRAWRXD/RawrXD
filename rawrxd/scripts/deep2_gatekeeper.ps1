[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('CaptureBaseline', 'VerifyBaseline', 'Restore', 'Recover', 'FaultTest')]
    [string]$Action,
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [Parameter(Mandatory = $false)]
    [string[]]$Paths = @(),
    [Parameter(Mandatory = $false)]
    [string]$PathsJson,
    [Parameter(Mandatory = $false)]
    [string]$BaselinePath = '',
    [Parameter(Mandatory = $false)]
    [string]$SnapshotRoot = '',
    [Parameter(Mandatory = $false)]
    [string]$RecoveryPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = [System.Text.UTF8Encoding]::new($false)

if ($PathsJson) {
    try {
        $decodedPaths = ConvertFrom-Json -InputObject $PathsJson
    } catch {
        throw 'PathsJson must be a JSON array of strings.'
    }
    if ($decodedPaths -is [System.Array]) { $Paths = @($decodedPaths | ForEach-Object { [string]$_ }) }
    else { $Paths = @([string]$decodedPaths) }
}

function ConvertTo-CanonicalValue($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return [string]$Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $ordered[$key] = ConvertTo-CanonicalValue $Value[$key]
        }
        return $ordered
    }
    if ($Value -is [pscustomobject]) {
        $ordered = [ordered]@{}
        foreach ($property in @($Value.PSObject.Properties | Sort-Object Name)) {
            $ordered[$property.Name] = ConvertTo-CanonicalValue $property.Value
        }
        return $ordered
    }
    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
        return @($Value | ForEach-Object { ConvertTo-CanonicalValue $_ })
    }
    return $Value
}

function ConvertTo-CanonicalJson($Value) {
    return (ConvertTo-CanonicalValue $Value | ConvertTo-Json -Depth 100 -Compress)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-RelativePath([string]$Root, [string]$Path) {
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the repository: $Path"
    }
    return $fullPath.Substring($fullRoot.Length).Replace('\', '/')
}

function Resolve-RepoFile([string]$Root, [string]$Path) {
    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $Root $Path }
    $full = [System.IO.Path]::GetFullPath($candidate)
    $rootPrefix = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $full.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside the repository: $Path"
    }
    return $full
}

function Assert-OutsideRoot([string]$Root, [string]$Path) {
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Metadata path must be outside the accepted workspace: $Path"
    }
}

function Remove-OwnedTempDirectory([string]$Path, [string]$Prefix) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $full.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Refusing to remove outside the temp root: $Path" }
    $item = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    if (-not $item.PSIsContainer -or $item.Name -notlike ($Prefix + '*')) { throw "Refusing to remove an unowned temporary path: $Path" }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Refusing to remove a reparse-point temporary path: $Path" }
    Remove-Item -LiteralPath $full -Recurse -Force
}

function Get-ScopedFiles([string]$Root, [string[]]$Requested) {
    if ($Requested.Count -eq 0) { throw 'At least one explicit file or directory is required.' }
    $files = [System.Collections.Generic.List[string]]::new()
    foreach ($requestedPath in $Requested) {
        $resolved = Resolve-RepoFile $Root $requestedPath
        if (Test-Path -LiteralPath $resolved -PathType Leaf) {
            [void]$files.Add($resolved)
        } elseif (Test-Path -LiteralPath $resolved -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $resolved -File -Recurse -Force | Sort-Object FullName)) {
                [void]$files.Add($file.FullName)
            }
        } else {
            throw "Declared path is missing: $requestedPath"
        }
    }
    $unique = @($files | Sort-Object -Unique)
    if ($unique.Count -ne $files.Count) { throw 'Declared scope contains duplicate files.' }
    return $unique
}

function Get-Inventory([string]$Root, [string[]]$Requested) {
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($file in @(Get-ScopedFiles $Root $Requested)) {
        $item = Get-Item -LiteralPath $file
        [void]$entries.Add([ordered]@{
            path = Get-RelativePath $Root $file
            bytes = [int64]$item.Length
            sha256 = Get-Sha256 $file
        })
    }
    return @($entries | Sort-Object path)
}

function Get-InventoryHash($Entries) {
    $json = ConvertTo-CanonicalJson @($Entries)
    $bytes = $utf8.GetBytes($json)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant() } finally { $sha.Dispose() }
}

function Write-CreateOnly([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read, 4096, [System.IO.FileOptions]::WriteThrough)
    try {
        $bytes = $utf8.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Read-Baseline([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Baseline is missing: $Path" }
    $baseline = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($baseline.schema -ne 'RAWRXD_DEEP2_GATE21_BASELINE_001') { throw 'Baseline schema is invalid.' }
    if ($null -eq $baseline.files -or @($baseline.files).Count -eq 0) { throw 'Baseline has no files.' }
    if ([string]$baseline.inventory_sha256 -cne (Get-InventoryHash @($baseline.files))) { throw 'Baseline inventory digest is invalid.' }
    return $baseline
}

function Get-ExpectedEntry($Baseline, [string]$Relative) {
    return @($Baseline.files | Where-Object { $_.path -eq $Relative })[0]
}

function Compare-Inventory([string]$Root, $Baseline, [switch]$Exact) {
    $failures = [System.Collections.Generic.List[string]]::new()
    $current = @{}
    foreach ($entry in @($Baseline.files)) {
        $file = Join-Path $Root ($entry.path -replace '/', '\')
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            $failures.Add("MISSING:$($entry.path)")
            continue
        }
        $item = Get-Item -LiteralPath $file
        $hash = Get-Sha256 $file
        $current[$entry.path] = $true
        if ([int64]$item.Length -ne [int64]$entry.bytes) { $failures.Add("LENGTH:$($entry.path)") }
        if ($hash -cne [string]$entry.sha256) { $failures.Add("HASH:$($entry.path)") }
    }
    if ($failures.Count -gt 0) { throw ('Inventory mismatch: ' + ($failures -join ',')) }
    if ($Exact) {
        $rootPrefix = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
        $actual = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force | ForEach-Object { $_.FullName.Substring($rootPrefix.Length).Replace('\', '/') } | Sort-Object)
        $expected = @($Baseline.files | ForEach-Object { $_.path } | Sort-Object)
        if (($actual -join "`n") -cne ($expected -join "`n")) { throw 'Workspace contains missing or unexpected files.' }
    }
    return $true
}

function Compare-Snapshot([string]$Snapshot, $Baseline) {
    $paths = @($Baseline.files | ForEach-Object { Join-Path $Snapshot ($_.path -replace '/', '\') })
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Snapshot file is missing: $path" }
    }
    $actual = @(Get-ChildItem -LiteralPath $Snapshot -File -Recurse -Force | ForEach-Object { $_.FullName.Substring(([System.IO.Path]::GetFullPath($Snapshot).TrimEnd('\') + '\').Length).Replace('\', '/') } | Sort-Object)
    $expected = @($Baseline.files | ForEach-Object { $_.path } | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) { throw 'Snapshot contains missing or unexpected files.' }
    foreach ($entry in @($Baseline.files)) {
        $path = Join-Path $Snapshot ($entry.path -replace '/', '\')
        $item = Get-Item -LiteralPath $path
        if ([int64]$item.Length -ne [int64]$entry.bytes -or (Get-Sha256 $path) -cne [string]$entry.sha256) { throw "Snapshot identity mismatch: $($entry.path)" }
    }
}

function Write-Recovery([string]$Path, $Record) {
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [System.IO.File]::WriteAllText($temporary, (ConvertTo-CanonicalJson $Record) + [Environment]::NewLine, $utf8)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Restore-Baseline([string]$Root, [string]$BaselineFile, [string]$RecoveryFile) {
    $baseline = Read-Baseline $BaselineFile
    $snapshot = [string]$baseline.snapshot_root
    if (-not (Test-Path -LiteralPath $snapshot -PathType Container)) { throw "Snapshot root is missing: $snapshot" }
    Compare-Snapshot $snapshot $baseline
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_restore_stage_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        foreach ($entry in @($baseline.files)) {
            $source = Join-Path $snapshot ($entry.path -replace '/', '\')
            $destination = Join-Path $stage ($entry.path -replace '/', '\')
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination -Force
        }
        Compare-Snapshot $stage $baseline
        $record = [ordered]@{ schema = 'RAWRXD_DEEP2_GATE21_RECOVERY_001'; state = 'APPLYING'; repo_root = $Root; baseline = $BaselineFile; snapshot = $snapshot; started_utc = [DateTime]::UtcNow.ToString('o') }
        Write-Recovery $RecoveryFile $record
        foreach ($entry in @($baseline.files)) {
            $source = Join-Path $stage ($entry.path -replace '/', '\')
            $destination = Join-Path $Root ($entry.path -replace '/', '\')
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination -Force
        }
        Compare-Inventory $Root $baseline
        $record.state = 'COMPLETE'
        $record.completed_utc = [DateTime]::UtcNow.ToString('o')
        Write-Recovery $RecoveryFile $record
        return $true
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-OwnedTempDirectory $stage 'rawrxd_restore_stage_' }
    }
}

$root = [System.IO.Path]::GetFullPath($RepoRoot)
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Repository root is missing: $root" }

if ($Action -eq 'FaultTest') {
    $faultRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rawrxd_gate22_faults_' + [guid]::NewGuid().ToString('N'))
    $workspace = Join-Path $faultRoot 'workspace'
    $baseline = Join-Path $faultRoot 'baseline.json'
    $snapshot = Join-Path $faultRoot 'snapshot'
    $recovery = Join-Path $faultRoot 'recovery.json'
    $faults = [ordered]@{}
    $recoveryVerified = $false
    try {
        New-Item -ItemType Directory -Path $workspace -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $workspace 'a.txt') -Value 'alpha' -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $workspace 'nested.txt') -Value 'nested' -Encoding UTF8
        $entries = Get-Inventory $workspace @('a.txt', 'nested.txt')
        foreach ($entry in $entries) {
            $source = Join-Path $workspace ($entry.path -replace '/', '\')
            $destination = Join-Path $snapshot ($entry.path -replace '/', '\')
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination -Force
        }
        $baselineObject = [ordered]@{ schema = 'RAWRXD_DEEP2_GATE21_BASELINE_001'; repo_root = $workspace; snapshot_root = $snapshot; files = $entries; inventory_sha256 = Get-InventoryHash $entries; created_utc = [DateTime]::UtcNow.ToString('o') }
        Write-CreateOnly $baseline ((ConvertTo-CanonicalJson $baselineObject) + [Environment]::NewLine)
        $loadedBaseline = Read-Baseline $baseline
        Set-Content -LiteralPath (Join-Path $workspace 'a.txt') -Value 'changed' -Encoding UTF8
        try { Compare-Inventory $workspace $loadedBaseline; $faults.changed_workspace_rejected = $false } catch { $faults.changed_workspace_rejected = $true }
        [void](Restore-Baseline $workspace $baseline $recovery)
        [void](Compare-Inventory $workspace $loadedBaseline -Exact)
        Set-Content -LiteralPath (Join-Path $workspace 'unexpected.txt') -Value 'unexpected' -Encoding UTF8
        try { [void](Compare-Inventory $workspace $loadedBaseline -Exact); $faults.unexpected_workspace_rejected = $false } catch { $faults.unexpected_workspace_rejected = $true }
        Remove-Item -LiteralPath (Join-Path $workspace 'unexpected.txt') -Force
        Remove-Item -LiteralPath (Join-Path $workspace 'nested.txt') -Force
        try { [void](Compare-Inventory $workspace $loadedBaseline -Exact); $faults.missing_workspace_rejected = $false } catch { $faults.missing_workspace_rejected = $true }
        [void](Restore-Baseline $workspace $baseline $recovery)
        Set-Content -LiteralPath (Join-Path $snapshot 'unexpected.txt') -Value 'unexpected' -Encoding UTF8
        try { Compare-Snapshot $snapshot $loadedBaseline; $faults.unexpected_snapshot_rejected = $false } catch { $faults.unexpected_snapshot_rejected = $true }
        Remove-Item -LiteralPath (Join-Path $snapshot 'unexpected.txt') -Force
        Set-Content -LiteralPath (Join-Path $snapshot 'a.txt') -Value 'corrupt' -Encoding UTF8
        try { [void](Restore-Baseline $workspace $baseline $recovery); $faults.corrupt_snapshot_rejected = $false } catch { $faults.corrupt_snapshot_rejected = $true }
        Copy-Item -LiteralPath (Join-Path $workspace 'a.txt') -Destination (Join-Path $snapshot 'a.txt') -Force
        Remove-Item -LiteralPath (Join-Path $snapshot 'a.txt') -Force
        try { [void](Restore-Baseline $workspace $baseline $recovery); $faults.missing_snapshot_rejected = $false } catch { $faults.missing_snapshot_rejected = $true }
        Copy-Item -LiteralPath (Join-Path $workspace 'a.txt') -Destination (Join-Path $snapshot 'a.txt') -Force
        $malformed = Join-Path $faultRoot 'malformed.json'
        Set-Content -LiteralPath $malformed -Value '{not-json' -Encoding UTF8
        try { Read-Baseline $malformed; $faults.malformed_baseline_rejected = $false } catch { $faults.malformed_baseline_rejected = $true }
        $invalidSchema = Join-Path $faultRoot 'invalid_schema.json'
        $baselineText = Get-Content -LiteralPath $baseline -Raw
        $baselineText.Replace('RAWRXD_DEEP2_GATE21_BASELINE_001', 'INVALID_SCHEMA') | Set-Content -LiteralPath $invalidSchema -Encoding UTF8
        $invalidDigest = Join-Path $faultRoot 'invalid_digest.json'
        $baselineText.Replace([string]$loadedBaseline.inventory_sha256, ('0' * 64)) | Set-Content -LiteralPath $invalidDigest -Encoding UTF8
        $invalidBaseline = $true
        try { Read-Baseline $invalidSchema; $invalidBaseline = $false } catch { }
        try { Read-Baseline $invalidDigest; $invalidBaseline = $false } catch { }
        $faults.invalid_baseline_rejected = $invalidBaseline
        $faults.orphan_recovery_recovered = $false
        $orphan = [ordered]@{ schema = 'RAWRXD_DEEP2_GATE21_RECOVERY_001'; state = 'APPLYING'; repo_root = $workspace; baseline = $baseline; snapshot = $snapshot }
        Write-Recovery $recovery $orphan
        Set-Content -LiteralPath (Join-Path $workspace 'a.txt') -Value 'orphaned' -Encoding UTF8
        [void](Restore-Baseline $workspace $baseline $recovery)
        [void](Compare-Inventory $workspace $loadedBaseline -Exact)
        $faults.orphan_recovery_recovered = $true
        $recoveryVerified = $true
        $passed = @($faults.Values | Where-Object { -not $_ }).Count -eq 0 -and $recoveryVerified
        [ordered]@{ schema = 'RAWRXD_DEEP2_GATE22_FAULT_TEST_001'; passed = $passed; test_count = $faults.Count; faults = $faults; recovery_verified = $recoveryVerified; workspace = $workspace; generated_utc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Depth 10
        if (-not $passed) { exit 2 }
        exit 0
    } finally {
        if (Test-Path -LiteralPath $faultRoot) { Remove-OwnedTempDirectory $faultRoot 'rawrxd_gate22_faults_' }
    }
}

if ([string]::IsNullOrWhiteSpace($BaselinePath)) { throw 'BaselinePath is required for this action.' }
$baselinePath = [System.IO.Path]::GetFullPath($BaselinePath)
Assert-OutsideRoot $root $baselinePath

if ($Action -eq 'CaptureBaseline') {
    if ([string]::IsNullOrWhiteSpace($SnapshotRoot)) { throw 'SnapshotRoot is required for CaptureBaseline.' }
    $snapshotPath = [System.IO.Path]::GetFullPath($SnapshotRoot)
    Assert-OutsideRoot $root $snapshotPath
    if (Test-Path -LiteralPath $baselinePath) { throw "Baseline already exists: $baselinePath" }
    if (Test-Path -LiteralPath $snapshotPath) {
        $existing = @(Get-ChildItem -LiteralPath $snapshotPath -Force -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) { throw "Snapshot root is not empty: $snapshotPath" }
    }
    New-Item -ItemType Directory -Path $snapshotPath -Force | Out-Null
    $entries = Get-Inventory $root $Paths
    foreach ($entry in $entries) {
        $source = Join-Path $root ($entry.path -replace '/', '\')
        $destination = Join-Path $snapshotPath ($entry.path -replace '/', '\')
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
    $baseline = [ordered]@{ schema = 'RAWRXD_DEEP2_GATE21_BASELINE_001'; baseline_id = [guid]::NewGuid().ToString(); repo_root = $root; snapshot_root = $snapshotPath; files = $entries; inventory_sha256 = Get-InventoryHash $entries; created_utc = [DateTime]::UtcNow.ToString('o') }
    Compare-Snapshot $snapshotPath ([pscustomobject]$baseline)
    Write-CreateOnly $baselinePath ((ConvertTo-CanonicalJson $baseline) + [Environment]::NewLine)
    Write-Output "GATE21_CAPTURED=1 BASELINE=$baselinePath SNAPSHOT=$snapshotPath INVENTORY=$($baseline.inventory_sha256)"
    exit 0
}

$loaded = Read-Baseline $baselinePath
if ($Action -eq 'VerifyBaseline') {
    Compare-Inventory $root $loaded
    Compare-Snapshot ([string]$loaded.snapshot_root) $loaded
    Write-Output "GATE21_VERIFIED=1 INVENTORY=$($loaded.inventory_sha256)"
    exit 0
}

if ([string]::IsNullOrWhiteSpace($RecoveryPath)) { $RecoveryPath = "$baselinePath.recovery.json" }
$recoveryPath = [System.IO.Path]::GetFullPath($RecoveryPath)
Assert-OutsideRoot $root $recoveryPath
if ($Action -eq 'Restore') {
    Restore-Baseline $root $baselinePath $recoveryPath
    Write-Output "RESTORE_VERIFIED=1 RECOVERY=$recoveryPath"
    exit 0
}

if (-not (Test-Path -LiteralPath $recoveryPath -PathType Leaf)) { throw "Recovery record is missing: $recoveryPath" }
$recoveryRecord = Get-Content -LiteralPath $recoveryPath -Raw | ConvertFrom-Json
if ($recoveryRecord.state -eq 'COMPLETE') {
    Compare-Inventory $root $loaded
    Write-Output 'RECOVERY_ALREADY_COMPLETE=1'
    exit 0
}
Restore-Baseline $root $baselinePath $recoveryPath
Write-Output "ORPHAN_RECOVERY_VERIFIED=1 RECOVERY=$recoveryPath"

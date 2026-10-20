[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Append', 'Verify')]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$LedgerPath,
    [Parameter(Mandatory = $false)]
    [string]$RecordJson = '',
    [Parameter(Mandatory = $false)]
    [string]$HeadPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utf8 = [System.Text.UTF8Encoding]::new($false)
$zeroHash = '0' * 64

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

function Get-Utf8Bytes([string]$Text) {
    return ,$utf8.GetBytes($Text)
}

function ConvertTo-Hex([byte[]]$Bytes) {
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
}

function ConvertFrom-Hex([string]$Hex) {
    if ($Hex.Length -ne 64 -or $Hex -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "Invalid 256-bit hash: $Hex"
    }
    $bytes = [byte[]]::new(32)
    for ($index = 0; $index -lt 32; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return ,$bytes
}

function Get-RecordHash([string]$PreviousHash, [byte[]]$RecordBytes) {
    $previousBytes = ConvertFrom-Hex $PreviousHash
    $lengthBytes = [BitConverter]::GetBytes([int64]$RecordBytes.Length)
    $payload = [byte[]]::new($previousBytes.Length + $lengthBytes.Length + $RecordBytes.Length)
    [Buffer]::BlockCopy($previousBytes, 0, $payload, 0, $previousBytes.Length)
    [Buffer]::BlockCopy($lengthBytes, 0, $payload, $previousBytes.Length, $lengthBytes.Length)
    [Buffer]::BlockCopy($RecordBytes, 0, $payload, $previousBytes.Length + $lengthBytes.Length, $RecordBytes.Length)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ConvertTo-Hex ($sha.ComputeHash($payload)) } finally { $sha.Dispose() }
}

function Resolve-FullPath([string]$Path) {
    return [System.IO.Path]::GetFullPath($Path)
}

function Read-LedgerRecords([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $records = [System.Collections.Generic.List[object]]::new()
    $lines = [System.IO.File]::ReadAllLines($Path, $utf8)
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { throw "Ledger contains a blank record: $Path" }
        [void]$records.Add(($line | ConvertFrom-Json))
    }
    return @($records)
}

function Verify-Ledger([string]$Path, [string]$Head) {
    $records = @(Read-LedgerRecords $Path)
    $previous = $zeroHash
    $sequence = 1
    foreach ($entry in $records) {
        if ([string]$entry.schema -cne 'RAWRXD_MUTATION_LEDGER_ENTRY_001') { throw "Ledger schema mismatch at $sequence." }
        if ([int64]$entry.sequence -ne $sequence) { throw "Ledger sequence mismatch at $sequence." }
        if ([string]$entry.previous_hash -ne $previous) { throw "Ledger previous hash mismatch at $sequence." }
        $recordJson = [string]$entry.record_json
        if ([int64]$entry.record_length -lt 0 -or [int64]$entry.record_length -gt 1073741824) { throw "Ledger record length is invalid at $sequence." }
        $record = $recordJson | ConvertFrom-Json
        $canonical = ConvertTo-CanonicalJson $record
        if ($canonical -cne $recordJson) { throw "Ledger canonical record mismatch at $sequence." }
        $recordBytes = Get-Utf8Bytes $recordJson
        if ([int64]$entry.record_length -ne $recordBytes.Length) { throw "Ledger length mismatch at $sequence." }
        $expected = Get-RecordHash $previous $recordBytes
        if ([string]$entry.record_hash -ne $expected) { throw "Ledger hash mismatch at $sequence." }
        $previous = $expected
        $sequence++
    }
    if (Test-Path -LiteralPath $Head -PathType Leaf) {
        $trusted = ([System.IO.File]::ReadAllText($Head, $utf8)).Trim()
        $expectedHead = if ($records.Count -eq 0) { $zeroHash } else { $previous }
        if ($trusted -cne $expectedHead) { throw "Trusted ledger head mismatch." }
    } elseif ($records.Count -gt 0) {
        throw "Trusted ledger head is missing."
    }
    return [pscustomobject]@{ valid = $true; count = $records.Count; head = $previous }
}

function Write-TrustedHead([string]$Path, [string]$Hash) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::WriteAllText($temporary, $Hash + [Environment]::NewLine, $utf8)
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

$ledger = Resolve-FullPath $LedgerPath
if ([string]::IsNullOrWhiteSpace($HeadPath)) { $HeadPath = "$ledger.head" }
$head = Resolve-FullPath $HeadPath
$parent = Split-Path -Parent $ledger
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

$identityBytes = $utf8.GetBytes($ledger.ToLowerInvariant())
$identitySha = [System.Security.Cryptography.SHA256]::Create()
try { $identity = ConvertTo-Hex ($identitySha.ComputeHash($identityBytes)) } finally { $identitySha.Dispose() }
$mutexName = 'Global\RawrXD.MutationLedger.' + $identity
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$mutexAcquired = $false
try {
    try {
        $mutexAcquired = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
    } catch [System.Threading.AbandonedMutexException] {
        $mutexAcquired = $true
        Write-Output 'LEDGER_MUTEX_ABANDONED=1'
    }
    if (-not $mutexAcquired) { throw "Timed out acquiring ledger mutex: $mutexName" }

    if ($Action -eq 'Verify') {
        $result = Verify-Ledger $ledger $head
        Write-Output ('LEDGER_VALID={0} RECORDS={1} HEAD={2}' -f $result.valid, $result.count, $result.head)
        return
    }

    if ([string]::IsNullOrWhiteSpace($RecordJson)) { throw 'RecordJson is required for Append.' }
    $record = $RecordJson | ConvertFrom-Json
    $canonicalRecord = ConvertTo-CanonicalJson $record
    $recordBytes = Get-Utf8Bytes $canonicalRecord
    $existing = Verify-Ledger $ledger $head
    $previousHash = $existing.head
    $nextSequence = [int64]$existing.count + 1
    $recordHash = Get-RecordHash $previousHash $recordBytes
    $entry = [ordered]@{
        schema = 'RAWRXD_MUTATION_LEDGER_ENTRY_001'
        sequence = $nextSequence
        previous_hash = $previousHash
        record_length = [int64]$recordBytes.Length
        record_json = $canonicalRecord
        record_hash = $recordHash
    }
    $line = ConvertTo-CanonicalJson $entry
    $lineBytes = Get-Utf8Bytes ($line + [Environment]::NewLine)
    $stream = $null
    try {
        $stream = [System.IO.FileStream]::new($ledger, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read, 4096, [System.IO.FileOptions]::WriteThrough)
        $stream.Write($lineBytes, 0, $lineBytes.Length)
        $stream.Flush($true)
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
    Write-TrustedHead $head $recordHash
    Write-Output ('LEDGER_APPENDED=1 SEQUENCE={0} HASH={1}' -f $nextSequence, $recordHash)
} finally {
    if ($mutexAcquired) { [void]$mutex.ReleaseMutex() }
    $mutex.Dispose()
}

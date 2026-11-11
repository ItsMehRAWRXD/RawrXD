[CmdletBinding()]
param(
    [string]$EvidenceRoot = 'F:\rawrxd\evidence'
)

# Read-only evidence check. It never writes, promotes, certifies, or mutates a candidate.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$textExtensions = @('.json', '.jsonl', '.md', '.txt', '.log', '.csv', '.yaml', '.yml', '.ini')
$pathPattern = '(?im)^\s*[-*]?\s*(?:CANDIDATE_PATH|REPAIR CANDIDATE|CERT_EXE|BINARY|TARGET_EXE|EXE)\s*[:=]\s*["''`]?(.+?\.exe)["''`]?\s*$'
$hashPattern = '(?im)^\s*[-*]?\s*(?<label>[A-Za-z0-9_ -]*(?:SHA(?:256)?|HASH|DIGEST)[A-Za-z0-9_ -]*)\s*[:=]\s*["''`]*(?<hash>[0-9A-F]{64})'

function Resolve-DeclaredPath([string]$DeclaredPath) {
    $p = $DeclaredPath.Trim().Trim('`', '"', "'").TrimEnd('.', ',', ';', ')')
    $p = $p -replace '\\\\', '\'
    if ([IO.Path]::IsPathRooted($p)) { return $p }
    return (Join-Path $EvidenceRoot $p)
}

if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) {
    throw "Evidence root does not exist: $EvidenceRoot"
}

$records = [System.Collections.Generic.List[object]]::new()
$files = Get-ChildItem -LiteralPath $EvidenceRoot -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $textExtensions -contains $_.Extension.ToLowerInvariant() }

foreach ($file in $files) {
    try { $lines = [IO.File]::ReadAllLines($file.FullName) } catch { continue }
    $pathMatches = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $pm = [regex]::Match($lines[$i], $pathPattern)
        if ($pm.Success) {
            $pathMatches.Add([pscustomobject]@{
                Line = $i
                DeclaredPath = $pm.Groups[1].Value
            })
        }
    }
    if ($pathMatches.Count -eq 0) { continue }

    $hashLines = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $hm = [regex]::Match($lines[$i], $hashPattern)
        if (-not $hm.Success) { continue }
        $label = $hm.Groups['label'].Value
        if ($label -match '(?i)before|after|autosave|expected|motd|content|request|source_tree') { continue }
        $hashLines += [pscustomobject]@{
            Line = $i
            Label = $label
            Hash = $hm.Groups['hash'].Value.ToUpperInvariant()
        }
    }

    foreach ($pm in $pathMatches) {
        $declared = Resolve-DeclaredPath $pm.DeclaredPath
        $pathLine = $pm.Line
        $candidateHashes = $hashLines |
            Where-Object { [math]::Abs($_.Line - $pathLine) -le 10 } |
            Sort-Object @{Expression={
                $score = [math]::Abs($_.Line - $pathLine)
                if ($_.Label -match '(?i)candidate|binary|cert|exe') { $score -= 20 }
                $score
            }}
        $chosen = $candidateHashes | Select-Object -First 1
        if (-not $chosen) {
            $records.Add([pscustomobject]@{
                Receipt = $file.FullName
                DeclaredPath = $declared
                DeclaredSHA256 = $null
                ActualSHA256 = $null
                Status = 'UNPAIRED'
            })
            continue
        }

        if (-not (Test-Path -LiteralPath $declared -PathType Leaf)) {
            $records.Add([pscustomobject]@{
                Receipt = $file.FullName
                DeclaredPath = $declared
                DeclaredSHA256 = $chosen.Hash
                ActualSHA256 = $null
                Status = 'MISSING_PATH'
            })
            continue
        }

        $actual = (Get-FileHash -LiteralPath $declared -Algorithm SHA256).Hash.ToUpperInvariant()
        $records.Add([pscustomobject]@{
            Receipt = $file.FullName
            DeclaredPath = $declared
            DeclaredSHA256 = $chosen.Hash
            ActualSHA256 = $actual
            Status = if ($actual -eq $chosen.Hash) { 'MATCH' } else { 'MISMATCH' }
        })
    }
}

$summary = [pscustomobject]@{
    EvidenceRoot = $EvidenceRoot
    FilesScanned = $files.Count
    IdentityRecords = $records.Count
    Matches = @($records | Where-Object Status -eq 'MATCH').Count
    Mismatches = @($records | Where-Object Status -eq 'MISMATCH').Count
    MissingPaths = @($records | Where-Object Status -eq 'MISSING_PATH').Count
    Unpaired = @($records | Where-Object Status -eq 'UNPAIRED').Count
    WritesPerformed = 0
    PromotionPerformed = 0
    CertificationPerformed = 0
    Records = $records
}

$summary | ConvertTo-Json -Depth 5
if ($summary.Mismatches -gt 0) { exit 2 }
if ($summary.MissingPaths -gt 0 -or $summary.Unpaired -gt 0) { exit 3 }
exit 0

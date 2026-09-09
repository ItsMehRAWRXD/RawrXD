param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$map = Join-Path $Root 'evidence\RAWRXD_PERFORMANCE_001\RUNTIME_EVIDENCE_512_IDE_CLAIM_MAP_001.tsv'
if (!(Test-Path $map)) {
    $map = Join-Path $Root 'evidence\RUNTIME_EVIDENCE_512_IDE_CLAIM_MAP_001.tsv'
}
$asm = Join-Path $Root 'src\asm\RuntimeEvidence512_IDEEmit.asm'
$inc = Join-Path $Root 'src\asm\RuntimeEvidence512_IDEClaims.inc'

if (!(Test-Path $map) -or !(Test-Path $asm) -or !(Test-Path $inc)) {
    throw 'required source-drop files missing'
}

$rows = Import-Csv -Delimiter "`t" $map
if ($rows.Count -ne 96) {
    throw "claim map count=$($rows.Count), expected=96"
}

$ids = @($rows | ForEach-Object { [int]$_.ClaimId })
if (($ids | Sort-Object -Unique).Count -ne 96) {
    throw 'ClaimId values are not unique'
}
if (($ids | Measure-Object -Minimum).Minimum -ne 1 -or
    ($ids | Measure-Object -Maximum).Maximum -ne 96) {
    throw 'ClaimId range must be 1..96'
}

$names = @($rows.ClaimName)
if (($names | Sort-Object -Unique).Count -ne 96) {
    throw 'ClaimName values are not unique'
}

$emitters = @($rows.Emitter)
if (($emitters | Sort-Object -Unique).Count -ne 96) {
    throw 'Emitter names are not unique'
}

$asmText = Get-Content -Raw $asm
$incText = Get-Content -Raw $inc

if ($asmText -match '(?im)^\s*PUBLIC\s+EvidenceIDEEmitCore512\s*$') {
    throw 'private generic IDE emitter core was exported'
}
if ($asmText -match '(?im)^\s*PUBLIC\s+EvidenceEmit\s*$') {
    throw 'generic EvidenceEmit export found'
}

# New IDs 18..96 must have a claim constant and macro-instantiated emitter.
foreach ($r in $rows | Where-Object { [int]$_.ClaimId -ge 18 }) {
    $claimConst = 'CLAIM_' + $r.ClaimName
    if ($incText -notmatch ('(?m)^\s*' + [regex]::Escape($claimConst) + '\s+EQU\s+' + [regex]::Escape($r.ClaimId) + '\s*$')) {
        throw "missing or mismatched claim constant: $claimConst=$($r.ClaimId)"
    }
    if ($asmText -notmatch [regex]::Escape($r.Emitter)) {
        throw "missing emitter instantiation: $($r.Emitter)"
    }
}

$required = @($rows | Where-Object { $_.RequiredProductE2E -eq '1' })
$optional = @($rows | Where-Object { $_.RequiredProductE2E -eq '0' })

"RUNTIME_EVIDENCE_512_IDE_STATIC_COVERAGE=PASS"
"CLAIMS_TOTAL=$($rows.Count)"
"CLAIMS_REQUIRED_PRODUCT=$($required.Count)"
"CLAIMS_OPTIONAL=$($optional.Count)"
"CLAIM_IDS=1..96"
"NEW_EMITTERS=79"
"GENERIC_PUBLIC_EMIT=0"
"SEQ_CAP=512"
"NOTE=STATIC_SOURCE_COVERAGE_ONLY_NOT_RUNTIME_EVIDENCE"

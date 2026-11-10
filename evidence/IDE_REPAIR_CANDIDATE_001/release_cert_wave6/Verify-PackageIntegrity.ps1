#Requires -Version 5.1
<#
.SYNOPSIS
  W6 packaging integrity verifier (prepare-only / fail-closed).
.DESCRIPTION
  Hashes declared package members, compares to SHA_LEDGER entries when filled,
  and emits a receipt under release_cert_wave6/runs/. Never sets PROMOTE=1.
  Does not invent PASS: missing ledger rows => FAIL_CLOSED / NOT_RUN.
.NOTES
  PROMOTE=0 CERTIFIED=0. Independent verifier must re-run on a clean machine.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$PackageDir = '',

    [Parameter(Mandatory = $false)]
    [string]$LedgerPath = '',

    [Parameter(Mandatory = $false)]
    [string]$OutDir = '',

    [switch]$AllowPartial
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $LedgerPath) { $LedgerPath = Join-Path $Root 'SHA_LEDGER_TEMPLATE.txt' }
if (-not $OutDir) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutDir = Join-Path $Root ("runs\verify_" + $stamp)
}

function Write-Utf8([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Get-Sha256File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$lines = @()
$lines += 'VERIFY_PACKAGE_INTEGRITY=W6'
$lines += 'ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$lines += 'PROMOTE=0'
$lines += 'CERTIFIED=0'
$lines += 'PACKAGE_DIR=' + $(if ($PackageDir) { $PackageDir } else { 'UNSET' })
$lines += 'LEDGER=' + $LedgerPath
$lines += 'ALLOW_PARTIAL=' + $(if ($AllowPartial) { '1' } else { '0' })

if (-not $PackageDir -or -not (Test-Path -LiteralPath $PackageDir)) {
    $lines += 'VERDICT=NOT_RUN'
    $lines += 'CLASS=PACKAGE_DIR_MISSING_OR_UNSET'
    $lines += 'NOTE=Fill PackageDir + SHA_LEDGER expected hashes, then re-run.'
    Write-Utf8 (Join-Path $OutDir 'RECEIPT.txt') (($lines -join "`r`n") + "`r`n")
    Write-Host "NOT_RUN: PackageDir unset/missing. Receipt: $OutDir\RECEIPT.txt"
    exit 2
}

if (-not (Test-Path -LiteralPath $LedgerPath)) {
    $lines += 'VERDICT=NOT_RUN'
    $lines += 'CLASS=SHA_LEDGER_MISSING'
    Write-Utf8 (Join-Path $OutDir 'RECEIPT.txt') (($lines -join "`r`n") + "`r`n")
    Write-Host "NOT_RUN: ledger missing."
    exit 2
}

$expected = @{}
Get-Content -LiteralPath $LedgerPath | ForEach-Object {
    $t = $_.Trim()
    if (-not $t -or $t.StartsWith('#') -or $t.StartsWith('SHA_LEDGER') -or $t -match '^=') { return }
    if ($t -match '^(PROMOTE|CERTIFIED|ASOF|CANDIDATE|BAND|STATUS|TEMPLATE|INSTRUCTIONS|FILL)=') { return }
    # Rows: REL_PATH<TAB>EXPECTED_SHA256<TAB>ROLE
    $parts = $t -split "`t"
    if ($parts.Count -ge 2 -and $parts[1] -match '^[0-9A-Fa-f]{64}$') {
        $expected[$parts[0].Trim()] = $parts[1].Trim().ToUpperInvariant()
    }
}

if ($expected.Count -eq 0) {
    $lines += 'VERDICT=NOT_RUN'
    $lines += 'CLASS=SHA_LEDGER_TEMPLATE_UNFILLED'
    $lines += 'NOTE=No EXPECTED_SHA256 rows yet. Template only — EARNED=0.'
    Write-Utf8 (Join-Path $OutDir 'RECEIPT.txt') (($lines -join "`r`n") + "`r`n")
    Write-Host "NOT_RUN: ledger template unfilled."
    exit 2
}

$mismatch = 0
$missing = 0
$ok = 0
$rowLog = New-Object System.Collections.Generic.List[string]
$rowLog.Add("rel_path`texpected`tactual`tstatus")

foreach ($rel in ($expected.Keys | Sort-Object)) {
    $want = $expected[$rel]
    $full = Join-Path $PackageDir $rel
    $got = Get-Sha256File $full
    if (-not $got) {
        $missing++
        $rowLog.Add("$rel`t$want`tMISSING`tMISSING")
        continue
    }
    if ($got -ne $want) {
        $mismatch++
        $rowLog.Add("$rel`t$want`t$got`tMISMATCH")
    } else {
        $ok++
        $rowLog.Add("$rel`t$want`t$got`tMATCH")
    }
}

Write-Utf8 (Join-Path $OutDir 'HASH_COMPARE.tsv') (($rowLog -join "`r`n") + "`r`n")

$lines += "ROWS_OK=$ok"
$lines += "ROWS_MISSING=$missing"
$lines += "ROWS_MISMATCH=$mismatch"

if ($missing -gt 0 -or $mismatch -gt 0) {
    $lines += 'VERDICT=FAIL'
    $lines += 'CLASS=PACKAGE_INTEGRITY_FAIL'
    $exit = 1
} elseif (-not $AllowPartial -and $ok -lt 1) {
    $lines += 'VERDICT=NOT_RUN'
    $lines += 'CLASS=NO_ROWS_COMPARED'
    $exit = 2
} else {
    $lines += 'VERDICT=PASS_INTEGRITY_ONLY'
    $lines += 'CLASS=HASH_MATCH_DECLARED_MEMBERS'
    $lines += 'NOTE=Integrity PASS != RELEASE_CERT / != INDEPENDENT_E2E / != PROMOTE'
    $exit = 0
}

$lines += 'PROMOTE=0'
$lines += 'CERTIFIED=0'
Write-Utf8 (Join-Path $OutDir 'RECEIPT.txt') (($lines -join "`r`n") + "`r`n")
Write-Host "Verdict written: $OutDir\RECEIPT.txt"
exit $exit

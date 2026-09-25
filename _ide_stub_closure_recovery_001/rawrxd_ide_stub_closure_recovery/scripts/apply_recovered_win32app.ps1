[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [switch]$Force,
    [switch]$NoBackup
)
$ErrorActionPreference = 'Stop'
$dropRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $dropRoot 'recovered_apply'
$targetRoot = Join-Path $RepoRoot 'src\win32app'
if (-not (Test-Path $targetRoot)) { throw "Win32 app source directory not found: $targetRoot" }

function Get-FirstNonBlankLine([string]$Path) {
    foreach ($line in [System.IO.File]::ReadLines($Path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) { return $line.Trim() }
    }
    return ''
}
function Test-PureStub([string]$Path) {
    if (-not (Test-Path $Path)) { return $false }
    $first = Get-FirstNonBlankLine $Path
    return $first -match '^//\s*STUB\b'
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
$backupRoot = Join-Path $RepoRoot ".rawrxd_stub_recovery_backup\$stamp"
$applied = 0; $skipped = 0; $missing = 0; $refused = 0
foreach ($src in Get-ChildItem $sourceRoot -Filter '*.cpp' | Sort-Object Name) {
    $dst = Join-Path $targetRoot $src.Name
    if (-not (Test-Path $dst)) {
        Write-Host "MISSING_TARGET $($src.Name)"
        $missing++
        continue
    }
    $isPureStub = Test-PureStub $dst
    if (-not $isPureStub -and -not $Force) {
        Write-Host "SKIP_NONSTUB $($src.Name)"
        $skipped++
        continue
    }
    if (-not $NoBackup) {
        New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
        Copy-Item -LiteralPath $dst -Destination (Join-Path $backupRoot $src.Name) -Force
    }
    if ($PSCmdlet.ShouldProcess($dst, "replace with recovered historical production body")) {
        Copy-Item -LiteralPath $src.FullName -Destination $dst -Force
        Write-Host "APPLIED $($src.Name) pure_stub=$isPureStub"
        $applied++
    }
}
Write-Host "RECOVERY_APPLIED=$applied"
Write-Host "RECOVERY_SKIPPED_NONSTUB=$skipped"
Write-Host "RECOVERY_MISSING_TARGET=$missing"
Write-Host "RECOVERY_REFUSED=$refused"
if (-not $NoBackup) { Write-Host "BACKUP_ROOT=$backupRoot" }

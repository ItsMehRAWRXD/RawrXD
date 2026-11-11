#Requires -Version 5.1
<#
.SYNOPSIS
  W6 clean-machine smoke driver (checklist-bound, fail-closed).
.DESCRIPTION
  Records environment claims + optional launch probe. Does not certify product-final.
  Operator must complete CLEAN_MACHINE_CHECKLIST.txt before claiming PASS.
.NOTES
  PROMOTE=0 CERTIFIED=0. Independent host required for band 97→100 credit.
#>
[CmdletBinding()]
param(
    [string]$PackageDir = '',
    [string]$ExeRelPath = 'RawrXD-Win32IDE-Native-Ext.exe',
    [string]$OutDir = '',
    [switch]$LaunchProbe
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutDir = Join-Path $Root ("runs\clean_machine_" + $stamp)
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Write-Utf8([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('CLEAN_MACHINE_SMOKE=W6')
$lines.Add('ASOF_UTC=' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
$lines.Add('PROMOTE=0')
$lines.Add('CERTIFIED=0')
$lines.Add('HOST=' + $env:COMPUTERNAME)
$lines.Add('USER=' + $env:USERNAME)
$lines.Add('OS=' + [System.Environment]::OSVersion.VersionString)
$lines.Add('CHECKLIST=' + (Join-Path $Root 'CLEAN_MACHINE_CHECKLIST.txt'))
$lines.Add('PACKAGE_DIR=' + $(if ($PackageDir) { $PackageDir } else { 'UNSET' }))

$checklistDone = Join-Path $OutDir 'CHECKLIST_OPERATOR_SIGN.txt'
Write-Utf8 $checklistDone @"
OPERATOR_SIGN=UNFILLED
CLEAN_CLONE=UNCHECKED
NO_DEV_TREE_PATH=UNCHECKED
NO_HIDDEN_ENV_CREDENTIALS=UNCHECKED
INDEPENDENT_HOST=UNCHECKED
SHA_LEDGER_MATCH=UNCHECKED
LAUNCH_SMOKE=UNCHECKED
AGENT_E2E=UNCHECKED
ROLLBACK=UNCHECKED
PROMOTE=0
CERTIFIED=0
NOTE=Fill after human verification. Script does not auto-PASS checklist rows.
"@

if (-not $PackageDir -or -not (Test-Path -LiteralPath $PackageDir)) {
    $lines.Add('VERDICT=NOT_RUN')
    $lines.Add('CLASS=PACKAGE_DIR_MISSING_OR_UNSET')
    Write-Utf8 (Join-Path $OutDir 'RECEIPT.txt') (($lines -join "`r`n") + "`r`n")
    Write-Host "NOT_RUN: set -PackageDir to extracted package root."
    exit 2
}

$exe = Join-Path $PackageDir $ExeRelPath
if (-not (Test-Path -LiteralPath $exe)) {
    $lines.Add('EXE=' + $exe)
    $lines.Add('VERDICT=NOT_RUN')
    $lines.Add('CLASS=EXE_MISSING')
    Write-Utf8 (Join-Path $OutDir 'RECEIPT.txt') (($lines -join "`r`n") + "`r`n")
    Write-Host "NOT_RUN: exe missing."
    exit 2
}

$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToUpperInvariant()
$lines.Add('EXE=' + $exe)
$lines.Add('EXE_SHA256=' + $sha)

if ($LaunchProbe) {
    try {
        $p = Start-Process -FilePath $exe -PassThru -WindowStyle Minimized
        Start-Sleep -Seconds 3
        if ($p.HasExited) {
            $lines.Add('LAUNCH=EXITED_EARLY')
            $lines.Add('EXIT_CODE=' + $p.ExitCode)
            $lines.Add('VERDICT=FAIL')
            $lines.Add('CLASS=LAUNCH_EXITED_EARLY')
            $code = 1
        } else {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $lines.Add('LAUNCH=PROCESS_STARTED')
            $lines.Add('VERDICT=SMOKE_LAUNCH_ONLY')
            $lines.Add('CLASS=LAUNCH_PROBE_OK_NOT_PRODUCT_FINAL')
            $lines.Add('NOTE=Launch smoke != independent E2E != CERTIFIED')
            $code = 0
        }
    } catch {
        $lines.Add('LAUNCH=EXCEPTION')
        $lines.Add('ERROR=' + $_.Exception.Message)
        $lines.Add('VERDICT=FAIL')
        $lines.Add('CLASS=LAUNCH_EXCEPTION')
        $code = 1
    }
} else {
    $lines.Add('LAUNCH=SKIPPED')
    $lines.Add('VERDICT=NOT_RUN')
    $lines.Add('CLASS=LAUNCH_PROBE_NOT_REQUESTED')
    $code = 2
}

$lines.Add('PROMOTE=0')
$lines.Add('CERTIFIED=0')
Write-Utf8 (Join-Path $OutDir 'RECEIPT.txt') (($lines -join "`r`n") + "`r`n")
Write-Host "Receipt: $OutDir\RECEIPT.txt"
exit $code

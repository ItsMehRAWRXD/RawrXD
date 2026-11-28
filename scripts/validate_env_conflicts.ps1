#requires -Version 5.1
<#
.SYNOPSIS
  Detects unknown, deprecated and conflicting RAWRXD_* overrides (M-CFG-05).
  Input: a file of NAME=VALUE lines, or the current process environment.
  Exit code 2 when conflicts/unknown names are found.
#>
[CmdletBinding()]
param(
    [string]$InputFile,
    [string]$InventoryPath
)
$ErrorActionPreference = 'Stop'
if (-not $InventoryPath) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $InventoryPath = Join-Path $base '..\config\env_inventory.json'
}

$known = @{}
if (Test-Path $InventoryPath) {
    $inv = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json
    foreach ($v in $inv.variables) { $known[$v.name] = $v.classification }
}

$pairs = @()
if ($InputFile -and (Test-Path $InputFile)) {
    foreach ($line in Get-Content -LiteralPath $InputFile) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') { $pairs += [pscustomobject]@{ Name = $Matches[1]; Value = $Matches[2] } }
    }
} else {
    foreach ($k in [Environment]::GetEnvironmentVariables().Keys) {
        if ($k -like 'RAWRXD_*') { $pairs += [pscustomobject]@{ Name = $k; Value = [Environment]::GetEnvironmentVariable($k) } }
    }
}

$problems = @()
$seen = @{}
foreach ($p in $pairs) {
    if (-not $known.ContainsKey($p.Name)) { $problems += "unknown variable: $($p.Name)" }
    elseif ($known[$p.Name] -eq 'deprecated') { $problems += "deprecated variable in use: $($p.Name)" }
    if ($seen.ContainsKey($p.Name) -and $seen[$p.Name] -ne $p.Value) {
        $problems += "conflicting override for $($p.Name): '$($seen[$p.Name])' vs '$($p.Value)'"
    }
    $seen[$p.Name] = $p.Value
}

if ($problems.Count -gt 0) {
    Write-Warning ($problems -join "`n")
    exit 2
}
Write-Host "Environment overrides OK ($($pairs.Count) variables)"
exit 0
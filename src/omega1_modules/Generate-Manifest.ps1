# RawrXD OMEGA-1 Manifest Generator
# Creates and validates the deployment manifest
# Compatible with PowerShell 5.1+

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RootPath = $(if ($env:RAWRXD_OMEGA_ROOT) { $env:RAWRXD_OMEGA_ROOT } else { "D:\lazy init ide\auto_generated_methods" }),
    
    [Parameter(Mandatory=$false)]
    [string]$BinaryPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'

function Get-FileHashSHA256 {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha.ComputeHash($stream)
        return [BitConverter]::ToString($hash).Replace('-', '').ToLower()
    }
    finally {
        $stream.Close()
    }
}

$manifestPath = Join-Path $RootPath 'manifest.json'

if ($ValidateOnly) {
    if (-not (Test-Path $manifestPath)) {
        Write-Error "Manifest not found: $manifestPath"
        exit 1
    }
    
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $valid = $true
    $issues = @()
    
    foreach ($module in $manifest.Modules) {
        $modulePath = Join-Path $RootPath "$module.psm1"
        if (-not (Test-Path $modulePath)) {
            $valid = $false
            $issues += "Missing module: $module"
        }
    }
    
    if ($valid) {
        Write-Host "✓ Manifest valid - $($manifest.Modules.Count) modules verified" -ForegroundColor Green
        exit 0
    } else {
        Write-Error "Manifest validation failed:`n$($issues -join "`n")"
        exit 1
    }
}

# Generate manifest
$modules = Get-ChildItem -Path $RootPath -Filter 'RawrXD.*.psm1' -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty BaseName | 
    Sort-Object

$moduleHashes = @{}
foreach ($mod in $modules) {
    $modPath = Join-Path $RootPath "$mod.psm1"
    $moduleHashes[$mod] = Get-FileHashSHA256 -Path $modPath
}

$manifest = @{
    SchemaVersion = '1.0.0-OMEGA'
    Timestamp = [DateTime]::UtcNow.ToString('o')
    Generator = 'RawrXD.Omega1.ManifestGenerator'
    Modules = @($modules)
    ModuleCount = $modules.Count
    ModuleHashes = $moduleHashes
    GlobalHash = [BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes(($moduleHashes.Values -join '|'))
        )
    ).Replace('-', '').ToLower()
    Environment = @{
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Platform = $PSVersionTable.Platform
        OS = $PSVersionTable.OS
    }
}

$json = $manifest | ConvertTo-Json -Depth 10
$manifestDir = Split-Path -Parent $manifestPath
if (!(Test-Path $manifestDir)) {
    New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
}
Set-Content -Path $manifestPath -Value $json -Encoding UTF8

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        RawrXD OMEGA-1 Manifest Generated                   ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Modules: $($manifest.ModuleCount.ToString().PadRight(47)) ║" -ForegroundColor Cyan
Write-Host "║  Global Hash: $($manifest.GlobalHash.Substring(0, 16).PadRight(41))... ║" -ForegroundColor Cyan
Write-Host "║  Location: $($manifestPath.PadRight(48)) ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

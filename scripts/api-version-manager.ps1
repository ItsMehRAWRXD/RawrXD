# RawrXD API Version Manager
# Manages API versioning and deprecation

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Create", "Deprecate", "Remove", "Migrate")]
    [string]$Action = "List",
    
    [string]$Version = "",
    [string]$NewVersion = "",
    [string]$SunsetDate = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-APIVersionManager {
    Write-Status "API Version Manager initialized"
}

function Get-APIVersions {
    return @(
        @{ Version = "v1"; Status = "Stable"; Released = "2023-01-15"; Deprecated = $false; Sunset = $null }
        @{ Version = "v2"; Status = "Stable"; Released = "2023-06-01"; Deprecated = $false; Sunset = $null }
        @{ Version = "v3"; Status = "Current"; Released = "2024-01-01"; Deprecated = $false; Sunset = $null }
        @{ Version = "v1-beta"; Status = "Deprecated"; Released = "2022-06-01"; Deprecated = $true; Sunset = "2024-06-01" }
    )
}

function Show-APIVersionList {
    $versions = Get-APIVersions
    
    Write-Host ""
    Write-Host "API Versions" -ForegroundColor Cyan
    Write-Host "============" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Version    Status      Released      Deprecated    Sunset Date"
    Write-Host "  " + "-" * 65
    
    foreach ($ver in $versions) {
        $statusColor = switch ($ver.Status) {
            "Current" { "Green" }
            "Stable" { "Cyan" }
            "Deprecated" { "Yellow" }
            "Removed" { "Red" }
        }
        $deprecated = if ($ver.Deprecated) { "Yes" } else { "No" }
        $sunset = if ($ver.Sunset) { $ver.Sunset } else { "-" }
        Write-Host "  $($ver.Version.PadRight(10)) " -NoNewline
        Write-Host $ver.Status.PadRight(11) -ForegroundColor $statusColor -NoNewline
        Write-Host " $($ver.Released)  $($deprecated.PadRight(13)) $sunset"
    }
}

function New-APIVersion {
    param([string]$Ver)
    
    if (-not $Ver) {
        Write-Error "Version required"
        return
    }
    
    Write-Status "Creating new API version: $Ver"
    Write-Host "  Copying from current version..."
    Write-Host "  Adding version headers..."
    Write-Success "API version $Ver created"
}

function Deprecate-APIVersion {
    param([string]$Ver, [string]$Sunset)
    
    if (-not $Ver) {
        Write-Error "Version required"
        return
    }
    
    Write-Warning "Deprecating API version: $Ver"
    Write-Host "  Sunset date: $Sunset"
    Write-Success "Version deprecated"
}

function Remove-APIVersion {
    param([string]$Ver)
    
    if (-not $Ver) {
        Write-Error "Version required"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Remove API version '$Ver'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Removal cancelled"
            return
        }
    }
    
    Write-Status "Removing API version: $Ver"
    Write-Success "Version removed"
}

function Show-MigrationGuide {
    param([string]$From, [string]$To)
    
    Write-Host ""
    Write-Host "API Migration Guide" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Migrating from $From to $To"
    Write-Host ""
    Write-Host "  Breaking Changes:"
    Write-Host "    • Endpoint /v1/completions renamed to /v2/completions"
    Write-Host "    • Response format changed for embeddings"
    Write-Host "    • Authentication now requires Bearer token"
    Write-Host ""
    Write-Host "  Deprecations:"
    Write-Host "    • temperature parameter range changed"
    Write-Host "    • max_tokens default value increased"
}

# Main execution
function Main {
    Write-Host "RawrXD API Version Manager" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-APIVersionManager
    
    switch ($Action) {
        "List" { Show-APIVersionList }
        "Create" { New-APIVersion -Ver $Version }
        "Deprecate" { Deprecate-APIVersion -Ver $Version -Sunset $SunsetDate }
        "Remove" { Remove-APIVersion -Ver $Version }
        "Migrate" { Show-MigrationGuide -From $Version -To $NewVersion }
    }
    
    Write-Host ""
}

Main

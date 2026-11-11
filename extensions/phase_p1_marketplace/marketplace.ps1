#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase P.1: Extension Marketplace Manager
    
.DESCRIPTION
    Manages the RawrXD extension marketplace including package validation,
    publishing, installation, and versioning.
    
.PARAMETER Action
    Action to perform: publish, install, uninstall, list, search, validate
    
.PARAMETER PackagePath
    Path to extension package
    
.PARAMETER ExtensionId
    Extension identifier
    
.EXAMPLE
    .\marketplace.ps1 -Action publish -PackagePath .\my-extension.zip
    .\marketplace.ps1 -Action install -ExtensionId "rawrxd-syntax-highlighting"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("publish", "install", "uninstall", "list", "search", "validate", "update")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$PackagePath,
    
    [Parameter(Mandatory=$false)]
    [string]$ExtensionId,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchQuery,
    
    [Parameter(Mandatory=$false)]
    [string]$MarketplacePath = ".\marketplace_data",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = ".\installed_extensions"
)

$ErrorActionPreference = "Stop"

# Marketplace registry
$MarketplaceRegistry = @{
    Extensions = @{}
    Categories = @("language", "theme", "tool", "integration", "model")
    LastUpdated = $null
}

# Extension manifest schema version
$ManifestSchemaVersion = "1.0"

function Write-MarketplaceHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase P.1: Extension Marketplace                                  ║
║  Package management for RawrXD extensions                            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-Marketplace {
    if (-not (Test-Path $MarketplacePath)) {
        New-Item -ItemType Directory -Path $MarketplacePath -Force | Out-Null
    }
    if (-not (Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }
    
    $registryFile = Join-Path $MarketplacePath "marketplace_registry.json"
    if (Test-Path $registryFile) {
        $script:MarketplaceRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-Marketplace {
    $registryFile = Join-Path $MarketplacePath "marketplace_registry.json"
    $script:MarketplaceRegistry.LastUpdated = Get-Date -Format "o"
    $script:MarketplaceRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Test-ExtensionManifest {
    param($ManifestPath)
    
    $errors = @()
    
    if (-not (Test-Path $ManifestPath)) {
        $errors += "Extension manifest not found (extension.json)"
        return $errors
    }
    
    try {
        $manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json -AsHashtable
    } catch {
        $errors += "Invalid JSON in extension.json"
        return $errors
    }
    
    # Required fields
    $required = @("id", "name", "version", "description", "author", "category")
    foreach ($field in $required) {
        if (-not $manifest.ContainsKey($field)) {
            $errors += "Missing required field: $field"
        }
    }
    
    # Validate ID format
    if ($manifest.id -and $manifest.id -notmatch '^[a-z0-9-]+$') {
        $errors += "Invalid extension ID format (use lowercase letters, numbers, hyphens)"
    }
    
    # Validate version format
    if ($manifest.version -and $manifest.version -notmatch '^\d+\.\d+\.\d+$') {
        $errors += "Invalid version format (use semantic versioning: x.y.z)"
    }
    
    # Validate category
    if ($manifest.category -and $manifest.category -notin $script:MarketplaceRegistry.Categories) {
        $errors += "Invalid category. Valid: $($script:MarketplaceRegistry.Categories -join ', ')"
    }
    
    return $errors
}

function Publish-Extension {
    param($PackagePath)
    
    Write-Host "`nPublishing extension..." -ForegroundColor Yellow
    
    if (-not (Test-Path $PackagePath)) {
        Write-Error "Package not found: $PackagePath"
        return
    }
    
    # Extract and validate
    $tempDir = Join-Path $env:TEMP "rawrxd_ext_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    
    try {
        if ($PackagePath -like "*.zip") {
            Expand-Archive -Path $PackagePath -DestinationPath $tempDir -Force
        } else {
            Copy-Item -Path $PackagePath -Destination $tempDir -Recurse -Force
        }
        
        $manifestPath = Join-Path $tempDir "extension.json"
        $errors = Test-ExtensionManifest -ManifestPath $manifestPath
        
        if ($errors.Count -gt 0) {
            Write-Host "`nValidation errors:" -ForegroundColor Red
            foreach ($error in $errors) {
                Write-Host "  ✗ $error" -ForegroundColor Red
            }
            return
        }
        
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -AsHashtable
        
        # Check if extension already exists
        if ($script:MarketplaceRegistry.Extensions.ContainsKey($manifest.id)) {
            $existing = $script:MarketplaceRegistry.Extensions[$manifest.id]
            if ([version]$manifest.version -le [version]$existing.version) {
                Write-Error "Version $($manifest.version) must be greater than existing $($existing.version)"
                return
            }
        }
        
        # Calculate package hash
        $hash = Get-FileHash -Path $PackagePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
        
        # Register extension
        $extension = @{
            Id = $manifest.id
            Name = $manifest.name
            Version = $manifest.version
            Description = $manifest.description
            Author = $manifest.author
            Category = $manifest.category
            Tags = $manifest.tags
            PublishedAt = Get-Date -Format "o"
            DownloadUrl = "marketplace://$($manifest.id)/$($manifest.version)"
            Hash = $hash
            Size = (Get-Item $PackagePath).Length
            Installs = 0
            Rating = 0
            Reviews = @()
        }
        
        $script:MarketplaceRegistry.Extensions[$manifest.id] = $extension
        
        # Store package
        $extDir = Join-Path $MarketplacePath $manifest.id
        New-Item -ItemType Directory -Path $extDir -Force | Out-Null
        Copy-Item -Path $PackagePath -Destination (Join-Path $extDir "$($manifest.version).zip") -Force
        
        Save-Marketplace
        
        Write-Host "  ✓ Extension published successfully" -ForegroundColor Green
        Write-Host "  ✓ ID: $($manifest.id)" -ForegroundColor Gray
        Write-Host "  ✓ Version: $($manifest.version)" -ForegroundColor Gray
        Write-Host "  ✓ Category: $($manifest.category)" -ForegroundColor Gray
    }
    finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-Extension {
    param($ExtensionId)
    
    Write-Host "`nInstalling extension: $ExtensionId..." -ForegroundColor Yellow
    
    if (-not $script:MarketplaceRegistry.Extensions.ContainsKey($ExtensionId)) {
        Write-Error "Extension not found: $ExtensionId"
        return
    }
    
    $extension = $script:MarketplaceRegistry.Extensions[$ExtensionId]
    $packagePath = Join-Path $MarketplacePath $ExtensionId "$($extension.version).zip"
    
    if (-not (Test-Path $packagePath)) {
        Write-Error "Package file not found for $ExtensionId"
        return
    }
    
    # Install
    $installDir = Join-Path $InstallPath $ExtensionId
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    
    Expand-Archive -Path $packagePath -DestinationPath $installDir -Force
    
    # Update install count
    $extension.Installs++
    Save-Marketplace
    
    Write-Host "  ✓ Extension installed successfully" -ForegroundColor Green
    Write-Host "  ✓ Location: $installDir" -ForegroundColor Gray
    
    # Load and display post-install info
    $manifestPath = Join-Path $installDir "extension.json"
    if (Test-Path $manifestPath) {
        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -AsHashtable
        if ($manifest.postInstall) {
            Write-Host "`nPost-install message:" -ForegroundColor Cyan
            Write-Host "  $($manifest.postInstall)" -ForegroundColor White
        }
    }
}

function Uninstall-Extension {
    param($ExtensionId)
    
    Write-Host "`nUninstalling extension: $ExtensionId..." -ForegroundColor Yellow
    
    $installDir = Join-Path $InstallPath $ExtensionId
    if (-not (Test-Path $installDir)) {
        Write-Error "Extension not installed: $ExtensionId"
        return
    }
    
    Remove-Item -Path $installDir -Recurse -Force
    
    Write-Host "  ✓ Extension uninstalled successfully" -ForegroundColor Green
}

function Get-ExtensionList {
    param($Category)
    
    Write-Host "`nMarketplace Extensions:" -ForegroundColor Yellow
    Write-Host ""
    
    $extensions = $script:MarketplaceRegistry.Extensions.Values
    if ($Category) {
        $extensions = $extensions | Where-Object { $_.Category -eq $Category }
    }
    
    if ($extensions.Count -eq 0) {
        Write-Host "  No extensions found" -ForegroundColor Gray
        return
    }
    
    Write-Host "  {0,-25} {1,-10} {2,-12} {3,-8} {4}" -f "Name", "Version", "Category", "Installs", "Description" -ForegroundColor White
    Write-Host "  $("-" * 90)" -ForegroundColor Gray
    
    foreach ($ext in ($extensions | Sort-Object Name)) {
        $desc = $ext.Description
        if ($desc.Length -gt 30) { $desc = $desc.Substring(0, 27) + "..." }
        Write-Host "  {0,-25} {1,-10} {2,-12} {3,-8} {4}" -f $ext.Name, $ext.Version, $ext.Category, $ext.Installs, $desc -ForegroundColor Gray
    }
    
    Write-Host "`n  Total: $($extensions.Count) extensions" -ForegroundColor Cyan
}

function Search-Extensions {
    param($Query)
    
    Write-Host "`nSearching for: '$Query'..." -ForegroundColor Yellow
    Write-Host ""
    
    $results = $script:MarketplaceRegistry.Extensions.Values | Where-Object {
        $_.Name -like "*$Query*" -or
        $_.Description -like "*$Query*" -or
        $_.Tags -contains $Query -or
        $_.Category -eq $Query
    }
    
    if ($results.Count -eq 0) {
        Write-Host "  No results found" -ForegroundColor Gray
        return
    }
    
    foreach ($ext in ($results | Sort-Object Name)) {
        Write-Host "  $($ext.Name) v$($ext.version) [$($ext.Category)]" -ForegroundColor White
        Write-Host "    $($ext.Description)" -ForegroundColor Gray
        Write-Host "    By: $($ext.Author) | Installs: $($ext.Installs)" -ForegroundColor DarkGray
        Write-Host ""
    }
}

function Update-Extensions {
    Write-Host "`nChecking for extension updates..." -ForegroundColor Yellow
    
    $installed = Get-ChildItem -Path $InstallPath -Directory -ErrorAction SilentlyContinue
    $updates = @()
    
    foreach ($dir in $installed) {
        $extId = $dir.Name
        $manifestPath = Join-Path $dir.FullName "extension.json"
        
        if (Test-Path $manifestPath) {
            $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -AsHashtable
            
            if ($script:MarketplaceRegistry.Extensions.ContainsKey($extId)) {
                $marketplace = $script:MarketplaceRegistry.Extensions[$extId]
                if ([version]$marketplace.version -gt [version]$manifest.version) {
                    $updates += @{
                        Id = $extId
                        Current = $manifest.version
                        Available = $marketplace.version
                    }
                }
            }
        }
    }
    
    if ($updates.Count -eq 0) {
        Write-Host "  All extensions are up to date!" -ForegroundColor Green
        return
    }
    
    Write-Host "  Updates available:" -ForegroundColor Yellow
    foreach ($update in $updates) {
        Write-Host "    $($update.Id): $($update.Current) → $($update.Available)" -ForegroundColor Cyan
    }
}

# Main execution
Write-MarketplaceHeader
Initialize-Marketplace

switch ($Action) {
    "publish" {
        if (-not $PackagePath) {
            Write-Error "PackagePath required for publish action"
            exit 1
        }
        Publish-Extension -PackagePath $PackagePath
    }
    "install" {
        if (-not $ExtensionId) {
            Write-Error "ExtensionId required for install action"
            exit 1
        }
        Install-Extension -ExtensionId $ExtensionId
    }
    "uninstall" {
        if (-not $ExtensionId) {
            Write-Error "ExtensionId required for uninstall action"
            exit 1
        }
        Uninstall-Extension -ExtensionId $ExtensionId
    }
    "list" {
        Get-ExtensionList -Category $Category
    }
    "search" {
        if (-not $SearchQuery) {
            Write-Error "SearchQuery required for search action"
            exit 1
        }
        Search-Extensions -Query $SearchQuery
    }
    "validate" {
        if (-not $PackagePath) {
            Write-Error "PackagePath required for validate action"
            exit 1
        }
        $errors = Test-ExtensionManifest -ManifestPath (Join-Path $PackagePath "extension.json")
        if ($errors.Count -eq 0) {
            Write-Host "  ✓ Manifest is valid" -ForegroundColor Green
        } else {
            Write-Host "`nValidation errors:" -ForegroundColor Red
            foreach ($error in $errors) {
                Write-Host "  ✗ $error" -ForegroundColor Red
            }
        }
    }
    "update" {
        Update-Extensions
    }
}

Write-Host "`n✅ Marketplace operation complete" -ForegroundColor Green

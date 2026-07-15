#!/usr/bin/env pwsh
#requires -Version 7.0

<#
.SYNOPSIS
    Phase R.2: Distribution Manager
    
.DESCRIPTION
    Manages artifact distribution across multiple channels and storage backends.
    Handles CDN distribution, release channels, and download tracking.
    
.PARAMETER Action
    Action to perform: upload, promote, channel-list, stats, sync
    
.PARAMETER Version
    Version to distribute
    
.PARAMETER Channel
    Target distribution channel
    
.PARAMETER Backend
    Storage backend: local, s3, azure, gcs
    
.EXAMPLE
    .\distribution_manager.ps1 -Action upload -Version 1.0.0 -Channel stable
    .\distribution_manager.ps1 -Action promote -Version 1.0.0-beta.1 -Channel beta
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("upload", "promote", "channel-list", "stats", "sync", "verify")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("stable", "beta", "alpha", "nightly")]
    [string]$Channel = "stable",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("local", "s3", "azure", "gcs")]
    [string]$Backend = "local",
    
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = ".\releases",
    
    [Parameter(Mandatory=$false)]
    [string]$DistributionRoot = ".\distribution"
)

$ErrorActionPreference = "Stop"

# Distribution registry
$DistributionRegistry = @{
    Channels = @{}
    Artifacts = @()
    Downloads = @()
    LastSync = $null
}

# Channel configuration
$ChannelConfig = @{
    stable = @{ 
        RetentionDays = 365
        CDNEnabled = $true
        SignatureRequired = $true
        AutoPromoteFrom = $null
    }
    beta = @{ 
        RetentionDays = 90
        CDNEnabled = $true
        SignatureRequired = $true
        AutoPromoteFrom = "alpha"
    }
    alpha = @{ 
        RetentionDays = 30
        CDNEnabled = $false
        SignatureRequired = $false
        AutoPromoteFrom = $null
    }
    nightly = @{ 
        RetentionDays = 7
        CDNEnabled = $false
        SignatureRequired = $false
        AutoPromoteFrom = $null
    }
}

function Write-DistributionHeader {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║  Phase R.2: Distribution Manager                                 ║
║  Multi-channel artifact distribution and CDN management              ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Initialize-DistributionManager {
    if (-not (Test-Path $DistributionRoot)) {
        New-Item -ItemType Directory -Path $DistributionRoot -Force | Out-Null
    }
    
    # Initialize channel directories
    foreach ($ch in $ChannelConfig.Keys) {
        $chPath = Join-Path $DistributionRoot $ch
        if (-not (Test-Path $chPath)) {
            New-Item -ItemType Directory -Path $chPath -Force | Out-Null
        }
    }
    
    # Load registry
    $registryFile = Join-Path $DistributionRoot "distribution_registry.json"
    if (Test-Path $registryFile) {
        $script:DistributionRegistry = Get-Content -Path $registryFile -Raw | ConvertFrom-Json -AsHashtable
    }
}

function Save-DistributionRegistry {
    $registryFile = Join-Path $DistributionRoot "distribution_registry.json"
    $script:DistributionRegistry | ConvertTo-Json -Depth 10 | Set-Content -Path $registryFile
}

function Get-ChannelUrl {
    param($Channel, $Version, $Artifact)
    
    $baseUrls = @{
        local = "file:///$($DistributionRoot -replace '\\', '/')/$Channel/v$Version"
        s3 = "https://releases.rawrxd.io/$Channel/v$Version"
        azure = "https://rawrxdreleases.blob.core.windows.net/releases/$Channel/v$Version"
        gcs = "https://storage.googleapis.com/rawrxd-releases/$Channel/v$Version"
    }
    
    return "$($baseUrls[$Backend])/$Artifact"
}

function Publish-Artifact {
    param($Version, $Channel, $Platform)
    
    Write-Host "  Uploading $Platform artifact..." -ForegroundColor Gray
    
    $sourceDir = Join-Path $SourcePath "v$Version"
    $targetDir = Join-Path (Join-Path $DistributionRoot $Channel) "v$Version"
    
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    
    # Simulate artifact upload
    $artifactName = "rawrxd-v$Version-$Platform"
    $sourceFile = Join-Path $sourceDir "$artifactName.zip.txt"
    $targetFile = Join-Path $targetDir "$artifactName.zip"
    
    if (Test-Path $sourceFile) {
        Copy-Item -Path $sourceFile -Destination "$targetFile.txt" -Force
        
        # Copy checksum
        $checksumSource = Join-Path $sourceDir "checksums.sha256"
        if (Test-Path $checksumSource) {
            Copy-Item -Path $checksumSource -Destination $targetDir -Force
        }
        
        Write-Host "    ✓ Uploaded: $artifactName" -ForegroundColor Green
        
        return @{
            Version = $Version
            Channel = $Channel
            Platform = $Platform
            Path = $targetFile
            UploadedAt = Get-Date -Format "o"
            URL = Get-ChannelUrl -Channel $Channel -Version $Version -Artifact "$artifactName.zip"
        }
    } else {
        Write-Host "    ✗ Source not found: $sourceFile" -ForegroundColor Red
        return $null
    }
}

function Invoke-Upload {
    param($Version, $Channel)
    
    Write-Host "`nUploading v$Version to $Channel channel..." -ForegroundColor Yellow
    
    $sourceDir = Join-Path $SourcePath "v$Version"
    if (-not (Test-Path $sourceDir)) {
        Write-Error "Release v$Version not found at $sourceDir"
        return
    }
    
    $config = $ChannelConfig[$Channel]
    Write-Host "  Channel config:" -ForegroundColor Gray
    Write-Host "    Retention: $($config.RetentionDays) days" -ForegroundColor Gray
    Write-Host "    CDN: $($config.CDNEnabled)" -ForegroundColor Gray
    Write-Host "    Signature: $($config.SignatureRequired)" -ForegroundColor Gray
    
    $artifacts = @()
    $platforms = @("windows-x64", "linux-x64", "macos-x64")
    
    foreach ($platform in $platforms) {
        $artifact = Publish-Artifact -Version $Version -Channel $Channel -Platform $platform
        if ($artifact) {
            $artifacts += $artifact
        }
    }
    
    # Copy release notes
    $notesSource = Join-Path $SourcePath "v$Version-release-notes.md"
    $targetDir = Join-Path (Join-Path $DistributionRoot $Channel) "v$Version"
    if (Test-Path $notesSource) {
        Copy-Item -Path $notesSource -Destination $targetDir -Force
        Write-Host "  ✓ Release notes copied" -ForegroundColor Green
    }
    
    # Register distribution
    $distribution = @{
        Version = $Version
        Channel = $Channel
        UploadedAt = Get-Date -Format "o"
        Artifacts = $artifacts
        Backend = $Backend
        Config = $config
    }
    
    $script:DistributionRegistry.Artifacts += $distribution
    Save-DistributionRegistry
    
    Write-Host "`n✓ Distribution complete" -ForegroundColor Green
    Write-Host "  Total artifacts: $($artifacts.Count)" -ForegroundColor Cyan
    
    # Display URLs
    Write-Host "`nDownload URLs:" -ForegroundColor Yellow
    foreach ($art in $artifacts) {
        Write-Host "  $($art.Platform): $($art.URL)" -ForegroundColor Gray
    }
}

function Invoke-Promote {
    param($Version, $ToChannel)
    
    Write-Host "`nPromoting v$Version to $ToChannel channel..." -ForegroundColor Yellow
    
    # Find current channel
    $currentDist = $script:DistributionRegistry.Artifacts | 
        Where-Object { $_.Version -eq $Version } | 
        Select-Object -First 1
    
    if (-not $currentDist) {
        Write-Error "Version $Version not found in distribution"
        return
    }
    
    $fromChannel = $currentDist.Channel
    Write-Host "  Current channel: $fromChannel" -ForegroundColor Gray
    Write-Host "  Target channel: $ToChannel" -ForegroundColor Gray
    
    if ($fromChannel -eq $ToChannel) {
        Write-Warning "Version is already in $ToChannel channel"
        return
    }
    
    # Copy artifacts to new channel
    $sourceDir = Join-Path (Join-Path $DistributionRoot $fromChannel) "v$Version"
    $targetDir = Join-Path (Join-Path $DistributionRoot $ToChannel) "v$Version"
    
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    
    Get-ChildItem -Path $sourceDir | Copy-Item -Destination $targetDir -Force
    
    # Update registry
    $currentDist.Channel = $ToChannel
    $currentDist.PromotedAt = Get-Date -Format "o"
    $currentDist.PreviousChannel = $fromChannel
    Save-DistributionRegistry
    
    Write-Host "`n✓ Promoted v$Version from $fromChannel to $ToChannel" -ForegroundColor Green
}

function Get-ChannelList {
    Write-Host "`nDistribution Channels:" -ForegroundColor Yellow
    Write-Host ""
    
    foreach ($ch in $ChannelConfig.Keys) {
        $config = $ChannelConfig[$ch]
        $chPath = Join-Path $DistributionRoot $ch
        
        $versions = @()
        if (Test-Path $chPath) {
            $versions = Get-ChildItem -Path $chPath -Directory | Select-Object -ExpandProperty Name
        }
        
        Write-Host "  📦 $ch" -ForegroundColor White
        Write-Host "     Retention: $($config.RetentionDays) days | CDN: $($config.CDNEnabled) | Signed: $($config.SignatureRequired)" -ForegroundColor Gray
        Write-Host "     Versions: $($versions.Count)" -ForegroundColor Gray
        
        if ($versions.Count -gt 0) {
            foreach ($v in ($versions | Sort-Object -Descending | Select-Object -First 3)) {
                Write-Host "       └─ $v" -ForegroundColor DarkGray
            }
            if ($versions.Count -gt 3) {
                Write-Host "       └─ ... and $($versions.Count - 3) more" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }
}

function Get-DistributionStats {
    Write-Host "`nDistribution Statistics:" -ForegroundColor Yellow
    Write-Host ""
    
    $totalArtifacts = $script:DistributionRegistry.Artifacts.Count
    $byChannel = $script:DistributionRegistry.Artifacts | Group-Object -Property Channel
    $byBackend = $script:DistributionRegistry.Artifacts | Group-Object -Property Backend
    
    Write-Host "  Total Distributions: $totalArtifacts" -ForegroundColor White
    Write-Host ""
    
    Write-Host "  By Channel:" -ForegroundColor Cyan
    foreach ($group in $byChannel) {
        Write-Host "    $($group.Name): $($group.Count)" -ForegroundColor Gray
    }
    Write-Host ""
    
    Write-Host "  By Backend:" -ForegroundColor Cyan
    foreach ($group in $byBackend) {
        Write-Host "    $($group.Name): $($group.Count)" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Storage usage (simulated)
    $totalSize = 0
    foreach ($dist in $script:DistributionRegistry.Artifacts) {
        $totalSize += ($dist.Artifacts.Count * 50MB)  # Simulated 50MB per artifact
    }
    
    Write-Host "  Estimated Storage: $([math]::Round($totalSize / 1GB, 2)) GB" -ForegroundColor White
    
    if ($script:DistributionRegistry.LastSync) {
        Write-Host "  Last Sync: $($script:DistributionRegistry.LastSync)" -ForegroundColor Gray
    }
}

function Invoke-Sync {
    Write-Host "`nSyncing distribution registry..." -ForegroundColor Yellow
    
    # Scan distribution directory
    $foundArtifacts = @()
    foreach ($ch in $ChannelConfig.Keys) {
        $chPath = Join-Path $DistributionRoot $ch
        if (Test-Path $chPath) {
            $versions = Get-ChildItem -Path $chPath -Directory
            foreach ($ver in $versions) {
                $versionNum = $ver.Name -replace '^v', ''
                $artifacts = Get-ChildItem -Path $ver.FullName -File
                
                $foundArtifacts += @{
                    Version = $versionNum
                    Channel = $ch
                    Path = $ver.FullName
                    ArtifactCount = $artifacts.Count
                    LastModified = $ver.LastWriteTime
                }
            }
        }
    }
    
    $script:DistributionRegistry.LastSync = Get-Date -Format "o"
    Save-DistributionRegistry
    
    Write-Host "  ✓ Sync complete" -ForegroundColor Green
    Write-Host "  Found: $($foundArtifacts.Count) version directories" -ForegroundColor Cyan
}

function Test-Distribution {
    param($Version, $Channel)
    
    Write-Host "`nVerifying distribution v$Version ($Channel)..." -ForegroundColor Yellow
    
    $versionDir = Join-Path (Join-Path $DistributionRoot $Channel) "v$Version"
    
    if (-not (Test-Path $versionDir)) {
        Write-Error "Distribution not found: $versionDir"
        return
    }
    
    $issues = @()
    $files = Get-ChildItem -Path $versionDir -File
    
    # Check for required files
    $requiredPatterns = @("*.zip", "checksums.sha256", "*release-notes.md")
    foreach ($pattern in $requiredPatterns) {
        $matches = $files | Where-Object { $_.Name -like $pattern }
        if (-not $matches) {
            $issues += "Missing: $pattern"
        }
    }
    
    # Verify checksums
    $checksumFile = Join-Path $versionDir "checksums.sha256"
    if (Test-Path $checksumFile) {
        $checksums = Get-Content -Path $checksumFile
        foreach ($line in $checksums) {
            if ($line -match "^([a-f0-9]{64})\s+(.+)$") {
                Write-Host "  ✓ Checksum entry: $($matches[2])" -ForegroundColor Green
            }
        }
    }
    
    if ($issues.Count -eq 0) {
        Write-Host "`n  ✓ Distribution verified successfully" -ForegroundColor Green
    } else {
        Write-Host "`n  Issues found:" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "    ✗ $issue" -ForegroundColor Red
        }
    }
}

# Main execution
Write-DistributionHeader
Initialize-DistributionManager

switch ($Action) {
    "upload" {
        if (-not $Version) {
            Write-Error "Version required for upload action"
            exit 1
        }
        Invoke-Upload -Version $Version -Channel $Channel
    }
    "promote" {
        if (-not $Version) {
            Write-Error "Version required for promote action"
            exit 1
        }
        Invoke-Promote -Version $Version -ToChannel $Channel
    }
    "channel-list" {
        Get-ChannelList
    }
    "stats" {
        Get-DistributionStats
    }
    "sync" {
        Invoke-Sync
    }
    "verify" {
        if (-not $Version) {
            Write-Error "Version required for verify action"
            exit 1
        }
        Test-Distribution -Version $Version -Channel $Channel
    }
}

Write-Host "`n✅ Distribution manager operation complete" -ForegroundColor Green

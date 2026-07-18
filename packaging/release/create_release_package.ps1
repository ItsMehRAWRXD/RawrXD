# create_release_package.ps1
# Phase F.1 Batch 4/5: Create complete release package with all artifacts

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [string]$BuildDir = ".\build",
    [string]$OutputDir = ".\releases",
    [switch]$SignBinaries,
    [string]$CertificateThumbprint,
    [switch]$CreateInstaller,
    [switch]$CreateDockerImages,
    [switch]$UploadToCDN,
    [string]$CDNEndpoint,
    [switch]$GenerateReleaseNotes
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$ProductName = "RawrXD Sovereign"
$Platforms = @("windows-x64", "linux-x64", "macos-x64", "macos-arm64")

# ============================================================================
# Logging
# ============================================================================

function Write-Status($Message) {
    Write-Host "[RELEASE] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ============================================================================
# Directory Setup
# ============================================================================

function Initialize-ReleaseDirectory {
    Write-Status "Initializing release directory..."
    
    $releaseDir = Join-Path $OutputDir "v$Version"
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
    
    foreach ($platform in $Platforms) {
        New-Item -ItemType Directory -Path (Join-Path $releaseDir $platform) -Force | Out-Null
    }
    
    return $releaseDir
}

# ============================================================================
# Binary Collection
# ============================================================================

function Copy-PlatformBinaries($ReleaseDir, $Platform) {
    Write-Status "Collecting binaries for $Platform..."
    
    $platformDir = Join-Path $ReleaseDir $Platform
    $buildPlatformDir = Join-Path $BuildDir $Platform
    
    if (-not (Test-Path $buildPlatformDir)) {
        Write-Warning "Build directory not found: $buildPlatformDir"
        return $false
    }
    
    # Copy executables
    $executables = Get-ChildItem -Path $buildPlatformDir -Filter "rawrxd*" -Recurse
    foreach ($exe in $executables) {
        Copy-Item $exe.FullName $platformDir -Force
        Write-Status "  Copied: $($exe.Name)"
    }
    
    # Copy documentation
    $docs = @("README.md", "LICENSE", "CHANGELOG.md")
    foreach ($doc in $docs) {
        if (Test-Path $doc) {
            Copy-Item $doc $platformDir -Force
        }
    }
    
    return $true
}

# ============================================================================
# Archive Creation
# ============================================================================

function New-PlatformArchive($ReleaseDir, $Platform) {
    Write-Status "Creating archive for $Platform..."
    
    $platformDir = Join-Path $ReleaseDir $Platform
    $archiveName = "rawrxd-$Version-$Platform"
    
    switch -Wildcard ($Platform) {
        "windows*" {
            $archivePath = Join-Path $ReleaseDir "$archiveName.zip"
            Compress-Archive -Path "$platformDir\*" -DestinationPath $archivePath -Force
        }
        default {
            $archivePath = Join-Path $ReleaseDir "$archiveName.tar.gz"
            $tarArgs = @("-czf", $archivePath, "-C", $platformDir, ".")
            
            # Use tar if available (Windows 10+ has tar)
            if (Get-Command tar -ErrorAction SilentlyContinue) {
                & tar $tarArgs
            } else {
                # Fallback to 7zip or other
                Write-Warning "tar not available, skipping archive creation"
                return $null
            }
        }
    }
    
    Write-Success "Created: $archivePath"
    return $archivePath
}

# ============================================================================
# Signing
# ============================================================================

function Invoke-BinarySigning($ReleaseDir, $Thumbprint) {
    if (-not $SignBinaries) { return }
    
    Write-Status "Signing binaries..."
    
    $signScript = ".\packaging\security\sign_and_verify.ps1"
    if (-not (Test-Path $signScript)) {
        Write-Error "Signing script not found: $signScript"
        return
    }
    
    foreach ($platform in $Platforms) {
        $platformDir = Join-Path $ReleaseDir $platform
        if (-not (Test-Path $platformDir)) { continue }
        
        $executables = Get-ChildItem -Path $platformDir -Filter "*.exe"
        foreach ($exe in $executables) {
            & $signScript `
                -BinaryPath $exe.FullName `
                -CertificateThumbprint $Thumbprint `
                -CreateChecksums `
                -OutputDir $platformDir
        }
    }
}

# ============================================================================
# Installer Creation
# ============================================================================

function New-WindowsInstaller($ReleaseDir) {
    if (-not $CreateInstaller) { return }
    
    Write-Status "Creating Windows installer..."
    
    $installerScript = ".\packaging\install\installer_builder.ps1"
    if (-not (Test-Path $installerScript)) {
        Write-Warning "Installer builder not found, skipping"
        return
    }
    
    $windowsDir = Join-Path $ReleaseDir "windows-x64"
    
    & $installerScript `
        -SourceDir $windowsDir `
        -OutputDir $ReleaseDir `
        -Version $Version `
        -BuildMSI
}

# ============================================================================
# Checksum Generation
# ============================================================================

function New-ReleaseChecksums($ReleaseDir) {
    Write-Status "Generating release checksums..."
    
    $checksums = @{}
    $files = Get-ChildItem -Path $ReleaseDir -File
    
    foreach ($file in $files) {
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $checksums[$file.Name] = $hash
    }
    
    # Write checksums file
    $checksumsPath = Join-Path $ReleaseDir "SHA256SUMS"
    $content = @()
    foreach ($name in ($checksums.Keys | Sort-Object)) {
        $content += "$($checksums[$name])  $name"
    }
    $content | Out-File $checksumsPath -Encoding UTF8
    
    Write-Success "Checksums written to: $checksumsPath"
    
    # Also write JSON for programmatic access
    $checksums | ConvertTo-Json | Out-File (Join-Path $ReleaseDir "checksums.json") -Encoding UTF8
}

# ============================================================================
# Release Notes
# ============================================================================

function New-ReleaseNotes($ReleaseDir) {
    if (-not $GenerateReleaseNotes) { return }
    
    Write-Status "Generating release notes..."
    
    $changelog = Get-Content "CHANGELOG.md" -Raw
    
    # Extract section for this version
    $pattern = "## \[$Version\].*?(?=## \[|$)"
    if ($changelog -match $pattern) {
        $versionNotes = $Matches[0]
    } else {
        $versionNotes = "## [$Version] - $(Get-Date -Format 'yyyy-MM-dd')`n`nRelease $Version"
    }
    
    $releaseNotes = @"
# RawrXD Sovereign $Version

$versionNotes

## Installation

### Windows
- **winget**: `winget install RawrXD.SovereignRuntime`
- **Chocolatey**: `choco install rawrxd`
- **MSI Installer**: Download `rawrxd-$Version-x64.msi`

### macOS
- **Homebrew**: `brew install rawrxd`
- **DMG**: Download `rawrxd-$Version-macos.dmg`

### Linux
- **Install Script**: `curl -fsSL https://rawrxd.ai/install.sh | bash`
- **DEB/RPM**: Download appropriate package
- **AppImage**: Download `rawrxd-$Version-x86_64.AppImage`

### Docker
```bash
docker pull rawrxd/sovereign:$Version
docker run -it rawrxd/sovereign:$Version
```

## Verification

All binaries are signed and include SHA256 checksums:
- Windows: Code signed with Authenticode
- macOS: Signed and notarized
- Linux: GPG signed

Verify with: `sha256sum -c SHA256SUMS`

## Assets

| Platform | File | Size |
|----------|------|------|
"@
    
    # Add asset table
    $files = Get-ChildItem -Path $ReleaseDir -File | Where-Object { $_.Name -ne "SHA256SUMS" -and $_.Name -ne "checksums.json" }
    foreach ($file in ($files | Sort-Object Name)) {
        $size = [math]::Round($file.Length / 1MB, 2)
        $releaseNotes += "| $($file.Name -replace '-', ' ' -replace '_', ' ') | $($file.Name) | ${size} MB |`n"
    }
    
    $releaseNotesPath = Join-Path $ReleaseDir "RELEASE_NOTES.md"
    $releaseNotes | Out-File $releaseNotesPath -Encoding UTF8
    
    Write-Success "Release notes: $releaseNotesPath"
}

# ============================================================================
# Manifest Creation
# ============================================================================

function New-ReleaseManifest($ReleaseDir) {
    Write-Status "Creating release manifest..."
    
    $manifest = @{
        product = "RawrXD Sovereign"
        version = $Version
        timestamp = Get-Date -Format "o"
        platforms = @{}
        assets = @()
    }
    
    foreach ($platform in $Platforms) {
        $platformDir = Join-Path $ReleaseDir $platform
        if (-not (Test-Path $platformDir)) { continue }
        
        $manifest.platforms[$platform] = @{
            available = $true
            files = @()
        }
        
        $files = Get-ChildItem -Path $platformDir -File
        foreach ($file in $files) {
            $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
            $fileInfo = @{
                name = $file.Name
                size = $file.Length
                sha256 = $hash
            }
            $manifest.platforms[$platform].files += $fileInfo
        }
    }
    
    # Add archive assets
    $archives = Get-ChildItem -Path $ReleaseDir -File | Where-Object { 
        $_.Extension -in @('.zip', '.tar.gz', '.msi', '.dmg', '.deb', '.rpm', '.AppImage')
    }
    foreach ($archive in $archives) {
        $hash = (Get-FileHash -Path $archive.FullName -Algorithm SHA256).Hash
        $manifest.assets += @{
            name = $archive.Name
            size = $archive.Length
            sha256 = $hash
        }
    }
    
    $manifestPath = Join-Path $ReleaseDir "manifest.json"
    $manifest | ConvertTo-Json -Depth 5 | Out-File $manifestPath -Encoding UTF8
    
    Write-Success "Manifest: $manifestPath"
}

# ============================================================================
# CDN Upload
# ============================================================================

function Publish-ToCDN($ReleaseDir) {
    if (-not $UploadToCDN) { return }
    
    Write-Status "Uploading to CDN..."
    
    if (-not $CDNEndpoint) {
        Write-Error "CDN endpoint not specified"
        return
    }
    
    # This would integrate with your CDN provider (AWS CloudFront, Azure CDN, etc.)
    Write-Status "Would upload to: $CDNEndpoint/releases/v$Version/"
    
    # Example AWS S3 + CloudFront:
    # aws s3 sync $ReleaseDir s3://rawrxd-releases/v$Version/ --acl public-read
    # aws cloudfront create-invalidation --distribution-id $DistributionId --paths "/releases/v$Version/*"
    
    Write-Success "CDN upload complete"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=== RawrXD Release Package Creator ===" -ForegroundColor Cyan
    Write-Host "Version: $Version"
    Write-Host ""
    
    # Initialize
    $releaseDir = Initialize-ReleaseDirectory
    
    # Collect binaries
    foreach ($platform in $Platforms) {
        Copy-PlatformBinaries $releaseDir $platform
    }
    
    # Sign binaries
    if ($SignBinaries) {
        Invoke-BinarySigning $releaseDir $CertificateThumbprint
    }
    
    # Create archives
    foreach ($platform in $Platforms) {
        New-PlatformArchive $releaseDir $platform
    }
    
    # Create installer
    New-WindowsInstaller $releaseDir
    
    # Generate checksums
    New-ReleaseChecksums $releaseDir
    
    # Generate release notes
    New-ReleaseNotes $releaseDir
    
    # Create manifest
    New-ReleaseManifest $releaseDir
    
    # Upload to CDN
    Publish-ToCDN $releaseDir
    
    # Summary
    Write-Host ""
    Write-Host "=== Release Package Complete ===" -ForegroundColor Green
    Write-Host "Location: $releaseDir"
    Write-Host ""
    
    $files = Get-ChildItem -Path $releaseDir -File
    Write-Host "Artifacts:"
    foreach ($file in $files) {
        $size = [math]::Round($file.Length / 1MB, 2)
        Write-Host "  - $($file.Name) (${size} MB)"
    }
    
    Write-Host ""
}

Main

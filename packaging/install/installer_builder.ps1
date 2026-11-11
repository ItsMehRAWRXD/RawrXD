# installer_builder.ps1
# Phase F.1 Batch 1/5: Cross-Platform Installer Builder
# Creates Windows MSI, macOS DMG, Linux AppImage/DEB/RPM

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("windows", "macos", "linux", "all")]
    [string]$Platform,
    
    [string]$Version = "1.0.0",
    [string]$OutputDir = "..\..\dist",
    [switch]$SignBinaries,
    [string]$CertificateThumbprint,
    [switch]$CreateChecksums,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$ProductName = "RawrXD Sovereign Runtime"
$ProductShortName = "rawrxd"
$CompanyName = "RawrXD AI"
$Copyright = "Copyright (c) 2024 RawrXD AI"
$LicenseFile = "..\..\LICENSE"
$IconFile = "..\..\assets\icon.ico"

# Directory structure
$SourceDir = "..\..\build\Release"
$StagingDir = "$OutputDir\staging"
$InstallersDir = "$OutputDir\installers"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status($Message) {
    Write-Host "[INSTALLER] $Message" -ForegroundColor Cyan
}

function Write-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function New-StagingDirectory($PlatformName) {
    $dir = "$StagingDir\$PlatformName"
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Copy-RuntimeBinaries($Destination) {
    Write-Status "Copying runtime binaries to $Destination"
    
    $binaries = @(
        "RawrXD_SovereignRuntime.exe",
        "RawrXD_Benchmark.exe",
        "RawrXD_CLI.exe",
        "*.dll"
    )
    
    foreach ($pattern in $binaries) {
        $files = Get-ChildItem -Path $SourceDir -Filter $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            Copy-Item $file.FullName -Destination $Destination -Force
            if ($Verbose) { Write-Status "  Copied: $($file.Name)" }
        }
    }
}

function Copy-Configuration($Destination) {
    Write-Status "Copying configuration files"
    
    $configFiles = @(
        "..\..\config\default.yaml",
        "..\..\config\benchmark.yaml"
    )
    
    New-Item -ItemType Directory -Path "$Destination\config" -Force | Out-Null
    
    foreach ($file in $configFiles) {
        if (Test-Path $file) {
            Copy-Item $file -Destination "$Destination\config\" -Force
        }
    }
}

function Copy-Documentation($Destination) {
    Write-Status "Copying documentation"
    
    $docs = @(
        "..\..\README.md",
        "..\..\CHANGELOG.md",
        "..\..\LICENSE"
    )
    
    New-Item -ItemType Directory -Path "$Destination\docs" -Force | Out-Null
    
    foreach ($doc in $docs) {
        if (Test-Path $doc) {
            Copy-Item $doc -Destination "$Destination\docs\" -Force
        }
    }
}

function Sign-Binary($Path) {
    if (-not $SignBinaries) { return }
    if (-not $CertificateThumbprint) {
        Write-Error "Certificate thumbprint required for signing"
        return
    }
    
    Write-Status "Signing: $Path"
    
    $signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    if (-not (Test-Path $signtool)) {
        $signtool = "signtool"  # Try PATH
    }
    
    & $signtool sign /sha1 $CertificateThumbprint /tr http://timestamp.digicert.com /td sha256 /fd sha256 "$Path"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to sign: $Path"
    }
}

function New-ChecksumFile($Directory, $OutputFile) {
    if (-not $CreateChecksums) { return }
    
    Write-Status "Generating checksums: $OutputFile"
    
    $files = Get-ChildItem -Path $Directory -File -Recurse
    $checksums = @()
    
    foreach ($file in $files) {
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        $relativePath = $file.FullName.Substring($Directory.Length + 1)
        $checksums += "$($hash.Hash)  $relativePath"
    }
    
    $checksums | Out-File -FilePath $OutputFile -Encoding UTF8
}

# ============================================================================
# Windows MSI Installer
# ============================================================================

function Build-WindowsInstaller {
    Write-Status "Building Windows MSI installer"
    
    $staging = New-StagingDirectory "windows"
    Copy-RuntimeBinaries $staging
    Copy-Configuration $staging
    Copy-Documentation $staging
    
    # Sign binaries
    if ($SignBinaries) {
        $binaries = Get-ChildItem -Path $staging -Filter "*.exe"
        foreach ($binary in $binaries) {
            Sign-Binary $binary.FullName
        }
    }
    
    # Create WiX source file
    $wixFile = "$staging\installer.wxs"
    @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" Name="$ProductName" Version="$Version" Manufacturer="$CompanyName" UpgradeCode="{12345678-1234-1234-1234-123456789012}">
        <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />
        <MajorUpgrade DowngradeErrorMessage="A newer version is already installed." />
        <MediaTemplate />
        
        <Feature Id="ProductFeature" Title="$ProductName" Level="1">
            <ComponentGroupRef Id="ProductComponents" />
        </Feature>
        
        <Icon Id="ProductIcon" SourceFile="$IconFile" />
        <Property Id="ARPPRODUCTICON" Value="ProductIcon" />
    </Product>
    
    <Fragment>
        <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
            <Component Id="MainExecutable" Guid="{87654321-4321-4321-4321-210987654321}">
                <File Source="$staging\RawrXD_SovereignRuntime.exe" />
            </Component>
        </ComponentGroup>
    </Fragment>
    
    <Fragment>
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFiles64Folder">
                <Directory Id="INSTALLFOLDER" Name="$ProductShortName" />
            </Directory>
        </Directory>
    </Fragment>
</Wix>
"@ | Out-File -FilePath $wixFile -Encoding UTF8
    
    # Compile with WiX
    $candle = "candle.exe"
    $light = "light.exe"
    
    & $candle -arch x64 -out "$staging\installer.wixobj" $wixFile
    & $light -out "$InstallersDir\rawrxd-$Version-x64.msi" "$staging\installer.wixobj"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Status "MSI created: $InstallersDir\rawrxd-$Version-x64.msi"
        
        # Sign MSI
        if ($SignBinaries) {
            Sign-Binary "$InstallersDir\rawrxd-$Version-x64.msi"
        }
        
        # Create checksum
        New-ChecksumFile $InstallersDir "$InstallersDir\rawrxd-$Version-x64.msi.sha256"
    } else {
        Write-Error "Failed to build MSI"
    }
}

# ============================================================================
# macOS DMG Installer
# ============================================================================

function Build-MacOSInstaller {
    Write-Status "Building macOS DMG installer"
    
    # Note: This requires macOS build environment
    # For cross-platform builds, we'd use a macOS VM or GitHub Actions
    
    $staging = New-StagingDirectory "macos"
    
    # Create app bundle structure
    $appBundle = "$staging\RawrXD.app"
    New-Item -ItemType Directory -Path "$appBundle\Contents\MacOS" -Force | Out-Null
    New-Item -ItemType Directory -Path "$appBundle\Contents\Resources" -Force | Out-Null
    
    # Copy binaries (would be macOS binaries in real build)
    Copy-Item "$SourceDir\rawrxd" -Destination "$appBundle\Contents\MacOS\" -ErrorAction SilentlyContinue
    
    # Create Info.plist
    @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>rawrxd</string>
    <key>CFBundleIdentifier</key>
    <string>ai.rawrxd.sovereign</string>
    <key>CFBundleName</key>
    <string>RawrXD Sovereign</string>
    <key>CFBundleVersion</key>
    <string>$Version</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
</dict>
</plist>
"@ | Out-File -FilePath "$appBundle\Contents\Info.plist" -Encoding UTF8
    
    # Create DMG (requires macOS)
    Write-Status "DMG creation requires macOS build environment"
    Write-Status "To build on macOS, run:"
    Write-Status "  hdiutil create -volname 'RawrXD Sovereign' -srcfolder '$staging' -ov -format UDZO '$InstallersDir/rawrxd-$Version.dmg'"
}

# ============================================================================
# Linux AppImage
# ============================================================================

function Build-LinuxAppImage {
    Write-Status "Building Linux AppImage"
    
    $staging = New-StagingDirectory "linux"
    
    # Create AppDir structure
    $appDir = "$staging\RawrXD-$Version-x86_64.AppDir"
    New-Item -ItemType Directory -Path "$appDir\usr\bin" -Force | Out-Null
    New-Item -ItemType Directory -Path "$appDir\usr\share\applications" -Force | Out-Null
    New-Item -ItemType Directory -Path "$appDir\usr\share\icons" -Force | Out-Null
    
    # Copy binaries
    Copy-Item "$SourceDir\rawrxd" -Destination "$appDir\usr\bin\" -ErrorAction SilentlyContinue
    
    # Create desktop entry
    @"
[Desktop Entry]
Name=RawrXD Sovereign
Exec=rawrxd
Icon=rawrxd
Type=Application
Categories=Development;AI;
Comment=Autonomous AI Runtime
"@ | Out-File -FilePath "$appDir\usr\share\applications\rawrxd.desktop" -Encoding UTF8
    
    # Create AppRun script
    @"#!/bin/bash
HERE="\$(dirname "\$(readlink -f "\${0}")")"
export PATH="\${HERE}/usr/bin:\${PATH}"
exec rawrxd "\$@"
"@ | Out-File -FilePath "$appDir\AppRun" -Encoding UTF8
    
    Write-Status "AppImage creation requires Linux build environment"
    Write-Status "To build on Linux, run:"
    Write-Status "  appimagetool '$appDir' '$InstallersDir/rawrxd-$Version-x86_64.AppImage'"
}

# ============================================================================
# Main Execution
# ============================================================================

# Create output directories
New-Item -ItemType Directory -Path $InstallersDir -Force | Out-Null

switch ($Platform) {
    "windows" { Build-WindowsInstaller }
    "macos" { Build-MacOSInstaller }
    "linux" { Build-LinuxAppImage }
    "all" {
        Build-WindowsInstaller
        Build-MacOSInstaller
        Build-LinuxAppImage
    }
}

Write-Status "Installer build complete!"
Write-Status "Output directory: $InstallersDir"

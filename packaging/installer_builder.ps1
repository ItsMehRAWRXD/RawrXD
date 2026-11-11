# Phase F.1 Batch 1/5: Installer Builder
# Cross-platform installer generation for RawrXD Sovereign Runtime
# Copyright (c) 2026 RawrXD Team

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("windows", "macos", "linux")]
    [string]$Platform,
    
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\dist",
    
    [Parameter(Mandatory=$false)]
    [switch]$SignBinaries,
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePath,
    
    [Parameter(Mandatory=$false)]
    [switch]$BuildDocker
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    ProductName = "RawrXD Sovereign Runtime"
    ProductVersion = $Version
    CompanyName = "RawrXD Technologies"
    Copyright = "Copyright (c) 2026 RawrXD Team"
    Website = "https://rawrxd.ai"
    SupportEmail = "support@rawrxd.ai"
    
    # Component manifests
    Components = @{
        Core = @(
            "bin\rawrxd.exe",
            "bin\rawrxd.dll",
            "lib\inference_core.dll",
            "lib\kv_cache_mgr.dll",
            "config\default.yaml"
        )
        
        Benchmarks = @(
            "bin\sovereign_benchmark.exe",
            "bin\hotpatch_benchmark.exe",
            "benchmarks\*"
        )
        
        Documentation = @(
            "docs\*.md",
            "docs\*.pdf",
            "README.md",
            "LICENSE"
        )
        
        Examples = @(
            "examples\*.cpp",
            "examples\*.py",
            "examples\README.md"
        )
    }
    
    # Platform-specific settings
    Platforms = @{
        Windows = @{
            Extension = ".msi"
            Tool = "WiX Toolset"
            MinOS = "Windows 10 1903+"
            Arch = @("x64", "arm64")
        }
        
        MacOS = @{
            Extension = ".dmg"
            Tool = "create-dmg"
            MinOS = "macOS 12.0+"
            Arch = @("x64", "arm64")
        }
        
        Linux = @{
            Extension = ".AppImage"
            Tool = "appimagetool"
            MinOS = "Ubuntu 20.04+, Fedora 34+"
            Arch = @("x64", "arm64")
        }
    }
}

# ============================================================================
# Logging
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# ============================================================================
# Validation
# ============================================================================

function Test-Prerequisites {
    Write-Log "Checking prerequisites for $Platform..."
    
    # Check build artifacts exist
    if (-not (Test-Path "..\build\Release\rawrxd.exe")) {
        throw "Build artifacts not found. Run build.ps1 first."
    }
    
    # Platform-specific checks
    switch ($Platform) {
        "windows" {
            $wixPaths = @(
                "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
                "${env:ProgramFiles}\WiX Toolset v3.11\bin"
            )
            $wixFound = $wixPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
            if (-not $wixFound) {
                throw "WiX Toolset not found. Install from https://wixtoolset.org/"
            }
            $env:PATH = "$wixFound;$env:PATH"
        }
        
        "macos" {
            if (-not (Get-Command "create-dmg" -ErrorAction SilentlyContinue)) {
                throw "create-dmg not found. Run: brew install create-dmg"
            }
        }
        
        "linux" {
            if (-not (Get-Command "appimagetool" -ErrorAction SilentlyContinue)) {
                throw "appimagetool not found. See https://github.com/AppImage/AppImageKit"
            }
        }
    }
    
    Write-Log "Prerequisites validated" "SUCCESS"
}

# ============================================================================
# Windows MSI Builder
# ============================================================================

function Build-WindowsInstaller {
    Write-Log "Building Windows MSI installer..."
    
    $buildDir = "$OutputDir\windows"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    
    # Generate WiX source files
    $wxsPath = "$buildDir\rawrxd.wxs"
    
    $wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" 
             Name="$($Config.ProductName)" 
             Version="$($Config.ProductVersion)" 
             Manufacturer="$($Config.CompanyName)" 
             UpgradeCode="12345678-1234-1234-1234-123456789012"
             Language="1033" 
             Codepage="1252">
        
        <Package InstallerVersion="500" 
                 Compressed="yes" 
                 InstallScope="perMachine"
                 Platform="x64"
                 Description="$($Config.ProductName)"
                 Manufacturer="$($Config.CompanyName)" />
        
        <MajorUpgrade DowngradeErrorMessage="A newer version is already installed." />
        
        <MediaTemplate EmbedCab="yes" />
        
        <Feature Id="ProductFeature" Title="RawrXD Sovereign" Level="1">
            <ComponentGroupRef Id="ProductComponents" />
            <ComponentGroupRef Id="BenchmarkComponents" />
            <ComponentGroupRef Id="DocumentationComponents" />
        </Feature>
        
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="ProgramFiles64Folder">
                <Directory Id="INSTALLFOLDER" Name="RawrXD">
                    <Directory Id="BINDIR" Name="bin" />
                    <Directory Id="LIBDIR" Name="lib" />
                    <Directory Id="CONFIGDIR" Name="config" />
                    <Directory Id="DOCDIR" Name="docs" />
                    <Directory Id="EXAMPLEDIR" Name="examples" />
                </Directory>
            </Directory>
            <Directory Id="ProgramMenuFolder">
                <Directory Id="ApplicationProgramsFolder" Name="RawrXD" />
            </Directory>
        </Directory>
        
        <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
            <Component Id="MainExecutable" Guid="*">
                <File Id="RawrXDExe" Source="..\build\Release\rawrxd.exe" KeyPath="yes">
                    <Shortcut Id="StartMenuShortcut" 
                              Directory="ApplicationProgramsFolder"
                              Name="RawrXD Sovereign"
                              WorkingDirectory="INSTALLFOLDER"
                              Icon="RawrXDIcon.exe"
                              Advertise="yes" />
                </File>
            </Component>
        </ComponentGroup>
        
        <Icon Id="RawrXDIcon.exe" SourceFile="..\assets\icon.ico" />
        
        <Property Id="ARPPRODUCTICON" Value="RawrXDIcon.exe" />
        <Property Id="ARPURLINFOABOUT" Value="$($Config.Website)" />
        <Property Id="ARPCONTACT" Value="$($Config.SupportEmail)" />
        
    </Product>
</Wix>
"@
    
    $wxsContent | Out-File -FilePath $wxsPath -Encoding UTF8
    
    # Compile WiX
    Write-Log "Compiling WiX source..."
    & candle.exe -arch x64 -out "$buildDir\rawrxd.wixobj" $wxsPath
    if ($LASTEXITCODE -ne 0) { throw "WiX compilation failed" }
    
    # Link MSI
    Write-Log "Linking MSI package..."
    $msiPath = "$OutputDir\rawrxd-$Version-x64.msi"
    & light.exe -ext WixUIExtension -cultures:en-us `
        -out $msiPath "$buildDir\rawrxd.wixobj"
    if ($LASTEXITCODE -ne 0) { throw "WiX linking failed" }
    
    # Generate checksum
    $hash = Get-FileHash $msiPath -Algorithm SHA256
    $hash.Hash | Out-File "$msiPath.sha256"
    
    Write-Log "Windows MSI built: $msiPath" "SUCCESS"
    return $msiPath
}

# ============================================================================
# macOS DMG Builder
# ============================================================================

function Build-MacOSInstaller {
    Write-Log "Building macOS DMG installer..."
    
    $buildDir = "$OutputDir\macos"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    
    # Create app bundle structure
    $appDir = "$buildDir\RawrXD.app"
    $contentsDir = "$appDir\Contents"
    $macOSDir = "$contentsDir\MacOS"
    $resourcesDir = "$contentsDir\Resources"
    
    New-Item -ItemType Directory -Force -Path $macOSDir | Out-Null
    New-Item -ItemType Directory -Force -Path $resourcesDir | Out-Null
    
    # Copy binaries
    Copy-Item "..\build\Release\rawrxd" $macOSDir\rawrxd
    Copy-Item "..\assets\icon.icns" $resourcesDir\AppIcon.icns
    
    # Create Info.plist
    $plistContent = @"
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
    <key>CFBundleShortVersionString</key>
    <string>$Version</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
"@
    
    $plistContent | Out-File -FilePath "$contentsDir\Info.plist" -Encoding UTF8
    
    # Sign the app bundle
    if ($SignBinaries) {
        Write-Log "Signing macOS app bundle..."
        & codesign --deep --force --verify --verbose=2 `
            --sign "Developer ID Application" $appDir
    }
    
    # Create DMG
    $dmgPath = "$OutputDir\rawrxd-$Version-macos.dmg"
    & create-dmg `
        --volname "RawrXD Sovereign" `
        --window-pos 200 120 `
        --window-size 800 400 `
        --icon-size 100 `
        --app-drop-link 600 185 `
        --icon "RawrXD.app" 200 185 `
        --hide-extension "RawrXD.app" `
        $dmgPath $buildDir
    
    # Generate checksum
    $hash = Get-FileHash $dmgPath -Algorithm SHA256
    $hash.Hash | Out-File "$dmgPath.sha256"
    
    Write-Log "macOS DMG built: $dmgPath" "SUCCESS"
    return $dmgPath
}

# ============================================================================
# Linux AppImage Builder
# ============================================================================

function Build-LinuxInstaller {
    Write-Log "Building Linux AppImage..."
    
    $buildDir = "$OutputDir\linux"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    
    # Create AppDir structure
    $appDir = "$buildDir\RawrXD-x86_64.AppDir"
    $usrDir = "$appDir\usr"
    $binDir = "$usrDir\bin"
    $shareDir = "$usrDir\share"
    
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    New-Item -ItemType Directory -Force -Path $shareDir | Out-Null
    
    # Copy binaries
    Copy-Item "..\build\Release\rawrxd" $binDir\rawrxd
    
    # Create desktop entry
    $desktopContent = @"
[Desktop Entry]
Name=RawrXD Sovereign
Exec=rawrxd
Icon=rawrxd
Type=Application
Categories=Development;AI;Science;
Comment=Autonomous AI Runtime
Terminal=true
"@
    
    $desktopContent | Out-File -FilePath "$appDir\rawrxd.desktop" -Encoding UTF8
    
    # Create AppRun script
    $appRunContent = @'#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="${HERE}/usr/bin:${PATH}"
exec "${HERE}/usr/bin/rawrxd" "$@"
'@
    
    $appRunContent | Out-File -FilePath "$appDir\AppRun" -Encoding UTF8NoBOM
    & chmod +x "$appDir\AppRun"
    
    # Build AppImage
    $appImagePath = "$OutputDir\rawrxd-$Version-x86_64.AppImage"
    & appimagetool $appDir $appImagePath
    if ($LASTEXITCODE -ne 0) { throw "AppImage build failed" }
    
    # Generate checksum
    $hash = Get-FileHash $appImagePath -Algorithm SHA256
    $hash.Hash | Out-File "$appImagePath.sha256"
    
    Write-Log "Linux AppImage built: $appImagePath" "SUCCESS"
    return $appImagePath
}

# ============================================================================
# Docker Builder
# ============================================================================

function Build-DockerImages {
    Write-Log "Building Docker images..."
    
    $dockerDir = "$OutputDir\docker"
    New-Item -ItemType Directory -Force -Path $dockerDir | Out-Null
    
    # Sovereign Runtime Dockerfile
    $runtimeDockerfile = @"
FROM ubuntu:22.04

LABEL maintainer="RawrXD Team <support@rawrxd.ai>"
LABEL version="$Version"
LABEL description="RawrXD Sovereign Runtime"

# Install dependencies
RUN apt-get update && apt-get install -y \\
    libvulkan1 \\
    libnvidia-ml1 \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY build/Release/rawrxd /usr/local/bin/
COPY build/Release/*.so /usr/local/lib/
RUN ldconfig

# Create non-root user
RUN useradd -m -s /bin/bash rawrxd
USER rawrxd
WORKDIR /home/rawrxd

# Expose API port
EXPOSE 8080

ENTRYPOINT ["rawrxd"]
CMD ["--help"]
"@
    
    $runtimeDockerfile | Out-File -FilePath "$dockerDir\Dockerfile.runtime" -Encoding UTF8
    
    # Benchmark Dockerfile
    $benchmarkDockerfile = @"
FROM rawrxd/sovereign-runtime:$Version

LABEL description="RawrXD Benchmark Suite"

USER root
COPY benchmarks/ /opt/benchmarks/
COPY scripts/run_benchmarks.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run_benchmarks.sh

USER rawrxd
WORKDIR /opt/benchmarks

ENTRYPOINT ["run_benchmarks.sh"]
"@
    
    $benchmarkDockerfile | Out-File -FilePath "$dockerDir\Dockerfile.benchmark" -Encoding UTF8
    
    # Build images
    Write-Log "Building runtime image..."
    & docker build -f "$dockerDir\Dockerfile.runtime" -t "rawrxd/sovereign-runtime:$Version" ..
    & docker tag "rawrxd/sovereign-runtime:$Version" "rawrxd/sovereign-runtime:latest"
    
    Write-Log "Building benchmark image..."
    & docker build -f "$dockerDir\Dockerfile.benchmark" -t "rawrxd/benchmark-suite:$Version" ..
    & docker tag "rawrxd/benchmark-suite:$Version" "rawrxd/benchmark-suite:latest"
    
    Write-Log "Docker images built" "SUCCESS"
}

# ============================================================================
# Package Manager Manifests
# ============================================================================

function Generate-PackageManagerManifests {
    Write-Log "Generating package manager manifests..."
    
    $manifestDir = "$OutputDir\manifests"
    New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
    
    # Homebrew formula (macOS/Linux)
    $brewFormula = @"
class Rawrxd < Formula
  desc "Autonomous AI Runtime with Sovereign Execution"
  homepage "https://rawrxd.ai"
  url "https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/rawrxd-$Version-macos.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  version "$Version"

  depends_on "vulkan-loader"

  def install
    bin.install "rawrxd"
    lib.install Dir["lib/*.dylib"]
    doc.install Dir["docs/*"]
  end

  test do
    system "#{bin}/rawrxd", "--version"
  end
end
"@
    
    $brewFormula | Out-File -FilePath "$manifestDir\rawrxd.rb" -Encoding UTF8
    
    # Chocolatey package (Windows)
    $chocoNuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>rawrxd</id>
    <version>$Version</version>
    <title>RawrXD Sovereign Runtime</title>
    <authors>RawrXD Team</authors>
    <owners>ItsMehRAWRXD</owners>
    <licenseUrl>https://github.com/ItsMehRAWRXD/RawrXD/blob/main/LICENSE</licenseUrl>
    <projectUrl>https://rawrxd.ai</projectUrl>
    <iconUrl>https://rawrxd.ai/icon.png</iconUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>Autonomous AI Runtime with Sovereign Execution</description>
    <summary>Sovereign AI runtime for local inference</summary>
    <releaseNotes>https://github.com/ItsMehRAWRXD/RawrXD/releases/tag/v$Version</releaseNotes>
    <copyright>$($Config.Copyright)</copyright>
    <tags>ai inference runtime sovereign local</tags>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
"@
    
    $chocoNuspec | Out-File -FilePath "$manifestDir\rawrxd.nuspec" -Encoding UTF8
    
    # winget manifest (Windows)
    $wingetManifest = @"
PackageIdentifier: RawrXD.SovereignRuntime
PackageVersion: $Version
PackageLocale: en-US
Publisher: RawrXD Technologies
PublisherUrl: https://rawrxd.ai
PackageName: RawrXD Sovereign Runtime
PackageUrl: https://rawrxd.ai
License: MIT
LicenseUrl: https://github.com/ItsMehRAWRXD/RawrXD/blob/main/LICENSE
ShortDescription: Autonomous AI Runtime with Sovereign Execution
Moniker: rawrxd
Tags:
  - ai
  - inference
  - runtime
  - sovereign
  - local
Installers:
  - Architecture: x64
    InstallerType: msi
    InstallerUrl: https://github.com/ItsMehRAWRXD/RawrXD/releases/download/v$Version/rawrxd-$Version-x64.msi
    InstallerSha256: PLACEHOLDER_SHA256
ManifestType: singleton
ManifestVersion: 1.0.0
"@
    
    $wingetManifest | Out-File -FilePath "$manifestDir\rawrxd.winget.yaml" -Encoding UTF8
    
    Write-Log "Package manager manifests generated" "SUCCESS"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Log "RawrXD Installer Builder v1.0"
    Write-Log "Platform: $Platform, Version: $Version"
    Write-Log "Output directory: $OutputDir"
    
    # Validate prerequisites
    Test-Prerequisites
    
    # Create output directory
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    
    # Build platform-specific installer
    $installerPath = switch ($Platform) {
        "windows" { Build-WindowsInstaller }
        "macos" { Build-MacOSInstaller }
        "linux" { Build-LinuxInstaller }
    }
    
    # Build Docker images if requested
    if ($BuildDocker) {
        Build-DockerImages
    }
    
    # Generate package manager manifests
    Generate-PackageManagerManifests
    
    # Summary
    Write-Log "========================================" "SUCCESS"
    Write-Log "Build Complete!" "SUCCESS"
    Write-Log "========================================" "SUCCESS"
    Write-Log "Installer: $installerPath"
    Write-Log "Checksum: $installerPath.sha256"
    Write-Log "Manifests: $OutputDir\manifests\"
    
    if ($BuildDocker) {
        Write-Log "Docker Images:"
        Write-Log "  - rawrxd/sovereign-runtime:$Version"
        Write-Log "  - rawrxd/benchmark-suite:$Version"
    }
}

# Run main
Main

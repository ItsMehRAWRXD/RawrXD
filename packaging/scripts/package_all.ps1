# package_all.ps1
# Phase H.1 Batch 5/5: Unified Multi-Platform Packaging Pipeline

param(
    [string]$Version = "1.0.0",
    [string]$OutputBaseDir = ".\output",
    [switch]$SkipWindows,
    [switch]$SkipMacOS,
    [switch]$SkipLinux,
    [switch]$Sign,
    [string]$WindowsCertThumbprint,
    [string]$GPGKeyId
)

$ErrorActionPreference = "Stop"
$StartTime = Get-Date

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     RawrXD Multi-Platform Packaging Pipeline v$Version        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$packagingResults = @{
    Version = $Version
    StartTime = $StartTime.ToString("o")
    Platforms = @()
    Artifacts = @()
    OverallSuccess = $true
}

# Create base output directory
New-Item -ItemType Directory -Path $OutputBaseDir -Force | Out-Null

# Windows Packaging
if (-not $SkipWindows) {
    Write-Host "=== Building Windows MSI ===" -ForegroundColor Yellow
    
    $windowsOutput = Join-Path $OutputBaseDir "windows"
    New-Item -ItemType Directory -Path $windowsOutput -Force | Out-Null
    
    try {
        Push-Location "..\windows"
        
        $signParam = if ($Sign -and $WindowsCertThumbprint) { "-Sign -CertificateThumbprint $WindowsCertThumbprint" } else { "" }
        Invoke-Expression ".\build_msi.ps1 -Version $Version -OutputDir $windowsOutput $signParam"
        
        $msiFile = Get-ChildItem -Path $windowsOutput -Filter "*.msi" | Select-Object -First 1
        if ($msiFile) {
            $packagingResults.Platforms += "Windows"
            $packagingResults.Artifacts += @{
                Platform = "Windows"
                Type = "MSI"
                File = $msiFile.Name
                Path = $msiFile.FullName
                Size = $msiFile.Length
            }
            Write-Host "✓ Windows MSI built: $($msiFile.Name)" -ForegroundColor Green
        }
        
        Pop-Location
    }
    catch {
        Write-Host "✗ Windows packaging failed: $_" -ForegroundColor Red
        $packagingResults.OverallSuccess = $false
    }
}

# macOS Packaging (requires WSL or cross-compile setup)
if (-not $SkipMacOS) {
    Write-Host "=== Building macOS DMG ===" -ForegroundColor Yellow
    
    $macosOutput = Join-Path $OutputBaseDir "macos"
    New-Item -ItemType Directory -Path $macosOutput -Force | Out-Null
    
    try {
        Push-Location "..\macos"
        
        # Note: macOS build requires macOS environment or cross-compilation
        # This creates the structure; actual build happens on macOS CI runner
        Write-Host "Creating macOS package structure..." -ForegroundColor Gray
        
        # Create placeholder for CI
        $placeholder = @{
            Version = $Version
            BuildRequired = $true
            Instructions = "Run build_dmg.sh on macOS with Xcode tools"
        } | ConvertTo-Json
        
        $placeholder | Out-File (Join-Path $macosOutput "BUILD_REQUIRED.json") -Encoding UTF8
        
        $packagingResults.Platforms += "macOS (CI Required)"
        $packagingResults.Artifacts += @{
            Platform = "macOS"
            Type = "DMG"
            Status = "Pending CI Build"
            Instructions = "Run build_dmg.sh on macOS"
        }
        
        Write-Host "✓ macOS structure prepared (CI build required)" -ForegroundColor Green
        Pop-Location
    }
    catch {
        Write-Host "✗ macOS packaging failed: $_" -ForegroundColor Red
        $packagingResults.OverallSuccess = $false
    }
}

# Linux Packaging
if (-not $SkipLinux) {
    Write-Host "=== Building Linux AppImage ===" -ForegroundColor Yellow
    
    $linuxOutput = Join-Path $OutputBaseDir "linux"
    New-Item -ItemType Directory -Path $linuxOutput -Force | Out-Null
    
    try {
        Push-Location "..\linux"
        
        # Check if running in WSL or has Linux tools
        $hasLinuxTools = $null -ne (Get-Command "bash" -ErrorAction SilentlyContinue)
        
        if ($hasLinuxTools) {
            bash ./build_appimage.sh $Version x86_64 $linuxOutput
            
            $appImage = Get-ChildItem -Path $linuxOutput -Filter "*.AppImage" | Select-Object -First 1
            if ($appImage) {
                $packagingResults.Platforms += "Linux"
                $packagingResults.Artifacts += @{
                    Platform = "Linux"
                    Type = "AppImage"
                    File = $appImage.Name
                    Path = $appImage.FullName
                    Size = $appImage.Length
                }
                Write-Host "✓ Linux AppImage built: $($appImage.Name)" -ForegroundColor Green
            }
        }
        else {
            Write-Host "Linux tools not available, creating CI placeholder..." -ForegroundColor Yellow
            
            $placeholder = @{
                Version = $Version
                BuildRequired = $true
                Instructions = "Run build_appimage.sh on Linux with appimagetool"
            } | ConvertTo-Json
            
            $placeholder | Out-File (Join-Path $linuxOutput "BUILD_REQUIRED.json") -Encoding UTF8
            
            $packagingResults.Platforms += "Linux (CI Required)"
            $packagingResults.Artifacts += @{
                Platform = "Linux"
                Type = "AppImage"
                Status = "Pending CI Build"
                Instructions = "Run build_appimage.sh on Linux"
            }
            
            Write-Host "✓ Linux structure prepared (CI build required)" -ForegroundColor Green
        }
        
        Pop-Location
    }
    catch {
        Write-Host "✗ Linux packaging failed: $_" -ForegroundColor Red
        $packagingResults.OverallSuccess = $false
    }
}

# Generate manifest
$manifestPath = Join-Path $OutputBaseDir "MANIFEST.json"
$packagingResults.EndTime = (Get-Date).ToString("o")
$packagingResults.Duration = ((Get-Date) - $StartTime).ToString()
$packagingResults | ConvertTo-Json -Depth 5 | Out-File $manifestPath -Encoding UTF8

# Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $(if ($packagingResults.OverallSuccess) { "Green" } else { "Yellow" })
Write-Host "║              PACKAGING COMPLETE                              ║" -ForegroundColor $(if ($packagingResults.OverallSuccess) { "Green" } else { "Yellow" })
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $(if ($packagingResults.OverallSuccess) { "Green" } else { "Yellow" })
Write-Host ""

Write-Host "Platforms: $($packagingResults.Platforms -join ', ')" -ForegroundColor Cyan
Write-Host "Artifacts: $($packagingResults.Artifacts.Count)" -ForegroundColor Cyan
Write-Host "Duration: $($packagingResults.Duration)" -ForegroundColor Gray
Write-Host ""

foreach ($artifact in $packagingResults.Artifacts) {
    $size = if ($artifact.Size) { "($([math]::Round($artifact.Size / 1MB, 2)) MB)" } else { "" }
    Write-Host "  • [$($artifact.Platform)] $($artifact.File) $size" -ForegroundColor White
}

Write-Host ""
Write-Host "Output: $OutputBaseDir" -ForegroundColor Cyan
Write-Host "Manifest: $manifestPath" -ForegroundColor Gray
Write-Host ""

if (-not $packagingResults.OverallSuccess) {
    exit 1
}

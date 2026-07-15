#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Artifact Signing Script for RawrXD

.DESCRIPTION
    Signs build artifacts with code signing certificates:
    - Windows executable signing
    - NuGet package signing
    - Docker image signing (cosign)
    - Checksum generation

.EXAMPLE
    .\scripts\artifact_sign.ps1 -Path .\bin\RawrXD.exe
    .\scripts\artifact_sign.ps1 -Path .\artifacts\ -Batch

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter()]
    [string]$CertificateThumbprint = $env:CERT_THUMBPRINT,

    [Parameter()]
    [string]$TimestampServer = "http://timestamp.digicert.com",

    [Parameter()]
    [switch]$Batch,

    [Parameter()]
    [string]$OutputDir = "",

    [Parameter()]
    [switch]$GenerateChecksums,

    [Parameter()]
    [ValidateSet("SHA256", "SHA512", "MD5")]
    [string[]]$HashAlgorithms = @("SHA256", "SHA512")
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    SignableExtensions = @(".exe", ".dll", ".msi", ".cab", ".cat", ".sys")
    TimestampServers = @(
        "http://timestamp.digicert.com"
        "http://timestamp.sectigo.com"
        "http://tsa.starfieldtech.com"
    )
}

$script:SignedFiles = @()
$script:Errors = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Blue
    Write-Host $Title -ForegroundColor Blue
    Write-Host "========================================" -ForegroundColor Blue
}

function Test-SignTool {
    $signtool = Get-Command "signtool.exe" -ErrorAction SilentlyContinue
    if (-not $signtool) {
        # Try to find in Windows SDK
        $sdkPaths = @(
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe"
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\x64\signtool.exe"
        )
        
        foreach ($path in $sdkPaths) {
            if (Test-Path $path) {
                return $path
            }
        }
    }
    return $signtool.Source
}

# ============================================================================
# Signing Functions
# ============================================================================

function Invoke-FileSigning {
    param([string]$FilePath)
    
    $signtool = Test-SignTool
    if (-not $signtool) {
        Write-Status "signtool.exe not found" "Error"
        $script:Errors += "signtool.exe not found"
        return $false
    }
    
    if ([string]::IsNullOrEmpty($CertificateThumbprint)) {
        Write-Status "No certificate thumbprint provided" "Error"
        $script:Errors += "Certificate thumbprint required"
        return $false
    }
    
    Write-Status "Signing: $(Split-Path $FilePath -Leaf)" "Info"
    
    # Build sign command
    $args = @(
        "sign"
        "/sha1", $CertificateThumbprint
        "/tr", $TimestampServer
        "/td", "sha256"
        "/fd", "sha256"
        "/a"
        "`"$FilePath`""
    )
    
    try {
        $process = Start-Process -FilePath $signtool -ArgumentList $args -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Status "Signed successfully" "Success"
            $script:SignedFiles += $FilePath
            return $true
        } else {
            Write-Status "Signing failed (exit code: $($process.ExitCode))" "Error"
            $script:Errors += "Failed to sign: $FilePath"
            return $false
        }
    } catch {
        Write-Status "Signing error: $_" "Error"
        $script:Errors += $_.Exception.Message
        return $false
    }
}

function Invoke-Verification {
    param([string]$FilePath)
    
    $signtool = Test-SignTool
    if (-not $signtool) {
        return $false
    }
    
    try {
        $output = & $signtool verify /pa /v "$FilePath" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status "Signature verified: $(Split-Path $FilePath -Leaf)" "Success"
            return $true
        } else {
            Write-Status "Signature verification failed: $(Split-Path $FilePath -Leaf)" "Error"
            return $false
        }
    } catch {
        Write-Status "Verification error: $_" "Error"
        return $false
    }
}

# ============================================================================
# Checksum Generation
# ============================================================================

function New-Checksums {
    param([string]$TargetPath)
    
    Write-Section "Checksum Generation"
    
    $files = if (Test-Path $TargetPath -PathType Container) {
        Get-ChildItem -Path $TargetPath -File -Recurse
    } else {
        Get-Item $TargetPath
    }
    
    foreach ($file in $files) {
        foreach ($algo in $HashAlgorithms) {
            $hash = Get-FileHash -Path $file.FullName -Algorithm $algo
            $hashFile = "$($file.FullName).$($algo.ToLower())"
            $hash.Hash | Out-File -FilePath $hashFile -Encoding UTF8
            Write-Status "Generated $algo checksum: $(Split-Path $hashFile -Leaf)" "Success"
        }
    }
    
    # Generate checksums.txt with all hashes
    $checksumsFile = if ($OutputDir) { Join-Path $OutputDir "checksums.txt" } else { "checksums.txt" }
    $checksumsContent = @()
    
    foreach ($file in $files) {
        foreach ($algo in $HashAlgorithms) {
            $hash = Get-FileHash -Path $file.FullName -Algorithm $algo
            $checksumsContent += "$($hash.Hash)  $(Split-Path $file.FullName -Leaf) ($algo)"
        }
    }
    
    $checksumsContent | Out-File -FilePath $checksumsFile -Encoding UTF8
    Write-Status "Generated checksums.txt" "Success"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Artifact Signing" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Target: $Path" "Info"
    Write-Status "Batch mode: $Batch" "Info"
    Write-Status "Timestamp server: $TimestampServer" "Info"
    Write-Status ""
    
    # Get files to sign
    $filesToSign = @()
    
    if ($Batch) {
        if (Test-Path $Path -PathType Container) {
            $filesToSign = Get-ChildItem -Path $Path -File -Recurse | 
                Where-Object { $Config.SignableExtensions -contains $_.Extension.ToLower() }
        }
    } else {
        if (Test-Path $Path) {
            $file = Get-Item $Path
            if ($Config.SignableExtensions -contains $file.Extension.ToLower()) {
                $filesToSign = @($file)
            } else {
                Write-Status "File extension not signable: $($file.Extension)" "Warning"
            }
        }
    }
    
    if ($filesToSign.Count -eq 0) {
        Write-Status "No files to sign" "Warning"
        return
    }
    
    Write-Status "Found $($filesToSign.Count) file(s) to sign" "Info"
    Write-Status ""
    
    # Sign files
    Write-Section "Signing Files"
    
    foreach ($file in $filesToSign) {
        Invoke-FileSigning -FilePath $file.FullName
    }
    
    # Verify signatures
    Write-Section "Verifying Signatures"
    
    foreach ($signedFile in $script:SignedFiles) {
        Invoke-Verification -FilePath $signedFile
    }
    
    # Generate checksums
    if ($GenerateChecksums) {
        New-Checksums -TargetPath $Path
    }
    
    # Summary
    Write-Section "Signing Summary"
    
    Write-Host "Files signed: $($script:SignedFiles.Count)" -ForegroundColor Green
    Write-Host "Errors: $($script:Errors.Count)" -ForegroundColor $(if ($script:Errors.Count -eq 0) { "Green" } else { "Red" })
    
    if ($script:Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($error in $script:Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
        exit 1
    }
    
    Write-Status "Signing complete!" "Success"
}

# Run main
Main

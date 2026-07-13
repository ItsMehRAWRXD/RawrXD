#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Installer Validation Script for RawrXD

.DESCRIPTION
    Validates installation packages:
    - MSI/EXE installer testing
    - Silent install verification
    - File integrity checks
    - Registry verification
    - Uninstall testing

.EXAMPLE
    .\scripts\validate_installer.ps1 -Installer RawrXD-v1.0.0-win64.exe
    .\scripts\validate_installer.ps1 -Installer RawrXD-v1.0.0-win64.msi -Silent

.NOTES
    Part of RawrXD Phase AB: CI/CD Pipeline & Automation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Installer,

    [Parameter()]
    [switch]$Silent,

    [Parameter()]
    [string]$InstallDir = "$env:ProgramFiles\RawrXD",

    [Parameter()]
    [switch]$TestUninstall,

    [Parameter()]
    [switch]$SignCheck,

    [Parameter()]
    [string]$OutputFile = "installer-validation.json"
)

# ============================================================================
# Configuration
# ============================================================================

$Config = @{
    RequiredFiles = @(
        "RawrXD.exe"
        "LICENSE"
        "README.md"
    )
    RequiredRegistryKeys = @(
        "HKLM:\SOFTWARE\RawrXD"
    )
    MinFileSize = 1024  # 1KB
}

$script:Results = @{
    InstallerPath = $Installer
    TestsPassed = 0
    TestsFailed = 0
    Errors = @()
    Warnings = @()
}

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

function Add-Result {
    param([string]$Test, [bool]$Passed, [string]$Message)
    if ($Passed) {
        $script:Results.TestsPassed++
        Write-Status "$Test`: PASSED" "Success"
    } else {
        $script:Results.TestsFailed++
        $script:Results.Errors += "$Test`: $Message"
        Write-Status "$Test`: FAILED - $Message" "Error"
    }
}

# ============================================================================
# Pre-Install Checks
# ============================================================================

function Test-InstallerFile {
    Write-Section "Pre-Install Validation"

    # Check installer exists
    if (-not (Test-Path $Installer)) {
        Write-Status "Installer not found: $Installer" "Error"
        exit 1
    }
    Write-Status "Installer found: $Installer" "Success"

    # Check file size
    $fileInfo = Get-Item $Installer
    if ($fileInfo.Length -lt $Config.MinFileSize) {
        Add-Result "FileSize" $false "Installer file too small ($($fileInfo.Length) bytes)"
    } else {
        Add-Result "FileSize" $true "File size: $($fileInfo.Length) bytes"
    }

    # Check digital signature
    if ($SignCheck) {
        $signature = Get-AuthenticodeSignature -FilePath $Installer
        if ($signature.Status -eq "Valid") {
            Add-Result "DigitalSignature" $true "Signed by: $($signature.SignerCertificate.Subject)"
        } else {
            Add-Result "DigitalSignature" $false "Signature status: $($signature.Status)"
        }
    }

    # Check file extension
    $ext = [System.IO.Path]::GetExtension($Installer).ToLower()
    if ($ext -in @(".exe", ".msi")) {
        Add-Result "FileExtension" $true "Valid extension: $ext"
    } else {
        Add-Result "FileExtension" $false "Invalid extension: $ext"
    }
}

# ============================================================================
# Installation
# ============================================================================

function Install-Package {
    Write-Section "Installation"

    $ext = [System.IO.Path]::GetExtension($Installer).ToLower()
    $installLog = "install_$([Guid]::NewGuid().ToString().Substring(0,8)).log"

    try {
        if ($ext -eq ".msi") {
            # MSI installation
            $args = "/i `"$Installer`" /l*v `"$installLog`""
            if ($Silent) {
                $args += " /qn /norestart"
            }

            Write-Status "Running MSI installer..." "Info"
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
            $exitCode = $process.ExitCode
        } else {
            # EXE installation
            $args = "/SILENT /SUPPRESSMSGBOXES /NORESTART /LOG=`"$installLog`""
            if (-not $Silent) {
                $args = ""
            }

            Write-Status "Running EXE installer..." "Info"
            $process = Start-Process -FilePath $Installer -ArgumentList $args -Wait -PassThru
            $exitCode = $process.ExitCode
        }

        # Check exit code
        if ($exitCode -eq 0 -or $exitCode -eq 3010) {
            Add-Result "Installation" $true "Exit code: $exitCode"
        } else {
            Add-Result "Installation" $false "Exit code: $exitCode"
            if (Test-Path $installLog) {
                Write-Status "Install log saved to $installLog" "Info"
            }
        }
    } catch {
        Add-Result "Installation" $false $_.Exception.Message
    }
}

# ============================================================================
# Post-Install Validation
# ============================================================================

function Test-Installation {
    Write-Section "Post-Install Validation"

    # Check installation directory
    if (Test-Path $InstallDir) {
        Add-Result "InstallDirectory" $true "Found: $InstallDir"
    } else {
        Add-Result "InstallDirectory" $false "Not found: $InstallDir"
        return
    }

    # Check required files
    foreach ($file in $Config.RequiredFiles) {
        $filePath = Join-Path $InstallDir $file
        if (Test-Path $filePath) {
            Add-Result "File_$file" $true "Found: $file"
        } else {
            Add-Result "File_$file" $false "Missing: $file"
        }
    }

    # Check executable
    $exePath = Join-Path $InstallDir "RawrXD.exe"
    if (Test-Path $exePath) {
        try {
            $version = (Get-Item $exePath).VersionInfo.FileVersion
            Add-Result "ExecutableVersion" $true "Version: $version"
        } catch {
            Add-Result "ExecutableVersion" $false "Could not read version"
        }

        # Test executable runs
        try {
            $output = & $exePath --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                Add-Result "ExecutableRun" $true "Runs successfully"
            } else {
                Add-Result "ExecutableRun" $false "Exit code: $LASTEXITCODE"
            }
        } catch {
            Add-Result "ExecutableRun" $false $_.Exception.Message
        }
    }

    # Check registry
    foreach ($key in $Config.RequiredRegistryKeys) {
        if (Test-Path $key) {
            Add-Result "Registry_$key" $true "Found: $key"
        } else {
            Add-Result "Registry_$key" $false "Missing: $key"
        }
    }

    # Check PATH
    $pathDirs = $env:Path -split ";"
    $inPath = $pathDirs | Where-Object { $_ -like "*$InstallDir*" }
    if ($inPath) {
        Add-Result "PathVariable" $true "In PATH"
    } else {
        $script:Results.Warnings += "Not in PATH"
        Write-Status "PathVariable: WARNING - Not in PATH" "Warning"
    }
}

# ============================================================================
# Uninstall Testing
# ============================================================================

function Test-Uninstall {
    if (-not $TestUninstall) {
        return
    }

    Write-Section "Uninstallation"

    # Find uninstaller
    $uninstallReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RawrXD*"
    $uninstallKey = Get-ChildItem -Path $uninstallReg -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($uninstallKey) {
        $uninstallString = (Get-ItemProperty -Path $uninstallKey.PSPath).UninstallString
        Write-Status "Found uninstaller: $uninstallString" "Info"

        try {
            $process = Start-Process -FilePath $uninstallString -ArgumentList "/SILENT" -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Add-Result "Uninstallation" $true "Exit code: $($process.ExitCode)"
            } else {
                Add-Result "Uninstallation" $false "Exit code: $($process.ExitCode)"
            }
        } catch {
            Add-Result "Uninstallation" $false $_.Exception.Message
        }

        # Verify removal
        if (Test-Path $InstallDir) {
            Add-Result "InstallDirectoryRemoved" $false "Directory still exists"
        } else {
            Add-Result "InstallDirectoryRemoved" $true "Directory removed"
        }
    } else {
        Add-Result "UninstallerFound" $false "Uninstaller not found in registry"
    }
}

# ============================================================================
# Report Generation
# ============================================================================

function Write-Report {
    Write-Section "Validation Report"

    $script:Results.Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $script:Results.Passed = ($script:Results.TestsFailed -eq 0)

    Write-Host "Tests Passed: $($script:Results.TestsPassed)" -ForegroundColor Green
    Write-Host "Tests Failed: $($script:Results.TestsFailed)" -ForegroundColor $(if ($script:Results.TestsFailed -eq 0) { "Green" } else { "Red" })

    if ($script:Results.Warnings.Count -gt 0) {
        Write-Host "`nWarnings:" -ForegroundColor Yellow
        foreach ($warning in $script:Results.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
        }
    }

    if ($script:Results.Errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        foreach ($error in $script:Results.Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
    }

    # Save JSON report
    $script:Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Status "Report saved to $OutputFile" "Success"

    # Exit code
    if ($script:Results.TestsFailed -gt 0) {
        exit 1
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Installer Validation" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Status "Installer: $Installer" "Info"
    Write-Status "Silent mode: $Silent" "Info"
    Write-Status "Install directory: $InstallDir" "Info"
    Write-Status ""

    Test-InstallerFile
    Install-Package
    Test-Installation
    Test-Uninstall
    Write-Report
}

# Run main
Main

#Requires -RunAsAdministrator
#Requires -Version 7.0

<#
.SYNOPSIS
    Installs the RawrXDSecurity PowerShell Module

.DESCRIPTION
    This script installs the RawrXDSecurity module to the PowerShell modules directory,
    making it available for import in any PowerShell session.

.PARAMETER Scope
    Installation scope: CurrentUser or AllUsers

.PARAMETER Force
    Force installation even if module already exists

.EXAMPLE
    .\Install-RawrXDSecurityModule.ps1

.EXAMPLE
    .\Install-RawrXDSecurityModule.ps1 -Scope CurrentUser

.EXAMPLE
    .\Install-RawrXDSecurityModule.ps1 -Force
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

begin {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXDSecurity Module Installer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $ModuleName = 'RawrXDSecurity'
    $ModuleVersion = '1.0.0'
    $SourcePath = Join-Path $PSScriptRoot $ModuleName

    # Determine installation path based on scope
    if ($Scope -eq 'AllUsers') {
        $DestinationPath = Join-Path $env:ProgramFiles 'PowerShell\Modules'
    }
    else {
        $DestinationPath = Join-Path $env:USERPROFILE 'Documents\PowerShell\Modules'
    }

    $ModuleInstallPath = Join-Path $DestinationPath $ModuleName
    $VersionInstallPath = Join-Path $ModuleInstallPath $ModuleVersion
}

process {
    try {
        # Verify source exists
        if (-not (Test-Path $SourcePath)) {
            throw "Module source not found at: $SourcePath"
        }

        Write-Host "Installing $ModuleName v$ModuleVersion..." -ForegroundColor Yellow
        Write-Host "  Source: $SourcePath" -ForegroundColor Gray
        Write-Host "  Destination: $VersionInstallPath" -ForegroundColor Gray
        Write-Host "  Scope: $Scope" -ForegroundColor Gray
        Write-Host ""

        # Check if module already exists
        if (Test-Path $ModuleInstallPath) {
            if (-not $Force) {
                $existingVersion = Get-ChildItem -Path $ModuleInstallPath -Directory | Select-Object -First 1
                if ($existingVersion) {
                    Write-Warning "Module already exists (version $($existingVersion.Name))"
                    $response = Read-Host "Overwrite? (Y/N)"
                    if ($response -ne 'Y') {
                        Write-Host "Installation cancelled." -ForegroundColor Yellow
                        return
                    }
                }
            }

            # Remove existing installation
            if ($PSCmdlet.ShouldProcess($ModuleInstallPath, 'Remove existing module')) {
                Remove-Item -Path $ModuleInstallPath -Recurse -Force
                Write-Host "✓ Removed existing module" -ForegroundColor Green
            }
        }

        # Create destination directory
        if ($PSCmdlet.ShouldProcess($VersionInstallPath, 'Create module directory')) {
            New-Item -ItemType Directory -Path $VersionInstallPath -Force | Out-Null
            Write-Host "✓ Created module directory" -ForegroundColor Green
        }

        # Copy module files
        if ($PSCmdlet.ShouldProcess($SourcePath, 'Copy module files')) {
            Copy-Item -Path "$SourcePath\*" -Destination $VersionInstallPath -Recurse -Force
            Write-Host "✓ Copied module files" -ForegroundColor Green
        }

        # Verify installation
        $manifestPath = Join-Path $VersionInstallPath 'RawrXDSecurity.psd1'
        if (-not (Test-Path $manifestPath)) {
            throw "Module manifest not found after installation"
        }

        # Test module import
        Write-Host ""
        Write-Host "Testing module import..." -ForegroundColor Yellow
        Import-Module $ModuleName -Force -ErrorAction Stop
        Write-Host "✓ Module imported successfully" -ForegroundColor Green

        # Display module info
        $module = Get-Module $ModuleName
        Write-Host ""
        Write-Host "Module Information:" -ForegroundColor Cyan
        Write-Host "  Name: $($module.Name)" -ForegroundColor Gray
        Write-Host "  Version: $($module.Version)" -ForegroundColor Gray
        Write-Host "  Description: $($module.Description)" -ForegroundColor Gray
        Write-Host "  Exported Commands: $($module.ExportedCommands.Count)" -ForegroundColor Gray
        Write-Host "  Exported Aliases: $($module.ExportedAliases.Count)" -ForegroundColor Gray

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Installation Complete!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Usage:" -ForegroundColor White
        Write-Host "  Import-Module $ModuleName" -ForegroundColor Gray
        Write-Host "  Initialize-RawrXDSecurity -Environment production" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Or use the alias:" -ForegroundColor White
        Write-Host "  irxs -Environment production" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Get help:" -ForegroundColor White
        Write-Host "  Get-Help Initialize-RawrXDSecurity -Full" -ForegroundColor Gray
        Write-Host ""
    }
    catch {
        Write-Error "Installation failed: $_"
        exit 1
    }
}

end {
    # Cleanup
    if (Get-Module $ModuleName) {
        Remove-Module $ModuleName -Force -ErrorAction SilentlyContinue
    }
}

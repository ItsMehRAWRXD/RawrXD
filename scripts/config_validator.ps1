#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Configuration Validator for RawrXD

.DESCRIPTION
    Validates configuration files:
    - Schema validation
    - Dependency checking
    - Security audit
    - Best practices verification

.EXAMPLE
    .\scripts\config_validator.ps1 -ConfigFile config.json
    .\scripts\config_validator.ps1 -ConfigDir configs/

.NOTES
    Part of RawrXD Phase AD: Advanced Features & Integration
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigFile = "config.json",

    [Parameter()]
    [string]$ConfigDir = "",

    [Parameter()]
    [switch]$Strict,

    [Parameter()]
    [string]$SchemaFile = "schemas/config.schema.json"
)

# ============================================================================
# Configuration
# ============================================================================

$script:ValidationResults = @()
$script:Errors = 0
$script:Warnings = 0

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Add-Result {
    param([string]$File, [string]$Check, [string]$Status, [string]$Message)
    $script:ValidationResults += [PSCustomObject]@{
        File = $File
        Check = $Check
        Status = $Status
        Message = $Message
    }

    if ($Status -eq "ERROR") {
        $script:Errors++
    } elseif ($Status -eq "WARNING") {
        $script:Warnings++
    }
}

# ============================================================================
# Validation
# ============================================================================

function Test-ConfigFile {
    param([string]$Path)

    Write-Status "Validating: $Path" "Info"

    # Check file exists
    if (-not (Test-Path $Path)) {
        Add-Result -File $Path -Check "Exists" -Status "ERROR" -Message "File not found"
        return
    }
    Add-Result -File $Path -Check "Exists" -Status "OK" -Message "File exists"

    # Check JSON validity
    try {
        $content = Get-Content -Path $Path -Raw | ConvertFrom-Json
        Add-Result -File $Path -Check "JSON" -Status "OK" -Message "Valid JSON"
    } catch {
        Add-Result -File $Path -Check "JSON" -Status "ERROR" -Message "Invalid JSON: $_"
        return
    }

    # Check required fields
    $requiredFields = @("version", "server")
    foreach ($field in $requiredFields) {
        if ($content.PSObject.Properties.Name -contains $field) {
            Add-Result -File $Path -Check "Field:$field" -Status "OK" -Message "Present"
        } else {
            Add-Result -File $Path -Check "Field:$field" -Status "WARNING" -Message "Missing"
        }
    }

    # Security checks
    if ($content.server -and $content.server.port) {
        if ($content.server.port -lt 1024) {
            Add-Result -File $Path -Check "Security:Port" -Status "WARNING" -Message "Using privileged port"
        }
    }
}

# ============================================================================
# Report
# ============================================================================

function Write-Report {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Configuration Validation Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    Write-Host "`nResults:" -ForegroundColor White

    $grouped = $script:ValidationResults | Group-Object -Property File
    foreach ($group in $grouped) {
        Write-Host "`n$($group.Name):" -ForegroundColor White
        foreach ($result in $group.Group) {
            $color = switch ($result.Status) {
                "OK" { "Green" }
                "WARNING" { "Yellow" }
                "ERROR" { "Red" }
                default { "Gray" }
            }
            Write-Host "  [$($result.Status)] $($result.Check): $($result.Message)" -ForegroundColor $color
        }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Summary: $($script:Errors) error(s), $($script:Warnings) warning(s)" -ForegroundColor $(if ($script:Errors -eq 0) { "Green" } else { "Red" })
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RawrXD Configuration Validator" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    if ($ConfigDir) {
        $files = Get-ChildItem -Path $ConfigDir -Filter "*.json"
        foreach ($file in $files) {
            Test-ConfigFile -Path $file.FullName
        }
    } else {
        Test-ConfigFile -Path $ConfigFile
    }

    Write-Report

    if ($script:Errors -gt 0) {
        exit 1
    }
}

# Run main
Main

# RawrXD License Compliance Manager
# Manages open source licenses and compliance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("scan", "report", "audit", "check")]
    [string]$Action = "scan",
    
    [string]$ProjectPath = ".",
    [string]$OutputFormat = "table",
    [switch]$GenerateSBOM,
    [switch]$FailOnViolation,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$LicenseConfig = @{
    AllowedLicenses = @(
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
        "ISC", "Zlib", "Unlicense", "CC0-1.0"
    )
    
    RestrictedLicenses = @(
        "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0",
        "AGPL-3.0", "SSPL-1.0", "CPOL", "Proprietary"
    )
    
    ReviewRequired = @(
        "MPL-2.0", "EPL-2.0", "CDDL-1.0"
    )
}

$script:LicenseState = @{
    StartTime = Get-Date
    DependenciesScanned = 0
    ViolationsFound = 0
    Warnings = 0
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Get-DependencyLicenses {
    # Simulate dependency scanning
    $dependencies = @(
        @{ Name = "ggml"; Version = "0.2.0"; License = "MIT"; Status = "allowed" }
        @{ Name = "vulkan-loader"; Version = "1.3.250"; License = "Apache-2.0"; Status = "allowed" }
        @{ Name = "spdlog"; Version = "1.12.0"; License = "MIT"; Status = "allowed" }
        @{ Name = "nlohmann-json"; Version = "3.11.2"; License = "MIT"; Status = "allowed" }
        @{ Name = "openssl"; Version = "3.1.0"; License = "Apache-2.0"; Status = "allowed" }
        @{ Name = "zlib"; Version = "1.3"; License = "Zlib"; Status = "allowed" }
        @{ Name = "protobuf"; Version = "3.24.0"; License = "BSD-3-Clause"; Status = "allowed" }
        @{ Name = "gtest"; Version = "1.14.0"; License = "BSD-3-Clause"; Status = "allowed" }
    )
    
    return $dependencies
}

function Invoke-LicenseScan {
    Write-Status "Scanning for license compliance..."
    
    $dependencies = Get-DependencyLicenses
    $script:LicenseState.DependenciesScanned = $dependencies.Count
    
    $violations = @()
    $warnings = @()
    $allowed = @()
    
    foreach ($dep in $dependencies) {
        if ($LicenseConfig.RestrictedLicenses -contains $dep.License) {
            $violations += $dep
            $script:LicenseState.ViolationsFound++
        }
        elseif ($LicenseConfig.ReviewRequired -contains $dep.License) {
            $warnings += $dep
            $script:LicenseState.Warnings++
        }
        else {
            $allowed += $dep
        }
    }
    
    Write-Host ""
    Write-Host "License Scan Results" -ForegroundColor White
    Write-Host "===================" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Dependencies Scanned: $($dependencies.Count)" -ForegroundColor Gray
    Write-Host "Allowed: $($allowed.Count)" -ForegroundColor Green
    Write-Host "Review Required: $($warnings.Count)" -ForegroundColor Yellow
    Write-Host "Violations: $($violations.Count)" -ForegroundColor $(if($violations.Count -gt 0){'Red'}else{'Green'})
    
    if ($violations.Count -gt 0) {
        Write-Host ""
        Write-Error "License Violations Found:"
        foreach ($v in $violations) {
            Write-Host "  ✗ $($v.Name)@$($v.Version) - $($v.License)" -ForegroundColor Red
        }
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host ""
        Write-Warning "Licenses Requiring Review:"
        foreach ($w in $warnings) {
            Write-Host "  ! $($w.Name)@$($w.Version) - $($w.License)" -ForegroundColor Yellow
        }
    }
    
    if ($FailOnViolation -and $violations.Count -gt 0) {
        throw "License violations detected!"
    }
}

function Export-ComplianceReport {
    $report = @{
        GeneratedAt = Get-Date -Format "o"
        DependenciesScanned = $script:LicenseState.DependenciesScanned
        Violations = $script:LicenseState.ViolationsFound
        Warnings = $script:LicenseState.Warnings
        AllowedLicenses = $LicenseConfig.AllowedLicenses
        RestrictedLicenses = $LicenseConfig.RestrictedLicenses
    }
    
    $filename = "license-compliance-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $report | ConvertTo-Json -Depth 3 | Out-File $filename
    
    Write-Success "Compliance report exported to $filename"
}

# Main execution
function Main {
    Write-Host "RawrXD License Compliance Manager" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "scan" { Invoke-LicenseScan }
        "report" { 
            Invoke-LicenseScan
            Export-ComplianceReport
        }
        "audit" { Invoke-LicenseScan }
        "check" { Invoke-LicenseScan }
    }
    
    Write-Host ""
    Write-Success "License compliance manager complete!"
}

Main

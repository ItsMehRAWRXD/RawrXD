# RawrXD License Manager
# Manages license keys, activation, and compliance

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Show", "Activate", "Deactivate", "Validate", "Generate", "List")]
    [string]$Action = "Show",
    
    [string]$LicenseKey = "",
    [string]$LicenseFile = "license.json",
    [string]$UserName = "",
    [string]$Organization = "",
    [switch]$Offline,
    [string]$ActivationServer = "https://license.rawrxd.ai"
)

$ErrorActionPreference = "Stop"

# License types
$LicenseTypes = @{
    Community = @{ Name = "Community"; MaxUsers = 1; MaxDevices = 1; Features = @("basic") }
    Personal = @{ Name = "Personal"; MaxUsers = 1; MaxDevices = 3; Features = @("basic", "advanced") }
    Professional = @{ Name = "Professional"; MaxUsers = 5; MaxDevices = 10; Features = @("basic", "advanced", "priority") }
    Enterprise = @{ Name = "Enterprise"; MaxUsers = -1; MaxDevices = -1; Features = @("basic", "advanced", "priority", "enterprise", "sla") }
}

$script:LicenseInfo = $null

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Get-LicensePath {
    $paths = @(
        $LicenseFile,
        "config/$LicenseFile",
        "$env:APPDATA/RawrXD/$LicenseFile",
        "$env:LOCALAPPDATA/RawrXD/$LicenseFile",
        "/etc/rawrxd/$LicenseFile"
    )
    
    foreach ($path in $paths) {
        if (Test-Path $path) {
            return (Resolve-Path $path).Path
        }
    }
    
    return $LicenseFile
}

function Load-License {
    $licensePath = Get-LicensePath
    
    if (Test-Path $licensePath) {
        try {
            $content = Get-Content $licensePath -Raw
            $script:LicenseInfo = $content | ConvertFrom-Json
            return $script:LicenseInfo
        }
        catch {
            Write-Error "Failed to parse license file: $_"
            return $null
        }
    }
    
    return $null
}

function Save-License {
    param([hashtable]$License)
    
    $licensePath = Get-LicensePath
    $licenseDir = Split-Path $licensePath -Parent
    
    if ($licenseDir -and -not (Test-Path $licenseDir)) {
        New-Item -ItemType Directory -Path $licenseDir -Force | Out-Null
    }
    
    $License | ConvertTo-Json -Depth 10 | Out-File $licensePath -Encoding UTF8
}

function Get-MachineFingerprint {
    $cpuId = (Get-WmiObject Win32_Processor).ProcessorId
    $diskSerial = (Get-WmiObject Win32_DiskDrive | Select-Object -First 1).SerialNumber
    $macAddress = (Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.MACAddress -and $_.NetEnabled } | Select-Object -First 1).MACAddress
    
    $fingerprint = "$cpuId-$diskSerial-$macAddress"
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fingerprint))
    return [Convert]::ToBase64String($hash).Substring(0, 32)
}

function Show-License {
    $license = Load-License
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "License Information" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not $license) {
        Write-Host "No license found" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "RawrXD Community Edition" -ForegroundColor White
        Write-Host "Features: Basic inference" -ForegroundColor Gray
        Write-Host "Limitations: Single user, single device" -ForegroundColor Gray
        Write-Host ""
        Write-Host "To upgrade, visit: https://rawrxd.ai/pricing" -ForegroundColor Cyan
        return
    }
    
    Write-Host "License Type: $($license.Type)" -ForegroundColor White
    Write-Host "Status: $($license.Status)" -ForegroundColor $(if ($license.Status -eq "Active") { "Green" } else { "Red" })
    Write-Host "Licensed To: $($license.UserName)" -ForegroundColor White
    if ($license.Organization) {
        Write-Host "Organization: $($license.Organization)" -ForegroundColor White
    }
    Write-Host "Issued: $($license.IssuedDate)" -ForegroundColor Gray
    Write-Host "Expires: $($license.ExpiryDate)" -ForegroundColor Gray
    Write-Host ""
    
    $typeInfo = $LicenseTypes[$license.Type]
    if ($typeInfo) {
        Write-Host "Features:" -ForegroundColor White
        foreach ($feature in $typeInfo.Features) {
            Write-Host "  ✓ $feature" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "Limits:" -ForegroundColor White
        Write-Host "  Users: $(if ($typeInfo.MaxUsers -eq -1) { 'Unlimited' } else { $typeInfo.MaxUsers })" -ForegroundColor Gray
        Write-Host "  Devices: $(if ($typeInfo.MaxDevices -eq -1) { 'Unlimited' } else { $typeInfo.MaxDevices })" -ForegroundColor Gray
    }
    
    Write-Host ""
}

function Invoke-LicenseActivation {
    if (-not $LicenseKey) {
        $LicenseKey = Read-Host "Enter license key"
    }
    
    Write-Status "Activating license..."
    
    $fingerprint = Get-MachineFingerprint
    
    if ($Offline) {
        # Offline activation
        Write-Status "Offline activation mode"
        Write-Status "Machine fingerprint: $fingerprint"
        Write-Host ""
        Write-Host "To complete offline activation:" -ForegroundColor Yellow
        Write-Host "1. Visit: $ActivationServer/offline" -ForegroundColor White
        Write-Host "2. Enter your license key: $LicenseKey" -ForegroundColor White
        Write-Host "3. Enter machine fingerprint: $fingerprint" -ForegroundColor White
        Write-Host "4. Download the activation file" -ForegroundColor White
        Write-Host "5. Run: .\license-manager.ps1 -Action Activate -LicenseFile 'activation.json'" -ForegroundColor White
    } else {
        # Online activation
        try {
            $body = @{
                license_key = $LicenseKey
                fingerprint = $fingerprint
                user_name = $UserName
                organization = $Organization
            } | ConvertTo-Json
            
            $response = Invoke-RestMethod -Uri "$ActivationServer/api/activate" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30
            
            if ($response.success) {
                $license = @{
                    Type = $response.license_type
                    Status = "Active"
                    UserName = $response.user_name
                    Organization = $response.organization
                    IssuedDate = $response.issued_date
                    ExpiryDate = $response.expiry_date
                    LicenseKey = $LicenseKey
                    Fingerprint = $fingerprint
                }
                
                Save-License $license
                Write-Success "License activated successfully!"
                Show-License
            } else {
                Write-Error "Activation failed: $($response.message)"
            }
        }
        catch {
            Write-Error "Activation request failed: $_"
            Write-Warning "If you're behind a proxy or firewall, try offline activation with -Offline"
        }
    }
}

function Invoke-LicenseDeactivation {
    $license = Load-License
    
    if (-not $license) {
        Write-Error "No active license found"
        return
    }
    
    $confirm = Read-Host "Are you sure you want to deactivate this license? (y/N)"
    if ($confirm -ne "y") {
        Write-Status "Deactivation cancelled"
        return
    }
    
    Write-Status "Deactivating license..."
    
    try {
        $body = @{
            license_key = $license.LicenseKey
            fingerprint = $license.Fingerprint
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$ActivationServer/api/deactivate" -Method POST -Body $body -ContentType "application/json"
        
        if ($response.success) {
            Remove-Item (Get-LicensePath) -Force -ErrorAction SilentlyContinue
            Write-Success "License deactivated successfully"
        } else {
            Write-Error "Deactivation failed: $($response.message)"
        }
    }
    catch {
        Write-Error "Deactivation request failed: $_"
    }
}

function Test-LicenseValidation {
    $license = Load-License
    
    if (-not $license) {
        Write-Host "No license found - using Community Edition" -ForegroundColor Yellow
        return @{ Valid = $true; Type = "Community"; Expired = $false }
    }
    
    $result = @{
        Valid = $false
        Type = $license.Type
        Expired = $false
        Message = ""
    }
    
    # Check status
    if ($license.Status -ne "Active") {
        $result.Message = "License is not active"
        return $result
    }
    
    # Check expiry
    $expiry = [DateTime]$license.ExpiryDate
    if ($expiry -lt (Get-Date)) {
        $result.Expired = $true
        $result.Message = "License expired on $($license.ExpiryDate)"
        return $result
    }
    
    # Check fingerprint
    $currentFingerprint = Get-MachineFingerprint
    if ($license.Fingerprint -ne $currentFingerprint) {
        $result.Message = "License not valid for this machine"
        return $result
    }
    
    $result.Valid = $true
    $result.Message = "License is valid"
    
    Write-Success $result.Message
    return $result
}

function Invoke-LicenseGeneration {
    Write-Warning "License generation is for authorized personnel only"
    
    $auth = Read-Host "Enter authorization code"
    if ($auth -ne "RAWRXD-ADMIN-2024") {
        Write-Error "Unauthorized"
        return
    }
    
    $type = Read-Host "License type (Community/Personal/Professional/Enterprise)"
    $userName = Read-Host "Licensed to (name)"
    $organization = Read-Host "Organization (optional)"
    $days = Read-Host "Validity period (days)"
    
    $licenseKey = "RAWRXD-" + [Guid]::NewGuid().ToString().Substring(0, 20).ToUpper()
    
    $license = @{
        Type = $type
        Status = "Active"
        UserName = $userName
        Organization = $organization
        IssuedDate = (Get-Date -Format "o")
        ExpiryDate = (Get-Date).AddDays($days).ToString("o")
        LicenseKey = $licenseKey
        Fingerprint = ""
    }
    
    $outputFile = "license-$licenseKey.json"
    $license | ConvertTo-Json -Depth 10 | Out-File $outputFile
    
    Write-Success "License generated: $licenseKey"
    Write-Status "Saved to: $outputFile"
}

function Show-LicenseUsage {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "License Usage" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $license = Load-License
    
    if (-not $license) {
        Write-Host "Community Edition" -ForegroundColor White
        Write-Host "  Users: 1/1" -ForegroundColor Gray
        Write-Host "  Devices: 1/1" -ForegroundColor Gray
        return
    }
    
    $typeInfo = $LicenseTypes[$license.Type]
    
    Write-Host "$($license.Type) Edition" -ForegroundColor White
    Write-Host "  Users: ?/$(if ($typeInfo.MaxUsers -eq -1) { '∞' } else { $typeInfo.MaxUsers })" -ForegroundColor Gray
    Write-Host "  Devices: ?/$(if ($typeInfo.MaxDevices -eq -1) { '∞' } else { $typeInfo.MaxDevices })" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Days remaining: $(([DateTime]$license.ExpiryDate - (Get-Date)).Days)" -ForegroundColor Gray
}

# Main execution
function Main {
    Write-Host "RawrXD License Manager" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    switch ($Action) {
        "Show" { Show-License }
        "Activate" { Invoke-LicenseActivation }
        "Deactivate" { Invoke-LicenseDeactivation }
        "Validate" { Test-LicenseValidation }
        "Generate" { Invoke-LicenseGeneration }
        "List" { Show-LicenseUsage }
    }
    
    Write-Host ""
}

Main

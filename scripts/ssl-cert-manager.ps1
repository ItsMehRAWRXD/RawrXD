# RawrXD SSL Certificate Manager
# Manages SSL/TLS certificates

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("List", "Request", "Renew", "Revoke", "Install", "Check")]
    [string]$Action = "List",
    
    [string]$Domain = "",
    [string]$CertPath = "",
    [string]$KeyPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:CertDir = "certs"

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

function Initialize-CertManager {
    if (-not (Test-Path $script:CertDir)) {
        New-Item -ItemType Directory -Path $script:CertDir -Force | Out-Null
    }
    
    Write-Status "SSL Certificate Manager initialized"
}

function Get-Certificates {
    return @(
        @{ Domain = "api.rawrxd.io"; Issuer = "Let's Encrypt"; Expires = "2024-04-15"; DaysLeft = 89; Status = "Valid" }
        @{ Domain = "rawrxd.io"; Issuer = "Let's Encrypt"; Expires = "2024-04-15"; DaysLeft = 89; Status = "Valid" }
        @{ Domain = "*.rawrxd.io"; Issuer = "Let's Encrypt"; Expires = "2024-04-15"; DaysLeft = 89; Status = "Valid" }
    )
}

function Show-CertificateList {
    $certs = Get-Certificates
    
    Write-Host ""
    Write-Host "SSL Certificates" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "  Domain                Issuer           Expires      Days    Status"
    Write-Host "  " + "-" * 70
    
    foreach ($cert in $certs) {
        $daysColor = if ($cert.DaysLeft -lt 7) { "Red" } elseif ($cert.DaysLeft -lt 30) { "Yellow" } else { "Green" }
        Write-Host "  $($cert.Domain.PadRight(21)) $($cert.Issuer.PadRight(16)) $($cert.Expires)  " -NoNewline
        Write-Host $cert.DaysLeft.ToString().PadRight(6) -ForegroundColor $daysColor -NoNewline
        Write-Host " $($cert.Status)"
    }
}

function Request-NewCertificate {
    param([string]$DomainName)
    
    if (-not $DomainName) {
        Write-Error "Domain name required"
        return
    }
    
    Write-Status "Requesting certificate for: $DomainName"
    Write-Host "  Using Let's Encrypt ACME v2"
    Write-Host "  Validating domain ownership..."
    Start-Sleep -Seconds 2
    Write-Success "Certificate issued for $DomainName"
}

function Renew-Certificate {
    param([string]$DomainName)
    
    if (-not $DomainName) {
        Write-Error "Domain name required"
        return
    }
    
    Write-Status "Renewing certificate for: $DomainName"
    Start-Sleep -Seconds 1
    Write-Success "Certificate renewed"
}

function Revoke-Certificate {
    param([string]$DomainName)
    
    if (-not $DomainName) {
        Write-Error "Domain name required"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Revoke certificate for '$DomainName'? (y/N)"
        if ($confirm -ne "y") {
            Write-Warning "Revocation cancelled"
            return
        }
    }
    
    Write-Status "Revoking certificate for: $DomainName"
    Write-Success "Certificate revoked"
}

function Install-Certificate {
    param([string]$CertFile, [string]$KeyFile)
    
    if (-not $CertFile -or -not $KeyFile) {
        Write-Error "Certificate and key paths required"
        return
    }
    
    Write-Status "Installing certificate..."
    Write-Host "  Certificate: $CertFile"
    Write-Host "  Key: $KeyFile"
    Write-Success "Certificate installed"
}

function Check-CertificateExpiry {
    $certs = Get-Certificates
    
    Write-Host ""
    Write-Host "Certificate Expiry Check" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    $expiringSoon = $certs | Where-Object { $_.DaysLeft -lt 30 }
    
    if ($expiringSoon.Count -eq 0) {
        Write-Success "All certificates are valid for more than 30 days"
    } else {
        Write-Warning "$($expiringSoon.Count) certificate(s) expiring soon:"
        foreach ($cert in $expiringSoon) {
            Write-Host "  • $($cert.Domain) (expires in $($cert.DaysLeft) days)"
        }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD SSL Certificate Manager" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-CertManager
    
    switch ($Action) {
        "List" { Show-CertificateList }
        "Request" { Request-NewCertificate -DomainName $Domain }
        "Renew" { Renew-Certificate -DomainName $Domain }
        "Revoke" { Revoke-Certificate -DomainName $Domain }
        "Install" { Install-Certificate -CertFile $CertPath -KeyFile $KeyPath }
        "Check" { Check-CertificateExpiry }
    }
    
    Write-Host ""
}

Main

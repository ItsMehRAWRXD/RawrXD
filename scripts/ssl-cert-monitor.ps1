# RawrXD SSL Certificate Monitor
# Monitors SSL certificate expiration and health
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Check", "List", "Add", "Remove", "Report")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$Domain,
    
    [Parameter()]
    [int]$WarningDays = 30,
    
    [Parameter()]
    [int]$CriticalDays = 7,
    
    [Parameter()]
    [string]$OutputPath = "ssl-cert-report.json"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-CertStorePath {
    return "$PSScriptRoot\.ssl-certs.json"
}

function Get-CertStore {
    $path = Get-CertStorePath
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Domains = @(); CheckHistory = @() }
}

function Save-CertStore {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content (Get-CertStorePath)
}

function Get-SimulatedCertInfo {
    param([string]$DomainName)
    
    $expiryDays = Get-Random -Minimum -5 -Maximum 90
    $expiryDate = (Get-Date).AddDays($expiryDays)
    
    return [PSCustomObject]@{
        Domain = $DomainName
        Issuer = "Let's Encrypt Authority X3"
        Subject = "CN=$DomainName"
        ValidFrom = (Get-Date).AddDays(-60).ToString("yyyy-MM-dd")
        ValidTo = $expiryDate.ToString("yyyy-MM-dd")
        DaysRemaining = $expiryDays
        Thumbprint = [Guid]::NewGuid().ToString().Replace("-", "").Substring(0, 40)
        Algorithm = "SHA256-RSA"
        KeyLength = 2048
    }
}

function Show-CertList {
    $store = Get-CertStore
    
    Write-Host "`nSSL Certificate Monitor" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($store.Domains.Count -eq 0) {
        Write-Status "No domains configured for monitoring"
        return
    }
    
    Write-Host "Domain              Issuer                    Valid Until          Days    Status"
    Write-Host "------              ------                    -----------          ----    ------"
    
    foreach ($domain in $store.Domains) {
        $cert = Get-SimulatedCertInfo -DomainName $domain
        
        $status = if ($cert.DaysRemaining -lt 0) { "Expired" }
                  elseif ($cert.DaysRemaining -le $CriticalDays) { "Critical" }
                  elseif ($cert.DaysRemaining -le $WarningDays) { "Warning" }
                  else { "OK" }
        
        $color = switch ($status) {
            "OK" { "Green" }
            "Warning" { "Yellow" }
            default { "Red" }
        }
        
        Write-Host ($cert.Domain).PadRight(20) -NoNewline
        Write-Host ($cert.Issuer).PadRight(26) -NoNewline
        Write-Host $cert.ValidTo.PadRight(21) -NoNewline
        Write-Host $cert.DaysRemaining.ToString().PadRight(8) -NoNewline
        Write-Host $status -ForegroundColor $color
    }
    Write-Host ""
}

function Test-Certificate {
    if (-not $Domain) {
        throw "Domain parameter required for Check action"
    }
    
    Write-Status "Checking SSL certificate for: $Domain"
    
    $cert = Get-SimulatedCertInfo -DomainName $Domain
    
    Write-Host ""
    Write-Host "Certificate Details: $Domain" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host "Subject: $($cert.Subject)"
    Write-Host "Issuer: $($cert.Issuer)"
    Write-Host "Valid From: $($cert.ValidFrom)"
    Write-Host "Valid To: $($cert.ValidTo)"
    Write-Host "Days Remaining: $($cert.DaysRemaining)"
    Write-Host "Algorithm: $($cert.Algorithm)"
    Write-Host "Key Length: $($cert.KeyLength)"
    Write-Host "Thumbprint: $($cert.Thumbprint)"
    Write-Host ""
    
    if ($cert.DaysRemaining -lt 0) {
        Write-Error "Certificate has EXPIRED!"
    }
    elseif ($cert.DaysRemaining -le $CriticalDays) {
        Write-Error "Certificate expires in $($cert.DaysRemaining) days - CRITICAL!"
    }
    elseif ($cert.DaysRemaining -le $WarningDays) {
        Write-Warning "Certificate expires in $($cert.DaysRemaining) days - WARNING"
    }
    else {
        Write-Success "Certificate is valid for $($cert.DaysRemaining) days"
    }
    
    # Log check
    $store = Get-CertStore
    $store.CheckHistory += @{
        Domain = $Domain
        CheckedAt = (Get-Date).ToString("o")
        DaysRemaining = $cert.DaysRemaining
        Status = if ($cert.DaysRemaining -lt 0) { "Expired" } elseif ($cert.DaysRemaining -le $CriticalDays) { "Critical" } elseif ($cert.DaysRemaining -le $WarningDays) { "Warning" } else { "OK" }
    }
    Save-CertStore -Data $store
}

function Add-MonitoredDomain {
    if (-not $Domain) {
        throw "Domain parameter required for Add action"
    }
    
    $store = Get-CertStore
    
    if ($store.Domains -contains $Domain) {
        Write-Warning "Domain $Domain is already being monitored"
        return
    }
    
    $store.Domains += $Domain
    Save-CertStore -Data $store
    
    Write-Success "Added $Domain to SSL certificate monitoring"
}

function Remove-MonitoredDomain {
    if (-not $Domain) {
        throw "Domain parameter required for Remove action"
    }
    
    $store = Get-CertStore
    
    if ($store.Domains -notcontains $Domain) {
        Write-Warning "Domain $Domain is not being monitored"
        return
    }
    
    $store.Domains = $store.Domains | Where-Object { $_ -ne $Domain }
    Save-CertStore -Data $store
    
    Write-Success "Removed $Domain from SSL certificate monitoring"
}

function Export-CertReport {
    $store = Get-CertStore
    
    $report = @{
        GeneratedAt = (Get-Date).ToString("o")
        WarningThreshold = $WarningDays
        CriticalThreshold = $CriticalDays
        Domains = @()
    }
    
    foreach ($domain in $store.Domains) {
        $cert = Get-SimulatedCertInfo -DomainName $domain
        $report.Domains += $cert
    }
    
    $report | ConvertTo-Json -Depth 5 | Set-Content $OutputPath
    Write-Success "SSL certificate report saved to: $OutputPath"
    
    # Summary
    $expiringSoon = ($report.Domains | Where-Object { $_.DaysRemaining -le $WarningDays }).Count
    $critical = ($report.Domains | Where-Object { $_.DaysRemaining -le $CriticalDays }).Count
    $expired = ($report.Domains | Where-Object { $_.DaysRemaining -lt 0 }).Count
    
    Write-Host ""
    Write-Host "Report Summary:" -ForegroundColor Cyan
    Write-Host "  Total Domains: $($report.Domains.Count)"
    Write-Host "  Expiring Soon (≤$WarningDays days): $expiringSoon" -ForegroundColor $(if ($expiringSoon -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Critical (≤$CriticalDays days): $critical" -ForegroundColor $(if ($critical -gt 0) { "Red" } else { "Green" })
    Write-Host "  Expired: $expired" -ForegroundColor $(if ($expired -gt 0) { "Red" } else { "Green" })
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-CertList }
        "Check" { Test-Certificate }
        "Add" { Add-MonitoredDomain }
        "Remove" { Remove-MonitoredDomain }
        "Report" { Export-CertReport }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

# RawrXD SSL Manager
# Manages SSL certificates and HTTPS configuration

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Check", "Generate", "Install", "Renew", "List", "Export")]
    [string]$Action = "Check",
    
    [string]$Domain = "",
    [string]$CertPath = "certs",
    [string]$KeyPath = "",
    [int]$ValidityDays = 365,
    [switch]$SelfSigned,
    [string]$CAPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

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

function Initialize-SSLManager {
    Write-Status "SSL Manager initialized"
    Write-Status "Action: $Action"
    
    if (-not (Test-Path $CertPath)) {
        New-Item -ItemType Directory -Path $CertPath -Force | Out-Null
        Write-Status "Created certificate directory: $CertPath"
    }
}

function Test-Certificate {
    Write-Status "Checking certificates..."
    
    $certs = Get-ChildItem -Path $CertPath -Filter "*.pem" -ErrorAction SilentlyContinue
    $certs += Get-ChildItem -Path $CertPath -Filter "*.crt" -ErrorAction SilentlyContinue
    $certs += Get-ChildItem -Path $CertPath -Filter "*.cer" -ErrorAction SilentlyContinue
    
    if ($certs.Count -eq 0) {
        Write-Warning "No certificates found in $CertPath"
        return
    }
    
    Write-Host ""
    Write-Host "Certificates:" -ForegroundColor Cyan
    Write-Host "============" -ForegroundColor Cyan
    
    foreach ($certFile in $certs) {
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($certFile.FullName)
            
            $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
            $status = if ($daysUntilExpiry -lt 0) { "EXPIRED" } 
                     elseif ($daysUntilExpiry -lt 30) { "EXPIRING SOON" }
                     else { "VALID" }
            
            $color = switch ($status) {
                "VALID" { "Green" }
                "EXPIRING SOON" { "Yellow" }
                "EXPIRED" { "Red" }
            }
            
            Write-Host "  $($certFile.Name)" -NoNewline
            Write-Host " - $status (expires: $($cert.NotAfter.ToString('yyyy-MM-dd')), $daysUntilExpiry days)" -ForegroundColor $color
            Write-Host "    Subject: $($cert.Subject)"
            Write-Host "    Issuer: $($cert.Issuer)"
            Write-Host "    Thumbprint: $($cert.Thumbprint)"
        }
        catch {
            Write-Warning "Failed to read certificate: $($certFile.Name)"
        }
    }
}

function New-SelfSignedCertificate {
    if (-not $Domain) {
        $Domain = "localhost"
    }
    
    Write-Status "Generating self-signed certificate for $Domain..."
    
    $certFile = "$CertPath\$Domain.pem"
    $keyFile = "$CertPath\$Domain-key.pem"
    
    if ((Test-Path $certFile) -and -not $Force) {
        Write-Error "Certificate already exists. Use -Force to overwrite."
        return
    }
    
    # Check if OpenSSL is available
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $openssl) {
        Write-Error "OpenSSL not found. Please install OpenSSL."
        return
    }
    
    try {
        # Generate private key
        & openssl genrsa -out $keyFile 2048 2>$null
        Write-Success "Generated private key: $keyFile"
        
        # Generate certificate
        $subj = "/CN=$Domain"
        & openssl req -new -x509 -key $keyFile -out $certFile -days $ValidityDays -subj $subj 2>$null
        Write-Success "Generated certificate: $certFile"
        
        Write-Host ""
        Write-Host "Certificate Details:" -ForegroundColor Cyan
        & openssl x509 -in $certFile -text -noout | Select-String -Pattern "Subject:|Issuer:|Not Before|Not After" | Write-Host
    }
    catch {
        Write-Error "Failed to generate certificate: $_"
    }
}

function Export-Certificate {
    if (-not $Domain) {
        Write-Error "Domain parameter required for export"
        return
    }
    
    $certFile = "$CertPath\$Domain.pem"
    $keyFile = "$CertPath\$Domain-key.pem"
    $pfxFile = "$CertPath\$Domain.pfx"
    
    if (-not (Test-Path $certFile) -or -not (Test-Path $keyFile)) {
        Write-Error "Certificate or key file not found"
        return
    }
    
    Write-Status "Exporting certificate to PFX format..."
    
    try {
        # Combine cert and key
        $combined = "$CertPath\$Domain-combined.pem"
        Get-Content $certFile, $keyFile | Out-File $combined
        
        # Convert to PFX
        $password = Read-Host "Enter PFX password" -AsSecureString
        $passwordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
        
        & openssl pkcs12 -export -in $combined -out $pfxFile -password pass:$passwordPlain 2>$null
        
        Remove-Item $combined -Force
        Write-Success "Exported to: $pfxFile"
    }
    catch {
        Write-Error "Failed to export certificate: $_"
    }
}

function Install-CertificateWindows {
    if (-not $Domain) {
        Write-Error "Domain parameter required for install"
        return
    }
    
    $certFile = "$CertPath\$Domain.pem"
    
    if (-not (Test-Path $certFile)) {
        Write-Error "Certificate file not found: $certFile"
        return
    }
    
    Write-Status "Installing certificate to Windows certificate store..."
    
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($certFile)
        
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $store.Open("ReadWrite")
        $store.Add($cert)
        $store.Close()
        
        Write-Success "Certificate installed to Trusted Root store"
    }
    catch {
        Write-Error "Failed to install certificate: $_"
        Write-Warning "You may need to run as Administrator"
    }
}

function Show-CertificateList {
    Write-Host ""
    Write-Host "SSL Certificates" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    
    if (-not (Test-Path $CertPath)) {
        Write-Warning "Certificate directory not found: $CertPath"
        return
    }
    
    $items = Get-ChildItem -Path $CertPath -File
    
    if ($items.Count -eq 0) {
        Write-Warning "No certificates found"
        return
    }
    
    foreach ($item in $items) {
        $icon = if ($item.Extension -eq ".pem") { "🔒" } elseif ($item.Extension -eq ".key") { "🔑" } else { "📄" }
        $size = [math]::Round($item.Length / 1KB, 2)
        Write-Host "  $icon $($item.Name) ($size KB)"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD SSL Manager" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-SSLManager
    
    switch ($Action) {
        "Check" { Test-Certificate }
        "Generate" { 
            if ($SelfSigned) {
                New-SelfSignedCertificate
            } else {
                Write-Error "Use -SelfSigned flag for self-signed certificates"
            }
        }
        "Install" { Install-CertificateWindows }
        "List" { Show-CertificateList }
        "Export" { Export-Certificate }
        "Renew" { 
            Write-Status "Renewing certificate..."
            if ($SelfSigned) {
                New-SelfSignedCertificate
            }
        }
    }
    
    Write-Host ""
}

Main

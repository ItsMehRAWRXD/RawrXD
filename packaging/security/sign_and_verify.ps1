# sign_and_verify.ps1
# Phase F.1 Batch 3/5: Code signing and verification pipeline

param(
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,
    
    [string]$CertificateThumbprint,
    [string]$CertificatePath,
    [SecureString]$CertificatePassword,
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [string]$OutputDir = ".\signed",
    [switch]$VerifyOnly,
    [switch]$CreateChecksums,
    [switch]$SignInstaller,
    [string]$InstallerPath
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Logging
# ============================================================================

function Write-Status($Message) {
    Write-Host "[SIGN] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ============================================================================
# Certificate Management
# ============================================================================

function Get-SigningCertificate {
    param(
        [string]$Thumbprint,
        [string]$Path,
        [SecureString]$Password
    )
    
    if ($Thumbprint) {
        Write-Status "Loading certificate from store (thumbprint: $Thumbprint)..."
        $cert = Get-ChildItem -Path "Cert:\CurrentUser\My" | 
                Where-Object { $_.Thumbprint -eq $Thumbprint } |
                Select-Object -First 1
        
        if (-not $cert) {
            $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | 
                    Where-Object { $_.Thumbprint -eq $Thumbprint } |
                    Select-Object -First 1
        }
        
        if (-not $cert) {
            throw "Certificate with thumbprint $Thumbprint not found"
        }
        
        return $cert
    }
    
    if ($Path) {
        Write-Status "Loading certificate from file: $Path..."
        if (-not (Test-Path $Path)) {
            throw "Certificate file not found: $Path"
        }
        
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($Path, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        return $cert
    }
    
    throw "No certificate specified. Use -CertificateThumbprint or -CertificatePath"
}

# ============================================================================
# Code Signing
# ============================================================================

function Invoke-CodeSign {
    param(
        [string]$FilePath,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$TimestampUrl
    )
    
    Write-Status "Signing: $FilePath"
    
    # Use signtool.exe
    $signtool = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    if (-not (Test-Path $signtool)) {
        $signtool = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe"
    }
    if (-not (Test-Path $signtool)) {
        $signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits" -Recurse -Filter "signtool.exe" | 
                    Select-Object -First 1 -ExpandProperty FullName
    }
    
    if (-not (Test-Path $signtool)) {
        throw "signtool.exe not found. Please install Windows SDK."
    }
    
    # Export certificate to temp file
    $tempCert = [System.IO.Path]::GetTempFileName() + ".pfx"
    $certBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
    [System.IO.File]::WriteAllBytes($tempCert, $certBytes)
    
    try {
        $args = @(
            "sign",
            "/f", $tempCert,
            "/tr", $TimestampUrl,
            "/td", "sha256",
            "/fd", "sha256",
            "/a",
            "/v",
            $FilePath
        )
        
        $output = & $signtool $args 2>&1
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -ne 0) {
            throw "Signing failed with exit code $exitCode`n$output"
        }
        
        Write-Success "Signed: $FilePath"
    }
    finally {
        Remove-Item $tempCert -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# Signature Verification
# ============================================================================

function Test-Signature {
    param([string]$FilePath)
    
    Write-Status "Verifying signature: $FilePath"
    
    $signtool = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    if (-not (Test-Path $signtool)) {
        $signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits" -Recurse -Filter "signtool.exe" | 
                    Select-Object -First 1 -ExpandProperty FullName
    }
    
    if (-not (Test-Path $signtool)) {
        # Fallback to PowerShell Get-AuthenticodeSignature
        $sig = Get-AuthenticodeSignature -FilePath $FilePath
        if ($sig.Status -eq "Valid") {
            Write-Success "Signature valid: $($sig.SignerCertificate.Subject)"
            return $true
        } else {
            Write-Error "Signature invalid: $($sig.Status)"
            return $false
        }
    }
    
    $output = & $signtool "verify", "/pa", "/v", $FilePath 2>&1
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0) {
        Write-Success "Signature verified"
        return $true
    } else {
        Write-Error "Signature verification failed"
        return $false
    }
}

# ============================================================================
# Checksum Generation
# ============================================================================

function New-ChecksumFile {
    param(
        [string]$FilePath,
        [string]$OutputPath
    )
    
    Write-Status "Generating checksums for: $FilePath"
    
    $hashes = @{}
    
    # SHA256
    $sha256 = Get-FileHash -Path $FilePath -Algorithm SHA256
    $hashes["sha256"] = $sha256.Hash.ToLower()
    
    # SHA512
    $sha512 = Get-FileHash -Path $FilePath -Algorithm SHA512
    $hashes["sha512"] = $sha512.Hash.ToLower()
    
    # MD5 (for compatibility)
    $md5 = Get-FileHash -Path $FilePath -Algorithm MD5
    $hashes["md5"] = $md5.Hash.ToLower()
    
    # Write checksum file
    $checksumContent = @"
# RawrXD Checksums
# File: $(Split-Path $FilePath -Leaf)
# Generated: $(Get-Date -Format "o")

SHA256: $($hashes.sha256)
SHA512: $($hashes.sha512)
MD5:    $($hashes.md5)
"@
    
    $checksumContent | Out-File $OutputPath -Encoding UTF8
    
    # Also write individual hash files for easy verification
    $hashes.sha256 | Out-File "$OutputPath.sha256" -Encoding ASCII -NoNewline
    $hashes.sha512 | Out-File "$OutputPath.sha512" -Encoding ASCII -NoNewline
    $hashes.md5 | Out-File "$OutputPath.md5" -Encoding ASCII -NoNewline
    
    Write-Success "Checksums written to: $OutputPath"
    
    return $hashes
}

function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ExpectedHash,
        [string]$Algorithm = "SHA256"
    )
    
    Write-Status "Verifying $Algorithm checksum..."
    
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm $Algorithm).Hash.ToLower()
    $expectedHash = $ExpectedHash.ToLower()
    
    if ($actualHash -eq $expectedHash) {
        Write-Success "Checksum verified"
        return $true
    } else {
        Write-Error "Checksum mismatch!"
        Write-Error "  Expected: $expectedHash"
        Write-Error "  Actual:   $actualHash"
        return $false
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=== RawrXD Code Signing Pipeline ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Create output directory
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    
    if ($VerifyOnly) {
        # Verification mode
        $valid = Test-Signature -FilePath $BinaryPath
        
        if ($CreateChecksums) {
            $checksumFile = Join-Path $OutputDir "$(Split-Path $BinaryPath -Leaf).checksums"
            New-ChecksumFile -FilePath $BinaryPath -OutputPath $checksumFile
        }
        
        exit ($valid ? 0 : 1)
    }
    
    # Signing mode
    $cert = Get-SigningCertificate -Thumbprint $CertificateThumbprint -Path $CertificatePath -Password $CertificatePassword
    Write-Success "Loaded certificate: $($cert.Subject)"
    
    # Sign main binary
    Invoke-CodeSign -FilePath $BinaryPath -Certificate $cert -TimestampUrl $TimestampServer
    
    # Verify signature
    $valid = Test-Signature -FilePath $BinaryPath
    if (-not $valid) {
        exit 1
    }
    
    # Sign installer if provided
    if ($SignInstaller -and $InstallerPath -and (Test-Path $InstallerPath)) {
        Invoke-CodeSign -FilePath $InstallerPath -Certificate $cert -TimestampUrl $TimestampServer
        Test-Signature -FilePath $InstallerPath | Out-Null
    }
    
    # Generate checksums
    if ($CreateChecksums) {
        $checksumFile = Join-Path $OutputDir "$(Split-Path $BinaryPath -Leaf).checksums"
        $hashes = New-ChecksumFile -FilePath $BinaryPath -OutputPath $checksumFile
        
        # Also create JSON manifest
        $manifest = @{
            file = Split-Path $BinaryPath -Leaf
            signed = $true
            timestamp = Get-Date -Format "o"
            certificate = @{
                subject = $cert.Subject
                issuer = $cert.Issuer
                thumbprint = $cert.Thumbprint
                not_after = $cert.NotAfter.ToString("o")
            }
            hashes = $hashes
        }
        
        $manifestPath = Join-Path $OutputDir "$(Split-Path $BinaryPath -Leaf).manifest.json"
        $manifest | ConvertTo-Json -Depth 3 | Out-File $manifestPath -Encoding UTF8
        Write-Success "Manifest written: $manifestPath"
    }
    
    Write-Host ""
    Write-Success "Code signing complete!"
    Write-Host ""
}

Main

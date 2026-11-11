# secure_update_channel.ps1
# Phase F.1 Batch 3/5: Secure update channel with signature verification

param(
    [string]$UpdateServer = "https://updates.rawrxd.ai",
    [string]$Channel = "stable",
    [string]$CurrentVersion = "1.0.0",
    [switch]$CheckOnly,
    [switch]$AutoUpdate,
    [string]$InstallDir = "$env:ProgramFiles\RawrXD",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$ProductName = "RawrXD Sovereign"
$UpdateConfigFile = "$env:ProgramData\RawrXD\update_config.json"
$UpdateCacheDir = "$env:LOCALAPPDATA\RawrXD\updates"
$PublicKey = @"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"@

# ============================================================================
# Logging
# ============================================================================

function Write-Status($Message) {
    Write-Host "[UPDATE] $Message" -ForegroundColor Cyan
}

function Write-Success($Message) {
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning($Message) {
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ============================================================================
# Version Comparison
# ============================================================================

function Compare-Version($Current, $Available) {
    $currentParts = $Current -split '\.' | ForEach-Object { [int]$_ }
    $availableParts = $Available -split '\.' | ForEach-Object { [int]$_ }
    
    for ($i = 0; $i -lt [Math]::Max($currentParts.Length, $availableParts.Length); $i++) {
        $c = if ($i -lt $currentParts.Length) { $currentParts[$i] } else { 0 }
        $a = if ($i -lt $availableParts.Length) { $availableParts[$i] } else { 0 }
        
        if ($a -gt $c) { return 1 }
        if ($a -lt $c) { return -1 }
    }
    
    return 0
}

# ============================================================================
# Update Check
# ============================================================================

function Get-LatestVersion {
    Write-Status "Checking for updates on $Channel channel..."
    
    $updateUrl = "$UpdateServer/$Channel/latest.json"
    
    try {
        $response = Invoke-RestMethod -Uri $updateUrl -Method GET -TimeoutSec 30
        return $response
    } catch {
        Write-Error "Failed to check for updates: $_"
        return $null
    }
}

function Test-UpdateAvailable($LatestInfo) {
    if (-not $LatestInfo) { return $false }
    
    $comparison = Compare-Version $CurrentVersion $LatestInfo.version
    
    if ($comparison -lt 0) {
        Write-Success "Update available: v$CurrentVersion -> v$($LatestInfo.version)"
        return $true
    } else {
        Write-Status "Already up to date (v$CurrentVersion)"
        return $false
    }
}

# ============================================================================
# Secure Download
# ============================================================================

function Invoke-SecureDownload {
    param(
        [string]$Url,
        [string]$ExpectedHash,
        [string]$OutputPath
    )
    
    Write-Status "Downloading from $Url..."
    
    # Download with progress
    $ProgressPreference = 'Continue'
    
    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
    } catch {
        throw "Download failed: $_"
    }
    
    Write-Status "Verifying download integrity..."
    
    # Verify checksum
    $actualHash = (Get-FileHash -Path $OutputPath -Algorithm SHA256).Hash.ToLower()
    $expectedHash = $ExpectedHash.ToLower()
    
    if ($actualHash -ne $expectedHash) {
        Remove-Item $OutputPath -Force
        throw "Checksum verification failed! Expected: $expectedHash, Got: $actualHash"
    }
    
    Write-Success "Download verified"
}

# ============================================================================
# Signature Verification
# ============================================================================

function Test-UpdateSignature {
    param(
        [string]$FilePath,
        [string]$SignatureBase64
    )
    
    Write-Status "Verifying update signature..."
    
    # Load public key
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($PublicKey)
    
    # Verify signature
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $signature = [Convert]::FromBase64String($SignatureBase64)
    
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash($fileBytes)
    
    $valid = $rsa.VerifyHash($hash, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    
    if ($valid) {
        Write-Success "Signature verified"
    } else {
        throw "Signature verification failed!"
    }
    
    return $valid
}

# ============================================================================
# Update Installation
# ============================================================================

function Install-Update {
    param(
        [string]$UpdatePackage,
        [hashtable]$UpdateInfo
    )
    
    Write-Status "Installing update..."
    
    # Create backup
    $backupDir = "$env:ProgramData\RawrXD\backups\$CurrentVersion"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    Write-Status "Creating backup..."
    Copy-Item "$InstallDir\*" $backupDir -Recurse -Force
    
    try {
        # Extract update
        $tempDir = "$UpdateCacheDir\extract"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        
        Write-Status "Extracting update package..."
        Expand-Archive -Path $UpdatePackage -DestinationPath $tempDir -Force
        
        # Stop service if running
        $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq "Running") {
            Write-Status "Stopping RawrXD service..."
            Stop-Service -Name "RawrXD" -Force
        }
        
        # Install update
        Write-Status "Installing files..."
        Copy-Item "$tempDir\*" $InstallDir -Recurse -Force
        
        # Update version in registry
        Set-ItemProperty -Path "HKLM:\Software\RawrXD" -Name "Version" -Value $UpdateInfo.version
        Set-ItemProperty -Path "HKLM:\Software\RawrXD" -Name "LastUpdate" -Value (Get-Date -Format "o")
        
        # Restart service
        if ($service) {
            Write-Status "Restarting RawrXD service..."
            Start-Service -Name "RawrXD"
        }
        
        # Cleanup
        Remove-Item $tempDir -Recurse -Force
        Remove-Item $UpdatePackage -Force
        
        Write-Success "Update installed successfully!"
        Write-Success "Version: v$($UpdateInfo.version)"
        
    } catch {
        # Restore backup
        Write-Error "Update failed: $_"
        Write-Status "Restoring from backup..."
        Copy-Item "$backupDir\*" $InstallDir -Recurse -Force
        throw "Update failed and was rolled back"
    }
}

# ============================================================================
# Rollback
# ============================================================================

function Invoke-Rollback {
    param([string]$TargetVersion)
    
    Write-Status "Rolling back to v$TargetVersion..."
    
    $backupDir = "$env:ProgramData\RawrXD\backups\$TargetVersion"
    
    if (-not (Test-Path $backupDir)) {
        throw "Backup for v$TargetVersion not found"
    }
    
    # Stop service
    $service = Get-Service -Name "RawrXD" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        Stop-Service -Name "RawrXD" -Force
    }
    
    # Restore
    Copy-Item "$backupDir\*" $InstallDir -Recurse -Force
    
    # Update registry
    Set-ItemProperty -Path "HKLM:\Software\RawrXD" -Name "Version" -Value $TargetVersion
    
    # Restart
    if ($service) {
        Start-Service -Name "RawrXD"
    }
    
    Write-Success "Rolled back to v$TargetVersion"
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Host ""
    Write-Host "=== $ProductName Update Channel ===" -ForegroundColor Cyan
    Write-Host "Current Version: v$CurrentVersion"
    Write-Host "Channel: $Channel"
    Write-Host ""
    
    # Create directories
    New-Item -ItemType Directory -Path $UpdateCacheDir -Force | Out-Null
    
    # Check for updates
    $latest = Get-LatestVersion
    
    if (-not $latest) {
        exit 1
    }
    
    $updateAvailable = Test-UpdateAvailable $latest
    
    if ($CheckOnly -or -not $updateAvailable) {
        exit ($updateAvailable ? 0 : 0)
    }
    
    if (-not $AutoUpdate) {
        Write-Host ""
        Write-Host "Update Details:" -ForegroundColor Yellow
        Write-Host "  Version: v$($latest.version)"
        Write-Host "  Size: $([math]::Round($latest.size / 1MB, 2)) MB"
        Write-Host "  Release Notes: $($latest.release_notes_url)"
        Write-Host ""
        
        $response = Read-Host "Install update? (y/N)"
        if ($response -ne "y" -and $response -ne "Y") {
            Write-Status "Update cancelled by user"
            exit 0
        }
    }
    
    # Download update
    $updateFile = "$UpdateCacheDir\rawrxd-$($latest.version).zip"
    Invoke-SecureDownload -Url $latest.download_url -ExpectedHash $latest.sha256 -OutputPath $updateFile
    
    # Verify signature
    if ($latest.signature) {
        Test-UpdateSignature -FilePath $updateFile -SignatureBase64 $latest.signature
    }
    
    # Install
    Install-Update -UpdatePackage $updateFile -UpdateInfo $latest
    
    Write-Host ""
    Write-Success "Update complete!"
    Write-Host ""
}

Main

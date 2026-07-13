# RawrXD Enterprise License Manager
# Phase F.1 Batch 4/5: Enterprise License Management
# Usage: .\enterprise\license-manager.ps1 [validate|generate|renew|revoke|audit]

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("validate", "generate", "renew", "revoke", "audit", "init")]
    [string]$Action,
    
    [string]$LicenseKey = "",
    [string]$CustomerId = "",
    [string]$Tier = "professional",
    [int]$DurationDays = 365,
    [string]$OutputPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Configuration
$LicenseStorePath = "$env:PROGRAMDATA\RawrXD\licenses"
$LicenseDbPath = "$LicenseStorePath\licenses.db"
$PrivateKeyPath = "$LicenseStorePath\private.key"
$PublicKeyPath = "$LicenseStorePath\public.key"

# License Tiers
$LicenseTiers = @{
    "community" = @{
        Name = "Community"
        MaxUsers = 1
        MaxModels = 3
        Features = @("inference", "streaming", "basic_benchmarks")
        Support = "community"
        Hotpatch = $false
        Swarm = $false
        Audit = $false
    }
    "professional" = @{
        Name = "Professional"
        MaxUsers = 5
        MaxModels = 10
        Features = @("inference", "streaming", "benchmarks", "hotpatch", "swarm")
        Support = "email"
        Hotpatch = $true
        Swarm = $true
        Audit = $false
    }
    "enterprise" = @{
        Name = "Enterprise"
        MaxUsers = -1  # Unlimited
        MaxModels = -1  # Unlimited
        Features = @("*")  # All features
        Support = "24x7"
        Hotpatch = $true
        Swarm = $true
        Audit = $true
    }
}

# ============================================================================
# Cryptographic Functions
# ============================================================================

function Initialize-LicenseStore {
    if (-not (Test-Path $LicenseStorePath)) {
        New-Item -ItemType Directory -Path $LicenseStorePath -Force | Out-Null
        Write-Host "Created license store: $LicenseStorePath" -ForegroundColor Green
    }
    
    # Generate RSA key pair if not exists
    if (-not (Test-Path $PrivateKeyPath)) {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
        
        $privateKey = $rsa.ToXmlString($true)
        $publicKey = $rsa.ToXmlString($false)
        
        $privateKey | Set-Content $PrivateKeyPath
        $publicKey | Set-Content $PublicKeyPath
        
        # Secure the private key
        $acl = Get-Acl $PrivateKeyPath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "SYSTEM", "FullControl", "Allow"
        )
        $acl.SetAccessRule($rule)
        Set-Acl $PrivateKeyPath $acl
        
        Write-Host "Generated RSA key pair" -ForegroundColor Green
    }
    
    # Initialize license database
    if (-not (Test-Path $LicenseDbPath)) {
        @{
            version = "1.0"
            licenses = @{}
            revoked = @()
            audit_log = @()
        } | ConvertTo-Json -Depth 10 | Set-Content $LicenseDbPath
        
        Write-Host "Initialized license database" -ForegroundColor Green
    }
}

function Get-PublicKey {
    if (-not (Test-Path $PublicKeyPath)) {
        throw "Public key not found. Run 'init' first."
    }
    return Get-Content $PublicKeyPath
}

function Get-PrivateKey {
    if (-not (Test-Path $PrivateKeyPath)) {
        throw "Private key not found. Run 'init' first."
    }
    return Get-Content $PrivateKeyPath
}

function Sign-Data($data) {
    $privateKey = Get-PrivateKey
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($privateKey)
    
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
    $signature = $rsa.SignData($bytes, "SHA256")
    return [Convert]::ToBase64String($signature)
}

function Verify-Signature($data, $signature) {
    try {
        $publicKey = Get-PublicKey
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($publicKey)
        
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($data)
        $sigBytes = [Convert]::FromBase64String($signature)
        
        return $rsa.VerifyData($dataBytes, "SHA256", $sigBytes)
    } catch {
        return $false
    }
}

# ============================================================================
# License Functions
# ============================================================================

function Get-LicenseDb {
    return Get-Content $LicenseDbPath | ConvertFrom-Json
}

function Save-LicenseDb($db) {
    $db | ConvertTo-Json -Depth 10 | Set-Content $LicenseDbPath
}

function Generate-LicenseKey {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($bytes)
    return ($bytes | ForEach-Object { $_.ToString("X2") }) -join "-"
}

function Format-LicenseKey($key) {
    # Format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
    $clean = $key -replace "[^A-Fa-f0-9]", ""
    $parts = @()
    for ($i = 0; $i -lt $clean.Length; $i += 5) {
        $parts += $clean.Substring($i, [Math]::Min(5, $clean.Length - $i))
    }
    return ($parts -join "-").ToUpper()
}

function New-License {
    param(
        [string]$CustomerId,
        [string]$Tier,
        [int]$DurationDays
    )
    
    if (-not $LicenseTiers.ContainsKey($Tier)) {
        throw "Invalid tier: $Tier. Valid tiers: $($LicenseTiers.Keys -join ', ')"
    }
    
    $licenseId = [Guid]::NewGuid().ToString()
    $licenseKey = Format-LicenseKey (Generate-LicenseKey)
    $issuedAt = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    $expiresAt = (Get-Date).AddDays($DurationDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    $licenseData = @{
        id = $licenseId
        key = $licenseKey
        customer_id = $CustomerId
        tier = $Tier
        issued_at = $issuedAt
        expires_at = $expiresAt
        features = $LicenseTiers[$Tier].Features
        max_users = $LicenseTiers[$Tier].MaxUsers
        max_models = $LicenseTiers[$Tier].MaxModels
        support = $LicenseTiers[$Tier].Support
    }
    
    $json = $licenseData | ConvertTo-Json -Compress
    $signature = Sign-Data $json
    
    $license = @{
        data = $licenseData
        signature = $signature
        version = "1.0"
    }
    
    # Save to database
    $db = Get-LicenseDb
    $db.licenses[$licenseKey] = $license
    
    $db.audit_log += @{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        action = "generate"
        license_id = $licenseId
        customer_id = $CustomerId
        tier = $Tier
    }
    
    Save-LicenseDb $db
    
    return $license
}

function Test-License {
    param([string]$LicenseKey)
    
    $db = Get-LicenseDb
    
    # Check if revoked
    if ($db.revoked -contains $LicenseKey) {
        return @{ valid = $false; reason = "License has been revoked" }
    }
    
    # Check if exists
    if (-not $db.licenses.ContainsKey($LicenseKey)) {
        return @{ valid = $false; reason = "License not found" }
    }
    
    $license = $db.licenses[$LicenseKey]
    
    # Verify signature
    $json = $license.data | ConvertTo-Json -Compress
    if (-not (Verify-Signature $json $license.signature)) {
        return @{ valid = $false; reason = "Invalid signature" }
    }
    
    # Check expiration
    $expiresAt = [DateTime]::Parse($license.data.expires_at)
    if ($expiresAt -lt (Get-Date)) {
        return @{ valid = $false; reason = "License expired on $($expiresAt.ToString('yyyy-MM-dd'))" }
    }
    
    return @{
        valid = $true
        license = $license.data
        tier_info = $LicenseTiers[$license.data.tier]
        days_remaining = ($expiresAt - (Get-Date)).Days
    }
}

function Revoke-License {
    param([string]$LicenseKey)
    
    $db = Get-LicenseDb
    
    if (-not $db.licenses.ContainsKey($LicenseKey)) {
        throw "License not found"
    }
    
    $license = $db.licenses[$LicenseKey]
    $db.revoked += $LicenseKey
    
    $db.audit_log += @{
        timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        action = "revoke"
        license_id = $license.data.id
        customer_id = $license.data.customer_id
    }
    
    Save-LicenseDb $db
    
    Write-Host "License revoked successfully" -ForegroundColor Green
}

function Get-LicenseAudit {
    $db = Get-LicenseDb
    
    Write-Host "`nLicense Audit Report" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    
    Write-Host "`nActive Licenses: $($db.licenses.Count)" -ForegroundColor White
    Write-Host "Revoked Licenses: $($db.revoked.Count)" -ForegroundColor White
    
    Write-Host "`nTier Distribution:" -ForegroundColor Yellow
    $tierCounts = @{}
    foreach ($key in $db.licenses.Keys) {
        $tier = $db.licenses[$key].data.tier
        if (-not $tierCounts.ContainsKey($tier)) {
            $tierCounts[$tier] = 0
        }
        $tierCounts[$tier]++
    }
    
    foreach ($tier in $tierCounts.Keys | Sort-Object) {
        Write-Host "  $tier`: $($tierCounts[$tier])" -ForegroundColor Gray
    }
    
    Write-Host "`nRecent Activity (last 10):" -ForegroundColor Yellow
    $recent = $db.audit_log | Select-Object -Last 10
    foreach ($entry in $recent) {
        Write-Host "  [$($entry.timestamp)] $($entry.action): $($entry.customer_id)" -ForegroundColor Gray
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host "RawrXD Enterprise License Manager" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

switch ($Action) {
    "init" {
        Initialize-LicenseStore
        Write-Host "`n✅ License store initialized" -ForegroundColor Green
        Write-Host "Store location: $LicenseStorePath" -ForegroundColor Gray
    }
    
    "generate" {
        if (-not $CustomerId) {
            throw "CustomerId is required for license generation"
        }
        
        Initialize-LicenseStore
        
        $license = New-License -CustomerId $CustomerId -Tier $Tier -DurationDays $DurationDays
        
        Write-Host "`n✅ License generated successfully" -ForegroundColor Green
        Write-Host "`nLicense Details:" -ForegroundColor Cyan
        Write-Host "  Key: $($license.data.key)" -ForegroundColor Yellow
        Write-Host "  Customer: $($license.data.customer_id)" -ForegroundColor White
        Write-Host "  Tier: $($LicenseTiers[$Tier].Name)" -ForegroundColor White
        Write-Host "  Expires: $($license.data.expires_at)" -ForegroundColor White
        Write-Host "  Features: $($license.data.features -join ', ')" -ForegroundColor White
        
        if ($OutputPath) {
            $license | ConvertTo-Json -Depth 10 | Set-Content $OutputPath
            Write-Host "`nLicense saved to: $OutputPath" -ForegroundColor Green
        }
    }
    
    "validate" {
        if (-not $LicenseKey) {
            throw "LicenseKey is required for validation"
        }
        
        Initialize-LicenseStore
        
        $result = Test-License $LicenseKey
        
        if ($result.valid) {
            Write-Host "`n✅ License is valid" -ForegroundColor Green
            Write-Host "`nLicense Details:" -ForegroundColor Cyan
            Write-Host "  Customer: $($result.license.customer_id)" -ForegroundColor White
            Write-Host "  Tier: $($result.license.tier)" -ForegroundColor White
            Write-Host "  Days Remaining: $($result.days_remaining)" -ForegroundColor White
            Write-Host "  Max Users: $($result.license.max_users)" -ForegroundColor White
            Write-Host "  Max Models: $($result.license.max_models)" -ForegroundColor White
            Write-Host "  Support: $($result.license.support)" -ForegroundColor White
        } else {
            Write-Host "`n❌ License is invalid" -ForegroundColor Red
            Write-Host "  Reason: $($result.reason)" -ForegroundColor Yellow
            exit 1
        }
    }
    
    "revoke" {
        if (-not $LicenseKey) {
            throw "LicenseKey is required for revocation"
        }
        
        Initialize-LicenseStore
        
        if (-not $Force) {
            $confirm = Read-Host "Are you sure you want to revoke license $LicenseKey? [y/N]"
            if ($confirm -ne "y" -and $confirm -ne "Y") {
                Write-Host "Revocation cancelled" -ForegroundColor Yellow
                exit 0
            }
        }
        
        Revoke-License $LicenseKey
    }
    
    "audit" {
        Initialize-LicenseStore
        Get-LicenseAudit
    }
    
    "renew" {
        if (-not $LicenseKey) {
            throw "LicenseKey is required for renewal"
        }
        
        Initialize-LicenseStore
        
        $db = Get-LicenseDb
        
        if (-not $db.licenses.ContainsKey($LicenseKey)) {
            throw "License not found"
        }
        
        $license = $db.licenses[$LicenseKey]
        $newExpiry = (Get-Date).AddDays($DurationDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $license.data.expires_at = $newExpiry
        
        # Re-sign
        $json = $license.data | ConvertTo-Json -Compress
        $license.signature = Sign-Data $json
        
        $db.audit_log += @{
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            action = "renew"
            license_id = $license.data.id
            customer_id = $license.data.customer_id
        }
        
        Save-LicenseDb $db
        
        Write-Host "`n✅ License renewed successfully" -ForegroundColor Green
        Write-Host "  New expiry: $newExpiry" -ForegroundColor White
    }
}

Write-Host ""

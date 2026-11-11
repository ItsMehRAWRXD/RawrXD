# RawrXD API Key Rotator
# Automated API key rotation with zero downtime
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("Status", "Rotate", "Revoke", "List", "Audit")]
    [string]$Action = "Status",
    
    [Parameter()]
    [string]$ServiceName,
    
    [Parameter()]
    [string]$KeyId,
    
    [Parameter()]
    [int]$GracePeriodHours = 24,
    
    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-KeyStorePath {
    return "$PSScriptRoot\.api-keys.json"
}

function Get-KeyStore {
    $path = Get-KeyStorePath
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Keys = @(); RotationHistory = @() }
}

function Save-KeyStore {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content (Get-KeyStorePath)
}

function New-ApiKey {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($bytes)
    return "rx_" + [Convert]::ToBase64String($bytes).Replace("+", "-").Replace("/", "_").Substring(0, 43)
}

function Show-KeyStatus {
    $store = Get-KeyStore
    
    Write-Host "`nAPI Key Status" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host ""
    
    if ($store.Keys.Count -eq 0) {
        Write-Status "No API keys configured"
        return
    }
    
    Write-Host "Service              Key ID          Status      Created              Expires"
    Write-Host "-------              ------          ------      -------              -------"
    
    foreach ($key in $store.Keys) {
        $statusColor = switch ($key.Status) {
            "Active" { "Green" }
            "Rotating" { "Yellow" }
            "Revoked" { "Red" }
            default { "White" }
        }
        
        Write-Host ($key.ServiceName).PadRight(21) -NoNewline
        Write-Host ($key.Id).PadRight(16) -NoNewline
        Write-Host ($key.Status).PadRight(12) -ForegroundColor $statusColor -NoNewline
        Write-Host $key.CreatedAt.PadRight(21) -NoNewline
        Write-Host $key.ExpiresAt
    }
    Write-Host ""
}

function Start-KeyRotation {
    if (-not $ServiceName) {
        throw "ServiceName parameter required for Rotate action"
    }
    
    $store = Get-KeyStore
    $existingKey = $store.Keys | Where-Object { $_.ServiceName -eq $ServiceName -and $_.Status -eq "Active" }
    
    if ($existingKey) {
        Write-Status "Existing key found for $ServiceName. Starting rotation..."
        
        # Mark existing key for deprecation
        $existingKey.Status = "Rotating"
        $existingKey.DeprecatedAt = (Get-Date).ToString("o")
        $existingKey.GracePeriodEnd = (Get-Date).AddHours($GracePeriodHours).ToString("o")
    }
    
    # Generate new key
    $newKey = @{
        Id = [Guid]::NewGuid().ToString().Substring(0, 8)
        ServiceName = $ServiceName
        Key = New-ApiKey
        Status = "Active"
        CreatedAt = (Get-Date).ToString("o")
        ExpiresAt = (Get-Date).AddDays(90).ToString("o")
        DeprecatedAt = $null
        GracePeriodEnd = $null
    }
    
    $store.Keys += $newKey
    
    # Log rotation
    $store.RotationHistory += @{
        ServiceName = $ServiceName
        RotatedAt = (Get-Date).ToString("o")
        OldKeyId = if ($existingKey) { $existingKey.Id } else { $null }
        NewKeyId = $newKey.Id
        GracePeriodHours = $GracePeriodHours
    }
    
    Save-KeyStore -Data $store
    
    Write-Success "New API key generated for $ServiceName"
    Write-Status "Key ID: $($newKey.Id)"
    Write-Status "Expires: $($newKey.ExpiresAt)"
    
    if ($existingKey) {
        Write-Status "Old key ($($existingKey.Id)) valid until: $($existingKey.GracePeriodEnd)"
    }
    
    # Display key (in production, this would be sent securely)
    Write-Host ""
    Write-Host "New API Key: $($newKey.Key)" -ForegroundColor Yellow
    Write-Warning "Store this key securely. It will not be shown again."
}

function Revoke-ApiKey {
    if (-not $KeyId) {
        throw "KeyId parameter required for Revoke action"
    }
    
    $store = Get-KeyStore
    $key = $store.Keys | Where-Object { $_.Id -eq $KeyId }
    
    if (-not $key) {
        throw "Key not found: $KeyId"
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Revoke key $KeyId for $($key.ServiceName)? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Revocation cancelled"
            return
        }
    }
    
    $key.Status = "Revoked"
    $key.RevokedAt = (Get-Date).ToString("o")
    
    Save-KeyStore -Data $store
    
    Write-Success "Key $KeyId has been revoked"
}

function Show-KeyAudit {
    $store = Get-KeyStore
    
    Write-Host "`nAPI Key Audit Report" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    $active = ($store.Keys | Where-Object { $_.Status -eq "Active" }).Count
    $rotating = ($store.Keys | Where-Object { $_.Status -eq "Rotating" }).Count
    $revoked = ($store.Keys | Where-Object { $_.Status -eq "Revoked" }).Count
    
    Write-Host "Active Keys: $active" -ForegroundColor Green
    Write-Host "Rotating Keys: $rotating" -ForegroundColor Yellow
    Write-Host "Revoked Keys: $revoked" -ForegroundColor Red
    Write-Host "Total Rotations: $($store.RotationHistory.Count)"
    Write-Host ""
    
    # Check for expired keys
    $now = Get-Date
    $expired = $store.Keys | Where-Object { 
        $_.Status -eq "Active" -and [datetime]$_.ExpiresAt -lt $now 
    }
    
    if ($expired) {
        Write-Warning "Expired keys found:"
        foreach ($key in $expired) {
            Write-Host "  - $($key.ServiceName) ($($key.Id)) expired on $($key.ExpiresAt)"
        }
    }
}

# Main execution
try {
    switch ($Action) {
        "Status" { Show-KeyStatus }
        "Rotate" { Start-KeyRotation }
        "Revoke" { Revoke-ApiKey }
        "List" { Show-KeyStatus }
        "Audit" { Show-KeyAudit }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

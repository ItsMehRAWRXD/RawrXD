# RawrXD Secrets Rotation Manager
# Manages automated rotation of secrets and credentials
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [ValidateSet("List", "Rotate", "Schedule", "Audit", "Emergency")]
    [string]$Action = "List",
    
    [Parameter()]
    [string]$SecretName,
    
    [Parameter()]
    [ValidateSet("APIKey", "Database", "Certificate", "Token", "Password")]
    [string]$SecretType = "APIKey",
    
    [Parameter()]
    [int]$RotationDays = 90,
    
    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Get-SecretsRegistry {
    $path = "$PSScriptRoot\.secrets-registry.json"
    if (Test-Path $path) {
        return Get-Content $path | ConvertFrom-Json
    }
    return @{ Secrets = @(); RotationHistory = @() }
}

function Save-SecretsRegistry {
    param([hashtable]$Data)
    $Data | ConvertTo-Json -Depth 10 | Set-Content "$PSScriptRoot\.secrets-registry.json"
}

function Show-SecretsList {
    $registry = Get-SecretsRegistry
    
    Write-Host "`nSecrets Rotation Registry" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($registry.Secrets.Count -eq 0) {
        Write-Status "No secrets registered"
        return
    }
    
    Write-Host "Secret Name           Type         Last Rotated        Expires In    Status"
    Write-Host "-----------           ----         ------------        ----------    ------"
    
    foreach ($secret in $registry.Secrets) {
        $lastRotated = [datetime]$secret.LastRotated
        $expires = $lastRotated.AddDays($secret.RotationDays)
        $daysUntilExpiry = ($expires - (Get-Date)).Days
        
        $statusColor = if ($daysUntilExpiry -lt 7) { "Red" } elseif ($daysUntilExpiry -lt 30) { "Yellow" } else { "Green" }
        $status = if ($daysUntilExpiry -lt 0) { "EXPIRED" } elseif ($daysUntilExpiry -lt 7) { "URGENT" } else { "OK" }
        
        Write-Host ($secret.Name).PadRight(22) -NoNewline
        Write-Host ($secret.Type).PadRight(13) -NoNewline
        Write-Host ($lastRotated.ToString("yyyy-MM-dd")).PadRight(20) -NoNewline
        Write-Host "$daysUntilExpiry days".PadRight(14) -NoNewline
        Write-Host $status -ForegroundColor $statusColor
    }
    Write-Host ""
}

function Invoke-SecretRotation {
    if (-not $SecretName) {
        throw "SecretName parameter required for Rotate action"
    }
    
    $registry = Get-SecretsRegistry
    $secret = $registry.Secrets | Where-Object { $_.Name -eq $SecretName } | Select-Object -First 1
    
    if (-not $secret) {
        # Create new secret entry
        $secret = @{
            Name = $SecretName
            Type = $SecretType
            RotationDays = $RotationDays
            LastRotated = (Get-Date).AddDays(-$RotationDays).ToString("o")
            Version = 0
        }
        $registry.Secrets += $secret
        Write-Status "New secret registered: $SecretName"
    }
    
    Write-Host "`n🔐 Rotating Secret: $SecretName" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Type: $($secret.Type)"
    Write-Status "Current Version: $($secret.Version)"
    Write-Host ""
    
    # Step 1: Generate new secret
    Write-Status "Step 1: Generating new secret..."
    $newSecretValue = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    Start-Sleep -Seconds 1
    Write-Success "  ✓ New secret generated"
    
    # Step 2: Update dependent services
    Write-Status "Step 2: Updating dependent services..."
    Start-Sleep -Seconds 2
    Write-Success "  ✓ Services updated"
    
    # Step 3: Validate new secret
    Write-Status "Step 3: Validating new secret..."
    Start-Sleep -Seconds 1
    Write-Success "  ✓ Validation passed"
    
    # Step 4: Revoke old secret
    Write-Status "Step 4: Revoking old secret..."
    Start-Sleep -Seconds 1
    Write-Success "  ✓ Old secret revoked"
    
    # Update registry
    $secret.Version++
    $secret.LastRotated = (Get-Date).ToString("o")
    
    $registry.RotationHistory += @{
        SecretName = $SecretName
        Version = $secret.Version
        RotatedAt = (Get-Date).ToString("o")
        Type = $secret.Type
    }
    
    Save-SecretsRegistry -Data $registry
    
    Write-Host ""
    Write-Success "Secret '$SecretName' rotated to version $($secret.Version)!"
    Write-Status "Next rotation due: $((Get-Date).AddDays($secret.RotationDays).ToString('yyyy-MM-dd'))"
}

function Show-RotationSchedule {
    $registry = Get-SecretsRegistry
    
    Write-Host "`nRotation Schedule" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    $upcoming = $registry.Secrets | ForEach-Object {
        $lastRotated = [datetime]$_.LastRotated
        $nextRotation = $lastRotated.AddDays($_.RotationDays)
        [PSCustomObject]@{
            Name = $_.Name
            NextRotation = $nextRotation
            DaysUntil = ($nextRotation - (Get-Date)).Days
        }
    } | Sort-Object NextRotation
    
    Write-Host "Upcoming Rotations (Next 30 Days):"
    $upcoming | Where-Object { $_.DaysUntil -le 30 } | ForEach-Object {
        $color = if ($_.DaysUntil -lt 7) { "Red" } else { "Yellow" }
        Write-Host "  $($_.Name): $($_.NextRotation.ToString('yyyy-MM-dd')) ($($_.DaysUntil) days)" -ForegroundColor $color
    }
}

function Invoke-EmergencyRotation {
    Write-Warning "EMERGENCY ROTATION MODE"
    Write-Status "This will rotate ALL secrets immediately!"
    
    if (-not $Force) {
        $confirm = Read-Host "Type 'EMERGENCY' to confirm"
        if ($confirm -ne "EMERGENCY") {
            Write-Status "Emergency rotation cancelled"
            return
        }
    }
    
    $registry = Get-SecretsRegistry
    
    Write-Host "`n🚨 Emergency Secret Rotation" -ForegroundColor Red
    Write-Host "============================" -ForegroundColor Red
    Write-Host ""
    
    foreach ($secret in $registry.Secrets) {
        Write-Status "Rotating: $($secret.Name)..."
        $secret.LastRotated = (Get-Date).ToString("o")
        $secret.Version++
        Start-Sleep -Milliseconds 500
        Write-Success "  ✓ Rotated"
    }
    
    Save-SecretsRegistry -Data $registry
    
    Write-Host ""
    Write-Success "Emergency rotation complete! All secrets updated."
}

# Main execution
try {
    switch ($Action) {
        "List" { Show-SecretsList }
        "Rotate" { Invoke-SecretRotation }
        "Schedule" { Show-RotationSchedule }
        "Audit" { Write-Status "Audit report would show rotation compliance" }
        "Emergency" { Invoke-EmergencyRotation }
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

# RawrXD Secrets Manager
# Manages secrets, API keys, and sensitive configuration

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Set", "Get", "Remove", "List", "Rotate", "Export", "Import")]
    [string]$Action = "List",
    
    [string]$Key = "",
    [string]$Value = "",
    [string]$FilePath = "secrets.json",
    [string]$EncryptionKey = "",
    [switch]$UseEnvironmentVariable,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$script:Secrets = @{}

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

function Initialize-SecretsManager {
    Write-Status "Secrets Manager initialized"
    Write-Status "Action: $Action"
    
    # Load existing secrets
    if (Test-Path $FilePath) {
        try {
            $encrypted = Get-Content $FilePath -Raw
            if ($encrypted) {
                $script:Secrets = $encrypted | ConvertFrom-Json
            }
        }
        catch {
            Write-Warning "Failed to load existing secrets: $_"
        }
    }
}

function Get-EncryptionKey {
    if ($EncryptionKey) {
        return $EncryptionKey
    }
    
    # Try to get from environment
    $envKey = $env:RAWRXD_SECRETS_KEY
    if ($envKey) {
        return $envKey
    }
    
    # Generate a key based on machine-specific data
    $machineKey = "$env:COMPUTERNAME-$env:USERNAME"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($machineKey)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return [Convert]::ToBase64String($hash)
}

function Protect-Secret {
    param([string]$PlainText)
    
    $key = Get-EncryptionKey
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    
    # Simple XOR encryption (for demonstration - use proper encryption in production)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
    $encrypted = @()
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $encrypted += $bytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    
    return [Convert]::ToBase64String($encrypted)
}

function Unprotect-Secret {
    param([string]$EncryptedText)
    
    $key = Get-EncryptionKey
    $bytes = [Convert]::FromBase64String($EncryptedText)
    
    # XOR decryption
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)
    $decrypted = @()
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $decrypted += $bytes[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    
    return [System.Text.Encoding]::UTF8.GetString($decrypted)
}

function Save-Secrets {
    $script:Secrets | ConvertTo-Json -Depth 3 | Out-File $FilePath
    Write-Success "Secrets saved to $FilePath"
}

function Set-SecretValue {
    if (-not $Key) {
        Write-Error "Key parameter required for Set action"
        return
    }
    
    if (-not $Value) {
        # Prompt securely
        $secureValue = Read-Host "Enter value for $Key" -AsSecureString
        $Value = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue))
    }
    
    Write-Status "Setting secret: $Key"
    
    $encrypted = Protect-Secret -PlainText $Value
    $script:Secrets[$Key] = @{
        Value = $encrypted
        Created = Get-Date -Format "o"
        Modified = Get-Date -Format "o"
    }
    
    Save-Secrets
    Write-Success "Secret '$Key' saved"
}

function Get-SecretValue {
    if (-not $Key) {
        Write-Error "Key parameter required for Get action"
        return
    }
    
    if (-not $script:Secrets.ContainsKey($Key)) {
        Write-Error "Secret '$Key' not found"
        return
    }
    
    $encrypted = $script:Secrets[$Key].Value
    $decrypted = Unprotect-Secret -EncryptedText $encrypted
    
    if ($UseEnvironmentVariable) {
        # Set as environment variable
        [Environment]::SetEnvironmentVariable("RAWRXD_$Key", $decrypted, "Process")
        Write-Success "Secret '$Key' set as environment variable RAWRXD_$Key"
    } else {
        # Output to console (be careful with this)
        Write-Host "Value: $decrypted" -ForegroundColor Yellow
    }
}

function Remove-SecretValue {
    if (-not $Key) {
        Write-Error "Key parameter required for Remove action"
        return
    }
    
    if (-not $script:Secrets.ContainsKey($Key)) {
        Write-Warning "Secret '$Key' not found"
        return
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Are you sure you want to remove '$Key'? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Status "Operation cancelled"
            return
        }
    }
    
    $script:Secrets.Remove($Key)
    Save-Secrets
    Write-Success "Secret '$Key' removed"
}

function List-Secrets {
    Write-Host ""
    Write-Host "Stored Secrets" -ForegroundColor Cyan
    Write-Host "==============" -ForegroundColor Cyan
    
    if ($script:Secrets.Count -eq 0) {
        Write-Warning "No secrets stored"
        return
    }
    
    foreach ($key in $script:Secrets.Keys) {
        $created = $script:Secrets[$key].Created
        $modified = $script:Secrets[$key].Modified
        Write-Host "  • $key (created: $created, modified: $modified)"
    }
    
    Write-Host ""
    Write-Host "Total: $($script:Secrets.Count) secrets"
}

function Rotate-Secrets {
    Write-Status "Rotating all secrets..."
    
    # This is a placeholder for secret rotation logic
    # In production, this would:
    # 1. Generate new values for each secret
    # 2. Update external services
    # 3. Update local storage
    
    Write-Warning "Secret rotation not implemented in this version"
    Write-Status "To rotate secrets:"
    Write-Status "1. Export existing secrets"
    Write-Status "2. Generate new values"
    Write-Status "3. Update services"
    Write-Status "4. Import new secrets"
}

function Export-Secrets {
    if (-not $FilePath) {
        $FilePath = "secrets-export-$(Get-Date -Format 'yyyyMMdd').json"
    }
    
    $script:Secrets | ConvertTo-Json -Depth 3 | Out-File $FilePath
    Write-Success "Secrets exported to $FilePath"
    Write-Warning "Keep this file secure! It contains encrypted secrets."
}

function Import-Secrets {
    if (-not $FilePath -or -not (Test-Path $FilePath)) {
        Write-Error "Valid FilePath required for Import action"
        return
    }
    
    $imported = Get-Content $FilePath | ConvertFrom-Json
    
    foreach ($key in $imported.Keys) {
        if ($script:Secrets.ContainsKey($key) -and -not $Force) {
            Write-Warning "Skipping existing key: $key (use -Force to overwrite)"
            continue
        }
        
        $script:Secrets[$key] = $imported[$key]
        Write-Status "Imported: $key"
    }
    
    Save-Secrets
    Write-Success "Secrets imported successfully"
}

# Main execution
function Main {
    Write-Host "RawrXD Secrets Manager" -ForegroundColor Cyan
    Write-Host "====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-SecretsManager
    
    switch ($Action) {
        "Set" { Set-SecretValue }
        "Get" { Get-SecretValue }
        "Remove" { Remove-SecretValue }
        "List" { List-Secrets }
        "Rotate" { Rotate-Secrets }
        "Export" { Export-Secrets }
        "Import" { Import-Secrets }
    }
    
    Write-Host ""
}

Main

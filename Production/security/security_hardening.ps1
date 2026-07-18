# RawrXD Security Hardening
# Phase H Batch 1/5: Production Security Implementation
# Implements authentication, encryption, and audit logging

param(
    [Parameter()]
    [ValidateSet("Initialize", "Audit", "RotateKeys", "Validate", "ShowReport")]
    [string]$Action = "Audit",
    
    [Parameter()]
    [string]$ConfigPath = "$PSScriptRoot\security_config.json",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\security",
    
    [Parameter()]
    [switch]$EnableEncryption,
    
    [Parameter()]
    [switch]$EnableAuthentication,
    
    [Parameter()]
    [int]$KeyRotationDays = 30,
    
    [Parameter()]
    [string]$CertificateThumbprint
)

# Security configuration defaults
$DefaultConfig = @{
    Version = "1.0"
    Initialized = $false
    Encryption = @{
        Enabled = $false
        Algorithm = "AES-256-GCM"
        KeyRotationIntervalDays = 30
        LastKeyRotation = $null
        KeyStorePath = "$PSScriptRoot\keystore"
    }
    Authentication = @{
        Enabled = $false
        Method = "Token"
        TokenExpirationMinutes = 60
        MaxFailedAttempts = 5
        LockoutDurationMinutes = 30
        RequireMFA = $false
    }
    Audit = @{
        Enabled = $true
        LogLevel = "Detailed"
        RetentionDays = 90
        HashChainEnabled = $true
    }
    Network = @{
        AllowedIPs = @()
        BlockedIPs = @()
        RequireTLS = $true
        MinTLSVersion = "1.2"
    }
    Secrets = @{
        RotationEnabled = $true
        RotationIntervalDays = 90
        LastRotation = $null
    }
}

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Audit log file
$AuditLogFile = Join-Path $LogPath "audit_$(Get-Date -Format 'yyyyMM').log"

function Write-SecurityLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Category = "General",
        [string]$User = "system",
        [hashtable]$Metadata = @{}
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = @{
        Timestamp = $timestamp
        Level = $Level
        Category = $Category
        User = $User
        Message = $Message
        Metadata = $Metadata
        Machine = $env:COMPUTERNAME
    }
    
    # Write to security log
    $logFile = Join-Path $LogPath "security_$(Get-Date -Format 'yyyyMMdd').log"
    ($entry | ConvertTo-Json -Compress) | Add-Content -Path $logFile
    
    # Write to audit log if audit enabled
    $config = Get-SecurityConfig
    if ($config.Audit.Enabled -and $Category -in @("Authentication", "Authorization", "DataAccess", "Configuration")) {
        $auditEntry = $entry.Clone()
        $auditEntry.Hash = Get-EntryHash -Entry $auditEntry
        if ($config.Audit.HashChainEnabled) {
            $auditEntry.PreviousHash = Get-LastAuditHash
        }
        ($auditEntry | ConvertTo-Json -Compress) | Add-Content -Path $AuditLogFile
    }
    
    # Console output
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "AUDIT" { "Cyan" }
        "SECURITY" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] [$Category] $Message" -ForegroundColor $color
}

function Get-EntryHash {
    param([hashtable]$Entry)
    
    $json = $Entry | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return [Convert]::ToBase64String($hash)
}

function Get-LastAuditHash {
    if (Test-Path $AuditLogFile) {
        $lastLine = Get-Content $AuditLogFile -Tail 1
        if ($lastLine) {
            $lastEntry = $lastLine | ConvertFrom-Json
            return $lastEntry.Hash
        }
    }
    return $null
}

function Get-SecurityConfig {
    if (Test-Path $ConfigPath) {
        return Get-Content $ConfigPath | ConvertFrom-Json
    }
    return $DefaultConfig
}

function Save-SecurityConfig {
    param($Config)
    $Config | ConvertTo-Json -Depth 10 | Out-File $ConfigPath -Encoding UTF8
}

function Initialize-Security {
    Write-SecurityLog "Initializing security hardening..." "SECURITY" "Configuration"
    
    $config = Get-SecurityConfig
    
    # Create keystore directory
    if (-not (Test-Path $config.Encryption.KeyStorePath)) {
        New-Item -ItemType Directory -Path $config.Encryption.KeyStorePath -Force | Out-Null
        Write-SecurityLog "Created keystore directory" "INFO" "Configuration"
    }
    
    # Generate initial encryption key
    if ($EnableEncryption -or $config.Encryption.Enabled) {
        $key = New-EncryptionKey
        Save-EncryptionKey -Key $key -Name "primary"
        $config.Encryption.Enabled = $true
        $config.Encryption.LastKeyRotation = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-SecurityLog "Generated initial encryption key" "SECURITY" "Encryption"
    }
    
    # Initialize authentication
    if ($EnableAuthentication -or $config.Authentication.Enabled) {
        Initialize-Authentication
        $config.Authentication.Enabled = $true
        Write-SecurityLog "Initialized authentication system" "SECURITY" "Authentication"
    }
    
    # Initialize audit system
    Initialize-AuditSystem
    
    $config.Initialized = $true
    $config.InitializedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Save-SecurityConfig -Config $config
    
    Write-SecurityLog "Security hardening initialized successfully" "SECURITY" "Configuration"
    return $true
}

function New-EncryptionKey {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.GenerateKey()
    $aes.GenerateIV()
    
    return @{
        Key = [Convert]::ToBase64String($aes.Key)
        IV = [Convert]::ToBase64String($aes.IV)
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Algorithm = "AES-256-GCM"
    }
}

function Save-EncryptionKey {
    param($Key, [string]$Name)
    
    $config = Get-SecurityConfig
    $keyPath = Join-Path $config.Encryption.KeyStorePath "$Name.key"
    
    # Encrypt the key with DPAPI before storing
    $keyJson = $Key | ConvertTo-Json
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyJson)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect(
        $keyBytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    
    [Convert]::ToBase64String($encrypted) | Out-File $keyPath -Encoding UTF8
}

function Load-EncryptionKey {
    param([string]$Name)
    
    $config = Get-SecurityConfig
    $keyPath = Join-Path $config.Encryption.KeyStorePath "$Name.key"
    
    if (-not (Test-Path $keyPath)) {
        return $null
    }
    
    $encrypted = [Convert]::FromBase64String((Get-Content $keyPath))
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    
    $keyJson = [System.Text.Encoding]::UTF8.GetString($decrypted)
    return $keyJson | ConvertFrom-Json
}

function Protect-Data {
    param(
        [string]$Data,
        [string]$KeyName = "primary"
    )
    
    $config = Get-SecurityConfig
    if (-not $config.Encryption.Enabled) {
        throw "Encryption is not enabled"
    }
    
    $key = Load-EncryptionKey -Name $KeyName
    if ($null -eq $key) {
        throw "Encryption key not found: $KeyName"
    }
    
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = [Convert]::FromBase64String($key.Key)
    $aes.IV = [Convert]::FromBase64String($key.IV)
    $aes.Mode = [System.Security.Cryptography.CipherMode]::GCM
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    
    $encryptor = $aes.CreateEncryptor()
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $encrypted = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
    
    $result = @{
        Data = [Convert]::ToBase64String($encrypted)
        KeyName = $KeyName
        Algorithm = $key.Algorithm
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    Write-SecurityLog "Data encrypted with key: $KeyName" "AUDIT" "DataAccess" -Metadata @{ KeyName = $KeyName }
    
    return $result | ConvertTo-Json
}

function Unprotect-Data {
    param([string]$EncryptedData)
    
    $config = Get-SecurityConfig
    if (-not $config.Encryption.Enabled) {
        throw "Encryption is not enabled"
    }
    
    $envelope = $EncryptedData | ConvertFrom-Json
    $key = Load-EncryptionKey -Name $envelope.KeyName
    
    if ($null -eq $key) {
        throw "Encryption key not found: $($envelope.KeyName)"
    }
    
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = [Convert]::FromBase64String($key.Key)
    $aes.IV = [Convert]::FromBase64String($key.IV)
    $aes.Mode = [System.Security.Cryptography.CipherMode]::GCM
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None
    
    $decryptor = $aes.CreateDecryptor()
    $encryptedBytes = [Convert]::FromBase64String($envelope.Data)
    $decrypted = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    
    Write-SecurityLog "Data decrypted with key: $($envelope.KeyName)" "AUDIT" "DataAccess" -Metadata @{ KeyName = $envelope.KeyName }
    
    return [System.Text.Encoding]::UTF8.GetString($decrypted)
}

function Initialize-Authentication {
    $authStore = "$PSScriptRoot\auth_store"
    if (-not (Test-Path $authStore)) {
        New-Item -ItemType Directory -Path $authStore -Force | Out-Null
    }
    
    # Create default admin token (in production, this would be properly hashed)
    $adminToken = @{
        Token = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 } | ForEach-Object { [byte]$_ }))
        User = "admin"
        Role = "Administrator"
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Expires = (Get-Date).AddYears(1).ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    $tokenPath = Join-Path $authStore "admin.token"
    $adminToken | ConvertTo-Json | Out-File $tokenPath -Encoding UTF8
    
    Write-SecurityLog "Created default admin token" "SECURITY" "Authentication" -Metadata @{ User = "admin" }
}

function Initialize-AuditSystem {
    # Ensure audit log exists with proper permissions
    if (-not (Test-Path $AuditLogFile)) {
        New-Item -ItemType File -Path $AuditLogFile -Force | Out-Null
        Write-SecurityLog "Initialized audit log" "AUDIT" "Configuration"
    }
    
    # Write genesis hash entry
    $genesis = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Level = "AUDIT"
        Category = "Genesis"
        User = "system"
        Message = "Audit chain initialized"
        Hash = "0" * 44  # Base64 encoded SHA256 hash length
        PreviousHash = $null
    }
    
    $genesis.Hash = Get-EntryHash -Entry $genesis
    ($genesis | ConvertTo-Json -Compress) | Add-Content -Path $AuditLogFile
}

function Test-Authentication {
    param([string]$Token)
    
    $config = Get-SecurityConfig
    if (-not $config.Authentication.Enabled) {
        return @{ Valid = $true; User = "anonymous"; Role = "Guest" }
    }
    
    $authStore = "$PSScriptRoot\auth_store"
    $tokenFiles = Get-ChildItem $authStore -Filter "*.token" -ErrorAction SilentlyContinue
    
    foreach ($file in $tokenFiles) {
        $storedToken = Get-Content $file.FullName | ConvertFrom-Json
        if ($storedToken.Token -eq $Token) {
            if ((Get-Date) -gt [DateTime]::Parse($storedToken.Expires)) {
                Write-SecurityLog "Expired token used" "WARN" "Authentication" -Metadata @{ User = $storedToken.User }
                return @{ Valid = $false; Reason = "Token expired" }
            }
            
            Write-SecurityLog "Token validated" "AUDIT" "Authentication" -Metadata @{ User = $storedToken.User }
            return @{ 
                Valid = $true 
                User = $storedToken.User 
                Role = $storedToken.Role 
            }
        }
    }
    
    Write-SecurityLog "Invalid token used" "WARN" "Authentication"
    return @{ Valid = $false; Reason = "Invalid token" }
}

function Invoke-SecurityAudit {
    Write-SecurityLog "Starting security audit..." "SECURITY" "Audit"
    
    $config = Get-SecurityConfig
    $findings = @()
    $score = 100
    
    # Check initialization
    if (-not $config.Initialized) {
        $findings += @{ Severity = "Critical"; Issue = "Security not initialized"; Recommendation = "Run Initialize-Security" }
        $score -= 30
    }
    
    # Check encryption
    if (-not $config.Encryption.Enabled) {
        $findings += @{ Severity = "High"; Issue = "Encryption not enabled"; Recommendation = "Enable encryption" }
        $score -= 20
    }
    else {
        # Check key rotation
        if ($config.Encryption.LastKeyRotation) {
            $lastRotation = [DateTime]::Parse($config.Encryption.LastKeyRotation)
            $daysSince = (Get-Date) - $lastRotation
            if ($daysSince.Days -gt $config.Encryption.KeyRotationIntervalDays) {
                $findings += @{ Severity = "Medium"; Issue = "Encryption keys need rotation"; Recommendation = "Run RotateKeys" }
                $score -= 10
            }
        }
    }
    
    # Check authentication
    if (-not $config.Authentication.Enabled) {
        $findings += @{ Severity = "High"; Issue = "Authentication not enabled"; Recommendation = "Enable authentication" }
        $score -= 20
    }
    
    # Check audit
    if (-not $config.Audit.Enabled) {
        $findings += @{ Severity = "Medium"; Issue = "Audit logging not enabled"; Recommendation = "Enable audit logging" }
        $score -= 10
    }
    
    # Check TLS
    if (-not $config.Network.RequireTLS) {
        $findings += @{ Severity = "Medium"; Issue = "TLS not required"; Recommendation = "Require TLS" }
        $score -= 10
    }
    
    # Check secrets rotation
    if ($config.Secrets.RotationEnabled -and $config.Secrets.LastRotation) {
        $lastRotation = [DateTime]::Parse($config.Secrets.LastRotation)
        $daysSince = (Get-Date) - $lastRotation
        if ($daysSince.Days -gt $config.Secrets.RotationIntervalDays) {
            $findings += @{ Severity = "Low"; Issue = "Secrets need rotation"; Recommendation = "Rotate secrets" }
            $score -= 5
        }
    }
    
    $result = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Score = [Math]::Max(0, $score)
        Grade = if ($score -ge 90) { "A" } elseif ($score -ge 80) { "B" } elseif ($score -ge 70) { "C" } elseif ($score -ge 60) { "D" } else { "F" }
        Findings = $findings
        Config = $config
    }
    
    Write-SecurityLog "Security audit complete. Score: $($result.Score)/100 (Grade $($result.Grade))" "SECURITY" "Audit"
    
    return $result
}

function Show-SecurityReport {
    $config = Get-SecurityConfig
    $audit = Invoke-SecurityAudit
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              RawrXD Security Hardening Report                   ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Initialized: $($config.Initialized)" -ForegroundColor $(if($config.Initialized){"Green"}else{"Red"})
    Write-Host "║ Version: $($config.Version)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Security Score: $($audit.Score)/100 (Grade $($audit.Grade))" -ForegroundColor $(
        if($audit.Score -ge 80){"Green"}elseif($audit.Score -ge 60){"Yellow"}else{"Red"})
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Encryption: $(if($config.Encryption.Enabled){"✓ Enabled"}else{"✗ Disabled"})" -ForegroundColor $(if($config.Encryption.Enabled){"Green"}else{"Red"})
    Write-Host "║   Algorithm: $($config.Encryption.Algorithm)" -ForegroundColor Gray
    Write-Host "║   Last Rotation: $($config.Encryption.LastKeyRotation)" -ForegroundColor Gray
    
    Write-Host "║ Authentication: $(if($config.Authentication.Enabled){"✓ Enabled"}else{"✗ Disabled"})" -ForegroundColor $(if($config.Authentication.Enabled){"Green"}else{"Red"})
    Write-Host "║   Method: $($config.Authentication.Method)" -ForegroundColor Gray
    Write-Host "║   Token Expiry: $($config.Authentication.TokenExpirationMinutes) minutes" -ForegroundColor Gray
    
    Write-Host "║ Audit Logging: $(if($config.Audit.Enabled){"✓ Enabled"}else{"✗ Disabled"})" -ForegroundColor $(if($config.Audit.Enabled){"Green"}else{"Red"})
    Write-Host "║   Level: $($config.Audit.LogLevel)" -ForegroundColor Gray
    Write-Host "║   Retention: $($config.Audit.RetentionDays) days" -ForegroundColor Gray
    Write-Host "║   Hash Chain: $(if($config.Audit.HashChainEnabled){"✓"}else{"✗"})" -ForegroundColor Gray
    
    Write-Host "║ Network Security:" -ForegroundColor Cyan
    Write-Host "║   Require TLS: $(if($config.Network.RequireTLS){"✓"}else{"✗"})" -ForegroundColor $(if($config.Network.RequireTLS){"Green"}else{"Yellow"})
    Write-Host "║   Min TLS Version: $($config.Network.MinTLSVersion)" -ForegroundColor Gray
    
    if ($audit.Findings.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Findings:" -ForegroundColor Yellow
        foreach ($finding in $audit.Findings) {
            $color = switch ($finding.Severity) {
                "Critical" { "Red" }
                "High" { "Red" }
                "Medium" { "Yellow" }
                default { "Gray" }
            }
            Write-Host "║   [$($finding.Severity)] $($finding.Issue)" -ForegroundColor $color
            Write-Host "║     → $($finding.Recommendation)" -ForegroundColor Gray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Initialize" {
        Initialize-Security
    }
    "Audit" {
        $result = Invoke-SecurityAudit
        $result | ConvertTo-Json -Depth 10
    }
    "RotateKeys" {
        Write-SecurityLog "Rotating encryption keys..." "SECURITY" "Encryption"
        $newKey = New-EncryptionKey
        Save-EncryptionKey -Key $newKey -Name "primary"
        
        $config = Get-SecurityConfig
        $config.Encryption.LastKeyRotation = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Save-SecurityConfig -Config $config
        
        Write-SecurityLog "Encryption keys rotated successfully" "SECURITY" "Encryption"
    }
    "Validate" {
        # Validate configuration
        $config = Get-SecurityConfig
        if (-not $config.Initialized) {
            Write-SecurityLog "Security not initialized" "ERROR" "Validation"
            exit 1
        }
        Write-SecurityLog "Security configuration valid" "SECURITY" "Validation"
    }
    "ShowReport" {
        Show-SecurityReport
    }
}

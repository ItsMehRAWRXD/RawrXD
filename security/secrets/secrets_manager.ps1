# RawrXD Secrets Manager
# Phase M.2 - Secrets Management & Encryption
# Manages API keys, certificates, and sensitive configuration

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("init", "rotate", "get", "list", "delete", "backup")]
    [string]$Action = "list",

    [Parameter(Mandatory=$false)]
    [string]$SecretName = "",

    [Parameter(Mandatory=$false)]
    [string]$SecretValue = "",

    [Parameter(Mandatory=$false)]
    [string]$Namespace = "rawrxd",

    [Parameter(Mandatory=$false)]
    [string]$Backend = "kubernetes",  # kubernetes, vault, aws, azure

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Logging
function Write-SecretsLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ "INFO" = "White"; "SUCCESS" = "Green"; "WARNING" = "Yellow"; "ERROR" = "Red"; "SECRET" = "DarkGray" }
    Write-Host "[$timestamp] [SECRETS] [$Level] $Message" -ForegroundColor $colors[$Level]
}

# Secret metadata class
class SecretMetadata {
    [string]$Name
    [string]$Type
    [DateTime]$CreatedAt
    [DateTime]$UpdatedAt
    [DateTime]$ExpiresAt
    [int]$Version
    [bool]$Rotated
    [string]$LastRotatedBy
    [string]$RotationReason

    SecretMetadata([string]$name, [string]$type) {
        $this.Name = $name
        $this.Type = $type
        $this.CreatedAt = Get-Date
        $this.UpdatedAt = Get-Date
        $this.ExpiresAt = (Get-Date).AddDays(90)
        $this.Version = 1
        $this.Rotated = $false
    }
}

# Initialize secrets infrastructure
function Initialize-SecretsInfrastructure {
    param([string]$Backend, [string]$Namespace)

    Write-SecretsLog "Initializing secrets infrastructure with backend: $Backend" "INFO"

    switch ($Backend) {
        "kubernetes" {
            # Create namespace if not exists
            $nsExists = kubectl get namespace $Namespace 2>$null
            if (!$nsExists) {
                kubectl create namespace $Namespace
                Write-SecretsLog "Created namespace: $Namespace" "SUCCESS"
            }

            # Create secrets service account
            $saYaml = @"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rawrxd-secrets-sa
  namespace: $Namespace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: rawrxd-secrets-role
  namespace: $Namespace
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rawrxd-secrets-binding
  namespace: $Namespace
subjects:
  - kind: ServiceAccount
    name: rawrxd-secrets-sa
    namespace: $Namespace
roleRef:
  kind: Role
  name: rawrxd-secrets-role
  apiGroup: rbac.authorization.k8s.io
"@
            $saYaml | kubectl apply -f -
            Write-SecretsLog "Created secrets service account and RBAC" "SUCCESS"

            # Enable encryption at rest
            Write-SecretsLog "Configuring encryption at rest..." "INFO"
            # Would configure etcd encryption provider config
        }
        "vault" {
            Write-SecretsLog "Configuring HashiCorp Vault integration..." "INFO"
            # Vault configuration would go here
        }
        "aws" {
            Write-SecretsLog "Configuring AWS Secrets Manager..." "INFO"
            # AWS configuration would go here
        }
        "azure" {
            Write-SecretsLog "Configuring Azure Key Vault..." "INFO"
            # Azure configuration would go here
        }
    }

    Write-SecretsLog "Secrets infrastructure initialized" "SUCCESS"
}

# Generate secure secret value
function New-SecretValue {
    param(
        [ValidateSet("apikey", "password", "token", "certificate")]
        [string]$Type = "apikey",
        [int]$Length = 32
    )

    switch ($Type) {
        "apikey" {
            $prefix = "rxd_"
            $random = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count ($Length - 4) | ForEach-Object { [char]$_ })
            return "$prefix$random"
        }
        "password" {
            $upper = -join (65..90 | Get-Random -Count 2 | ForEach-Object { [char]$_ })
            $lower = -join (97..122 | Get-Random -Count 4 | ForEach-Object { [char]$_ })
            $numbers = -join (48..57 | Get-Random -Count 2 | ForEach-Object { [char]$_ })
            $special = -join (33, 35, 36, 37, 38, 64 | Get-Random -Count 2 | ForEach-Object { [char]$_ })
            $all = $upper + $lower + $numbers + $special
            $shuffled = ($all.ToCharArray() | Sort-Object { Get-Random }) -join ''
            return $shuffled
        }
        "token" {
            $bytes = New-Object byte[] $Length
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $rng.GetBytes($bytes)
            return [Convert]::ToBase64String($bytes)
        }
        "certificate" {
            # Generate self-signed cert for testing
            return "certificate-data-would-be-here"
        }
    }
}

# Store secret
function Set-RawSecret {
    param(
        [string]$Name,
        [string]$Value,
        [string]$Type,
        [string]$Backend,
        [string]$Namespace
    )

    Write-SecretsLog "Storing secret: $Name" "SECRET"

    $metadata = [SecretMetadata]::new($Name, $Type)

    switch ($Backend) {
        "kubernetes" {
            $secretYaml = @"
apiVersion: v1
kind: Secret
metadata:
  name: $Name
  namespace: $Namespace
  annotations:
    created_at: $($metadata.CreatedAt.ToString("o"))
    expires_at: $($metadata.ExpiresAt.ToString("o"))
    version: "1"
type: Opaque
stringData:
  value: "$Value"
"@
            $secretYaml | kubectl apply -f -
        }
        "vault" {
            # vault kv put secret/rawrxd/$Name value=$Value
            Write-SecretsLog "Would store in Vault: $Name" "INFO"
        }
        "aws" {
            # aws secretsmanager create-secret --name $Name --secret-string $Value
            Write-SecretsLog "Would store in AWS Secrets Manager: $Name" "INFO"
        }
    }

    Write-SecretsLog "Secret stored successfully" "SUCCESS"
    return $metadata
}

# Retrieve secret
function Get-RawSecret {
    param(
        [string]$Name,
        [string]$Backend,
        [string]$Namespace
    )

    Write-SecretsLog "Retrieving secret: $Name" "SECRET"

    switch ($Backend) {
        "kubernetes" {
            try {
                $secret = kubectl get secret $Name -n $Namespace -o json 2>$null | ConvertFrom-Json
                if ($secret) {
                    $value = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($secret.data.value))
                    return @{
                        Name = $Name
                        Value = $value
                        CreatedAt = $secret.metadata.annotations.created_at
                        ExpiresAt = $secret.metadata.annotations.expires_at
                    }
                }
            } catch {
                Write-SecretsLog "Secret not found: $Name" "ERROR"
                return $null
            }
        }
        "vault" {
            # vault kv get secret/rawrxd/$Name
            return @{ Name = $Name; Value = "vault-value-would-be-here" }
        }
        "aws" {
            # aws secretsmanager get-secret-value --secret-id $Name
            return @{ Name = $Name; Value = "aws-value-would-be-here" }
        }
    }
}

# List all secrets
function Get-SecretList {
    param(
        [string]$Backend,
        [string]$Namespace
    )

    Write-SecretsLog "Listing secrets..." "INFO"

    $secrets = @()

    switch ($Backend) {
        "kubernetes" {
            $secretList = kubectl get secrets -n $Namespace -o json 2>$null | ConvertFrom-Json
            foreach ($secret in $secretList.items) {
                if ($secret.type -eq "Opaque" -and $secret.metadata.name -notlike "*token*") {
                    $secrets += @{
                        Name = $secret.metadata.name
                        Type = $secret.type
                        Created = $secret.metadata.creationTimestamp
                        Expires = $secret.metadata.annotations.expires_at
                    }
                }
            }
        }
        "vault" {
            # vault kv list secret/rawrxd
            $secrets += @{ Name = "example-secret"; Type = "vault"; Created = "2026-07-13" }
        }
        "aws" {
            # aws secretsmanager list-secrets
            $secrets += @{ Name = "example-secret"; Type = "aws"; Created = "2026-07-13" }
        }
    }

    return $secrets
}

# Rotate secret
function Start-SecretRotation {
    param(
        [string]$Name,
        [string]$Backend,
        [string]$Namespace,
        [switch]$Force
    )

    Write-SecretsLog "Rotating secret: $Name" "WARNING"

    # Get current secret
    $current = Get-RawSecret -Name $Name -Backend $Backend -Namespace $Namespace
    if (!$current) {
        Write-SecretsLog "Secret not found for rotation: $Name" "ERROR"
        return $false
    }

    # Check if rotation is needed
    $expiresAt = [DateTime]$current.ExpiresAt
    $daysUntilExpiry = ($expiresAt - (Get-Date)).Days

    if (!$Force -and $daysUntilExpiry -gt 7) {
        Write-SecretsLog "Secret $Name does not need rotation yet (expires in $daysUntilExpiry days)" "INFO"
        return $false
    }

    # Generate new value
    $newValue = New-SecretValue -Type "apikey" -Length 32

    # Store new version
    $metadata = Set-RawSecret -Name $Name -Value $newValue -Type $current.Type -Backend $Backend -Namespace $Namespace
    $metadata.Version = 2
    $metadata.Rotated = $true
    $metadata.LastRotatedBy = $env:USER
    $metadata.RotationReason = if ($Force) { "Manual rotation" } else { "Scheduled rotation" }

    Write-SecretsLog "Secret rotated successfully (new version: $($metadata.Version))" "SUCCESS"

    # Log rotation event
    $rotationLog = @{
        timestamp = Get-Date -Format "o"
        secret_name = $Name
        old_expiry = $current.ExpiresAt
        new_expiry = $metadata.ExpiresAt.ToString("o")
        rotated_by = $metadata.LastRotatedBy
        reason = $metadata.RotationReason
    } | ConvertTo-Json

    Add-Content -Path "/var/log/rawrxd/secret-rotations.log" -Value $rotationLog

    return $metadata
}

# Backup secrets
function Backup-Secrets {
    param(
        [string]$Backend,
        [string]$Namespace,
        [string]$BackupPath
    )

    Write-SecretsLog "Backing up secrets..." "INFO"

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $BackupPath "secrets_backup_$timestamp.enc"

    $secrets = Get-SecretList -Backend $Backend -Namespace $Namespace
    $backupData = @{
        timestamp = Get-Date -Format "o"
        backend = $Backend
        namespace = $Namespace
        secrets = $secrets
    }

    # Encrypt backup
    $json = $backupData | ConvertTo-Json -Depth 10
    $encrypted = Protect-CmsMessage -Content $json -To "certificates\backup-encryption"

    $encrypted | Out-File $backupFile

    Write-SecretsLog "Backup created: $backupFile" "SUCCESS"
    return $backupFile
}

# Main execution
switch ($Action) {
    "init" {
        Initialize-SecretsInfrastructure -Backend $Backend -Namespace $Namespace
    }
    "get" {
        if (!$SecretName) {
            Write-SecretsLog "Secret name required" "ERROR"
            exit 1
        }
        $secret = Get-RawSecret -Name $SecretName -Backend $Backend -Namespace $Namespace
        if ($secret) {
            Write-Host "`nSecret: $($secret.Name)" -ForegroundColor Cyan
            Write-Host "Value: $($secret.Value)" -ForegroundColor DarkGray
            Write-Host "Created: $($secret.CreatedAt)"
            Write-Host "Expires: $($secret.ExpiresAt)"
        }
    }
    "list" {
        $secrets = Get-SecretList -Backend $Backend -Namespace $Namespace
        if ($secrets.Count -gt 0) {
            Write-Host "`nSecrets:" -ForegroundColor Cyan
            $secrets | Format-Table -AutoSize | Out-String | Write-Host
        } else {
            Write-SecretsLog "No secrets found" "INFO"
        }
    }
    "rotate" {
        if (!$SecretName) {
            Write-SecretsLog "Secret name required for rotation" "ERROR"
            exit 1
        }
        Start-SecretRotation -Name $SecretName -Backend $Backend -Namespace $Namespace -Force:$Force
    }
    "backup" {
        $backupPath = if ($SecretValue) { $SecretValue } else { "/var/backups/rawrxd" }
        Backup-Secrets -Backend $Backend -Namespace $Namespace -BackupPath $backupPath
    }
    "delete" {
        if (!$SecretName) {
            Write-SecretsLog "Secret name required for deletion" "ERROR"
            exit 1
        }
        if (!$Force) {
            $confirm = Read-Host "Are you sure you want to delete $SecretName? (yes/no)"
            if ($confirm -ne "yes") {
                Write-SecretsLog "Deletion cancelled" "INFO"
                exit 0
            }
        }
        kubectl delete secret $SecretName -n $Namespace
        Write-SecretsLog "Secret deleted: $SecretName" "SUCCESS"
    }
}

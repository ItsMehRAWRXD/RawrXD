# RawrXD Security Hardening Guide

## Overview

This guide provides step-by-step instructions for hardening the RawrXD Security & Hotpatch System to meet enterprise security standards.

## Table of Contents

1. [Pre-Deployment Hardening](#pre-deployment-hardening)
2. [RBAC Hardening](#rbac-hardening)
3. [Audit Logging Hardening](#audit-logging-hardening)
4. [Network Security](#network-security)
5. [Secrets Management](#secrets-management)
6. [Monitoring & Alerting](#monitoring--alerting)
7. [Backup & Recovery](#backup--recovery)
8. [Compliance Validation](#compliance-validation)

---

## Pre-Deployment Hardening

### 1. System Requirements

**Minimum Security Requirements:**
- Windows Server 2019+ or Windows 10/11 Enterprise
- PowerShell 7.4+ (latest stable)
- TLS 1.2+ enforced
- Windows Defender or equivalent antivirus
- Firewall enabled with default-deny policy

**Recommended Security Configuration:**
- Windows Server 2022 Datacenter
- PowerShell 7.4 LTS
- BitLocker disk encryption
- Windows Defender Credential Guard
- Secure Boot enabled

### 2. Pre-Installation Checklist

```powershell
# Run system security check
.\security\scanning\vulnerability_scanner.ps1 -Action scan -ScanType quick

# Verify PowerShell version
if ($PSVersionTable.PSVersion -lt [Version]"7.4") {
    Write-Error "PowerShell 7.4+ required"
}

# Check execution policy
$execPolicy = Get-ExecutionPolicy
if ($execPolicy -ne "RemoteSigned" -and $execPolicy -ne "Bypass") {
    Write-Warning "Execution policy may need adjustment for scripts"
}
```

### 3. File System Security

```powershell
# Set secure permissions on security directory
$securityPath = "C:\RawrXD\security"
icacls $securityPath /inheritance:r
icacls $securityPath /grant:r "Administrators:(OI)(CI)F"
icacls $securityPath /grant:r "SYSTEM:(OI)(CI)F"
icacls $securityPath /deny "Users:(OI)(CI)(RX)"

# Protect audit logs
$auditPath = "C:\RawrXD\logs\audit"
icacls $auditPath /inheritance:r
icacls $auditPath /grant:r "SYSTEM:(OI)(CI)F"
icacls $auditPath /grant:r "Administrators:(OI)(CI)F"
```

---

## RBAC Hardening

### 1. Role Configuration

**Default Roles (Do Not Modify):**
- `super-admin` (level 100): Reserved for emergency access
- `security-auditor` (level 50): Compliance and audit

**Custom Role Creation:**

```powershell
# Create custom role with minimal permissions
$customRole = @{
    name = "limited-operator"
    level = 45
    permissions = @("patch:view", "monitor:view")
    inherits_from = "patch-viewer"
    description = "Limited operator with view-only access"
}

# Add to RBAC config
$config = Get-Content "..\security\rbac\rbac_config.json" | ConvertFrom-Json
$config.roles += $customRole
$config | ConvertTo-Json -Depth 10 | Out-File "..\security\rbac\rbac_config.json"
```

### 2. User Assignment Best Practices

```powershell
# Principle of least privilege
# Assign lowest level role that meets requirements

# Example: Developer needs to view patches only
.\security\rbac\rbac_manager.ps1 -Operation assign_role `
    -UserId "developer-1" `
    -RoleName "patch-viewer"

# Example: DevOps needs to apply patches
.\security\rbac\rbac_manager.ps1 -Operation assign_role `
    -UserId "devops-1" `
    -RoleName "patch-operator"

# Regular access review (monthly)
$users = .\security\rbac\rbac_manager.ps1 -Operation list -JsonOutput | ConvertFrom-Json
foreach ($user in $users) {
    Write-Host "Review: $($user.user_id) - $($user.role)"
}
```

### 3. Permission Validation

```powershell
# Validate all user permissions
$testPermissions = @("patch:apply", "patch:rollback", "audit:view", "secrets:access")
$users = @("user1", "user2", "user3")

foreach ($user in $users) {
    foreach ($perm in $testPermissions) {
        $result = .\security\rbac\rbac_manager.ps1 -Operation check_permission `
            -UserId $user -Permission $perm -JsonOutput | ConvertFrom-Json
        
        if ($result.granted -and $perm -eq "secrets:access") {
            Write-Warning "$user has secrets access - verify necessity"
        }
    }
}
```

---

## Audit Logging Hardening

### 1. Audit Configuration

```powershell
# Configure audit log retention (7 years)
$auditConfig = @{
    retention_days = 2555  # 7 years
    log_rotation = "daily"
    encryption = "AES256"
    immutable = $true
}

# Enable comprehensive auditing
$auditEvents = @(
    "permission_check",
    "role_assignment",
    "patch_applied",
    "patch_rollback",
    "backup_created",
    "restore_executed",
    "config_change",
    "login_attempt",
    "logout"
)
```

### 2. Audit Log Protection

```powershell
# Make audit logs append-only (Windows)
$auditLogPath = "C:\RawrXD\logs\audit"

# Set audit log permissions
icacls $auditLogPath /inheritance:r
icacls $auditLogPath /grant:r "SYSTEM:(OI)(CI)F"
icacls $auditLogPath /grant:r "Administrators:(OI)(CI)F"
icacls $auditLogPath /deny "Everyone:(OI)(CI)W"

# Enable audit logging on the audit directory
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

### 3. Audit Review Procedures

```powershell
# Daily audit review
$yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
$auditFile = "C:\RawrXD\logs\audit\audit_$($yesterday -replace '-','').jsonl"

if (Test-Path $auditFile) {
    $events = Get-Content $auditFile | ConvertFrom-Json
    
    # Check for suspicious activity
    $suspicious = $events | Where-Object { 
        $_.action -match "failed|denied|unauthorized" 
    }
    
    if ($suspicious.Count -gt 0) {
        Write-Warning "Found $($suspicious.Count) suspicious events"
        $suspicious | Format-Table timestamp, action, user_id, details
    }
}
```

---

## Network Security

### 1. Firewall Configuration

```powershell
# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Default deny inbound
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Allow specific ports for RawrXD
New-NetFirewallRule -DisplayName "RawrXD-Monitoring" `
    -Direction Inbound -LocalPort 9090 -Protocol TCP -Action Allow

New-NetFirewallRule -DisplayName "RawrXD-Health" `
    -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
```

### 2. TLS Configuration

```powershell
# Enforce TLS 1.2+
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Disable older protocols
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -PropertyType DWORD
```

---

## Secrets Management

### 1. Secrets Encryption

```powershell
# Store secret with encryption
$secretValue = Read-Host "Enter secret value" -AsSecureString
$encrypted = $secretValue | ConvertFrom-SecureString

# Save encrypted secret
$encrypted | Out-File "C:\RawrXD\secrets\api-key.encrypted"

# Protect secrets directory
icacls "C:\RawrXD\secrets" /inheritance:r
icacls "C:\RawrXD\secrets" /grant:r "SYSTEM:(OI)(CI)F"
icacls "C:\RawrXD\secrets" /deny "Everyone:(OI)(CI)F"
```

### 2. Secret Rotation

```powershell
# Rotate secrets quarterly
$secretsToRotate = @("api-key", "db-password", "service-account")

foreach ($secret in $secretsToRotate) {
    Write-Host "Rotating $secret..."
    # Generate new secret
    $newSecret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    # Store securely
    # Update services
    Write-Host "✓ $secret rotated"
}
```

---

## Monitoring & Alerting

### 1. Security Monitoring

```powershell
# Configure security alerts
$securityAlerts = @{
    failed_logins = @{ threshold = 5; window = "5m" }
    permission_denied = @{ threshold = 10; window = "10m" }
    unauthorized_access = @{ threshold = 1; window = "1m" }
    config_change = @{ threshold = 1; window = "1m" }
}

# Enable Prometheus alerts
.\monitoring\scripts\setup_monitoring.ps1 -EnableSecurityAlerts
```

### 2. Health Monitoring

```powershell
# Schedule health checks
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\RawrXD\monitoring\scripts\health_check.ps1"

$trigger = New-ScheduledTaskTrigger -Daily -At "00:00"
Register-ScheduledTask -TaskName "RawrXD-HealthCheck" `
    -Action $action -Trigger $trigger -User "SYSTEM"
```

---

## Backup & Recovery

### 1. Backup Strategy

```powershell
# Daily incremental backups
.\disaster-recovery\backups\backup_manager.ps1 `
    -BackupType Incremental `
    -Schedule Daily `
    -Time "02:00"

# Weekly full backups
.\disaster-recovery\backups\backup_manager.ps1 `
    -BackupType Full `
    -Schedule Weekly `
    -Day Sunday `
    -Time "03:00"
```

### 2. Backup Encryption

```powershell
# Encrypt backups
$backupPath = "C:\RawrXD-Backups"
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "Backup" }

Get-ChildItem $backupPath -Filter "*.zip" | ForEach-Object {
    Protect-CmsMessage -Path $_.FullName -To $cert -OutFile "$($_.FullName).enc"
    Remove-Item $_.FullName
}
```

---

## Compliance Validation

### 1. Automated Compliance Checks

```powershell
# Daily compliance check
$complianceResult = .\security\compliance\compliance_checker.ps1 `
    -Operation check -JsonOutput | ConvertFrom-Json

if ($complianceResult.summary.compliance_score -lt 80) {
    Send-Alert -Severity High -Message "Compliance below threshold"
}
```

### 2. Compliance Reporting

```powershell
# Generate monthly compliance report
$report = .\security\compliance\compliance_checker.ps1 `
    -Operation report `
    -OutputFormat html `
    -OutputPath "C:\Reports\compliance-$(Get-Date -Format 'yyyy-MM').html"
```

---

## Security Checklist

### Pre-Deployment
- [ ] System meets minimum requirements
- [ ] Vulnerability scan completed
- [ ] File permissions configured
- [ ] Firewall enabled
- [ ] TLS 1.2+ enforced

### RBAC
- [ ] Default roles reviewed
- [ ] Custom roles created
- [ ] Users assigned minimal permissions
- [ ] Access review scheduled

### Audit Logging
- [ ] Audit logging enabled
- [ ] 7-year retention configured
- [ ] Log permissions secured
- [ ] Daily review procedure established

### Secrets
- [ ] Secrets encrypted at rest
- [ ] Access controls configured
- [ ] Rotation schedule established
- [ ] Secrets directory secured

### Monitoring
- [ ] Security alerts configured
- [ ] Health checks scheduled
- [ ] Alert thresholds set
- [ ] Escalation procedures defined

### Backup
- [ ] Backup schedule configured
- [ ] Encryption enabled
- [ ] Recovery tested
- [ ] Offsite storage configured

### Compliance
- [ ] Compliance checks automated
- [ ] Reporting scheduled
- [ ] Thresholds configured
- [ ] Remediation procedures defined

---

## Emergency Procedures

### Security Incident Response

1. **Immediate Response**
   ```powershell
   # Disable affected user
   .\security\rbac\rbac_manager.ps1 -Operation revoke_role -UserId "suspected-user"
   
   # Preserve logs
   Copy-Item C:\RawrXD\logs\audit C:\Incident-$(Get-Date -Format 'yyyyMMdd-HHmmss') -Recurse
   ```

2. **Investigation**
   ```powershell
   # Review audit logs
   .\security\audit\audit_logger.ps1 -Action query `
       -StartDate (Get-Date).AddHours(-24) `
       -UserId "suspected-user"
   ```

3. **Recovery**
   ```powershell
   # Restore from backup if needed
   .\disaster-recovery\recovery_procedures.ps1 -Action restore `
       -BackupDate "2026-07-13" -PointInTime "14:00"
   ```

---

## Support

- **Documentation:** `docs/SECURITY_API_REFERENCE.md`
- **Emergency:** On-call security team
- **Compliance:** compliance@rawrxd.local

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-13 | Initial hardening guide |

---

*Security Hardening Status: ✅ COMPLETE*
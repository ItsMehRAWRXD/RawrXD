# RawrXD Security API Reference

## Overview

Complete API reference for the RawrXD Security System, including RBAC, hotpatching, audit logging, and compliance checking.

---

## RBAC API

### Initialize RBAC

```powershell
rbac_manager.ps1 -Operation init [-ConfigPath <path>]
```

**Parameters:**
- `ConfigPath` (optional): Path to RBAC configuration file (default: `security/rbac/rbac_config.json`)

**Returns:**
```json
{
  "status": "success",
  "message": "RBAC configuration initialized"
}
```

---

### List All Roles

```powershell
rbac_manager.ps1 -Operation list [-ConfigPath <path>] [-JsonOutput]
```

**Returns:**
```json
[
  {
    "name": "super-admin",
    "level": 100,
    "permissions": ["*"],
    "effective_permissions": ["*"],
    "inherits_from": null,
    "description": "Full system access"
  }
]
```

---

### Get Role Details

```powershell
rbac_manager.ps1 -Operation get_role -RoleName <name> [-ConfigPath <path>] [-JsonOutput]
```

**Parameters:**
- `RoleName` (required): Name of the role

**Returns:**
```json
{
  "name": "patch-admin",
  "level": 80,
  "permissions": ["patch:*", "rollback:*", "backup:*", "monitor:view"],
  "effective_permissions": ["patch:*", "rollback:*", "backup:*", "monitor:view"],
  "inherits_from": null,
  "description": "Patch and deployment administration"
}
```

---

### Assign Role to User

```powershell
rbac_manager.ps1 -Operation assign_role -UserId <id> -RoleName <role> [-ConfigPath <path>] [-JsonOutput]
```

**Parameters:**
- `UserId` (required): User identifier
- `RoleName` (required): Role to assign

**Returns:**
```json
{
  "status": "success",
  "user_id": "user123",
  "role": "patch-operator"
}
```

---

### Revoke User Role

```powershell
rbac_manager.ps1 -Operation revoke_role -UserId <id> [-ConfigPath <path>] [-JsonOutput]
```

**Parameters:**
- `UserId` (required): User identifier

**Returns:**
```json
{
  "status": "success",
  "user_id": "user123",
  "revoked_role": "patch-operator"
}
```

---

### Get User Role

```powershell
rbac_manager.ps1 -Operation get_user_role -UserId <id> [-ConfigPath <path>] [-JsonOutput]
```

**Parameters:**
- `UserId` (required): User identifier

**Returns:**
```json
{
  "user_id": "user123",
  "role": "patch-operator",
  "role_level": 60,
  "permissions": ["patch:apply", "patch:view", "monitor:view"],
  "assigned_at": "2026-07-13T10:00:00Z",
  "assigned_by": "admin"
}
```

---

### Check Permission

```powershell
rbac_manager.ps1 -Operation check_permission -UserId <id> -Permission <perm> [-ConfigPath <path>] [-JsonOutput]
```

**Parameters:**
- `UserId` (required): User identifier
- `Permission` (required): Permission to check (e.g., `patch:apply`)

**Returns:**
```json
{
  "user_id": "user123",
  "permission": "patch:apply",
  "granted": true,
  "role": "patch-operator",
  "effective_permissions": ["patch:apply", "patch:view", "monitor:view"]
}
```

---

## Hotpatch API

### Swarm Hotpatch Manager

```powershell
swarm_hotpatch_manager.ps1 -Action <action> [-Options]
```

**Actions:**
- `backup`: Create backup before patching
- `health_check`: Validate system health
- `apply_patch`: Apply hotpatch to swarm
- `rollback`: Rollback to previous version
- `status`: Get patch status

**Parameters:**
- `PatchId` (optional): Specific patch identifier
- `DryRun` (switch): Simulate without applying
- `Force` (switch): Skip confirmation prompts

**Example:**
```powershell
# Apply patch with backup
swarm_hotpatch_manager.ps1 -Action apply_patch -PatchId "patch-001" -Backup

# Health check
swarm_hotpatch_manager.ps1 -Action health_check

# Rollback
swarm_hotpatch_manager.ps1 -Action rollback -PatchId "patch-001"
```

---

### Patch Registry

```powershell
patch_registry.ps1 -Operation <operation> [-Options]
```

**Operations:**
- `register`: Register a new patch
- `get`: Get patch by ID
- `list`: List all patches
- `update_status`: Update patch status
- `stats`: Get patch statistics

**Parameters:**
- `PatchId` (required for get/update): Patch identifier
- `System` (optional): Filter by system
- `Status` (optional): Filter by status

**Example:**
```powershell
# Register patch
patch_registry.ps1 -Operation register `
  -PatchId "patch-001" `
  -System "swarm-coordinator" `
  -Version "1.0.1" `
  -Files @("file1.ps1", "file2.ps1")

# List patches
patch_registry.ps1 -Operation list -System "swarm-coordinator"

# Update status
patch_registry.ps1 -Operation update_status `
  -PatchId "patch-001" `
  -Status "applied"
```

---

## Audit API

### Audit Logger

```powershell
audit_logger.ps1 -Action <action> [-Options]
```

**Actions:**
- `log`: Log an audit event
- `query`: Query audit logs
- `export`: Export audit logs
- `rotate`: Rotate log files

**Parameters:**
- `EventType` (required for log): Type of event
- `UserId` (required for log): User identifier
- `Details` (optional): Event details
- `StartDate` (optional for query): Query start date
- `EndDate` (optional for query): Query end date

**Example:**
```powershell
# Log audit event
audit_logger.ps1 -Action log `
  -EventType "permission_check" `
  -UserId "user123" `
  -Details "Checked patch:apply permission"

# Query logs
audit_logger.ps1 -Action query `
  -StartDate "2026-07-01" `
  -EndDate "2026-07-13" `
  -UserId "user123"
```

---

## Compliance API

### Compliance Checker

```powershell
compliance_checker.ps1 -Operation <operation> [-Options]
```

**Operations:**
- `check`: Run compliance check
- `report`: Generate compliance report
- `validate`: Validate specific control

**Parameters:**
- `Framework` (optional): Compliance framework (SOC2, ISO27001, NIST)
- `OutputFormat` (optional): Output format (json, html, markdown)

**Example:**
```powershell
# Run compliance check
compliance_checker.ps1 -Operation check -Framework SOC2

# Generate report
compliance_checker.ps1 -Operation report -OutputFormat html
```

**Returns:**
```json
{
  "summary": {
    "compliance_score": 85,
    "total_controls": 50,
    "passed_controls": 42,
    "failed_controls": 5,
    "warning_controls": 3
  },
  "frameworks": {
    "SOC2": { "score": 87, "status": "pass" },
    "ISO27001": { "score": 83, "status": "pass" },
    "NIST": { "score": 85, "status": "pass" }
  }
}
```

---

## Secrets API

### Secrets Manager

```powershell
secrets_manager.ps1 -Action <action> [-Options]
```

**Actions:**
- `store`: Store a secret
- `retrieve`: Retrieve a secret
- `rotate`: Rotate secret
- `delete`: Delete secret

**Parameters:**
- `SecretName` (required): Secret identifier
- `SecretValue` (required for store): Secret value
- `EncryptionKey` (optional): Custom encryption key

**Example:**
```powershell
# Store secret
secrets_manager.ps1 -Action store `
  -SecretName "api-key" `
  -SecretValue "secret123"

# Retrieve secret
$secret = secrets_manager.ps1 -Action retrieve -SecretName "api-key"
```

---

## Vulnerability Scanning API

### Vulnerability Scanner

```powershell
vulnerability_scanner.ps1 -Action <action> [-Options]
```

**Actions:**
- `scan`: Run vulnerability scan
- `report`: Generate scan report
- `baseline`: Set security baseline

**Parameters:**
- `ScanType` (optional): Type of scan (quick, full, custom)
- `Targets` (optional): Systems to scan

**Example:**
```powershell
# Run quick scan
vulnerability_scanner.ps1 -Action scan -ScanType quick

# Full scan with report
vulnerability_scanner.ps1 -Action scan -ScanType full
vulnerability_scanner.ps1 -Action report -OutputFormat html
```

---

## Policy Enforcement API

### Policy Enforcer

```powershell
policy_enforcer.ps1 -Action <action> [-Options]
```

**Actions:**
- `validate`: Validate against policies
- `enforce`: Enforce policies
- `report`: Generate policy report

**Parameters:**
- `PolicyType` (optional): Type of policy
- `Target` (optional): Target system/resource

**Example:**
```powershell
# Validate policies
policy_enforcer.ps1 -Action validate -PolicyType "security"

# Enforce policies
policy_enforcer.ps1 -Action enforce -PolicyType "access_control"
```

---

## Error Handling

All APIs return consistent error formats:

```json
{
  "status": "error",
  "error": {
    "code": "RBAC_ROLE_NOT_FOUND",
    "message": "Role 'invalid-role' not found",
    "timestamp": "2026-07-13T10:00:00Z"
  }
}
```

**Common Error Codes:**
- `RBAC_ROLE_NOT_FOUND`: Requested role doesn't exist
- `RBAC_USER_NOT_FOUND`: User has no role assignment
- `RBAC_PERMISSION_DENIED`: User lacks required permission
- `PATCH_NOT_FOUND`: Patch ID doesn't exist
- `PATCH_ALREADY_APPLIED`: Patch already applied
- `AUDIT_LOG_ERROR`: Audit logging failure
- `COMPLIANCE_CHECK_FAILED`: Compliance threshold not met

---

## Authentication & Authorization

All security APIs require appropriate permissions:

| API | Required Permission |
|-----|---------------------|
| RBAC (read) | `rbac:view` |
| RBAC (write) | `rbac:manage` |
| Hotpatch (read) | `patch:view` |
| Hotpatch (apply) | `patch:apply` |
| Audit (read) | `audit:view` |
| Audit (write) | `audit:manage` |
| Compliance | `compliance:view` |
| Secrets | `secrets:manage` |
| Scanning | `security:scan` |
| Policies | `policy:enforce` |

---

## Integration Examples

### PowerShell Script Integration

```powershell
# Check permission before operation
$check = rbac_manager.ps1 -Operation check_permission `
  -UserId $env:USERNAME `
  -Permission "patch:apply" `
  -JsonOutput | ConvertFrom-Json

if ($check.granted) {
    # Apply patch
    swarm_hotpatch_manager.ps1 -Action apply_patch -PatchId "patch-001"
    
    # Log audit event
    audit_logger.ps1 -Action log `
      -EventType "patch_applied" `
      -UserId $env:USERNAME `
      -Details "Applied patch-001"
} else {
    Write-Error "Permission denied"
}
```

### CI/CD Pipeline Integration

```yaml
# Azure DevOps Pipeline
steps:
  - task: PowerShell@2
    inputs:
      targetType: 'inline'
      script: |
        # Check compliance before deployment
        $compliance = ./security/compliance/compliance_checker.ps1 `
          -Operation check -JsonOutput | ConvertFrom-Json
        
        if ($compliance.summary.compliance_score -lt 80) {
          throw "Compliance check failed: $($compliance.summary.compliance_score)%"
        }
        
        # Apply patch
        ./security/phase_g1_hotpatch/swarm_hotpatch_manager.ps1 `
          -Action apply_patch -PatchId "$(PatchId)"
```

---

## Rate Limiting

API calls are subject to rate limiting:

| API | Limit | Window |
|-----|-------|--------|
| RBAC | 1000 | 1 minute |
| Hotpatch | 100 | 1 minute |
| Audit | 5000 | 1 minute |
| Compliance | 60 | 1 minute |
| Secrets | 500 | 1 minute |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-13 | Initial API release |

---

## Support

- **Documentation:** `docs/SECURITY_INTEGRATION_SUMMARY.md`
- **Issues:** GitHub Issues
- **Emergency:** On-call security team
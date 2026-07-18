# Phase H: Enterprise Security

## Overview

Phase H implements enterprise-grade security features for the RawrXD hotpatch system, including Role-Based Access Control (RBAC), comprehensive audit logging, and compliance checking.

## Components

### 1. Role-Based Access Control (RBAC) - `rbac/`

**File:** `rbac_manager.ps1`

Manages user roles, permissions, and access control for enterprise deployments.

**Roles:**

| Role | Level | Description | Key Permissions |
|------|-------|-------------|---------------|
| `super-admin` | 100 | Full system access | `*:*` (all permissions) |
| `patch-admin` | 80 | Patch system administration | swarm:*, agent:*, tools:*, registry:* |
| `patch-operator` | 60 | Apply and rollback patches | swarm:apply/rollback/status, agent:apply/rollback/status |
| `patch-viewer` | 40 | Read-only access | swarm:status/list, agent:status/list, tools:status/list |
| `security-auditor` | 50 | Security audit access | audit:read, compliance:read, rbac:audit |

**Usage:**

```powershell
# Initialize RBAC system
.\rbac\rbac_manager.ps1 -Action init

# Add user with role
.\rbac\rbac_manager.ps1 -Action user-add -UserId "john.doe" -Role "patch-operator"

# Assign additional role
.\rbac\rbac_manager.ps1 -Action role-assign -UserId "john.doe" -Role "patch-admin"

# Check permission
.\rbac\rbac_manager.ps1 -Action check-permission -UserId "john.doe" -Resource "swarm" -Permission "apply"

# List users
.\rbac\rbac_manager.ps1 -Action list-users

# List roles
.\rbac\rbac_manager.ps1 -Action list-roles

# View audit log
.\rbac\rbac_manager.ps1 -Action audit
```

**Features:**
- Role hierarchy with permission inheritance
- User-role assignment with audit trail
- Permission checking with wildcard support
- Audit logging for all RBAC operations
- JSON-based configuration storage

### 2. Audit Logging - `audit/`

**File:** `audit_logger.ps1`

Comprehensive audit logging for compliance and forensic analysis.

**Event Types:**
- `patch` - Patch operations (apply, rollback, validate)
- `auth` - Authentication events (login, logout, permission check)
- `system` - System events (startup, shutdown, health check)
- `security` - Security events (unauthorized access, policy violation)
- `rbac` - RBAC operations (user add, role assign, permission change)

**Usage:**

```powershell
# Log patch event
.\audit\audit_logger.ps1 -EventType patch -Action apply -UserId "john.doe" -Details '{"patch_id": "123"}' -Severity info

# Log security event
.\audit\audit_logger.ps1 -EventType security -Action "unauthorized_access" -UserId "anonymous" -Severity critical

# Log RBAC event
.\audit\audit_logger.ps1 -EventType rbac -Action "role-assign" -UserId "admin" -Details '{"target_user": "john.doe", "role": "patch-admin"}' -Severity info
```

**Features:**
- JSON Lines format for easy parsing
- Automatic log rotation (100MB max, 10 files retained)
- Real-time streaming to console
- Critical events to Windows Event Log
- Tamper-evident logging (future enhancement)

**Log Format:**
```json
{
  "Timestamp": "2026-07-13T14:30:00Z",
  "EventType": "patch",
  "Action": "apply",
  "UserId": "john.doe",
  "Severity": "info",
  "SourceHost": "server01",
  "ProcessId": 1234,
  "SessionId": 1,
  "Details": {"patch_id": "123", "system": "swarm"}
}
```

### 3. Compliance Checking - `compliance/`

**File:** `compliance_checker.ps1`

Validates system compliance with security standards (SOC2, ISO27001, NIST).

**Supported Standards:**

| Standard | Controls | Focus |
|----------|----------|-------|
| SOC 2 Type II | CC6.1-CC8.1 | Security, Availability, Processing Integrity |
| ISO/IEC 27001:2022 | A.5.15-A.8.11 | Information Security Management |
| NIST CSF 2.0 | PR.AC-1-PR.AC-6 | Cybersecurity Framework |

**Usage:**

```powershell
# Check all standards
.\compliance\compliance_checker.ps1 -Standard ALL

# Check specific standard
.\compliance\compliance_checker.ps1 -Standard SOC2

# Generate HTML report
.\compliance\compliance_checker.ps1 -Standard ALL -OutputFormat html -GenerateReport

# JSON output for automation
.\compliance\compliance_checker.ps1 -Standard ALL -OutputFormat json
```

**Checks:**
- ✅ RBAC Configuration - Roles defined, users assigned, audit enabled
- ✅ Audit Logging - Log directory exists, writable, recent logs present
- ✅ Backup System - Backup directory exists, writable, recent backups present
- ⚠️ Encryption - Manual verification required (placeholder)

**Compliance Levels:**
- **PASS** (Green) - Control fully implemented
- **WARNING** (Yellow) - Control partially implemented or needs attention
- **FAIL** (Red) - Control not implemented or critical issue

## Integration with Phase G

Phase H security features integrate with Phase G hotpatch system:

1. **RBAC Enforcement** - All hotpatch operations check user permissions
2. **Audit Integration** - Patch operations automatically logged
3. **Compliance Validation** - Pre-deployment compliance checks

**Example Integration:**

```powershell
# Before applying patch, check permissions
$hasPermission = .\rbac\rbac_manager.ps1 -Action check-permission -UserId $env:USERNAME -Resource "swarm" -Permission "apply"
if ($hasPermission) {
    # Apply patch
    .\..\phase_g1_hotpatch\unified_hotpatch_orchestrator.ps1 -Action apply ...
    
    # Log the operation
    .\audit\audit_logger.ps1 -EventType patch -Action apply -UserId $env:USERNAME -Details '{"patch_id": "123"}'
}
```

## Enterprise Security Checklist

- [ ] RBAC initialized with appropriate roles
- [ ] Users assigned to roles
- [ ] Audit logging enabled
- [ ] Log retention policy configured
- [ ] Compliance checks passing (>80%)
- [ ] Security runbooks created
- [ ] Incident response procedures documented
- [ ] Regular compliance audits scheduled

## Security Best Practices

1. **Principle of Least Privilege** - Assign minimum required permissions
2. **Regular Access Reviews** - Review user roles quarterly
3. **Audit Log Monitoring** - Monitor for suspicious activity
4. **Compliance Validation** - Run checks before production deployment
5. **Incident Response** - Document and practice response procedures

## Next Steps

1. **Initialize RBAC** - Create roles and assign users
2. **Enable Audit Logging** - Configure log retention and monitoring
3. **Run Compliance Check** - Validate against security standards
4. **Integrate with CI/CD** - Add security gates to deployment pipeline
5. **Schedule Regular Audits** - Monthly compliance checks

## Support

For security issues or questions:
- Security Team: security@rawrxd.ai
- Compliance Team: compliance@rawrxd.ai
- On-Call: oncall@rawrxd.ai

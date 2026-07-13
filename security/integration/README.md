# Security Integration

## Overview

This directory contains integration components that connect Phase H (Enterprise Security) with Phase G (Hotpatch System), enforcing RBAC and audit logging on all hotpatch operations.

## Components

### 1. Security Wrapper (`security_wrapper.ps1`)

**Purpose:** Enforces security checks before any hotpatch operation

**Checks Performed:**
1. **RBAC Authorization** - Validates user has required permissions
2. **Compliance Validation** - Ensures system meets compliance thresholds
3. **Patch Bundle Security** - Validates patch metadata and approval status
4. **Audit Logging** - Logs all security events

**Usage:**
```powershell
# Direct usage (called by secure_hotpatch.ps1)
.\security_wrapper.ps1 -Operation apply -System swarm -UserId "john.doe" -PatchBundle "patches/hotfix.json"
```

**Exit Codes:**
- `0` - Security check passed
- `1` - Security check failed (access denied, compliance violation, etc.)

### 2. Secure Hotpatch (`secure_hotpatch.ps1`)

**Purpose:** Main entry point for secure hotpatch operations

**Features:**
- Wraps all hotpatch managers with security
- User confirmation for destructive operations
- Automatic audit logging
- Unified interface across all systems

**Usage:**
```powershell
# Apply patch to swarm
.\secure_hotpatch.ps1 -Action apply -System swarm -PatchBundle "patches/hotfix.json"

# Check status of all systems
.\secure_hotpatch.ps1 -Action status -System all

# Rollback agent patch
.\secure_hotpatch.ps1 -Action rollback -System agent -Target worker -AgentId "agent-001"

# Dry-run patch application
.\secure_hotpatch.ps1 -Action apply -System tools -PatchBundle "patches/config.json" -DryRun

# Skip confirmation (automated deployments)
.\secure_hotpatch.ps1 -Action apply -System swarm -PatchBundle "patches/hotfix.json" -Force
```

**Security Flow:**
1. Run security wrapper checks
2. Prompt for confirmation (unless -Force)
3. Execute hotpatch operation
4. Log result to audit system

## CI/CD Security Gates

### GitHub Actions Workflow (`.github/workflows/security/`)

**File:** `security-gates.yml`

**Jobs:**
1. **RBAC Check** - Validates user permissions
2. **Audit Log** - Creates audit entry for deployment attempt
3. **Compliance Check** - Runs compliance validation
4. **Patch Validation** - Validates patch bundle format and approval
5. **Security Wrapper Test** - Tests security integration
6. **Approval Gate** - Requires manual approval for production
7. **Final Audit** - Logs deployment result

**Usage:**
```yaml
# In your deployment workflow
- name: Security Gates
  uses: ./.github/workflows/security/security-gates.yml
  with:
    environment: production
    patch_bundle: patches/security_fix.json
```

## Migration Guide

### From Direct Hotpatch Calls

**Before (insecure):**
```powershell
.\phase_g1_hotpatch\unified_hotpatch_orchestrator.ps1 -Action apply -System all -PatchBundle "patches/hotfix.json"
```

**After (secure):**
```powershell
.\security\integration\secure_hotpatch.ps1 -Action apply -System all -PatchBundle "patches/hotfix.json"
```

### Required Changes

1. **Update all scripts** to use `secure_hotpatch.ps1` instead of direct manager calls
2. **Initialize RBAC** before first use
3. **Configure audit logging** directory
4. **Update CI/CD pipelines** to include security gates

## Security Enforcement

### RBAC Enforcement

All operations check user permissions:
- `apply` → requires `swarm:apply`, `agent:apply`, or `tools:apply`
- `rollback` → requires `swarm:rollback`, `agent:rollback`, or `tools:rollback`
- `status` → requires `swarm:status`, `agent:status`, or `tools:status`

### Audit Logging

All operations are logged:
- **Success** → Info level log with operation details
- **Failure** → Error level log with error message
- **Access Denied** → Warning level log with denial reason

### Compliance Validation

Pre-deployment checks:
- RBAC configuration exists
- Audit logging operational
- Backup system functional
- Compliance percentage ≥ 80%

## Troubleshooting

### "RBAC manager not found"

**Cause:** Phase H security not initialized
**Solution:**
```powershell
.\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Action init
```

### "Access DENIED" errors

**Cause:** User lacks required permissions
**Solution:**
```powershell
# Check user permissions
.\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Action check-permission -UserId $env:USERNAME -Resource "swarm" -Permission "apply"

# Assign role if needed (as admin)
.\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Action role-assign -UserId "username" -Role "patch-operator"
```

### "Compliance check failed"

**Cause:** System compliance below 80%
**Solution:**
```powershell
# Check compliance status
.\phase_h_enterprise_security\compliance\compliance_checker.ps1 -Standard ALL

# Fix identified issues
```

## Best Practices

1. **Always use secure_hotpatch.ps1** - Never call managers directly
2. **Initialize RBAC first** - Before any hotpatch operations
3. **Regular compliance checks** - Weekly validation
4. **Monitor audit logs** - Review for suspicious activity
5. **Test in staging** - Before production deployment

## Integration Architecture

```
User/CI/CD
    ↓
secure_hotpatch.ps1
    ↓
security_wrapper.ps1
    ↓
┌─────────────┬─────────────┬─────────────┐
↓             ↓             ↓             ↓
RBAC      Compliance   Patch        Audit
Check     Check        Validation   Logger
    ↓             ↓             ↓             ↓
    └─────────────┴─────────────┴─────────────┘
                    ↓
            Hotpatch Manager
                    ↓
            Target System
```

## Support

For integration issues:
- Security Team: security@rawrxd.ai
- DevOps Team: devops@rawrxd.ai

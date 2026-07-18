# Hotpatch Operations Guide
## RawrXD Security & Hotpatch System

**Version:** 1.0.0  
**Last Updated:** 2026-07-13  
**Audience:** Operations Engineers, SREs, Security Engineers

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Overview](#system-overview)
3. [Pre-Deployment Checklist](#pre-deployment-checklist)
4. [Standard Operations](#standard-operations)
5. [Emergency Procedures](#emergency-procedures)
6. [Monitoring & Alerting](#monitoring--alerting)
7. [Rollback Procedures](#rollback-procedures)

---

## Quick Start

### Verify System Health
```powershell
# Check all systems status
.\security\integration\secure_hotpatch.ps1 -Operation status

# Verify RBAC is initialized
.\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Operation list

# Check compliance status
.\security\phase_h_enterprise_security\compliance\compliance_checker.ps1 -Operation check
```

### Deploy a Patch (Secure)
```powershell
# Deploy swarm patch with full security
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation apply `
    -PatchPath "patches/swarm-fix-v1.2.3.json"
```

---

## System Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD Hotpatch System                    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Security Integration                               │
│  ├── security_wrapper.ps1 (RBAC + Compliance)               │
│  ├── secure_hotpatch.ps1 (Secure Entry Point)                │
│  └── security-gates.yml (CI/CD Gates)                        │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Enterprise Security                                  │
│  ├── RBAC Manager (5-tier role system)                      │
│  ├── Audit Logger (JSON Lines, real-time)                   │
│  └── Compliance Checker (SOC2/ISO27001/NIST)               │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Hotpatch Managers                                    │
│  ├── Swarm Hotpatch Manager                                 │
│  ├── Agent Hotpatch Manager                                 │
│  ├── Tools Hotpatch Manager                                 │
│  └── Unified Orchestrator                                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Patch Registry                                       │
│  └── Centralized patch tracking & statistics                │
└─────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Purpose | Criticality |
|-----------|---------|-------------|
| `secure_hotpatch.ps1` | Main entry point for all operations | **Critical** |
| `security_wrapper.ps1` | Enforces security policies | **Critical** |
| `rbac_manager.ps1` | Access control | **Critical** |
| `audit_logger.ps1` | Audit trail | **High** |
| `compliance_checker.ps1` | Compliance validation | **High** |
| `patch_registry.ps1` | Patch tracking | **Medium** |
| `*_hotpatch_manager.ps1` | System-specific patching | **Medium** |

---

## Pre-Deployment Checklist

### Environment Preparation

- [ ] PowerShell 7.0+ installed (`$PSVersionTable.PSVersion`)
- [ ] Git repository cloned and on correct branch
- [ ] Security scripts have execution permissions
- [ ] Audit log directory exists and is writable
- [ ] RBAC configuration initialized
- [ ] Compliance thresholds configured

### Verification Commands

```powershell
# 1. Check PowerShell version
$PSVersionTable.PSVersion -ge [Version]"7.0"

# 2. Verify git status
git status

# 3. Check execution policy
Get-ExecutionPolicy -Scope CurrentUser

# 4. Verify audit log path
Test-Path "logs/audit"

# 5. Initialize RBAC (first time only)
.\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Operation initialize

# 6. Verify compliance
.\security\phase_h_enterprise_security\compliance\compliance_checker.ps1 -Operation check
```

---

## Standard Operations

### 1. Status Check

**Purpose:** Verify system health before operations

```powershell
.\security\integration\secure_hotpatch.ps1 -Operation status
```

**Expected Output:**
```
RawrXD Secure Hotpatch System
==============================

System Status Check
-------------------
✓ Security wrapper loaded
✓ RBAC system initialized
✓ Audit logger initialized
✓ Compliance checker initialized
✓ Patch registry initialized

All systems operational.
```

### 2. List Patches

**Purpose:** View available patches in registry

```powershell
# All patches
.\security\integration\secure_hotpatch.ps1 -Operation list

# Filtered by system
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation list
```

### 3. Dry-Run Patch

**Purpose:** Validate patch without applying

```powershell
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation dryrun `
    -PatchPath "patches/swarm-fix-v1.2.3.json"
```

**Success Indicators:**
- RBAC check passes
- Compliance validation passes
- Patch validation passes
- No errors in output

### 4. Apply Patch

**Purpose:** Deploy patch to production

```powershell
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation apply `
    -PatchPath "patches/swarm-fix-v1.2.3.json"
```

**Confirmation Prompt:**
```
⚠️  DESTRUCTIVE OPERATION WARNING
This will apply patches to the swarm system.

Patch: patches/swarm-fix-v1.2.3.json
System: swarm
Operation: apply

Are you sure you want to continue? (yes/no): 
```

**Type "yes" to proceed.**

### 5. Rollback Patch

**Purpose:** Revert to previous state

```powershell
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation rollback `
    -PatchPath "patches/swarm-fix-v1.2.3.json"
```

---

## Emergency Procedures

### Critical System Failure

**Scenario:** Hotpatch causes system instability

```powershell
# 1. Immediate rollback
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation rollback `
    -PatchPath "patches/swarm-fix-v1.2.3.json"

# 2. Verify system recovery
.\security\integration\secure_hotpatch.ps1 -Operation status

# 3. Check audit logs for root cause
Get-Content "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl" | Select-Object -Last 50
```

### RBAC Lockout

**Scenario:** Cannot perform operations due to permissions

```powershell
# Check current user permissions
.\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Operation check

# If locked out, contact super-admin to:
# 1. Verify user role assignment
# 2. Check if role permissions are correct
# 3. Temporarily elevate if emergency
```

### Compliance Violation

**Scenario:** Compliance check fails

```powershell
# Run detailed compliance check
.\security\phase_h_enterprise_security\compliance\compliance_checker.ps1 `
    -Operation check `
    -OutputFormat json

# Review failed controls
# Address each failed control
# Re-run compliance check
```

---

## Monitoring & Alerting

### Key Metrics

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Patch Success Rate | >99% | <95% |
| Rollback Rate | <1% | >5% |
| Compliance Score | 100% | <80% |
| Audit Log Health | 100% | Any errors |
| RBAC Response Time | <100ms | >500ms |

### Monitoring Queries

```powershell
# Check recent patch operations
Get-Content "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl" |
    ConvertFrom-Json |
    Where-Object { $_.event_type -like "*patch*" } |
    Select-Object -Last 20

# Check for failures
Get-Content "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl" |
    ConvertFrom-Json |
    Where-Object { $_.event_data.status -eq "failure" } |
    Select-Object -Last 10

# Compliance trend
.\security\phase_h_enterprise_security\compliance\compliance_checker.ps1 `
    -Operation check `
    -OutputFormat json |
    ConvertFrom-Json |
    Select-Object -ExpandProperty summary
```

### Log Locations

| Log Type | Path | Retention |
|----------|------|-----------|
| Audit Logs | `logs/audit/audit_YYYYMM.jsonl` | 7 years |
| Security Events | `logs/audit/security_*.jsonl` | 7 years |
| Patch History | `security/phase_g1_hotpatch/registry/patch_registry.json` | Indefinite |
| Compliance Reports | `logs/compliance/` | 7 years |

---

## Rollback Procedures

### Standard Rollback

**When:** Patch causes issues but system is stable

```powershell
# Rollback specific patch
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation rollback `
    -PatchPath "patches/swarm-fix-v1.2.3.json"
```

### Emergency Rollback

**When:** Critical failure, immediate action needed

```powershell
# Bypass confirmation (use with caution!)
$env:HOTPATCH_CONFIRM = "true"
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation rollback `
    -PatchPath "patches/swarm-fix-v1.2.3.json"
```

### Full System Restore

**When:** Multiple patches need rollback

```powershell
# List all applied patches
.\security\phase_g1_hotpatch\registry\patch_registry.ps1 -Operation list

# Rollback each in reverse order
$patches = @(
    "patches/swarm-fix-v1.2.3.json",
    "patches/swarm-fix-v1.2.2.json",
    "patches/swarm-fix-v1.2.1.json"
)

foreach ($patch in $patches) {
    .\security\integration\secure_hotpatch.ps1 `
        -SystemType swarm `
        -Operation rollback `
        -PatchPath $patch
}
```

---

## Best Practices

### Before Applying Patches

1. **Always run dry-run first**
2. **Verify system status**
3. **Check compliance score**
4. **Review patch metadata**
5. **Ensure rollback is possible**

### During Patch Application

1. **Monitor real-time logs**
2. **Watch for error messages**
3. **Be ready to rollback**
4. **Document any anomalies**

### After Patch Application

1. **Verify system health**
2. **Check audit logs**
3. **Update documentation**
4. **Monitor for 24 hours**

---

## Support Contacts

| Role | Responsibility | Escalation Path |
|------|---------------|-----------------|
| L1 Support | Initial triage | L2 after 15 min |
| L2 Support | Technical investigation | L3 after 30 min |
| L3 Support | Architecture decisions | Engineering |
| Security Team | Security incidents | CISO |
| On-Call Engineer | Emergency response | Manager |

---

## Appendix

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | None |
| 1 | General error | Check logs |
| 2 | RBAC denied | Check permissions |
| 3 | Compliance failed | Fix compliance issues |
| 4 | Validation failed | Check patch format |
| 5 | System error | Contact L3 support |

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "RBAC check failed" | Insufficient permissions | Request role elevation |
| "Compliance check failed" | Score below threshold | Address compliance gaps |
| "Patch validation failed" | Invalid patch format | Verify patch JSON |
| "System not found" | Wrong system type | Check system type parameter |

---

*Document Version: 1.0.0*  
*Next Review Date: 2026-08-13*

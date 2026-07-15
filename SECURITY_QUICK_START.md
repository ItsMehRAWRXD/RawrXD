# RawrXD Security & Hotpatch - Quick Start Guide

## 🚀 Quick Commands

### Installation
```powershell
.\install.ps1 -Environment production
```

### RBAC Operations
```powershell
# Initialize
.\security\rbac\rbac_manager.ps1 -Operation init

# List roles
.\security\rbac\rbac_manager.ps1 -Operation list

# Assign role
.\security\rbac\rbac_manager.ps1 -Operation assign_role `
    -UserId "user" -RoleName "patch-operator"

# Check permission
.\security\rbac\rbac_manager.ps1 -Operation check_permission `
    -UserId "user" -Permission "patch:apply"

# Revoke role
.\security\rbac\rbac_manager.ps1 -Operation revoke_role -UserId "user"
```

### Health Check
```powershell
.\monitoring\scripts\health_check.ps1
```

### Backup
```powershell
.\disaster-recovery\backups\backup_manager.ps1 -BackupType Full
```

### Compliance
```powershell
.\security\compliance\compliance_checker.ps1 -Operation check
```

### Testing
```powershell
# Run RBAC tests
Invoke-Pester -Path "tests/unit/rbac_manager.tests.ps1"

# Run all tests
Invoke-Pester -Path "tests/unit"
```

## 📁 Key Files

| File | Purpose |
|------|---------|
| `install.ps1` | Installation script |
| `security/rbac/rbac_manager.ps1` | RBAC management |
| `monitoring/scripts/health_check.ps1` | Health monitoring |
| `deployment/deployment_orchestrator.ps1` | Deployment automation |
| `FINAL_IMPLEMENTATION_REPORT.md` | Complete documentation |

## 🔐 Role Hierarchy

| Role | Level | Key Permissions |
|------|-------|-----------------|
| super-admin | 100 | * (all) |
| patch-admin | 80 | patch:*, rollback:* |
| patch-operator | 60 | patch:apply, patch:view |
| patch-viewer | 40 | patch:view |
| security-auditor | 50 | audit:*, compliance:* |

## 📊 Status

- **Total Lines:** 18,200+
- **Total Files:** 76
- **Tests Passing:** 14/14 (100%)
- **Status:** ✅ Production Ready

## 📞 Support

- **Docs:** `docs/`
- **Examples:** `examples/`
- **API Ref:** `docs/SECURITY_API_REFERENCE.md`
- **Hardening:** `docs/SECURITY_HARDENING_GUIDE.md`

---
*Quick Start v1.0.0*

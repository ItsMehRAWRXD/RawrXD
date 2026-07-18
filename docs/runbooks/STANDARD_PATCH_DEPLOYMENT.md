# Standard Patch Deployment Runbook
## RawrXD Hotpatch System

**Priority:** P2 - Normal  
**Estimated Time:** 15-30 minutes  
**Owner:** Patch Operator or Patch Admin

---

## Prerequisites

- [ ] Valid RBAC role (patch-operator or higher)
- [ ] Patch bundle validated and signed
- [ ] Maintenance window scheduled (if required)
- [ ] Rollback plan prepared
- [ ] Stakeholders notified

---

## Pre-Deployment Phase (5 minutes)

### Step 1: Verify Permissions

```powershell
# Check current user role
.\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Operation check

# Verify patch permissions
$hasPermission = .\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 `
    -Operation check_permission `
    -PermissionName "patch:apply"

if (-not $hasPermission) {
    Write-Error "Insufficient permissions. Contact patch-admin."
    exit 1
}
```

### Step 2: System Health Check

```powershell
# Comprehensive status check
.\security\integration\secure_hotpatch.ps1 -Operation status

# Check compliance score
$compliance = .\security\phase_h_enterprise_security\compliance\compliance_checker.ps1 `
    -Operation check `
    -OutputFormat json |
    ConvertFrom-Json

if ($compliance.summary.compliance_score -lt 80) {
    Write-Warning "Compliance score below threshold. Proceed with caution."
}
```

### Step 3: Review Patch Metadata

```powershell
# Load and validate patch
$patchPath = "patches/swarm-fix-v1.2.3.json"
$patch = Get-Content $patchPath | ConvertFrom-Json

# Display patch info
Write-Host "Patch Information:" -ForegroundColor Cyan
Write-Host "  ID: $($patch.patch_id)"
Write-Host "  Version: $($patch.version)"
Write-Host "  System: $($patch.system_type)"
Write-Host "  Description: $($patch.description)"
Write-Host "  Author: $($patch.author)"
Write-Host "  Created: $($patch.created_at)"
Write-Host "  Components: $($patch.components -join ', ')"
```

---

## Deployment Phase (10-15 minutes)

### Step 4: Dry-Run Validation

```powershell
# Execute dry-run
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation dryrun `
    -PatchPath $patchPath

# Check exit code
if ($LASTEXITCODE -ne 0) {
    Write-Error "Dry-run failed. Aborting deployment."
    exit 1
}
```

**Expected Output:**
```
✓ RBAC check passed
✓ Compliance check passed (Score: 95%)
✓ Patch validation passed
✓ Security checks passed

Dry-run completed successfully.
Ready for deployment.
```

### Step 5: Create Backup

```powershell
# Backup current state
$backupDir = "backups/pre-patch-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force

# Backup relevant directories
$components = $patch.components
foreach ($component in $components) {
    $source = "src/swarm/$component"
    $dest = "$backupDir/$component"
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination $dest -Recurse -Force
    }
}

Write-Host "Backup created at: $backupDir"
```

### Step 6: Execute Deployment

```powershell
# Apply patch with full security
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `
    -Operation apply `
    -PatchPath $patchPath

# Check result
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Patch deployed successfully" -ForegroundColor Green
} else {
    Write-Error "❌ Patch deployment failed"
    exit 1
}
```

**Confirmation Prompt:**
```
⚠️  DESTRUCTIVE OPERATION WARNING
This will apply patches to the swarm system.

Patch: patches/swarm-fix-v1.2.3.json
System: swarm
Operation: apply
Backup: backups/pre-patch-20260713-143022

Are you sure you want to continue? (yes/no): 
```

---

## Post-Deployment Phase (5-10 minutes)

### Step 7: Verify Deployment

```powershell
# Check patch status
.\security\phase_g1_hotpatch\registry\patch_registry.ps1 `
    -Operation get `
    -PatchId $patch.patch_id

# Verify system health
.\security\integration\secure_hotpatch.ps1 -Operation status

# Check component health
foreach ($component in $patch.components) {
    $status = Test-ComponentHealth -Component $component
    Write-Host "Component $component`: $status"
}
```

### Step 8: Run Smoke Tests

```powershell
# Execute smoke tests
.\tests\smoke\run_smoke_tests.ps1 -System swarm

# Check results
$testResults = Get-Content "logs/smoke_test_results.json" | ConvertFrom-Json
if ($testResults.pass_rate -ge 95) {
    Write-Host "✅ Smoke tests passed" -ForegroundColor Green
} else {
    Write-Warning "⚠️ Smoke tests showed issues. Monitor closely."
}
```

### Step 9: Monitor Metrics

```powershell
# Watch key metrics for 5 minutes
$endTime = (Get-Date).AddMinutes(5)
while ((Get-Date) -lt $endTime) {
    $metrics = Get-SystemMetrics
    Write-Host "$(Get-Date -Format 'HH:mm:ss') - CPU: $($metrics.cpu)%, Memory: $($metrics.memory)%, Errors: $($metrics.errors)"
    
    if ($metrics.errors -gt 10) {
        Write-Warning "Elevated error rate detected!"
    }
    
    Start-Sleep -Seconds 30
}
```

---

## Completion Checklist

### Immediate (0-5 minutes)

- [ ] Patch status shows "applied"
- [ ] System status is healthy
- [ ] No critical errors in logs
- [ ] Smoke tests pass
- [ ] Metrics within normal range

### Short-term (5-30 minutes)

- [ ] Monitor error rates
- [ ] Check user-facing functionality
- [ ] Verify dependent systems
- [ ] Update deployment documentation

### Long-term (30+ minutes)

- [ ] Close maintenance window
- [ ] Notify stakeholders of completion
- [ ] Schedule post-deployment review
- [ ] Update CMDB

---

## Rollback Decision Matrix

| Condition | Action | Timeframe |
|-----------|--------|-----------|
| Critical error within 5 min | Immediate rollback | < 2 min |
| Error rate >10% | Evaluate rollback | < 10 min |
| Performance degradation >20% | Evaluate rollback | < 15 min |
| Smoke test failures | Immediate rollback | < 5 min |
| Compliance violation | Immediate rollback | < 2 min |

---

## Communication

### Deployment Start

```
🔧 DEPLOYMENT STARTED

Patch: [PATCH_ID]
System: [SYSTEM_NAME]
Engineer: [NAME]
Time: [TIMESTAMP]

Maintenance window: [START] - [END]
Expected duration: 30 minutes

No action required from users.
```

### Deployment Complete

```
✅ DEPLOYMENT COMPLETE

Patch: [PATCH_ID]
System: [SYSTEM_NAME]
Duration: [MINUTES] minutes
Status: SUCCESS

All systems operational.
Smoke tests: PASSED
Monitoring: ACTIVE

Maintenance window closed.
```

---

## Troubleshooting

### Deployment Fails at RBAC Check

```powershell
# Check current permissions
.\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Operation check

# Request elevation (if patch-admin)
.\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 `
    -Operation assign_role `
    -UserId $env:USERNAME `
    -RoleName "patch-admin"
```

### Deployment Fails at Compliance Check

```powershell
# Get detailed compliance report
.\security\phase_h_enterprise_security\compliance\compliance_checker.ps1 `
    -Operation check `
    -OutputFormat json |
    ConvertFrom-Json |
    Select-Object -ExpandProperty failed_controls

# Address failed controls or request waiver
```

### Patch Validation Fails

```powershell
# Validate patch format
$patch = Get-Content $patchPath | ConvertFrom-Json
$requiredFields = @("patch_id", "version", "system_type", "components", "files")
foreach ($field in $requiredFields) {
    if (-not $patch.$field) {
        Write-Error "Missing required field: $field"
    }
}
```

---

## Related Runbooks

- [Emergency Rollback](./EMERGENCY_ROLLBACK_RUNBOOK.md)
- [Compliance Violation Response](./COMPLIANCE_VIOLATION.md)
- [Security Incident Response](./SECURITY_INCIDENT_RESPONSE.md)

---

*Runbook Version: 1.0.0*  
*Last Updated: 2026-07-13*

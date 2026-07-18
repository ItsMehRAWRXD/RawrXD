# Emergency Rollback Runbook
## RawrXD Hotpatch System

**Priority:** P0 - Critical  
**Estimated Time:** 5-15 minutes  
**Owner:** On-Call Engineer

---

## Trigger Conditions

Execute this runbook when:
- ⚠️ System instability after patch deployment
- ⚠️ Critical functionality broken
- ⚠️ Security vulnerability introduced
- ⚠️ Performance degradation >50%
- ⚠️ Data integrity issues
- ⚠️ Service availability <99%

---

## Immediate Actions (First 2 Minutes)

### 1. Assess Severity

```powershell
# Check system status
.\security\integration\secure_hotpatch.ps1 -Operation status

# Check recent audit logs
Get-Content "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl" |
    ConvertFrom-Json |
    Select-Object -Last 10
```

**Decision Tree:**
```
Is system completely down?
├── YES → Execute Emergency Rollback (Section 3)
└── NO → Is functionality degraded?
    ├── YES → Execute Standard Rollback (Section 2)
    └── NO → Monitor and document
```

### 2. Notify Stakeholders

**Immediate (Slack #incidents):**
```
🚨 INCIDENT: Hotpatch rollback required
System: [swarm|agent|tools|unified]
Patch: [patch name]
Severity: [P0|P1|P2]
Impact: [description]
Engineer: [your name]
ETA: [estimated time]
```

**Within 5 minutes:**
- Page on-call manager if P0
- Update status page if customer-facing
- Create incident ticket

---

## Standard Rollback (Degraded but Stable)

### Step 1: Identify Patch to Rollback

```powershell
# List recent patches
.\security\phase_g1_hotpatch\registry\patch_registry.ps1 -Operation list |
    Select-Object -First 10

# Get patch details
$patchId = "PATCH_ID_FROM_ABOVE"
.\security\phase_g1_hotpatch\registry\patch_registry.ps1 `
    -Operation get `
    -PatchId $patchId
```

### Step 2: Execute Rollback

```powershell
# Rollback with full security checks
.\security\integration\secure_hotpatch.ps1 `
    -SystemType swarm `  # Change to: agent, tools, or unified
    -Operation rollback `
    -PatchPath "patches/$patchId.json"
```

**Expected Output:**
```
RawrXD Secure Hotpatch System
==============================

⚠️  DESTRUCTIVE OPERATION WARNING
This will rollback patches from the swarm system.

Patch: patches/swarm-fix-v1.2.3.json
System: swarm
Operation: rollback

Are you sure you want to continue? (yes/no): 
```

**Type "yes" and press Enter**

### Step 3: Verify Rollback

```powershell
# Check system status
.\security\integration\secure_hotpatch.ps1 -Operation status

# Verify patch status
.\security\phase_g1_hotpatch\registry\patch_registry.ps1 -Operation list |
    Where-Object { $_.patch_id -eq "$patchId" }
```

**Success Criteria:**
- [ ] Status check shows all systems operational
- [ ] Patch status shows "rolled_back"
- [ ] No errors in output
- [ ] System functionality restored

### Step 4: Document

```powershell
# Add incident note
$note = @{
    timestamp = Get-Date -Format "o"
    incident_id = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    patch_id = "$patchId"
    action = "rollback"
    engineer = $env:USERNAME
    result = "success"
    notes = "System functionality restored"
} | ConvertTo-Json

Add-Content -Path "logs/incidents.jsonl" -Value $note
```

---

## Emergency Rollback (System Down)

### Step 1: Bypass Security Gates (Emergency Only)

```powershell
# ⚠️ WARNING: Only use in true emergencies
# This bypasses RBAC and compliance checks

# Set emergency mode
$env:HOTPATCH_EMERGENCY = "true"
$env:HOTPATCH_CONFIRM = "true"

# Execute direct rollback
.\security\phase_g1_hotpatch\swarm_hotpatch_manager.ps1 `
    -Operation rollback `
    -PatchPath "patches/swarm-fix-v1.2.3.json" `
    -Force
```

### Step 2: Direct Registry Update

If manager scripts fail, manually update registry:

```powershell
# Load registry
$registryPath = "security/phase_g1_hotpatch/registry/patch_registry.json"
$registry = Get-Content $registryPath | ConvertFrom-Json

# Find and update patch
$patch = $registry.patches | Where-Object { $_.patch_id -eq "$patchId" }
if ($patch) {
    $patch.status = "rolled_back"
    $patch.rolled_back_at = Get-Date -Format "o"
    $patch.rollback_reason = "emergency"
    
    # Save registry
    $registry | ConvertTo-Json -Depth 10 | Set-Content $registryPath
}
```

### Step 3: Manual Restoration

If automated rollback fails:

```powershell
# 1. Stop affected services
Stop-Service -Name "RawrXD-Swarm-*" -Force

# 2. Restore from backup
$backupPath = "backups/swarm-$(Get-Date -Format 'yyyyMMdd').zip"
Expand-Archive -Path $backupPath -DestinationPath "src/swarm" -Force

# 3. Restart services
Start-Service -Name "RawrXD-Swarm-*"

# 4. Verify
Get-Service -Name "RawrXD-Swarm-*"
```

### Step 4: Post-Emergency Actions

```powershell
# Clear emergency mode
Remove-Item Env:\HOTPATCH_EMERGENCY
Remove-Item Env:\HOTPATCH_CONFIRM

# Run full security audit
.\security\phase_h_enterprise_security\compliance\compliance_checker.ps1 `
    -Operation check

# Review audit logs
Get-Content "logs/audit/audit_$(Get-Date -Format 'yyyyMM').jsonl" |
    ConvertFrom-Json |
    Where-Object { $_.event_data.patch_id -eq "$patchId" }
```

---

## Post-Rollback Checklist

### Immediate (0-15 minutes)

- [ ] System status verified
- [ ] Functionality tested
- [ ] Stakeholders notified
- [ ] Incident ticket updated
- [ ] Audit logs reviewed

### Short-term (15-60 minutes)

- [ ] Monitor system metrics
- [ ] Check for cascading failures
- [ ] Verify dependent systems
- [ ] Update status page
- [ ] Begin root cause analysis

### Long-term (1-24 hours)

- [ ] Complete incident report
- [ ] Schedule post-mortem
- [ ] Update runbooks if needed
- [ ] Review patch testing process
- [ ] Implement preventive measures

---

## Communication Templates

### Initial Notification

```
🚨 INCIDENT: Hotpatch rollback in progress

Time: [TIMESTAMP]
System: [SYSTEM_NAME]
Patch: [PATCH_ID]
Severity: P0

Impact: [BRIEF_DESCRIPTION]
Action: Rolling back to previous stable state
ETA: 10 minutes

Updates will be posted every 5 minutes.
```

### Resolution Notification

```
✅ INCIDENT RESOLVED: Hotpatch rollback complete

Time: [TIMESTAMP]
System: [SYSTEM_NAME]
Patch: [PATCH_ID]
Duration: [MINUTES] minutes

Resolution: Successfully rolled back to stable state
Impact: Service fully restored

Post-mortem scheduled: [DATE/TIME]
```

---

## Troubleshooting

### Rollback Stuck

```powershell
# Check for locks
Get-Process | Where-Object { $_.ProcessName -like "*hotpatch*" }

# Kill stuck processes
Get-Process | Where-Object { $_.ProcessName -like "*hotpatch*" } | Stop-Process -Force

# Clear lock files
Remove-Item -Path "logs/*.lock" -Force
```

### Registry Corruption

```powershell
# Restore registry from backup
$backupRegistry = "backups/patch_registry_$(Get-Date -Format 'yyyyMMdd').json"
Copy-Item $backupRegistry "security/phase_g1_hotpatch/registry/patch_registry.json"

# Re-initialize
.\security\phase_g1_hotpatch\registry\patch_registry.ps1 -Operation initialize
```

### Permission Denied

```powershell
# Check current user
whoami

# Check RBAC
.\security\phase_h_enterprise_security\rbac\rbac_manager.ps1 -Operation check

# Emergency: Use super-admin account
# Contact: security-team@rawrxd.local
```

---

## Escalation Matrix

| Time | Action | Contact |
|------|--------|---------|
| 0 min | Begin rollback | On-Call Engineer |
| 5 min | Notify manager | Engineering Manager |
| 10 min | Escalate to L3 | Senior Engineer |
| 15 min | Page CTO | CTO |
| 30 min | War room | All stakeholders |

---

## Related Runbooks

- [Standard Patch Deployment](./STANDARD_PATCH_DEPLOYMENT.md)
- [Security Incident Response](./SECURITY_INCIDENT_RESPONSE.md)
- [Compliance Violation Response](./COMPLIANCE_VIOLATION.md)

---

*Runbook Version: 1.0.0*  
*Last Tested: 2026-07-13*  
*Next Review: 2026-08-13*

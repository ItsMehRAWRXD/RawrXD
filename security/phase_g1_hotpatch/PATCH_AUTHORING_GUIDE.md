# Patch Authoring Guide

## Overview

This guide explains how to create, test, and deploy hotpatches for RawrXD using the Phase G.1 hotpatch system.

## Quick Start

### 1. Choose a Template

Select the appropriate template from `templates/`:

- **Security Hotfix** (`security_hotfix_template.json`) - Critical security patches
- **Performance Optimization** (`performance_optimization_template.json`) - Performance improvements
- **Configuration Update** (`config_update_template.json`) - Configuration changes
- **Emergency Rollback** (`emergency_rollback_template.json`) - Emergency procedures
- **Feature Flag** (`feature_flag_template.json`) - Gradual feature rollouts

### 2. Create Your Patch Bundle

Copy the template and customize:

```powershell
Copy-Item templates\security_hotfix_template.json patches\security\my_hotfix.json
```

### 3. Fill in Required Fields

```json
{
  "BundleId": "security-hotfix-20260713-001",
  "Version": "1.0.0",
  "Type": "security",
  "Severity": "critical",
  "Description": "Brief description of the patch",
  "Author": "your-email@rawrxd.ai",
  "CreatedAt": "2026-07-13T14:30:00Z",
  "ExpiresAt": "2026-08-13T14:30:00Z"
}
```

### 4. Define Patches

```json
"Patches": [
  {
    "System": "tools",           // swarm, agent, or tools
    "Target": "cli",             // component within system
    "PatchFile": "patches/security/fix_v1.0.1.json",
    "Priority": 1,                 // 1 = highest, 3 = lowest
    "RequiresRestart": false,
    "BackupRequired": true
  }
]
```

### 5. Test Your Patch

```powershell
# Unit tests
.\testing\patch_test_framework.ps1 -PatchBundle patches\security\my_hotfix.json -TestLevel unit

# Integration tests
.\testing\patch_test_framework.ps1 -PatchBundle patches\security\my_hotfix.json -TestLevel integration

# Full validation
.\testing\patch_test_framework.ps1 -PatchBundle patches\security\my_hotfix.json -TestLevel full
```

### 6. Register in Registry

```powershell
.\registry\patch_registry.ps1 -Action register -PatchBundle patches\security\my_hotfix.json
```

### 7. Deploy

```powershell
# Dry run first
.\unified_hotpatch_orchestrator.ps1 -Action apply -System all -PatchBundle patches\security\my_hotfix.json -DryRun

# Apply for real
.\unified_hotpatch_orchestrator.ps1 -Action apply -System all -PatchBundle patches\security\my_hotfix.json
```

## Patch Bundle Schema

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `BundleId` | string | Unique identifier for the patch bundle |
| `Version` | string | Semantic version (e.g., "1.0.0") |
| `Type` | string | One of: security, performance, configuration, feature, emergency |
| `Severity` | string | One of: critical, high, medium, low |
| `Description` | string | Human-readable description |
| `Author` | string | Email of the patch author |
| `CreatedAt` | string | ISO 8601 timestamp |
| `ExpiresAt` | string | ISO 8601 timestamp |
| `Patches` | array | List of individual patches |

### Patch Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `System` | string | Target system: swarm, agent, tools |
| `Target` | string | Component: coordinator, worker, cli, etc. |
| `PatchFile` | string | Path to patch file (relative to bundle) |
| `Priority` | int | 1-3, lower is higher priority |
| `RequiresRestart` | bool | Whether component needs restart |
| `BackupRequired` | bool | Whether to create backup |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `Dependencies` | array | Required system versions |
| `Conflicts` | array | Incompatible patches |
| `Prerequisites` | object | Pre-patch requirements |
| `Rollback` | object | Rollback configuration |
| `Notifications` | object | Email notifications |
| `Metadata` | object | Additional metadata |

## Patch Types

### Security Patches

**When to use:** Critical vulnerabilities, CVE fixes, security hardening

**Required metadata:**
```json
"Metadata": {
  "CVE": "CVE-2026-XXXX",
  "CVSS": 9.8,
  "AffectedVersions": ["1.0.0", "1.0.1"],
  "FixedVersions": ["1.0.2"],
  "ApprovalRequired": true
}
```

**Severity guidelines:**
- **Critical** (CVSS 9.0-10.0): Immediate deployment required
- **High** (CVSS 7.0-8.9): Deploy within 24 hours
- **Medium** (CVSS 4.0-6.9): Deploy within 1 week
- **Low** (CVSS 0.1-3.9): Deploy during next maintenance window

### Performance Patches

**When to use:** Throughput improvements, latency reductions, resource optimizations

**Required metadata:**
```json
"Metadata": {
  "ExpectedImprovement": {
    "ThroughputPercent": 15,
    "LatencyReductionPercent": 10,
    "MemoryReductionPercent": 5
  },
  "BenchmarkResults": "benchmarks/my_patch_results.json"
}
```

**Best practices:**
- Always include benchmark results
- Set minimum improvement threshold (5%)
- Test under realistic load

### Configuration Patches

**When to use:** Feature flags, tuning parameters, logging levels

**Required metadata:**
```json
"Metadata": {
  "ConfigChanges": [
    { "Key": "swarm.max_workers", "OldValue": "10", "NewValue": "20" }
  ]
}
```

**Best practices:**
- Document old and new values
- Include validation commands
- Test rollback path

### Feature Flag Patches

**When to use:** Gradual feature rollouts, A/B testing

**Required metadata:**
```json
"Metadata": {
  "FeatureName": "gpu_offloading",
  "RolloutPercentage": 10,
  "TargetAudience": "beta_users"
}
```

**Best practices:**
- Start with small percentage (5-10%)
- Monitor error rates closely
- Have rollback ready

## Testing Your Patch

### Unit Tests

Validates:
- JSON schema compliance
- Required fields present
- Patch file paths exist
- Dependency syntax

```powershell
.\testing\patch_test_framework.ps1 -PatchBundle my_patch.json -TestLevel unit
```

### Integration Tests

Validates:
- Dry-run execution
- Backup creation
- Prerequisites
- System availability

```powershell
.\testing\patch_test_framework.ps1 -PatchBundle my_patch.json -TestLevel integration
```

### Full Tests

Validates:
- End-to-end deployment
- Health checks
- Rollback capability
- Performance impact

```powershell
.\testing\patch_test_framework.ps1 -PatchBundle my_patch.json -TestLevel full
```

## Deployment Workflow

### 1. Local Development

```powershell
# Create patch
# Test locally
# Validate with test framework
```

### 2. Code Review

```powershell
# Submit PR
# CI/CD runs automated tests
# Peer review required for security patches
```

### 3. Staging Deployment

```powershell
# Deploy to staging
# Run smoke tests
# Monitor for 30 minutes
```

### 4. Production Deployment

```powershell
# Deploy to production
# Monitor health metrics
# Keep rollback ready
```

## Common Patterns

### Multi-System Patch

```json
"Patches": [
  { "System": "swarm", "Target": "coordinator", "PatchFile": "...", "Priority": 1 },
  { "System": "agent", "Target": "orchestrator", "PatchFile": "...", "Priority": 1 },
  { "System": "tools", "Target": "cli", "PatchFile": "...", "Priority": 2 }
]
```

### Dependency Declaration

```json
"Dependencies": [
  { "System": "swarm", "MinimumVersion": "1.0.0", "MaximumVersion": "1.0.99" },
  { "System": "agent", "MinimumVersion": "1.0.0" }
]
```

### Conflict Detection

```json
"Conflicts": [
  { "PatchId": "security-hotfix-*", "Reason": "Previous security patches must be reviewed" },
  { "PatchId": "config-change-*", "Reason": "Configuration changes may conflict" }
]
```

### Rollback Configuration

```json
"Rollback": {
  "AutomaticOnFailure": true,
  "MaxRetries": 3,
  "RetryDelaySeconds": 5,
  "NotifyOnRollback": ["ops@rawrxd.ai"]
}
```

## Troubleshooting

### Patch Fails Validation

1. Check JSON syntax: `Get-Content my_patch.json | ConvertFrom-Json`
2. Verify all required fields are present
3. Ensure patch files exist at specified paths
4. Check dependency versions match installed systems

### Patch Fails to Apply

1. Check system health: `.\unified_hotpatch_orchestrator.ps1 -Action health-check`
2. Verify prerequisites are met
3. Check for conflicting patches
4. Review logs in `$env:RAWRXD_HOME\logs\`

### Rollback Fails

1. Check backup integrity
2. Verify system is in consistent state
3. Use emergency rollback if needed
4. Contact on-call engineer

## Best Practices

1. **Always test in staging first**
2. **Create backups before patching**
3. **Use dry-run mode to validate**
4. **Monitor after deployment**
5. **Document all changes**
6. **Keep patches small and focused**
7. **Include rollback procedures**
8. **Set appropriate expiration dates**

## Examples

See `patches/` directory for example patch bundles:

- `security/cve_2026_0001_memory_safety.json` - Security hotfix
- `performance/inference_throughput_v1.1.0.json` - Performance optimization
- `config/logging_verbosity_v1.0.1.json` - Configuration update
- `features/beta_gpu_offloading_v1.1.0.json` - Feature flag
- `emergency/rollback_all_v1.0.0.json` - Emergency rollback

## Support

For questions or issues:
- Check the README.md in `security/phase_g1_hotpatch/`
- Review example patches in `patches/`
- Contact: hotpatch-team@rawrxd.ai

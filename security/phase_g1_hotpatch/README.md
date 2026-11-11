# Phase G.1: Extended Hotpatch System

## Overview

This directory contains the extended hotpatch system for RawrXD, providing runtime patching capabilities for:
- **Swarm components** (coordinator, workers, load balancer)
- **Agent components** (orchestrator, workers, tools, policy, memory)
- **Non-agentic tools** (CLI, utilities, extensions, plugins, scripts)

## Components

### 1. Swarm Hotpatch Manager (`swarm_hotpatch_manager.ps1`)
Manages hotpatching for swarm infrastructure components.

**Features:**
- Coordinator hotpatching
- Worker node updates
- Load balancer configuration changes
- Swarm-wide config updates
- Emergency failover patches

**Usage:**
```powershell
# Apply patch to coordinator
.\swarm_hotpatch_manager.ps1 -Action apply -Target coordinator -PatchFile .\patches\coord_v2.json

# Check status
.\swarm_hotpatch_manager.ps1 -Action status

# Emergency mode
.\swarm_hotpatch_manager.ps1 -Action emergency
```

### 2. Agent Hotpatch Manager (`agent_hotpatch_manager.ps1`)
Manages hotpatching for agentic framework components.

**Features:**
- Agent orchestrator updates
- Worker agent patches
- Tool configuration updates
- Policy engine updates
- Memory store configuration
- Agent-specific targeting

**Usage:**
```powershell
# Apply patch to all agent components
.\agent_hotpatch_manager.ps1 -Action apply -Target all -PatchFile .\patches\agent_v2.json

# Apply patch to specific agent
.\agent_hotpatch_manager.ps1 -Action apply -Target worker -AgentId "agent-001" -PatchFile .\patches\worker_v2.json

# Update policies
.\agent_hotpatch_manager.ps1 -Action policy-update -PatchFile .\patches\new_policies.json
```

### 3. Tools Hotpatch Manager (`tools_hotpatch_manager.ps1`)
Manages hotpatching for non-agentic tools and utilities.

**Features:**
- CLI tool updates
- Utility patches
- Extension management
- Plugin updates
- Script updates
- Library refreshes

**Usage:**
```powershell
# Scan for hotpatchable tools
.\tools_hotpatch_manager.ps1 -Action scan

# Apply patch to CLI tools
.\tools_hotpatch_manager.ps1 -Action apply -Target cli -PatchFile .\patches\cli_v2.json

# Apply patch to specific tool
.\tools_hotpatch_manager.ps1 -Action apply -Target scripts -ToolName "deploy.ps1" -PatchFile .\patches\deploy_v2.json
```

### 4. Unified Hotpatch Orchestrator (`unified_hotpatch_orchestrator.ps1`)
Coordinates hotpatching across all systems with dependency management.

**Features:**
- Coordinated multi-system patches
- Dependency validation
- Conflict detection
- Rollback coordination
- System health monitoring
- Emergency procedures

**Usage:**
```powershell
# Apply coordinated patch bundle
.\unified_hotpatch_orchestrator.ps1 -Action apply -System all -PatchBundle .\patches\hotfix_v1.1.json

# Check all systems status
.\unified_hotpatch_orchestrator.ps1 -Action status

# Health check
.\unified_hotpatch_orchestrator.ps1 -Action health-check

# Sync systems
.\unified_hotpatch_orchestrator.ps1 -Action sync
```

## Patch Bundle Format

```json
{
  "Version": "1.1.0",
  "Description": "Critical security fix for all systems",
  "Patches": [
    {
      "System": "tools",
      "Target": "cli",
      "PatchFile": "patches/cli_security_v1.1.json"
    },
    {
      "System": "agent",
      "Target": "orchestrator",
      "PatchFile": "patches/agent_security_v1.1.json"
    },
    {
      "System": "swarm",
      "Target": "coordinator",
      "PatchFile": "patches/swarm_security_v1.1.json"
    }
  ],
  "Dependencies": [
    { "System": "tools", "MinimumVersion": "1.0.0" },
    { "System": "agent", "MinimumVersion": "1.0.0" }
  ],
  "Conflicts": [
    { "PatchId": "old-security-patch" }
  ]
}
```

## Safety Features

1. **Backup Creation**: Automatic backups before applying patches
2. **Health Checks**: Component health validation before patching
3. **Dry Run Mode**: Test patches without applying
4. **Dependency Validation**: Ensure prerequisites are met
5. **Conflict Detection**: Prevent incompatible patches
6. **Coordinated Rollback**: Rollback all systems if any fails
7. **Emergency Mode**: Quick fixes for critical issues

## Integration

These hotpatch managers integrate with:
- Existing `unified_hotpatch_manager` (C++ layer)
- Phase G platform hardening
- Phase H enterprise security
- CI/CD pipelines for automated patching

## Status

| Component | Status | Lines |
|-----------|--------|-------|
| Swarm Hotpatch Manager | ✅ Complete | 450+ |
| Agent Hotpatch Manager | ✅ Complete | 500+ |
| Tools Hotpatch Manager | ✅ Complete | 450+ |
| Unified Orchestrator | ✅ Complete | 400+ |
| Patch Templates | ✅ Complete | 5 templates |
| Patch Test Framework | ✅ Complete | 600+ |
| Patch Dashboard | ✅ Complete | 500+ |
| CI/CD Integration | ✅ Complete | 250+ |
| **Total** | **✅ Complete** | **3,600+** |

## Patch Templates

Located in `templates/`:

- **security_hotfix_template.json** - Critical security patches with CVE tracking
- **performance_optimization_template.json** - Performance improvements with benchmarking
- **config_update_template.json** - Configuration changes across systems
- **emergency_rollback_template.json** - Emergency rollback procedures
- **feature_flag_template.json** - Gradual feature rollouts

## Testing Framework

Located in `testing/patch_test_framework.ps1`:

**Test Levels:**
- **Unit**: Schema validation, dependency checks, conflict detection
- **Integration**: Dry-run tests, backup creation, prerequisites
- **Full**: Health checks, end-to-end validation

**Usage:**
```powershell
.\patch_test_framework.ps1 -PatchBundle patches\hotfix.json -TestLevel full
```

## CI/CD Integration

Workflow: `.github/workflows/hotpatch-automation.yml`

**Features:**
- Automatic patch validation on PR
- Schema validation
- Multi-level testing (unit/integration/full)
- Dry-run deployment
- Staged deployment (staging → production)
- Health monitoring post-deployment
- Slack notifications

**Manual Trigger:**
```yaml
workflow_dispatch:
  inputs:
    patch_bundle: "patches/security_fix.json"
    test_level: "full"
    dry_run: true
    environment: "staging"
```

## Monitoring Dashboard

Located in `monitoring/patch_dashboard.ps1`:

**Modes:**
- **Console**: Real-time terminal dashboard with auto-refresh
- **HTML**: Web-based dashboard with auto-refresh
- **JSON**: Export for external monitoring systems

**Usage:**
```powershell
# Console mode (interactive)
.\patch_dashboard.ps1 -RefreshInterval 5

# HTML export
.\patch_dashboard.ps1 -OutputMode html -OutputPath dashboard.html

# JSON export
.\patch_dashboard.ps1 -OutputMode json -OutputPath status.json
```

**Dashboard Features:**
- Real-time system status (Swarm, Agent, Tools)
- Active patch display
- System health metrics (CPU, Memory, Disk)
- Recent patch activity history
- Interactive commands (Refresh, History, Details, Export)

## Patch Registry

Located in `registry/patch_registry.ps1`:

**Features:**
- Centralized patch tracking
- Status management (pending, active, failed, rolled-back)
- History tracking
- Expiration management
- Statistics and reporting

**Usage:**
```powershell
# Register a patch
.\registry\patch_registry.ps1 -Action register -PatchBundle patches\hotfix.json

# List all patches
.\registry\patch_registry.ps1 -Action list

# Get patch status
.\registry\patch_registry.ps1 -Action status -BundleId "hotfix-001"

# View statistics
.\registry\patch_registry.ps1 -Action status

# Cleanup expired patches
.\registry\patch_registry.ps1 -Action cleanup

# Validate registry integrity
.\registry\patch_registry.ps1 -Action validate
```

## Sample Patches

Located in `patches/`:

- **security/cve_2026_0001_memory_safety.json** - Critical CVE fix
- **performance/inference_throughput_v1.1.0.json** - 15% throughput improvement
- **config/logging_verbosity_v1.0.1.json** - Structured logging update
- **features/beta_gpu_offloading_v1.1.0.json** - 10% rollout feature
- **emergency/rollback_all_v1.0.0.json** - Emergency rollback procedure

## Documentation

- **README.md** - This file
- **PATCH_AUTHORING_GUIDE.md** - Complete guide for patch authors
- **PHASE_G1_COMPLETION.md** - Phase completion report

## Quick Start

```powershell
# 1. Create a patch from template
Copy-Item templates\security_hotfix_template.json patches\my_patch.json

# 2. Edit the patch
notepad patches\my_patch.json

# 3. Test the patch
.\testing\patch_test_framework.ps1 -PatchBundle patches\my_patch.json -TestLevel full

# 4. Register the patch
.\registry\patch_registry.ps1 -Action register -PatchBundle patches\my_patch.json

# 5. Deploy (dry-run first)
.\unified_hotpatch_orchestrator.ps1 -Action apply -System all -PatchBundle patches\my_patch.json -DryRun

# 6. Deploy for real
.\unified_hotpatch_orchestrator.ps1 -Action apply -System all -PatchBundle patches\my_patch.json

# 7. Monitor
.\monitoring\patch_dashboard.ps1 -RefreshInterval 5
```

# RawrXD OMEGA-1 Scripts Documentation

## Overview

This directory contains 17 PowerShell automation scripts for managing, monitoring, and maintaining RawrXD OMEGA-1.

## Script Categories

### 🧪 Testing & Validation (4 scripts)

| Script | Purpose | Usage |
|--------|---------|-------|
| `test_runner.ps1` | Comprehensive test orchestration | `.\test_runner.ps1 -Suite all` |
| `dual_gpu_live_test.ps1` | Dual GPU validation | `.\dual_gpu_live_test.ps1` |
| `ipc_validation_test.ps1` | IPC protocol testing | `.\ipc_validation_test.ps1` |
| `e2e_integration_test.ps1` | End-to-end integration | `.\e2e_integration_test.ps1` |

**Test Suites:**
- `all` - Run all tests
- `quick` - Fast validation only
- `gpu` - GPU-specific tests
- `ipc` - IPC communication tests
- `integration` - Integration tests
- `performance` - Performance benchmarks
- `ci` - CI/CD optimized suite

### 🔧 Build & Deployment (3 scripts)

| Script | Purpose | Usage |
|--------|---------|-------|
| `build_omega1_full.ps1` | Full build pipeline | `.\build_omega1_full.ps1` |
| `create_release_package.ps1` | Create release archive | `.\create_release_package.ps1` |
| `deploy_omega1.ps1` | Automated deployment | `.\deploy_omega1.ps1 -InstallDir "C:\RawrXD"` |

### 📊 Monitoring & Diagnostics (3 scripts)

| Script | Purpose | Usage |
|--------|---------|-------|
| `health_monitor.ps1` | Real-time health monitoring | `.\health_monitor.ps1 -RefreshInterval 5` |
| `diagnostic_toolkit.ps1` | Comprehensive diagnostics | `.\diagnostic_toolkit.ps1` |
| `troubleshoot.ps1` | Automated troubleshooting | `.\troubleshoot.ps1 -Category all -AutoFix` |

### ⚙️ Operations & Management (5 scripts)

| Script | Purpose | Usage |
|--------|---------|-------|
| `model_manager.ps1` | Model management | `.\model_manager.ps1 -Action list` |
| `log_rotator.ps1` | Log rotation | `.\log_rotator.ps1 -MaxSizeMB 100` |
| `service_wrapper.ps1` | Service management | `.\service_wrapper.ps1 -Action start` |
| `omega1_backup.ps1` | Backup/restore | `.\omega1_backup.ps1 -Action backup` |
| `config_wizard.ps1` | Interactive configuration | `.\config_wizard.ps1` |

### 🔄 Updates & Maintenance (2 scripts)

| Script | Purpose | Usage |
|--------|---------|-------|
| `update_system.ps1` | Update management | `.\update_system.ps1 -Action check` |
| `performance_benchmark.ps1` | TPS benchmarking | `.\performance_benchmark.ps1` |

## Quick Reference

### Daily Operations

```powershell
# Check system health
.\health_monitor.ps1 -RefreshInterval 5

# Run quick tests
.\test_runner.ps1 -Suite quick

# View logs
Get-Content ..\logs\omega1.log -Tail 50
```

### Weekly Maintenance

```powershell
# Rotate logs
.\log_rotator.ps1 -MaxSizeMB 100

# Create backup
.\omega1_backup.ps1 -Action backup

# Check for updates
.\update_system.ps1 -Action check
```

### Troubleshooting

```powershell
# Run diagnostics
.\diagnostic_toolkit.ps1

# Auto-fix common issues
.\troubleshoot.ps1 -Category all -AutoFix

# Check specific component
.\troubleshoot.ps1 -Category gpu
```

### CI/CD Integration

```powershell
# CI test suite
.\test_runner.ps1 -Suite ci -FailFast

# Build and package
.\build_omega1_full.ps1
.\create_release_package.ps1
```

## Common Parameters

Most scripts support these parameters:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-InstallDir` | Installation directory | `d:\rawrxd` |
| `-BinDir` | Binary directory | `d:\rawrxd\build\bin` |
| `-Verbose` | Enable verbose output | `$false` |
| `-DryRun` | Simulate without executing | `$false` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Test failure |
| 3 | Build failure |
| 4 | Deployment failure |

## Script Dependencies

- PowerShell 5.1 or later
- Windows 10/11 (64-bit)
- Administrative privileges (for some operations)

## Support

For detailed documentation, see:
- `OMEGA1_FINAL_REPORT.md` - Technical documentation
- `QUICKSTART.md` - Quick start guide
- `OMEGA1_API.md` - API reference

---

*RawrXD OMEGA-1 Scripts v1.0.0*

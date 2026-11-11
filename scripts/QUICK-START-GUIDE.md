# RawrXD Production Tooling Suite - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Use the Unified CLI

All operations are accessible through the unified CLI:

```powershell
# Navigate to scripts directory
cd D:\rawrxd\scripts

# Show all available commands
.\rawrxd-cli.ps1 help

# Check system status
.\rawrxd-cli.ps1 health check
```

### Step 2: Build the Project

```powershell
# Quick incremental build (2-5 minutes)
.\rawrxd-cli.ps1 build quick

# Full build with all optimizations (15-30 minutes)
.\rawrxd-cli.ps1 build full

# Release build with signing
.\rawrxd-cli.ps1 build release -Version 3.2.0
```

### Step 3: Run Tests

```powershell
# Quick smoke tests (1-2 minutes)
.\rawrxd-cli.ps1 test smoke

# Full test suite with coverage (10-20 minutes)
.\rawrxd-cli.ps1 test all -Coverage

# Specific test category
.\rawrxd-cli.ps1 test unit -Filter Core
```

### Step 4: Analyze Codebase (Critical!)

```powershell
# Analyze 9,001 unlinked files - generates reports
.\rawrxd-cli.ps1 analyze unlinked

# View the generated report
start analysis\unlinked-files\unlinked-analysis-report.html
```

### Step 5: Deploy

```powershell
# Deploy to staging
.\rawrxd-cli.ps1 deploy staging

# Deploy to production with blue-green strategy
.\rawrxd-cli.ps1 deploy production -Strategy blue-green
```

---

## 📋 Common Tasks Cheat Sheet

### Development Workflow

```powershell
# Start new feature
.\git-workflow-automation.ps1 -Action feature -BranchName my-feature -Push

# Check code quality before commit
.\code-quality-gate.ps1 -Mode pre-commit

# Run security scan
.\security-scanner.ps1 -ScanType quick

# Sync with remote
.\git-workflow-automation.ps1 -Action sync

# Clean up merged branches
.\git-workflow-automation.ps1 -Action cleanup
```

### Monitoring & Health

```powershell
# Start continuous monitoring
.\rawrxd-cli.ps1 monitor start

# Check workspace health
.\rawrxd-cli.ps1 health check

# Clean up temp files
.\rawrxd-cli.ps1 health cleanup

# View performance dashboard
.\performance-dashboard.ps1 -Format html
```

### Model Management

```powershell
# List registered models
.\rawrxd-cli.ps1 model list

# Add new model
.\rawrxd-cli.ps1 model add -Path D:\models\my-model.gguf

# Verify model integrity
.\rawrxd-cli.ps1 model verify -ModelId my-model

# Download from HuggingFace
.\rawrxd-cli.ps1 model download -Source huggingface -ModelId my-model
```

### Documentation

```powershell
# Generate all documentation
.\rawrxd-cli.ps1 docs generate

# Serve documentation locally
.\rawrxd-cli.ps1 docs serve -Port 8080

# Generate API reference only
.\rawrxd-cli.ps1 docs api
```

---

## 🔧 Advanced Usage

### Direct Script Execution

For advanced scenarios, use scripts directly with full parameter control:

```powershell
# Analyze unlinked files with custom options
.\analyze-unlinked-files.ps1 `
    -SourceDir D:\rawrxd\src `
    -GenerateReport `
    -ExportFormat json,html,cmake `
    -MinLines 50

# Security scan with auto-fix
.\security-scanner.ps1 `
    -ScanType full `
    -OutputFormat html `
    -AutoFix `
    -FailOnFinding

# Generate dependency visualization
.\dependency-visualizer.ps1 `
    -Format all `
    -FindCircular `
    -ShowStats

# Create release with all options
.\release-manager.ps1 `
    -Action full `
    -Version v3.2.0 `
    -SignArtifacts `
    -CertificateThumbprint ABC123 `
    -GitHubToken ghp_xxxxxxxx
```

### CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Build
  run: .\scripts\rawrxd-cli.ps1 build full

- name: Test
  run: .\scripts\rawrxd-cli.ps1 test all -Coverage

- name: Security Scan
  run: .\scripts\security-scanner.ps1 -ScanType full -FailOnFinding

- name: Deploy
  if: github.ref == 'refs/heads/main'
  run: .\scripts\rawrxd-cli.ps1 deploy production
```

---

## 🎯 Key Features by Category

### Build & Development
- ✅ Parallel builds with intelligent caching
- ✅ Automatic dependency resolution
- ✅ Cross-platform support (Windows/Linux/macOS)
- ✅ Auto-retry on transient failures

### Testing
- ✅ 7 test tiers: Unit, Integration, Performance, Stress, Compliance, Smoke, Regression
- ✅ Parallel test execution
- ✅ Code coverage tracking
- ✅ Multiple output formats (JSON, JUnit, HTML)

### Deployment
- ✅ Rolling deployment
- ✅ Blue-Green deployment
- ✅ Canary deployment with metrics
- ✅ 7-layer hotpatch system

### Analysis
- ✅ 9,001 unlinked file analysis
- ✅ Dependency visualization
- ✅ Security vulnerability scanning
- ✅ Code quality gates

### Monitoring
- ✅ Real-time health monitoring
- ✅ Performance dashboards
- ✅ Log aggregation
- ✅ Automated alerting

---

## 🆘 Troubleshooting

### Issue: Script won't execute
```powershell
# Check execution policy
Get-ExecutionPolicy

# Set execution policy (requires admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue: Build fails
```powershell
# Verify prerequisites
.\dev-setup.ps1 -Verify

# Clean and rebuild
.\rawrxd-cli.ps1 clean all
.\rawrxd-cli.ps1 build full
```

### Issue: Tests timeout
```powershell
# Increase timeout
.\test-harness.ps1 -TimeoutSeconds 600

# Run specific tests only
.\test-harness.ps1 -TestSuite smoke
```

### Issue: Security scan false positives
```powershell
# Add exclusions
.\security-scanner.ps1 -ExcludePatterns @("*.test.cpp", "*mock*")
```

---

## 📊 Performance Expectations

| Task | Duration | Command |
|------|----------|---------|
| Quick Build | 2-5 min | `build quick` |
| Full Build | 15-30 min | `build full` |
| Smoke Tests | 1-2 min | `test smoke` |
| Full Tests | 10-20 min | `test all` |
| Security Scan | 2-5 min | `security-scanner` |
| Analysis | 5-10 min | `analyze unlinked` |

---

## 🔗 Quick Links

- **Full Documentation**: `README-Production-Tooling.md`
- **Suite Summary**: `AUTOMATION-SUITE-SUMMARY.md`
- **Script Inventory**: `FINAL-TOOLING-INVENTORY.md`
- **Deliverable Doc**: `COMPLETE-SUITE-DELIVERABLE.md`

---

## 💡 Pro Tips

1. **Use Tab Completion**: PowerShell tab completion works with all scripts
2. **Dry Run Mode**: Add `-DryRun` to preview changes without executing
3. **Verbose Output**: Add `-Verbose` for detailed execution logs
4. **Parallel Jobs**: Adjust `-ParallelJobs` based on your CPU cores
5. **Cache Builds**: Builds are cached by SHA256 - reuse when possible

---

**Version**: 3.2.0  
**Last Updated**: 2025-01-20  
**Status**: Production Ready

*For detailed documentation, see README-Production-Tooling.md*

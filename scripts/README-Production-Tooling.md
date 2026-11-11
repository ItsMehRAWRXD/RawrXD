# RawrXD Production Tooling Suite

## Overview

This directory contains a comprehensive suite of production-grade PowerShell automation scripts for the **RawrXD Vision & Generation System v3.2.0**. These scripts provide complete coverage for development, build, test, deployment, and operational workflows.

## Quick Start

```powershell
# Use the unified CLI for all operations
.\rawrxd-cli.ps1 <command> [subcommand] [options]

# Examples:
.\rawrxd-cli.ps1 build full                    # Full build
.\rawrxd-cli.ps1 test smoke                    # Quick smoke tests
.\rawrxd-cli.ps1 deploy staging                 # Deploy to staging
.\rawrxd-cli.ps1 analyze unlinked               # Analyze unlinked files
```

## Script Categories

### 🏗️ Build & Development

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `build-orchestrator.ps1` | Comprehensive build management | Dependency resolution, SHA256 caching, parallel execution, auto-retry |
| `dev-setup.ps1` | Development environment setup | Chocolatey packages, VS Build Tools, CUDA, Docker |
| `integrate-unlinked-files.ps1` | Unlinked file integration | Compatibility testing, CMake generation, auto-integration |
| `code-quality-gate.ps1` | Pre-commit/CI quality checks | Syntax, style, complexity, security scanning |

### 🧪 Testing & Quality

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `test-harness.ps1` | Multi-tier testing framework | Unit/integration/performance/stress/compliance suites |
| `execute-analysis.ps1` | Analysis execution engine | Automated analysis runs, integration planning |
| `benchmark-runner.ps1` | Performance benchmarking | Quick/Standard/Extended/Stress benchmarks |

### 🚀 Deployment & Operations

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `deployment-orchestrator.ps1` | Multi-environment deployment | Rolling/Blue-Green/Canary/Hotpatch strategies |
| `hotpatch-manager.ps1` | 7-layer hotpatch management | PT Driver, Memory, Byte, Server, Live Binary, Shadow-Page, Sentinel |
| `workspace-health-monitor.ps1` | Continuous health monitoring | Disk, memory, CPU, process monitoring with alerts |

### 📊 Analysis & Reporting

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `analyze-unlinked-files.ps1` | Unlinked source file analysis | 9,001 file categorization, priority scoring, CMake suggestions |
| `performance-dashboard.ps1` | Performance visualization | HTML/Markdown/JSON dashboards with trends |
| `documentation-generator.ps1` | Automated documentation | API docs, architecture diagrams, guides |

### 🗄️ Model Management

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `model-registry-cli.ps1` | GGUF model registry | Add/remove/list/search/verify/download/import/export |
| `model-manager.ps1` | Model lifecycle management | 6 pre-configured models, quantization options |

### 🎛️ Unified Interface

| Script | Purpose | Key Features |
|--------|---------|--------------|
| `rawrxd-cli.ps1` | Unified command-line interface | Single entry point for all tooling |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RawrXD CLI (rawrxd-cli.ps1)               │
├─────────────────────────────────────────────────────────────┤
│  Build    Test    Deploy    Analyze    Monitor    Docs      │
│   │        │        │         │         │         │        │
│   ▼        ▼        ▼         ▼         ▼         ▼        │
│ ┌─────┐ ┌─────┐ ┌─────┐  ┌─────┐  ┌─────┐  ┌─────────┐     │
│ │Build│ │Test │ │Deploy│ │Analyze│ │Health│ │Generator│    │
│ │Orchestrator│ │Harness│ │Orchestrator│ │Monitor│ │Docs    │    │
│ └─────┘ └─────┘ └─────┘  └─────┘  └─────┘  └─────────┘     │
├─────────────────────────────────────────────────────────────┤
│              Specialized Tools (20+ scripts)                 │
│  • integrate-unlinked-files    • hotpatch-manager           │
│  • code-quality-gate          • performance-dashboard     │
│  • model-registry-cli         • workspace-health-monitor  │
│  • execute-analysis           • documentation-generator   │
│  • benchmark-runner           • [and more...]             │
└─────────────────────────────────────────────────────────────┘
```

## Key Capabilities

### Build Orchestration
- **Dependency Resolution**: Automatic target ordering based on dependencies
- **Intelligent Caching**: SHA256-based build caching to skip unchanged targets
- **Parallel Execution**: Multi-threaded builds with configurable worker count
- **Auto-Retry**: Automatic retry on transient failures (up to 3 attempts)

### Testing Framework
- **Multi-Tier**: Unit, integration, performance, stress, compliance, smoke, regression
- **Parallel Execution**: Run tests concurrently with worker pools
- **Multiple Formats**: Console, JSON, JUnit, HTML reports
- **Coverage Integration**: Code coverage tracking with thresholds

### Deployment Strategies
- **Rolling**: Gradual rollout across instances
- **Blue-Green**: Zero-downtime environment switching
- **Canary**: Percentage-based traffic splitting with metrics
- **Hotpatch**: 7-layer runtime patching without restart

### Analysis & Monitoring
- **Unlinked File Analysis**: Categorize and prioritize 9,001 unlinked source files
- **Health Monitoring**: Continuous disk, memory, CPU, and process monitoring
- **Performance Dashboard**: Visual performance metrics with trends
- **Quality Gates**: Pre-commit and CI quality checks

## Configuration

Most scripts support configuration via:
- Command-line parameters
- JSON configuration files
- Environment variables

Example configuration file (`config.json`):
```json
{
  "Build": {
    "ParallelJobs": 8,
    "CacheEnabled": true,
    "MaxRetries": 3
  },
  "Test": {
    "TimeoutSeconds": 300,
    "CoverageThreshold": 80
  },
  "Deployment": {
    "HealthCheckRetries": 5,
    "RollbackOnFailure": true
  }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Build failure |
| 3 | Test failure |
| 4 | Deployment failure |
| 5 | Quality gate failure |
| 6 | Health check failure |

## Logging

All scripts support structured logging:
- Console output with color coding
- File logging to `logs/` directory
- JSON format for machine parsing
- Integration with external log aggregation

## Integration

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Build
  run: .\scripts\rawrxd-cli.ps1 build full
  
- name: Test
  run: .\scripts\rawrxd-cli.ps1 test all -Coverage
  
- name: Deploy
  run: .\scripts\rawrxd-cli.ps1 deploy staging
```

### IDE Integration
Most scripts can be integrated into VS Code tasks:
```json
{
  "label": "Build RawrXD",
  "type": "shell",
  "command": "${workspaceFolder}/scripts/rawrxd-cli.ps1",
  "args": ["build", "quick"],
  "group": "build"
}
```

## Performance

| Operation | Typical Duration | Parallel Speedup |
|-----------|------------------|------------------|
| Quick Build | 2-5 min | 2-3x |
| Full Build | 15-30 min | 4-6x |
| Smoke Tests | 1-2 min | 3-4x |
| Full Test Suite | 10-20 min | 5-8x |
| Analysis | 5-10 min | N/A |

## Security

- All scripts validate inputs and sanitize paths
- No hardcoded credentials (use environment variables)
- Support for secure credential storage (Windows Credential Manager)
- Audit logging for sensitive operations

## Troubleshooting

### Common Issues

**Build fails with "CMake not found"**
```powershell
.\dev-setup.ps1 -InstallCMake
```

**Tests timeout**
```powershell
.\test-harness.ps1 -TimeoutSeconds 600
```

**Disk space low**
```powershell
.\rawrxd-cli.ps1 clean all
.\workspace-health-monitor.ps1 -Cleanup
```

### Debug Mode

Add `-Verbose` to any script for detailed output:
```powershell
.\build-orchestrator.ps1 -Verbose
```

## Contributing

When adding new scripts:
1. Follow the existing naming convention (`verb-noun.ps1`)
2. Include proper parameter validation
3. Add color-coded output functions
4. Support `-Verbose` and `-WhatIf` modes
5. Document in this README

## License

These scripts are part of the RawrXD project and follow the same license terms.

## Support

For issues or questions:
1. Check script help: `.\script-name.ps1 -Help`
2. Review logs in `logs/` directory
3. Run with `-Verbose` for detailed output
4. Contact the RawrXD development team

---

**Version**: 3.2.0  
**Last Updated**: 2025-01-20  
**Maintainer**: RawrXD Development Team

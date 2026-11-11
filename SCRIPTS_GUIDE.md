# Sovereign Substrate - Scripts Guide

This directory contains utility scripts for building, deploying, and managing the Sovereign Substrate.

## Quick Start Scripts

### `quick-start.sh` (Linux/macOS)
One-command setup for the Sovereign Substrate.

```bash
./scripts/quick-start.sh
```

**What it does:**
- Checks prerequisites
- Creates build directory
- Configures with CMake
- Builds the project
- Runs tests
- Runs the demo

### `quick-start.ps1` (Windows)
PowerShell version of quick-start.

```powershell
.\scripts\quick-start.ps1
```

## Deployment Scripts

### `deploy-sovereign.sh` (Linux/macOS)
Production deployment with automated rollback.

```bash
# Deploy to staging
./scripts/deploy-sovereign.sh staging 1.0.0

# Deploy to production
./scripts/deploy-sovereign.sh production 1.0.0
```

### `deploy-sovereign.ps1` (Windows)
PowerShell deployment script.

```powershell
.\scripts\deploy-sovereign.ps1 production 1.0.0
```

## Benchmarking

### `benchmark.sh`
Performance benchmarking suite.

```bash
./scripts/benchmark.sh [output_file]
```

## Common Workflows

### Development Workflow

```bash
# 1. Quick build and test
./scripts/quick-start.sh

# 2. Make changes to code
# ...

# 3. Rebuild and test
mkdir build && cd build
cmake --build . --parallel
ctest --output-on-failure
```

### Production Deployment Workflow

```bash
# 1. Run benchmarks
./scripts/benchmark.sh

# 2. Deploy to staging
./scripts/deploy-sovereign.sh staging 1.0.0

# 3. Deploy to production
./scripts/deploy-sovereign.sh production 1.0.0
```

## Support

For script issues:
- Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues

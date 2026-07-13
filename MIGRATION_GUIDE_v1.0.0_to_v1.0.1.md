# Migration Guide: RawrXD v1.0.0 to v1.0.1

**Date**: 2026-07-13  
**From**: v1.0.0  
**To**: v1.0.1  
**Priority**: Critical (Security Update)

---

## Overview

This guide helps you migrate from RawrXD v1.0.0 to v1.0.1. This is a **critical security update** that fixes 8 critical CVEs. All users should upgrade immediately.

## What's New in v1.0.1

### Security Fixes
- **8 Critical CVEs Fixed**: Including JSON parsing, OpenSSL, and Python library vulnerabilities
- **74% Reduction in High Severity Issues**: From 254 to ~65
- **Container Hardening**: Non-root users, read-only filesystems, security options
- **Dependency Updates**: 25+ Python packages, 6 Node.js packages updated

### New Features
- Security scanning infrastructure
- Automated vulnerability detection
- Enhanced container security
- Security documentation

## Migration Steps

### Step 1: Backup Your Data

```bash
# Backup configuration
cp -r config/ config.backup.$(date +%Y%m%d)

# Backup models (if stored locally)
cp -r models/ models.backup.$(date +%Y%m%d) 2>/dev/null || true

# Backup workspace
cp -r workspace/ workspace.backup.$(date +%Y%m%d) 2>/dev/null || true
```

### Step 2: Stop Current Services

```bash
# If using Docker
docker-compose down

# If running native
pkill -f RawrXD
```

### Step 3: Update Code

```bash
# Fetch latest changes
git fetch origin

# Checkout v1.0.1
git checkout v1.0.1

# Verify checkout
git log --oneline -1
# Should show: Security: v1.0.1-hotfix3 ...
```

### Step 4: Update Python Dependencies

```bash
cd services/

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install updated dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
pip list | grep -E "(flask|requests|cryptography)"
```

### Step 5: Update Node.js Dependencies

```bash
# Install updated dependencies
npm install

# Run security audit
npm audit

# Fix any issues
npm audit fix
```

### Step 6: Rebuild Containers (if using Docker)

```bash
# Rebuild with no cache to ensure latest base images
docker-compose build --no-cache

# Verify images
docker images | grep rawrxd
```

### Step 7: Start Services

```bash
# Using Docker
docker-compose up -d

# Native (development)
cd services/
source venv/bin/activate
python -m flask run
```

### Step 8: Verify Migration

```bash
# Health check
curl http://localhost:23959/health

# Expected response: {"status": "healthy"}

# Verify version
curl http://localhost:23959/version

# Expected response: {"version": "1.0.1"}
```

## Breaking Changes

### None

v1.0.1 is fully backward compatible with v1.0.0. No API changes or breaking modifications.

## Configuration Changes

### No Changes Required

Your existing configuration files remain compatible. However, review the following optional enhancements:

#### Enhanced Security Options (Optional)

```yaml
# docker-compose.yml additions (automatically applied)
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
read_only: true
```

## Troubleshooting

### Issue: Dependency Conflicts

**Symptom**: `pip install` fails with conflicts

**Solution**:
```bash
# Clear pip cache
pip cache purge

# Use fresh virtual environment
rm -rf venv/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: Container Build Fails

**Symptom**: `docker-compose build` fails

**Solution**:
```bash
# Clean build
docker-compose down
docker system prune -f
docker-compose build --no-cache
```

### Issue: Health Check Fails

**Symptom**: `/health` endpoint returns error

**Solution**:
```bash
# Check logs
docker-compose logs rawrxd-backend

# Verify dependencies
pip check

# Restart service
docker-compose restart rawrxd-backend
```

## Rollback Procedure

If you need to rollback to v1.0.0:

```bash
# Stop services
docker-compose down

# Checkout v1.0.0
git checkout v1.0.0

# Restore dependencies
cd services/
pip install -r requirements.txt  # Old versions

# Restart
docker-compose up -d
```

**Warning**: Rolling back reintroduces critical security vulnerabilities. Only use in emergencies.

## Post-Migration Tasks

### Security Verification

```bash
# Run security scans
cd services/
pip install pip-audit safety
pip-audit -r requirements.txt
safety check

# Container scan
docker run --rm aquasec/trivy image rawrxd-backend
```

### Performance Check

```bash
# Run benchmarks
./scripts/benchmark.sh

# Compare with baseline
# Results should be within 5% of v1.0.0
```

### Update Documentation

- Update internal documentation
- Notify team members
- Update deployment scripts

## Support

### Getting Help

- **Security Issues**: security@rawrxd.io
- **General Support**: GitHub Issues
- **Documentation**: See SECURITY.md

### Resources

- [SECURITY_ADVISORY_v1.0.1.md](SECURITY_ADVISORY_v1.0.1.md) - Security details
- [SECURITY_AUDIT_v1.0.1.md](SECURITY_AUDIT_v1.0.1.md) - Full audit report
- [CHANGELOG.md](CHANGELOG.md) - Version history

## Summary

| Task | Status | Time Required |
|------|--------|---------------|
| Backup | Required | 5 minutes |
| Code Update | Required | 2 minutes |
| Dependencies | Required | 5 minutes |
| Containers | If using Docker | 10 minutes |
| Verification | Required | 5 minutes |
| **Total** | | **~30 minutes** |

---

**Remember**: This is a critical security update. Do not delay migration.

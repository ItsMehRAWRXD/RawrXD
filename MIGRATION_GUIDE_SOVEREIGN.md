# Sovereign Substrate - Migration Guide

## Overview

This guide helps you migrate from the legacy RawrXD system to the new Sovereign Substrate architecture.

## Migration Path

### Phase 1: Preparation (Week 1)

1. **Backup Current System**
   ```bash
   # Backup existing configuration
   cp -r ~/.rawrxd ~/.rawrxd.backup
   
   # Backup project data
   tar -czf rawrxd-backup-$(date +%Y%m%d).tar.gz ~/RawrXD/
   ```

2. **Review New Architecture**
   - Read [START_HERE_SOVEREIGN.md](START_HERE_SOVEREIGN.md)
   - Review [SOVEREIGN_SUBSTRATE_COMPLETE.md](SOVEREIGN_SUBSTRATE_COMPLETE.md)
   - Understand the 8-layer architecture

3. **Check Compatibility**
   ```bash
   # Run compatibility check
   ./scripts/check-compatibility.sh
   ```

### Phase 2: Installation (Week 1-2)

1. **Install Sovereign Substrate**
   ```bash
   # Quick install
   ./scripts/quick-start.sh
   
   # Or manual install
   mkdir build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release
   cmake --build . --parallel
   ```

2. **Configure Environment**
   ```bash
   # Set environment variables
   export RAWR_HOME=/opt/sovereign
   export PATH=$PATH:$RAWR_HOME/bin
   
   # Or use config file
   cp config/sovereign.json ~/.sovereign/config.json
   ```

3. **Migrate Configuration**
   ```bash
   # Migrate old config to new format
   ./scripts/migrate-config.sh ~/.rawrxd/config.json ~/.sovereign/config.json
   ```

### Phase 3: Testing (Week 2)

1. **Run Test Suite**
   ```bash
   cd build
   ctest --output-on-failure
   ```

2. **Validate Integration**
   ```bash
   # Run integration tests
   ./tests/test_sovereign_substrate_e2e
   
   # Run demo
   ./demo/demo_sovereign_substrate
   ```

3. **Performance Benchmarking**
   ```bash
   ./scripts/benchmark.sh
   ```

### Phase 4: Production Deployment (Week 3)

1. **Deploy to Staging**
   ```bash
   ./scripts/deploy-sovereign.sh staging 1.0.0
   ```

2. **Validate Staging**
   ```bash
   curl http://staging:8080/health
   ./scripts/validate-deployment.sh staging
   ```

3. **Deploy to Production**
   ```bash
   ./scripts/deploy-sovereign.sh production 1.0.0
   ```

## Configuration Migration

### Legacy to New Mapping

| Legacy Setting | New Setting | Notes |
|---------------|-------------|-------|
| `rawrxd.api_key` | `model.api_key` | Now supports multiple backends |
| `rawrxd.model` | `model.model` | Added backend selection |
| `rawrxd.timeout` | `model.timeout_seconds` | Same functionality |
| `rawrxd.cache_size` | `performance.cache_size_mb` | Now in MB |
| `rawrxd.log_level` | `logging.level` | Same values |

### Example Migration

**Old Config (rawrxd.json):**
```json
{
  "api_key": "sk-...",
  "model": "gpt-4",
  "timeout": 30,
  "cache_size": 524288000,
  "log_level": "INFO"
}
```

**New Config (sovereign.json):**
```json
{
  "model": {
    "provider": "openai",
    "api_key": "sk-...",
    "model": "gpt-4",
    "timeout_seconds": 30
  },
  "performance": {
    "cache_size_mb": 500
  },
  "logging": {
    "level": "INFO"
  }
}
```

## API Migration

### Legacy API to New API

**Old API:**
```cpp
// Legacy RawrXD API
RawrXD::Completion completion;
completion.model = "gpt-4";
completion.prompt = "Hello";
auto result = completion.Execute();
```

**New API:**
```cpp
// Sovereign Substrate API
RawrXD::Intent intent;
intent.action = "complete";
intent.params["model"] = "gpt-4";
intent.params["prompt"] = "Hello";
auto result = kernel.ExecuteIntent(intent);
```

### Tool Migration

**Old Tool API:**
```cpp
// Legacy
auto result = RawrXD::Tools::Execute("read_file", path);
```

**New Tool API:**
```cpp
// New
auto result = RawrXD::Tools::TOOL_REGISTRY.Execute(
    "read_file", 
    {{"file_path", path}}
);
```

## Breaking Changes

### 1. Configuration Format
- **Change:** JSON structure completely redesigned
- **Impact:** All config files must be migrated
- **Migration:** Use provided migration script

### 2. API Structure
- **Change:** From direct calls to intent-based system
- **Impact:** All integrations must be updated
- **Migration:** See API migration examples above

### 3. Tool System
- **Change:** Tools now use parameter maps
- **Impact:** Tool calls must be updated
- **Migration:** Update parameter passing

### 4. Security Model
- **Change:** New capability-based security
- **Impact:** Permissions must be reconfigured
- **Migration:** Review security settings

## Rollback Plan

If issues occur during migration:

1. **Stop Sovereign Substrate**
   ```bash
   ./scripts/deploy-sovereign.sh production stop
   ```

2. **Restore Legacy System**
   ```bash
   # Restore from backup
   cp -r ~/.rawrxd.backup ~/.rawrxd
   
   # Restart legacy system
   systemctl restart rawrxd
   ```

3. **Verify Rollback**
   ```bash
   curl http://localhost:8080/health
   ```

## Troubleshooting Migration

### Issue: Config migration fails
**Solution:**
```bash
# Manual migration
./scripts/migrate-config.sh --manual ~/.rawrxd/config.json
```

### Issue: Tests fail after migration
**Solution:**
```bash
# Check compatibility
./scripts/check-compatibility.sh --fix

# Rebuild from scratch
rm -rf build
./scripts/quick-start.sh
```

### Issue: Performance degradation
**Solution:**
```bash
# Run benchmark
./scripts/benchmark.sh

# Adjust performance settings
# Edit config/sovereign.json:
# "performance": {"thread_pool_size": 16}
```

## Post-Migration Checklist

- [ ] All configurations migrated
- [ ] All tests passing
- [ ] Performance benchmarks acceptable
- [ ] Security settings validated
- [ ] Monitoring in place
- [ ] Documentation updated
- [ ] Team trained on new system
- [ ] Rollback tested

## Support

For migration assistance:
- **Documentation:** https://docs.rawrxd.dev/migration
- **GitHub Issues:** https://github.com/ItsMehRAWRXD/RawrXD/issues
- **Discord:** https://discord.gg/rawrxd

## Timeline

| Phase | Duration | Key Activities |
|-------|----------|----------------|
| Preparation | 1 week | Backup, review, compatibility check |
| Installation | 1 week | Install, configure, migrate |
| Testing | 1 week | Test suite, validation, benchmarking |
| Deployment | 1 week | Staging, production, monitoring |
| **Total** | **4 weeks** | Full migration |

---

**The Sovereign Substrate awaits. Migrate with confidence.**

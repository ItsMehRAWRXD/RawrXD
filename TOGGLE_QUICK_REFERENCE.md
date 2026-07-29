# Toggle Quick Reference

## Emergency Bypass (All Features)

```bash
# Environment variable (immediate)
export RAWR_INTENT_EMERGENCY_BYPASS=1

# CMake (compile-time)
cmake .. -DRAWR_INTENT_EMERGENCY_BYPASS=ON
```

## Feature Toggles

### Compile-Time (CMake)

```bash
# Enable all features
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=ON

# Disable specific features
cmake .. -DRAWR_INTENT_VALIDATION_ENABLED=OFF

# Minimal guardrails
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=ON \
         -DRAWR_INTENT_VALIDATION_ENABLED=OFF \
         -DRAWR_PATCH_TRANSACTION_ENABLED=OFF

# Disable entire system
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=OFF
```

### Runtime (Environment)

```bash
export RAWR_INTENT_GUARD_ENABLED=1
export RAWR_INTENT_VALIDATION_ENABLED=0
export RAWR_PATCH_TRANSACTION_ENABLED=1
export RAWR_CAPABILITY_TOKENS_ENABLED=1
export RAWR_HOTPATCH_JOURNAL_ENABLED=1
export RAWR_PATCH_FIREWALL_ENABLED=1
```

### Runtime (Config File)

```json
// .rawrxd/intent_config.json
{
  "enableGuardrails": true,
  "enableValidation": false,
  "enableTransactions": true,
  "emergencyBypass": false
}
```

### Per-Intent (Code)

```cpp
IntentRequest intent;
intent.skip_validation = true;
intent.require_human_approval = true;
```

## Quick Commands

```bash
# Full build with all features
./scripts/verify_build.ps1

# Minimal build (fastest)
./scripts/verify_build.ps1 -BuildType Release

# Clean build
./scripts/verify_build.ps1 -Clean

# Build without tests
./scripts/verify_build.ps1 -SkipTests
```

## Feature Matrix

| Feature | Compile | Env | Config | Per-Intent |
|---------|---------|-----|--------|------------|
| Intent Guard | ✅ | ✅ | ✅ | ✅ |
| Validation | ✅ | ✅ | ✅ | ✅ |
| Transactions | ✅ | ✅ | ✅ | ✅ |
| Capability Tokens | ✅ | ✅ | ✅ | ✅ |
| Hotpatch Journal | ✅ | ✅ | ✅ | ✅ |
| Patch Firewall | ✅ | ✅ | ✅ | ✅ |

## Emergency Procedures

```cpp
// Emergency bypass (scoped)
{
    ScopedFirewallBypass bypass("Critical fix");
    ApplyPatchDirectly();
}

// Emergency stop
PatchFirewall::Instance().EmergencyStop("Security breach");

// Revoke all tokens
CapabilityManager::Instance().EmergencyRevokeAll("Incident");

// Rollback all transactions
TransactionManager::Instance().EmergencyRollbackAll();
```

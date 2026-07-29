# Intent Guardrails Toggle Guide

## Overview

The Intent-to-Execution guardrail system is **fully toggleable** at multiple levels:
1. **Compile-time** - CMake options (permanent for build)
2. **Runtime** - Configuration files and environment variables
3. **Per-intent** - Individual intent overrides
4. **Emergency** - Global kill switch

## Quick Reference

### Master Toggle

```bash
# Disable entire system at compile time
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=OFF

# Or at runtime via environment
export RAWR_INTENT_EMERGENCY_BYPASS=1
```

### Feature Toggles

| Feature | Compile Flag | Environment Variable | Runtime Config |
|---------|-------------|---------------------|--------------|
| Intent Guard | `RAWR_INTENT_GUARD_ENABLED` | `RAWR_INTENT_GUARD_ENABLED` | `enableGuardrails` |
| Validation | `RAWR_INTENT_VALIDATION_ENABLED` | `RAWR_INTENT_VALIDATION_ENABLED` | `enableValidation` |
| Transactions | `RAWR_PATCH_TRANSACTION_ENABLED` | `RAWR_PATCH_TRANSACTION_ENABLED` | `enableTransactions` |
| Capability Tokens | `RAWR_CAPABILITY_TOKENS_ENABLED` | `RAWR_CAPABILITY_TOKENS_ENABLED` | `enableCapabilityTokens` |
| Hotpatch Journal | `RAWR_HOTPATCH_JOURNAL_ENABLED` | `RAWR_HOTPATCH_JOURNAL_ENABLED` | `enableJournal` |
| Patch Firewall | `RAWR_PATCH_FIREWALL_ENABLED` | `RAWR_PATCH_FIREWALL_ENABLED` | `enableFirewall` |
| Reflector Agent | `RAWR_REFLECTOR_AGENT_ENABLED` | `RAWR_REFLECTOR_AGENT_ENABLED` | `enableReflector` |
| Atomic Activation | `RAWR_ATOMIC_ACTIVATION_ENABLED` | `RAWR_ATOMIC_ACTIVATION_ENABLED` | `enableAtomicActivation` |
| First-Class Rollback | `RAWR_ROLLBACK_FIRST_CLASS_ENABLED` | `RAWR_ROLLBACK_FIRST_CLASS_ENABLED` | `enableRollback` |
| Model Adapter | `RAWR_MODEL_ADAPTER_ENABLED` | `RAWR_MODEL_ADAPTER_ENABLED` | `enableModelAdapter` |

## Compile-Time Configuration

### CMake Options

```bash
# Configure with all features ON (default)
cmake .. -G Ninja \
    -DRAWR_INTENT_SYSTEM_ENABLED=ON \
    -DRAWR_INTENT_GUARD_ENABLED=ON \
    -DRAWR_INTENT_VALIDATION_ENABLED=ON \
    -DRAWR_PATCH_TRANSACTION_ENABLED=ON \
    -DRAWR_CAPABILITY_TOKENS_ENABLED=ON \
    -DRAWR_HOTPATCH_JOURNAL_ENABLED=ON \
    -DRAWR_PATCH_FIREWALL_ENABLED=ON \
    -DRAWR_REFLECTOR_AGENT_ENABLED=ON \
    -DRAWR_ATOMIC_ACTIVATION_ENABLED=ON \
    -DRAWR_ROLLBACK_FIRST_CLASS_ENABLED=ON \
    -DRAWR_MODEL_ADAPTER_ENABLED=ON

# Configure with minimal guardrails (production)
cmake .. -G Ninja \
    -DRAWR_INTENT_SYSTEM_ENABLED=ON \
    -DRAWR_INTENT_GUARD_ENABLED=ON \
    -DRAWR_PATCH_FIREWALL_ENABLED=ON \
    -DRAWR_INTENT_VALIDATION_ENABLED=OFF \
    -DRAWR_PATCH_TRANSACTION_ENABLED=OFF \
    -DRAWR_CAPABILITY_TOKENS_ENABLED=OFF

# Disable entire system
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=OFF

# Emergency bypass (all guardrails disabled)
cmake .. -DRAWR_INTENT_EMERGENCY_BYPASS=ON
```

### Conditional Compilation

Code can be conditionally compiled:

```cpp
#if RAWR_INTENT_GUARD_ENABLED
    // Guardrail code
#endif

// Or using macros
RAWR_CT_GUARD({
    // Guardrail code
});
```

## Runtime Configuration

### Environment Variables

```bash
# Master switches
export RAWR_INTENT_GUARD_ENABLED=1              # Enable/disable guardrails
export RAWR_INTENT_VALIDATION_ENABLED=1         # Enable/disable validation
export RAWR_PATCH_TRANSACTION_ENABLED=1         # Enable/disable transactions
export RAWR_CAPABILITY_TOKENS_ENABLED=1          # Enable/disable capability tokens
export RAWR_HOTPATCH_JOURNAL_ENABLED=1          # Enable/disable journal
export RAWR_PATCH_FIREWALL_ENABLED=1            # Enable/disable firewall
export RAWR_REFLECTOR_AGENT_ENABLED=1           # Enable/disable reflector
export RAWR_ATOMIC_ACTIVATION_ENABLED=1         # Enable/disable atomic activation
export RAWR_ROLLBACK_FIRST_CLASS_ENABLED=1      # Enable/disable rollback
export RAWR_MODEL_ADAPTER_ENABLED=1             # Enable/disable model adapter

# Emergency bypass
export RAWR_INTENT_EMERGENCY_BYPASS=1           # Disable ALL guardrails

# Granular controls
export RAWR_INTENT_REQUIRE_AST=1                # Require AST validation
export RAWR_INTENT_REQUIRE_POLICY=1             # Require policy check
export RAWR_INTENT_REQUIRE_SANDBOX=1            # Require sandbox build
export RAWR_INTENT_REQUIRE_VERIFICATION=1       # Require runtime verification
export RAWR_INTENT_REQUIRE_HUMAN=0              # Require human approval for high-risk
export RAWR_INTENT_AUTO_COMMIT=1                # Auto-commit on success
export RAWR_INTENT_AUTO_ROLLBACK=1              # Auto-rollback on failure
```

### Configuration File

Create `.rawrxd/intent_config.json`:

```json
{
  "enableGuardrails": true,
  "enableValidation": true,
  "enableTransactions": true,
  "enableCapabilityTokens": true,
  "enableJournal": true,
  "enableFirewall": true,
  "enableReflector": true,
  "enableAtomicActivation": true,
  "enableRollback": true,
  "enableModelAdapter": true,
  
  "emergencyBypass": false,
  
  "requireASTValidation": true,
  "requirePolicyCheck": true,
  "requireSandboxBuild": true,
  "requireRuntimeVerification": true,
  "requireHumanApprovalForHighRisk": false,
  "autoCommitOnSuccess": true,
  "autoRollbackOnFailure": true,
  
  "fastPathForTrustedModels": false,
  "maxValidationTimeMs": 5000,
  "maxSandboxBuildTimeMs": 30000,
  "maxRollbackTimeMs": 1000
}
```

### Runtime API

```cpp
#include "intent/intent_config.hpp"

using namespace RawrXD::Intent;

// Get config
auto& config = IntentRuntimeConfig::Instance();

// Toggle features at runtime
config.enableGuardrails.store(false);        // Disable guardrails
config.enableValidation.store(false);        // Disable validation
config.enableTransactions.store(false);       // Disable transactions

// Emergency bypass
config.emergencyBypass.store(true);          // Disable EVERYTHING

// Check if feature is enabled
if (config.GuardrailsEnabled()) {
    // Apply guardrails
}

// Load from file
config.LoadFromFile(".rawrxd/intent_config.json");

// Save to file
config.SaveToFile(".rawrxd/intent_config.json");
```

## Per-Intent Overrides

Individual intents can override global settings:

```cpp
IntentRequest intent;
intent.type = IntentType::MODIFY_FUNCTION;
intent.target.file_path = "src/main.cpp";

// Override global settings for this intent only
intent.skip_validation = true;           // Skip validation for this intent
intent.skip_tests = true;                // Skip tests for this intent
intent.require_human_approval = true;    // Require human approval
intent.auto_rollback_on_failure = false; // Don't auto-rollback
```

## Emergency Procedures

### Emergency Bypass

```cpp
// Code-level emergency bypass
{
    ScopedFirewallBypass bypass("Critical fix needed");
    // All guardrails disabled in this scope
    ApplyPatchDirectly();
}
```

### Emergency Stop

```cpp
// Stop all execution
PatchFirewall::Instance().EmergencyStop("Security breach detected");

// Resume
PatchFirewall::Instance().Resume();
```

### Emergency Revoke

```cpp
// Revoke all capability tokens
CapabilityManager::Instance().EmergencyRevokeAll("Security incident");

// Rollback all transactions
TransactionManager::Instance().EmergencyRollbackAll();
```

## Use Cases

### Development Mode (All Features ON)

```bash
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=ON
export RAWR_INTENT_GUARD_ENABLED=1
export RAWR_INTENT_VALIDATION_ENABLED=1
export RAWR_PATCH_TRANSACTION_ENABLED=1
```

### Production Mode (Minimal Guardrails)

```bash
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=ON \
         -DRAWR_INTENT_VALIDATION_ENABLED=OFF \
         -DRAWR_PATCH_TRANSACTION_ENABLED=OFF
export RAWR_INTENT_GUARD_ENABLED=1
export RAWR_PATCH_FIREWALL_ENABLED=1
```

### Debug Mode (Firewall Only)

```bash
cmake .. -DRAWR_INTENT_SYSTEM_ENABLED=ON \
         -DRAWR_INTENT_VALIDATION_ENABLED=OFF \
         -DRAWR_PATCH_TRANSACTION_ENABLED=OFF \
         -DRAWR_CAPABILITY_TOKENS_ENABLED=OFF
export RAWR_PATCH_FIREWALL_ENABLED=1
```

### Emergency Mode (All OFF)

```bash
export RAWR_INTENT_EMERGENCY_BYPASS=1
```

## Feature Dependencies

Some features depend on others:

- **Transactions** require **Guardrails**
- **Capability Tokens** require **Guardrails**
- **Patch Firewall** requires **Validation**
- **Atomic Activation** requires **Transactions**
- **First-Class Rollback** requires **Transactions**

If a dependency is disabled, dependent features automatically disable themselves.

## Performance Impact

| Feature | Overhead | Can Disable? |
|---------|----------|--------------|
| Intent Guard | ~1μs | Yes |
| Validation | ~5-50ms | Yes |
| Transactions | ~10μs | Yes |
| Capability Tokens | ~500ns | Yes |
| Hotpatch Journal | ~1μs | Yes |
| Patch Firewall | ~2μs | Yes |
| Reflector Agent | ~100ms | Yes |
| Atomic Activation | ~1μs | Yes |
| First-Class Rollback | ~1μs | Yes |
| Model Adapter | ~5ms | Yes |

## Troubleshooting

### Check Current Configuration

```cpp
auto& config = IntentRuntimeConfig::Instance();

printf("Guardrails: %s\n", config.GuardrailsEnabled() ? "ON" : "OFF");
printf("Validation: %s\n", config.ValidationEnabled() ? "ON" : "OFF");
printf("Transactions: %s\n", config.TransactionsEnabled() ? "ON" : "OFF");
printf("Emergency Bypass: %s\n", config.emergencyBypass.load() ? "ON" : "OFF");
```

### Debug Mode

```bash
export RAWR_INTENT_LOG_LEVEL=debug
export RAWR_INTENT_LOG_ALL_CHECKS=1
```

### Reset to Defaults

```bash
rm .rawrxd/intent_config.json
# System will use compile-time defaults
```

## Summary

The Intent Guardrails system provides **maximum flexibility**:

1. **Compile-time**: Choose which features to include in binary
2. **Runtime**: Toggle features without recompilation
3. **Per-intent**: Override for specific operations
4. **Emergency**: Kill switch for critical situations

This allows the same binary to run in:
- **Development**: Full guardrails, maximum safety
- **Production**: Minimal overhead, essential protection
- **Emergency**: Bypass everything if needed

All toggles are **independent** and can be combined as needed.

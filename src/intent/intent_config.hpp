#pragma once
#include <cstdint>
#include <atomic>

// =============================================================================
// Intent System Configuration - Compile-Time and Runtime Toggles
// =============================================================================

// Compile-time feature flags (set via CMake or compiler defines)
#ifndef RAWR_INTENT_GUARD_ENABLED
    #define RAWR_INTENT_GUARD_ENABLED 1
#endif

#ifndef RAWR_INTENT_VALIDATION_ENABLED
    #define RAWR_INTENT_VALIDATION_ENABLED 1
#endif

#ifndef RAWR_PATCH_TRANSACTION_ENABLED
    #define RAWR_PATCH_TRANSACTION_ENABLED 1
#endif

#ifndef RAWR_CAPABILITY_TOKENS_ENABLED
    #define RAWR_CAPABILITY_TOKENS_ENABLED 1
#endif

#ifndef RAWR_HOTPATCH_JOURNAL_ENABLED
    #define RAWR_HOTPATCH_JOURNAL_ENABLED 1
#endif

#ifndef RAWR_PATCH_FIREWALL_ENABLED
    #define RAWR_PATCH_FIREWALL_ENABLED 1
#endif

#ifndef RAWR_REFLECTOR_AGENT_ENABLED
    #define RAWR_REFLECTOR_AGENT_ENABLED 1
#endif

#ifndef RAWR_ATOMIC_ACTIVATION_ENABLED
    #define RAWR_ATOMIC_ACTIVATION_ENABLED 1
#endif

#ifndef RAWR_ROLLBACK_FIRST_CLASS_ENABLED
    #define RAWR_ROLLBACK_FIRST_CLASS_ENABLED 1
#endif

#ifndef RAWR_MODEL_ADAPTER_ENABLED
    #define RAWR_MODEL_ADAPTER_ENABLED 1
#endif

// Emergency bypass mode (compile-time kill switch for all guardrails)
#ifndef RAWR_INTENT_EMERGENCY_BYPASS
    #define RAWR_INTENT_EMERGENCY_BYPASS 0
#endif

namespace RawrXD {
namespace Intent {

// =============================================================================
// Runtime Configuration - Mutable at Runtime
// =============================================================================

struct IntentRuntimeConfig {
    // Master switches
    std::atomic<bool> enableGuardrails{true};
    std::atomic<bool> enableValidation{true};
    std::atomic<bool> enableTransactions{true};
    std::atomic<bool> enableCapabilityTokens{true};
    std::atomic<bool> enableJournal{true};
    std::atomic<bool> enableFirewall{true};
    std::atomic<bool> enableReflector{true};
    std::atomic<bool> enableAtomicActivation{true};
    std::atomic<bool> enableRollback{true};
    std::atomic<bool> enableModelAdapter{true};
    
    // Emergency bypass (disables everything)
    std::atomic<bool> emergencyBypass{false};
    
    // Granular controls
    std::atomic<bool> requireASTValidation{true};
    std::atomic<bool> requirePolicyCheck{true};
    std::atomic<bool> requireSandboxBuild{true};
    std::atomic<bool> requireRuntimeVerification{true};
    std::atomic<bool> requireHumanApprovalForHighRisk{false};
    std::atomic<bool> autoCommitOnSuccess{true};
    std::atomic<bool> autoRollbackOnFailure{true};
    
    // Performance vs safety trade-offs
    std::atomic<bool> fastPathForTrustedModels{false};
    std::atomic<uint32_t> maxValidationTimeMs{5000};
    std::atomic<uint32_t> maxSandboxBuildTimeMs{30000};
    std::atomic<uint32_t> maxRollbackTimeMs{1000};
    
    // Singleton access
    static IntentRuntimeConfig& Instance();
    
    // Load from environment variables
    void LoadFromEnvironment();
    
    // Load from config file
    void LoadFromFile(const char* path);
    
    // Save to config file
    void SaveToFile(const char* path) const;
    
    // Check if feature is enabled (compile-time + runtime)
    template<bool CompileTimeFlag>
    bool IsFeatureEnabled(const std::atomic<bool>& runtimeFlag) const {
        #if RAWR_INTENT_EMERGENCY_BYPASS
            return false;
        #endif
        if (emergencyBypass.load()) return false;
        if (!CompileTimeFlag) return false;
        return runtimeFlag.load();
    }
    
    // Convenience accessors
    bool GuardrailsEnabled() const { 
        return IsFeatureEnabled<RAWR_INTENT_GUARD_ENABLED>(enableGuardrails); 
    }
    bool ValidationEnabled() const { 
        return IsFeatureEnabled<RAWR_INTENT_VALIDATION_ENABLED>(enableValidation); 
    }
    bool TransactionsEnabled() const { 
        return IsFeatureEnabled<RAWR_PATCH_TRANSACTION_ENABLED>(enableTransactions); 
    }
    bool CapabilityTokensEnabled() const { 
        return IsFeatureEnabled<RAWR_CAPABILITY_TOKENS_ENABLED>(enableCapabilityTokens); 
    }
    bool JournalEnabled() const { 
        return IsFeatureEnabled<RAWR_HOTPATCH_JOURNAL_ENABLED>(enableJournal); 
    }
    bool FirewallEnabled() const { 
        return IsFeatureEnabled<RAWR_PATCH_FIREWALL_ENABLED>(enableFirewall); 
    }
    bool ReflectorEnabled() const { 
        return IsFeatureEnabled<RAWR_REFLECTOR_AGENT_ENABLED>(enableReflector); 
    }
    bool AtomicActivationEnabled() const { 
        return IsFeatureEnabled<RAWR_ATOMIC_ACTIVATION_ENABLED>(enableAtomicActivation); 
    }
    bool RollbackEnabled() const { 
        return IsFeatureEnabled<RAWR_ROLLBACK_FIRST_CLASS_ENABLED>(enableRollback); 
    }
    bool ModelAdapterEnabled() const { 
        return IsFeatureEnabled<RAWR_MODEL_ADAPTER_ENABLED>(enableModelAdapter); 
    }
};

// =============================================================================
// Feature Toggle Macros - Use these for conditional compilation
// =============================================================================

#define RAWR_INTENT_IF_ENABLED(feature, code) \
    if (RawrXD::Intent::IntentRuntimeConfig::Instance().feature##Enabled()) { code }

#define RAWR_INTENT_GUARD_BLOCK(code) \
    do { if (!RawrXD::Intent::IntentRuntimeConfig::Instance().GuardrailsEnabled()) break; code } while(0)

#define RAWR_INTENT_VALIDATE_BLOCK(code) \
    do { if (!RawrXD::Intent::IntentRuntimeConfig::Instance().ValidationEnabled()) break; code } while(0)

#define RAWR_INTENT_TRANSACTION_BLOCK(code) \
    do { if (!RawrXD::Intent::IntentRuntimeConfig::Instance().TransactionsEnabled()) break; code } while(0)

// Compile-time conditional blocks
#if RAWR_INTENT_GUARD_ENABLED
    #define RAWR_CT_GUARD(code) code
#else
    #define RAWR_CT_GUARD(code)
#endif

#if RAWR_INTENT_VALIDATION_ENABLED
    #define RAWR_CT_VALIDATE(code) code
#else
    #define RAWR_CT_VALIDATE(code)
#endif

#if RAWR_PATCH_TRANSACTION_ENABLED
    #define RAWR_CT_TRANSACTION(code) code
#else
    #define RAWR_CT_TRANSACTION(code)
#endif

} // namespace Intent
} // namespace RawrXD

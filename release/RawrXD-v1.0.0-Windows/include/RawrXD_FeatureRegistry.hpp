// ============================================================================
// RawrXD_FeatureRegistry.hpp - Centralized Feature Flag Management
// ============================================================================
// Replaces scattered if(true/false) checks with centralized, config-driven
// feature activation. Prevents accidental enablement of broken features.
//
// Usage:
//   if (FeatureRegistry::IsAgentBridgeEnabled()) {
//       initializeAgentBridge();
//   }
//
// Philosophy: Explicit opt-in, safe defaults, runtime configurable
// ============================================================================

#pragma once

#include <string>

namespace RawrXD {

// Feature states - explicit and clear
enum class FeatureState {
    Disabled,       // Hard disabled (code may not even exist)
    Configurable,   // Controlled by rawrxd.config.json
    Enabled         // Hard enabled (always on)
};

// ============================================================================
// Feature Registry - Single source of truth for feature activation
// ============================================================================
class FeatureRegistry {
public:
    // P0: Critical Features (AI Control Bridge)
    static bool IsAgentBridgeEnabled();
    static bool IsAutonomousSystemsEnabled();
    
    // P1: Major Subsystems
    static bool IsOmegaOrchestratorEnabled();      // Currently hard-disabled
    static bool IsAgenticIntegrationEnabled();
    static bool IsAutonomousFeatureEngineEnabled();
    static bool IsAutonomousOrchestratorEnabled();
    static bool IsAutonomousModelManagerEnabled();
    
    // P2: Optional Features
    static bool IsVoiceAssistantEnabled();
    static bool IsExtensionHostEnabled();
    static bool IsDapServerAutoStartEnabled();
    static bool IsLspClientAutoStartEnabled();
    
    // Development/Debug Features
    static bool IsTelemetryVerboseEnabled();
    static bool IsPluginSystemEnabled();
    
    // Get raw state (for UI display)
    static FeatureState GetAgentBridgeState();
    static FeatureState GetOmegaOrchestratorState();
    
    // Runtime toggle (for menu commands)
    static void SetVoiceAssistantEnabled(bool enabled);
    static void SetExtensionHostEnabled(bool enabled);
    
    // Validation - check if feature can actually be enabled
    static bool CanEnableAgentBridge(std::string& out_reason);
    static bool CanEnableOmegaOrchestrator(std::string& out_reason);

    // Meyers Singleton - thread-safe, no static init order issues
    // All state is managed internally via GetState() in .cpp file
};

// ============================================================================
// Feature Guard Macros - Compile-time and runtime safety
// ============================================================================

// Runtime guard - checks registry before executing
#define RAWRXD_FEATURE_GUARD(feature_name, code) \
    do { \
        if (RawrXD::FeatureRegistry::Is##feature_name##Enabled()) { \
            code; \
        } else { \
            OutputDebugStringA("[FeatureGuard] " #feature_name " is disabled\n"); \
        } \
    } while(0)

// Runtime guard with fallback
#define RAWRXD_FEATURE_GUARD_ELSE(feature_name, code, fallback) \
    do { \
        if (RawrXD::FeatureRegistry::Is##feature_name##Enabled()) { \
            code; \
        } else { \
            fallback; \
        } \
    } while(0)

// Hard disable macro - for ghost features that should never run
// Use this to wrap code for features that are declared but not implemented
#define RAWRXD_GHOST_FEATURE_DISABLED \
    do { \
        static_assert(false, "This feature is ghost code - not implemented"); \
    } while(0)

} // namespace RawrXD

// ============================================================================
// C-compatible API for MASM/plugins
// ============================================================================

extern "C" {
    // C-compatible feature checks
    __declspec(dllexport) int RawrXD_IsAgentBridgeEnabled(void);
    __declspec(dllexport) int RawrXD_IsOmegaOrchestratorEnabled(void);
    __declspec(dllexport) int RawrXD_IsVoiceAssistantEnabled(void);
    __declspec(dllexport) int RawrXD_IsPluginSystemEnabled(void);
}

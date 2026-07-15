// ============================================================================
// RawrXD_FeatureRegistry.cpp - Feature Registry Implementation
// ============================================================================
// Centralized feature activation with safe defaults and config integration
// ============================================================================

#include "RawrXD_FeatureRegistry.hpp"
#include "../config/IDEConfig.h"  // For Config::Get()
#include <windows.h>

namespace RawrXD {

// ============================================================================
// Internal State - Meyers Singleton Pattern
// This eliminates Static Initialization Order Fiasco risks
// ============================================================================
struct FeatureRegistryState {
    bool configLoaded = false;
    bool voiceAssistantEnabled = false;
    bool extensionHostEnabled = false;
    
    // Config cache values
    bool agentBridgeEnabled = true;      // Default: enabled
    bool telemetryVerbose = false;       // Default: disabled
    bool pluginSystemEnabled = false;    // Default: disabled (not implemented)
    
    void LoadFromConfig() {
        if (configLoaded) return;
        
        // TODO: Load from Config::Get() when available
        // For now, use safe defaults
        voiceAssistantEnabled = false;   // Requires wiring
        extensionHostEnabled = false;    // Ghost feature
        
        configLoaded = true;
    }
};

// Meyers Singleton - thread-safe since C++11, no static init order issues
static FeatureRegistryState& GetState() {
    static FeatureRegistryState state;
    return state;
}

// ============================================================================
// P0: Critical Features
// ============================================================================

bool FeatureRegistry::IsAgentBridgeEnabled() {
    auto& state = GetState();
    state.LoadFromConfig();
    return state.agentBridgeEnabled;
}

bool FeatureRegistry::IsAutonomousSystemsEnabled() {
    return IsAgentBridgeEnabled();  // Dependent on AgentBridge
}

// ============================================================================
// P1: Major Subsystems - Ghost Features (Hard Disabled)
// ============================================================================

bool FeatureRegistry::IsOmegaOrchestratorEnabled() {
    // OMEGA ORCHESTRATOR IS GHOST CODE
    // Declared in Win32IDE.h but ZERO implementation exists
    // Hard-disabled until fully implemented
    // 
    // To enable: 
    // 1. Implement all 12+ methods in Win32IDE_Omega.cpp
    // 2. Create OmegaOrchestrator class
    // 3. Wire initialization in startup sequence
    // 4. Change this to return Config::Get("omega.enabled", false)
    
    return false;  // HARD DISABLED - Ghost feature
}

bool FeatureRegistry::IsAgenticIntegrationEnabled() {
    // AgenticIntegration exists but is never initialized
    // Safe to enable once initialization is wired
    return IsAgentBridgeEnabled();  // Dependent on AgentBridge
}

bool FeatureRegistry::IsAutonomousFeatureEngineEnabled() {
    // AutonomousFeatureEngine exists but is never initialized
    return IsAgentBridgeEnabled();
}

bool FeatureRegistry::IsAutonomousOrchestratorEnabled() {
    // AutonomousIntelligenceOrchestrator exists but is never initialized
    return IsAgentBridgeEnabled();
}

bool FeatureRegistry::IsAutonomousModelManagerEnabled() {
    // AutonomousModelManager exists but is never initialized
    return IsAgentBridgeEnabled();
}

// ============================================================================
// P2: Optional Features
// ============================================================================

bool FeatureRegistry::IsVoiceAssistantEnabled() {
    auto& state = GetState();
    state.LoadFromConfig();
    return state.voiceAssistantEnabled;
}

bool FeatureRegistry::IsExtensionHostEnabled() {
    auto& state = GetState();
    state.LoadFromConfig();
    return state.extensionHostEnabled;
}

bool FeatureRegistry::IsDapServerAutoStartEnabled() {
    // DAP Server is ON-DEMAND, not auto-start
    // User must explicitly start debugging
    return false;  // Never auto-start debugger
}

bool FeatureRegistry::IsLspClientAutoStartEnabled() {
    // LSP Client is MANUAL START
    // User must explicitly start language server via menu
    return false;  // Never auto-start LSP
}

// ============================================================================
// Development/Debug Features
// ============================================================================

bool FeatureRegistry::IsTelemetryVerboseEnabled() {
    auto& state = GetState();
    state.LoadFromConfig();
    return state.telemetryVerbose;
}

bool FeatureRegistry::IsPluginSystemEnabled() {
    auto& state = GetState();
    state.LoadFromConfig();
    return state.pluginSystemEnabled;
}

// ============================================================================
// State Getters (for UI display)
// ============================================================================

FeatureState FeatureRegistry::GetAgentBridgeState() {
    return FeatureState::Configurable;  // User can enable/disable
}

FeatureState FeatureRegistry::GetOmegaOrchestratorState() {
    return FeatureState::Disabled;  // Hard disabled - ghost feature
}

// ============================================================================
// Runtime Toggles
// ============================================================================

void FeatureRegistry::SetVoiceAssistantEnabled(bool enabled) {
    auto& state = GetState();
    state.voiceAssistantEnabled = enabled;
}

void FeatureRegistry::SetExtensionHostEnabled(bool enabled) {
    auto& state = GetState();
    state.extensionHostEnabled = enabled;
}

// ============================================================================
// Validation
// ============================================================================

bool FeatureRegistry::CanEnableAgentBridge(std::string& out_reason) {
    // Check prerequisites for AgentBridge
    // - Config file exists
    // - AI model path configured
    // - Backend manager initialized
    
    out_reason.clear();
    
    // TODO: Check if config file exists
    // TODO: Check if model path is configured
    // TODO: Check if backend manager is ready
    
    return true;  // For now, assume yes
}

bool FeatureRegistry::CanEnableOmegaOrchestrator(std::string& out_reason) {
    out_reason = "Omega Orchestrator is not implemented (ghost feature)";
    return false;  // Hard no - code doesn't exist
}

} // namespace RawrXD

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

__declspec(dllexport) int RawrXD_IsAgentBridgeEnabled(void) {
    return RawrXD::FeatureRegistry::IsAgentBridgeEnabled() ? 1 : 0;
}

__declspec(dllexport) int RawrXD_IsOmegaOrchestratorEnabled(void) {
    return RawrXD::FeatureRegistry::IsOmegaOrchestratorEnabled() ? 1 : 0;
}

__declspec(dllexport) int RawrXD_IsVoiceAssistantEnabled(void) {
    return RawrXD::FeatureRegistry::IsVoiceAssistantEnabled() ? 1 : 0;
}

__declspec(dllexport) int RawrXD_IsPluginSystemEnabled(void) {
    return RawrXD::FeatureRegistry::IsPluginSystemEnabled() ? 1 : 0;
}

}

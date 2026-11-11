// ============================================================================
// FeatureRegistry.cpp - Feature Flag Implementation
// ============================================================================
// Centralized control for all IDE features.
//
// Copyright (c) 2024-2026 RawrXD IDE Project
// ============================================================================

#include "FeatureRegistry.hpp"
#include "Win32IDE.h"
#include <cstdlib>
#include <sstream>

namespace RawrXD::Features {

// ============================================================================
// INTERNAL STATE
// ============================================================================

namespace {
    std::atomic<bool> g_agentBridgeInitialized{false};
    std::atomic<bool> g_voiceAssistantInitialized{false};
    std::atomic<bool> g_lspClientInitialized{false};
    std::atomic<bool> g_dapServerInitialized{false};
    
    bool g_registryInitialized = false;
}

// ============================================================================
// RUNTIME FEATURE FLAGS
// ============================================================================

bool IsAgentBridgeEnabled() {
    // Check config file or environment variable
    const char* env = std::getenv("RAWRXD_AGENT_BRIDGE_ENABLED");
    if (env && (std::strcmp(env, "1") == 0 || std::strcmp(env, "true") == 0)) {
        return true;
    }
    
    // Default: enabled for now (will check config file in future)
    return true;
}

bool IsAgentBridgeInitialized() {
    return g_agentBridgeInitialized.load();
}

void SetAgentBridgeInitialized(bool initialized) {
    g_agentBridgeInitialized.store(initialized);
}

bool IsVoiceAssistantEnabled() {
    const char* env = std::getenv("RAWRXD_VOICE_ENABLED");
    if (env && (std::strcmp(env, "1") == 0 || std::strcmp(env, "true") == 0)) {
        return true;
    }
    return false; // Disabled by default
}

bool IsVoiceAssistantInitialized() {
    return g_voiceAssistantInitialized.load();
}

void SetVoiceAssistantInitialized(bool initialized) {
    g_voiceAssistantInitialized.store(initialized);
}

bool IsLSPAutoStartEnabled() {
    const char* env = std::getenv("RAWRXD_LSP_AUTOSTART");
    if (env && (std::strcmp(env, "1") == 0 || std::strcmp(env, "true") == 0)) {
        return true;
    }
    return false; // Manual start by default
}

bool IsLSPClientInitialized() {
    return g_lspClientInitialized.load();
}

void SetLSPClientInitialized(bool initialized) {
    g_lspClientInitialized.store(initialized);
}

bool IsDAPServerEnabled() {
    const char* env = std::getenv("RAWRXD_DAP_ENABLED");
    if (env && (std::strcmp(env, "1") == 0 || std::strcmp(env, "true") == 0)) {
        return true;
    }
    return false; // On-demand by default
}

bool IsDAPServerInitialized() {
    return g_dapServerInitialized.load();
}

void SetDAPServerInitialized(bool initialized) {
    g_dapServerInitialized.store(initialized);
}

// ============================================================================
// FEATURE STATE QUERIES
// ============================================================================

bool IsAnyAgentFeatureEnabled() {
    return IsAgentBridgeEnabled() || 
           IsVoiceAssistantEnabled() ||
           IsAgenticIntegrationEnabled();
}

bool IsAnyAutonomousFeatureEnabled() {
    return IsAutonomousFeatureEngineEnabled() ||
           IsAutonomousOrchestratorEnabled() ||
           IsAutonomousModelManagerEnabled();
}

std::string GetFeatureStatusSummary() {
    std::ostringstream oss;
    oss << "Feature Status:\n";
    oss << "  AgentBridge: " << (IsAgentBridgeEnabled() ? "enabled" : "disabled");
    oss << " (" << (IsAgentBridgeInitialized() ? "initialized" : "not initialized") << ")\n";
    oss << "  VoiceAssistant: " << (IsVoiceAssistantEnabled() ? "enabled" : "disabled");
    oss << " (" << (IsVoiceAssistantInitialized() ? "initialized" : "not initialized") << ")\n";
    oss << "  LSP AutoStart: " << (IsLSPAutoStartEnabled() ? "enabled" : "disabled") << "\n";
    oss << "  DAP Server: " << (IsDAPServerEnabled() ? "enabled" : "disabled") << "\n";
    oss << "  Omega Orchestrator: " << (IsOmegaOrchestratorEnabled() ? "enabled" : "disabled (not implemented)") << "\n";
    oss << "  Extension Host: " << (IsExtensionHostEnabled() ? "enabled" : "disabled (stub)") << "\n";
    return oss.str();
}

// ============================================================================
// CONFIGURATION RELOAD
// ============================================================================

void ReloadFeatureFlags() {
    // In future: reload from rawrxd.config.json
    // For now: environment variables are checked on each call
}

void InitializeFeatureRegistry() {
    if (g_registryInitialized) return;
    
    // Set defaults
    g_agentBridgeInitialized = false;
    g_voiceAssistantInitialized = false;
    g_lspClientInitialized = false;
    g_dapServerInitialized = false;
    
    g_registryInitialized = true;
}

} // namespace RawrXD::Features

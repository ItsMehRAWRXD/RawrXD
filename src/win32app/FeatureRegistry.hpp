// ============================================================================
// FeatureRegistry.hpp - Centralized Feature Flag Management
// ============================================================================
// Single source of truth for all feature enablement in RawrXD IDE.
// Runtime flags read from config, compile-time gates for unfinished features.
//
// Phase 1: AgentBridge Activation
// Copyright (c) 2024-2026 RawrXD IDE Project
// ============================================================================

#pragma once

#ifndef RAWRXD_FEATURE_REGISTRY_HPP
#define RAWRXD_FEATURE_REGISTRY_HPP

#include <string>
#include <atomic>

namespace RawrXD::Features {

// ============================================================================
// RUNTIME FEATURE FLAGS (Read from rawrxd.config.json)
// ============================================================================

// AgentBridge - AI Control Bridge for external agent communication
bool IsAgentBridgeEnabled();
bool IsAgentBridgeInitialized();
void SetAgentBridgeInitialized(bool initialized);

// Voice Assistant - Speech recognition and voice commands
bool IsVoiceAssistantEnabled();
bool IsVoiceAssistantInitialized();
void SetVoiceAssistantInitialized(bool initialized);

// LSP Client - Language Server Protocol auto-start
bool IsLSPAutoStartEnabled();
bool IsLSPClientInitialized();
void SetLSPClientInitialized(bool initialized);

// DAP Server - Debug Adapter Protocol
bool IsDAPServerEnabled();
bool IsDAPServerInitialized();
void SetDAPServerInitialized(bool initialized);

// ============================================================================
// COMPILE-TIME FEATURE GATES (Hardcoded until implemented)
// ============================================================================

// Omega Orchestrator - "Phase Ω" autonomous development pipeline
// Status: DECLARED but NOT IMPLEMENTED (Win32IDE.h has 12+ methods with no .cpp)
constexpr bool IsOmegaOrchestratorEnabled() { return false; }

// Extension Host IPC - VS Code-style extension isolation
// Status: STUB implementation only (returns false/empty)
constexpr bool IsExtensionHostEnabled() { return false; }

// Autonomous Feature Engine - Advanced autonomous capabilities
// Status: DECLARED but NEVER INITIALIZED
constexpr bool IsAutonomousFeatureEngineEnabled() { return false; }

// Autonomous Orchestrator - Intelligence orchestration layer
// Status: DECLARED but NEVER INITIALIZED
constexpr bool IsAutonomousOrchestratorEnabled() { return false; }

// Autonomous Model Manager - Self-managing model lifecycle
// Status: DECLARED but NEVER INITIALIZED
constexpr bool IsAutonomousModelManagerEnabled() { return false; }

// Agentic Integration - Full agentic IDE integration
// Status: DECLARED but NEVER INITIALIZED
constexpr bool IsAgenticIntegrationEnabled() { return false; }

// ============================================================================
// FEATURE STATE QUERIES
// ============================================================================

// Returns true if any AI/Agent feature is active
bool IsAnyAgentFeatureEnabled();

// Returns true if any autonomous subsystem is enabled
bool IsAnyAutonomousFeatureEnabled();

// Get feature status summary for telemetry
std::string GetFeatureStatusSummary();

// ============================================================================
// CONFIGURATION RELOAD
// ============================================================================

// Reload feature flags from rawrxd.config.json
void ReloadFeatureFlags();

// Initialize feature registry (call once at startup)
void InitializeFeatureRegistry();

} // namespace RawrXD::Features

#endif // RAWRXD_FEATURE_REGISTRY_HPP

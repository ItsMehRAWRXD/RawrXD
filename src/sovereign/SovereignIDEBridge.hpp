// SovereignIDEBridge.hpp
// Bridge between RawrXD IDE and Sovereign Coordination System
// Wires all 10 coordination primitives into the IDE

#pragma once

#include "spine/ExecutionSpine.hpp"
#include "terminal/TerminalOwnership.hpp"
#include "build/BuildStateGraph.hpp"
#include "agent/AgentLease.hpp"
#include "bus/BeaconBus.hpp"
#include "compression/IntentCompression.hpp"
#include "awareness/SystemAwareness.hpp"
#include "validator/RealityValidator.hpp"
#include "recovery/AutonomousRecovery.hpp"
#include "control/SovereignControlPlane.hpp"
#include "capsule/ExecutionCapsule.hpp"
#include "ide/SovereignIDEIntegration.hpp"

#include <windows.h>
#include <string>
#include <memory>
#include <functional>

namespace RawrXD {
namespace SovereignBridge {

// Initialize the Sovereign Coordination System within the IDE
inline bool InitializeSovereignSystem(HWND mainWindow, HWND editorWindow, HWND terminalPanel, 
                                       HWND buildPanel, HWND statusBar) {
    using namespace Sovereign;
    using namespace Sovereign::IDE;
    
    // Setup IDE window handles
    IDEWindowHandles handles;
    handles.main_window = mainWindow;
    handles.editor_window = editorWindow;
    handles.terminal_panel = terminalPanel;
    handles.build_panel = buildPanel;
    handles.status_bar = statusBar;
    
    // Configure integration
    IDEIntegrationConfig config;
    config.enable_sovereign_capsule = true;
    config.enable_agent_panel = true;
    config.enable_build_graph_panel = true;
    config.enable_terminal_ownership = true;
    config.enable_beacon_overlay = true;
    config.enable_intent_compression = true;
    config.capsule_heartbeat_ms = 1000;
    config.ui_refresh_ms = 100;
    
    // Initialize the integration
    return SovereignIDEIntegration::Instance().Initialize(handles, config);
}

// Shutdown the Sovereign system
inline void ShutdownSovereignSystem() {
    Sovereign::IDE::SovereignIDEIntegration::Instance().Shutdown();
}

// Process a chat message through the coordination system
inline std::string ProcessChatMessage(const std::string& message) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().ProcessChatIntent(message);
}

// Execute a code intent through the coordination system
inline std::string ProcessCodeIntent(const std::string& intent) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().ProcessCodeIntent(intent);
}

// Trigger a build with full state tracking
inline bool TriggerBuild(const std::string& target) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().TriggerBuild(target);
}

// Cancel current build
inline bool CancelBuild() {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().CancelBuild();
}

// Get current build state
inline Sovereign::BuildState GetBuildState() {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().GetBuildState();
}

// Create a terminal with ownership
inline std::string CreateTerminal(const std::string& name) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().CreateTerminal(name);
}

// Execute command in owned terminal
inline bool ExecuteInTerminal(const std::string& terminalId, const std::string& command) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().ExecuteInTerminal(terminalId, command);
}

// Kill terminal
inline bool KillTerminal(const std::string& terminalId) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().KillTerminal(terminalId);
}

// Spawn an editor agent
inline std::string SpawnEditorAgent(const std::string& purpose) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().SpawnEditorAgent(purpose);
}

// Spawn a build agent
inline std::string SpawnBuildAgent(const std::string& purpose) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().SpawnBuildAgent(purpose);
}

// Spawn a debug agent
inline std::string SpawnDebugAgent(const std::string& purpose) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().SpawnDebugAgent(purpose);
}

// Terminate an agent
inline bool TerminateAgent(const std::string& agentId) {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().TerminateAgent(agentId);
}

// Get active agents
inline std::vector<std::string> GetActiveAgents() {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().GetActiveAgents();
}

// Update status bar with sovereign status
inline void UpdateSovereignStatus(const std::string& message) {
    Sovereign::IDE::SovereignIDEIntegration::Instance().UpdateStatusBar(message);
}

// Get system snapshot
inline Sovereign::SystemSnapshot GetSystemSnapshot() {
    return Sovereign::IDE::SovereignIDEIntegration::Instance().GetSystemSnapshot();
}

// Check if system is healthy
inline bool IsSystemHealthy() {
    auto snapshot = GetSystemSnapshot();
    return snapshot.overall_health == Sovereign::HealthStatus::HEALTHY;
}

// RAII guard for Sovereign system
class SovereignSystemGuard {
public:
    SovereignSystemGuard(HWND mainWindow, HWND editorWindow, HWND terminalPanel,
                         HWND buildPanel, HWND statusBar) 
        : initialized_(InitializeSovereignSystem(mainWindow, editorWindow, terminalPanel,
                                                   buildPanel, statusBar)) {}
    
    ~SovereignSystemGuard() {
        if (initialized_) {
            ShutdownSovereignSystem();
        }
    }
    
    bool IsReady() const { return initialized_; }
    
private:
    bool initialized_;
};

} // namespace SovereignBridge
} // namespace RawrXD

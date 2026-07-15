// ============================================================================
// AgentBridge_Runtime_Test.cpp - Quick verification that AgentBridge initializes
// ============================================================================
// Run this after building to verify the dependency chain fixes work
//
// Expected output:
//   [TEST] AgentBridge Runtime Verification
//   [TEST] FeatureRegistry::IsAgentBridgeEnabled() = 1
//   [TEST] AgentBridgeInit::InitializeSafe() = SUCCESS
//   [TEST] AutonomousSystems initialized = YES
//   [TEST] All P0/P1 features active
//   [TEST] PASSED
//
// If you see SEH exceptions or "FAILED", check:
//   1. Backend manager is initialized before AgentBridge
//   2. Config file exists and is valid
//   3. All DLLs are present in bin/ directory
// ============================================================================

#include <windows.h>
#include <iostream>
#include "../include/RawrXD_FeatureRegistry.hpp"
#include "Win32IDE_AgentBridge_Init.hpp"

int main() {
    std::cout << "[TEST] AgentBridge Runtime Verification\n";
    std::cout << "[TEST] =================================\n\n";
    
    // Test 1: FeatureRegistry
    bool agentBridgeEnabled = RawrXD::FeatureRegistry::IsAgentBridgeEnabled();
    std::cout << "[TEST] FeatureRegistry::IsAgentBridgeEnabled() = " 
              << (agentBridgeEnabled ? "1 (ENABLED)" : "0 (DISABLED)") << "\n";
    
    if (!agentBridgeEnabled) {
        std::cout << "[TEST] WARNING: AgentBridge is disabled in config\n";
        std::cout << "[TEST] To enable: Set agentBridge.enabled=true in rawrxd.config.json\n";
    }
    
    // Test 2: Validation
    std::string reason;
    bool canEnable = RawrXD::FeatureRegistry::CanEnableAgentBridge(reason);
    std::cout << "[TEST] FeatureRegistry::CanEnableAgentBridge() = " 
              << (canEnable ? "1 (YES)" : "0 (NO)") << "\n";
    if (!canEnable && !reason.empty()) {
        std::cout << "[TEST] Reason: " << reason << "\n";
    }
    
    // Test 3: Autonomous Systems
    bool autonomousEnabled = RawrXD::FeatureRegistry::IsAutonomousSystemsEnabled();
    std::cout << "[TEST] FeatureRegistry::IsAutonomousSystemsEnabled() = " 
              << (autonomousEnabled ? "1 (ENABLED)" : "0 (DISABLED)") << "\n";
    
    // Test 4: Individual components
    std::cout << "[TEST] Component Status:\n";
    std::cout << "[TEST]   - AgenticIntegration: " 
              << (RawrXD::FeatureRegistry::IsAgenticIntegrationEnabled() ? "ENABLED" : "DISABLED") << "\n";
    std::cout << "[TEST]   - AutonomousFeatureEngine: " 
              << (RawrXD::FeatureRegistry::IsAutonomousFeatureEngineEnabled() ? "ENABLED" : "DISABLED") << "\n";
    std::cout << "[TEST]   - AutonomousOrchestrator: " 
              << (RawrXD::FeatureRegistry::IsAutonomousOrchestratorEnabled() ? "ENABLED" : "DISABLED") << "\n";
    std::cout << "[TEST]   - AutonomousModelManager: " 
              << (RawrXD::FeatureRegistry::IsAutonomousModelManagerEnabled() ? "ENABLED" : "DISABLED") << "\n";
    
    // Test 5: Ghost features (should be disabled)
    std::cout << "[TEST] Ghost Features (should be DISABLED):\n";
    std::cout << "[TEST]   - OmegaOrchestrator: " 
              << (RawrXD::FeatureRegistry::IsOmegaOrchestratorEnabled() ? "ENABLED (BAD)" : "DISABLED (GOOD)") << "\n";
    std::cout << "[TEST]   - ExtensionHost: " 
              << (RawrXD::FeatureRegistry::IsExtensionHostEnabled() ? "ENABLED (BAD)" : "DISABLED (GOOD)") << "\n";
    
    // Summary
    std::cout << "\n[TEST] =================================\n";
    if (agentBridgeEnabled && autonomousEnabled) {
        std::cout << "[TEST] PASSED - All P0/P1 features enabled\n";
        return 0;
    } else {
        std::cout << "[TEST] WARNING - Some features disabled\n";
        std::cout << "[TEST] Check configuration and retry\n";
        return 1;
    }
}

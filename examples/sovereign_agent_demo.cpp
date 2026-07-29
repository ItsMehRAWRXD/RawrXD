// Sovereign Agent Demo - Complete Example Application
// Demonstrates the full Sovereign Substrate in action

#include <iostream>
#include <thread>
#include <chrono>

// All Sovereign Substrate headers
#include "../src/intent/intent_config.hpp"
#include "../src/intent/intent_abi.hpp"
#include "../src/guardrails/capability_policy.hpp"
#include "../src/guardrails/patch_firewall.hpp"
#include "../src/hotpatch/patch_transaction.hpp"
#include "../src/kernel/AgentKernel.hpp"
#include "../src/kernel/IntentExecutionPipeline.hpp"
#include "../src/kernel/TelemetryInjector.hpp"
#include "../src/memory/RepositoryMemoryGraph.hpp"
#include "../src/controlplane/ControlPlaneUI.hpp"

using namespace RawrXD;
using namespace RawrXD::Intent;
using namespace RawrXD::Guardrails;
using namespace RawrXD::Hotpatch;
using namespace RawrXD::Kernel;
using namespace RawrXD::Memory;
using namespace RawrXD::ControlPlane;

// ============================================================================
// Demo: Initialize the Sovereign Substrate
// ============================================================================

void demo_initialization() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  DEMO: Initializing Sovereign Substrate                          ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n\n";
    
    // Check toggle configuration
    auto& config = IntentRuntimeConfig::Instance();
    std::cout << "Intent Guardrails Configuration:\n";
    std::cout << "  Guardrails:    " << (config.GuardrailsEnabled() ? "ON" : "OFF") << "\n";
    std::cout << "  Validation:    " << (config.ValidationEnabled() ? "ON" : "OFF") << "\n";
    std::cout << "  Transactions:  " << (config.TransactionsEnabled() ? "ON" : "OFF") << "\n";
    std::cout << "  Firewall:      " << (config.FirewallEnabled() ? "ON" : "OFF") << "\n\n";
    
    // Initialize Repository Memory Graph
    std::cout << "Initializing Repository Memory Graph...\n";
    RepositoryGraph::Instance().Initialize(".");
    auto stats = RepositoryGraph::Instance().GetStats();
    std::cout << "  Files:   " << stats.fileCount << "\n";
    std::cout << "  Symbols: " << stats.symbolCount << "\n";
    std::cout << "  Edges:   " << stats.edgeCount << "\n\n";
    
    // Initialize Agent Kernel
    std::cout << "Initializing Agent Kernel...\n";
    AgentKernel::Instance().Initialize();
    std::cout << "  Resource Scheduler: OK\n";
    std::cout << "  Beacon Bus:           OK\n\n";
    
    // Initialize Intent Execution Pipeline
    std::cout << "Initializing Intent Execution Pipeline...\n";
    IntentExecutionPipeline::Instance().Initialize();
    std::cout << "  Handlers registered:  " 
              << IntentHandlerRegistry::Instance().GetRegisteredTypes().size() << "\n\n";
    
    // Initialize Control Plane
    std::cout << "Initializing Control Plane UI...\n";
    ControlPlaneUI::Instance().Initialize(8080);
    std::cout << "  Dashboard available at: http://localhost:8080\n\n";
    
    std::cout << "✓ Sovereign Substrate initialized successfully!\n\n";
}

// ============================================================================
// Demo: Create and Execute an Intent
// ============================================================================

void demo_intent_execution() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  DEMO: Intent Execution Pipeline                                 ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n\n";
    
    // Create an agent
    std::cout << "Creating agent 'CODER' with Kimi backend...\n";
    AgentId agentId = 1;
    std::cout << "  Agent ID: " << agentId << "\n\n";
    
    // Create an intent
    std::cout << "Creating intent to optimize function...\n";
    IntentRequest intent;
    intent.type = IntentType::OPTIMIZE;
    intent.target.file_path = "src/kernel/AgentKernel.cpp";
    intent.target.symbol_name = "AgentKernel::ExecuteIntent";
    intent.change.operation = "vectorize_loop";
    intent.change.reason = "improve cache locality";
    intent.change.expected_effect = "2x speedup";
    intent.confidence = 0.92f;
    
    std::cout << "  Intent Type:    " << IntentTypeToString(intent.type) << "\n";
    std::cout << "  Target File:    " << intent.target.file_path << "\n";
    std::cout << "  Target Symbol:  " << intent.target.symbol_name << "\n";
    std::cout << "  Operation:      " << intent.change.operation << "\n";
    std::cout << "  Confidence:     " << intent.confidence << "\n\n";
    
    // Validate through guardrails
    std::cout << "Validating intent through Patch Firewall...\n";
    auto fw_result = PatchFirewall::Instance().ValidateIntent(intent);
    std::cout << "  Result:         " << (fw_result.allowed ? "ALLOWED" : "REJECTED") << "\n";
    std::cout << "  Rule Applied:   " << static_cast<int>(fw_result.rule) << "\n";
    if (fw_result.requires_approval) {
        std::cout << "  ⚠ Requires human approval\n";
    }
    std::cout << "\n";
    
    if (!fw_result.allowed) {
        std::cout << "Intent rejected: " << fw_result.reason << "\n\n";
        return;
    }
    
    // Issue capability token
    std::cout << "Issuing capability token...\n";
    auto token = CapabilityManager::Instance().IssueToken(
        1,  // Intent ID
        Capability::MODIFY_FUNCTION | Capability::COMPILE | Capability::RUN_TEST,
        1,    // Max uses
        300   // Expiry seconds
    );
    
    if (token) {
        std::cout << "  Token ID:       " << token->GetTokenId() << "\n";
        std::cout << "  Capabilities:   MODIFY_FUNCTION, COMPILE, RUN_TEST\n";
        std::cout << "  Expires:        300 seconds\n\n";
    }
    
    // Create kernel intent
    std::cout << "Creating kernel intent...\n";
    Kernel::IntentRequest kernelIntent;
    kernelIntent.intentId = 1;
    kernelIntent.sourceAgent = agentId;
    kernelIntent.intentType = "OPTIMIZE_CODE";
    kernelIntent.priority = IntentPriority::HIGH;
    kernelIntent.requiredResources = {ResourceType::COMPILER, ResourceType::BUILD_SLOT};
    kernelIntent.targetFiles = {intent.target.file_path};
    kernelIntent.maxRetries = 3;
    kernelIntent.requiresHumanApproval = fw_result.requires_approval;
    kernelIntent.timeout = std::chrono::seconds(120);
    
    std::cout << "  Intent ID:      " << kernelIntent.intentId << "\n";
    std::cout << "  Priority:       HIGH\n";
    std::cout << "  Resources:      COMPILER, BUILD_SLOT\n";
    std::cout << "  Timeout:        120 seconds\n\n";
    
    // Execute through pipeline
    std::cout << "Executing intent through pipeline...\n";
    auto result = IntentExecutionPipeline::Instance().Execute(kernelIntent);
    
    std::cout << "  Result:         " << (result.IsSuccess() ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "  Outcome:        " << static_cast<int>(result.outcome) << "\n";
    std::cout << "  Validation:     " << result.validationTimeMs << " ms\n";
    std::cout << "  Execution:      " << result.executionTimeMs << " ms\n";
    std::cout << "  Total:          " << result.totalTimeMs << " ms\n";
    
    if (!result.IsSuccess()) {
        std::cout << "  Error:          " << result.errorMessage << "\n";
    }
    
    if (result.wasRolledBack) {
        std::cout << "  ⚠ Was rolled back to epoch " << result.rollbackEpoch << "\n";
    }
    
    std::cout << "\n✓ Intent execution complete!\n\n";
}

// ============================================================================
// Demo: Resource Coordination
// ============================================================================

void demo_resource_coordination() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  DEMO: Resource Coordination                                     ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n\n";
    
    std::cout << "Simulating 3 agents competing for resources...\n\n";
    
    // Agent 1 acquires terminal
    std::cout << "Agent 1: Acquiring TERMINAL lease...\n";
    auto lease1 = ResourceScheduler::Instance().AcquireLease(
        1, ResourceType::TERMINAL, 0,
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(30),
        "Build command execution",
        100
    );
    
    if (lease1) {
        std::cout << "  ✓ Acquired lease " << lease1->leaseId << "\n";
        std::cout << "    Resource:     TERMINAL #" << lease1->resourceId << "\n";
        std::cout << "    Capabilities: READ, WRITE, EXECUTE\n";
        std::cout << "    Expires:      30 seconds\n\n";
    }
    
    // Agent 2 tries to acquire same resource
    std::cout << "Agent 2: Trying to acquire same TERMINAL...\n";
    auto lease2 = ResourceScheduler::Instance().AcquireLease(
        2, ResourceType::TERMINAL, lease1 ? lease1->resourceId : 0,
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(30),
        "Debug session",
        101
    );
    
    if (!lease2) {
        std::cout << "  ✗ Resource contested - waiting...\n";
        std::cout << "    (In real scenario, would subscribe to beacon events)\n\n";
    }
    
    // Agent 3 acquires different resource
    std::cout << "Agent 3: Acquiring COMPILER lease...\n";
    auto lease3 = ResourceScheduler::Instance().AcquireLease(
        3, ResourceType::COMPILER, 0,
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(60),
        "Compilation task",
        102
    );
    
    if (lease3) {
        std::cout << "  ✓ Acquired lease " << lease3->leaseId << "\n";
        std::cout << "    Resource:     COMPILER #" << lease3->resourceId << "\n\n";
    }
    
    // Show resource status
    std::cout << "Resource Status:\n";
    std::cout << "  TERMINAL #" << (lease1 ? std::to_string(lease1->resourceId) : "N/A") 
              << ": LEASED by Agent 1\n";
    std::cout << "  COMPILER #" << (lease3 ? std::to_string(lease3->resourceId) : "N/A") 
              << ": LEASED by Agent 3\n\n";
    
    // Agent 1 releases
    std::cout << "Agent 1: Releasing TERMINAL...\n";
    if (lease1) {
        ResourceScheduler::Instance().ReleaseLease(lease1->leaseId, 1);
        std::cout << "  ✓ Released\n\n";
    }
    
    // Agent 2 can now acquire
    std::cout << "Agent 2: Re-trying TERMINAL acquisition...\n";
    lease2 = ResourceScheduler::Instance().AcquireLease(
        2, ResourceType::TERMINAL, 0,
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(30),
        "Debug session",
        101
    );
    
    if (lease2) {
        std::cout << "  ✓ Acquired lease " << lease2->leaseId << "\n\n";
    }
    
    // Cleanup
    if (lease2) ResourceScheduler::Instance().ReleaseLease(lease2->leaseId, 2);
    if (lease3) ResourceScheduler::Instance().ReleaseLease(lease3->leaseId, 3);
    
    std::cout << "✓ Resource coordination demo complete!\n\n";
}

// ============================================================================
// Demo: Telemetry and Learning
// ============================================================================

void demo_telemetry() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  DEMO: Telemetry and Self-Reflective Learning                    ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n\n";
    
    // Initialize telemetry
    TelemetryInjector::Instance().Initialize();
    
    std::cout << "Simulating intent execution with violations...\n\n";
    
    // Simulate a rejection
    std::cout << "Intent 1: MODIFY_FUNCTION on protected symbol\n";
    std::cout << "  → Firewall rejected: PROTECTED_MEMORY\n";
    TelemetryInjector::Instance().InjectRejectionFromFirewall(
        "MODIFY_FUNCTION",
        "Kernel::CriticalFunction",
        ViolationCode::PROTECTED_MEMORY,
        "Attempted to modify protected kernel symbol"
    );
    
    // Simulate another rejection
    std::cout << "Intent 2: OPTIMIZE with unaligned patch\n";
    std::cout << "  → Firewall rejected: UNALIGNED_PATCH\n";
    TelemetryInjector::Instance().InjectRejectionFromFirewall(
        "OPTIMIZE_CODE",
        "MatrixMul::Compute",
        ViolationCode::UNALIGNED_PATCH,
        "AVX-512 alignment violation at offset 0x42"
    );
    
    // Simulate a success
    std::cout << "Intent 3: MODIFY_FUNCTION on safe symbol\n";
    std::cout << "  → Success!\n";
    SuccessFeedback success;
    success.feedbackId = 1;
    success.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    success.intentId = 3;
    success.agentId = 1;
    success.intentType = "MODIFY_FUNCTION";
    success.targetSymbol = "UserFunction::Process";
    success.executionTimeMs = 45.2;
    success.latencyImprovement = 1.8;
    success.testsPassed = true;
    success.testsCount = 25;
    TelemetryInjector::Instance().InjectSuccess(success);
    
    std::cout << "\n";
    
    // Show telemetry stats
    auto stats = TelemetryInjector::Instance().GetStats();
    std::cout << "Telemetry Statistics:\n";
    std::cout << "  Total Rejections:  " << stats.totalRejections << "\n";
    std::cout << "  Total Successes:   " << stats.totalSuccesses << "\n";
    std::cout << "  Ring Buffer Size:    " << stats.ringBufferSize << "\n\n";
    
    // Pop rejections for model feedback
    std::cout << "Feedback for model:\n";
    auto rejection = TelemetryInjector::Instance().TryPopRejection();
    if (rejection) {
        std::cout << "  [REJECTION] " << rejection->intentType << ": "
                  << ViolationCodeToString(rejection->code) << "\n";
        std::cout << "  Suggestion: " << rejection->suggestedFix << "\n\n";
    }
    
    auto successFeedback = TelemetryInjector::Instance().TryPopSuccess();
    if (successFeedback) {
        std::cout << "  [SUCCESS] " << successFeedback->intentType << ": "
                  << successFeedback->targetSymbol << "\n";
        std::cout << "  Performance: " << successFeedback->latencyImprovement << "x improvement\n\n";
    }
    
    TelemetryInjector::Instance().Shutdown();
    
    std::cout << "✓ Telemetry demo complete!\n\n";
}

// ============================================================================
// Demo: Control Plane Dashboard
// ============================================================================

void demo_control_plane() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  DEMO: Control Plane Dashboard                                   ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n\n";
    
    std::cout << "Capturing system snapshot...\n\n";
    
    // Capture dashboard state
    auto state = ControlPlaneUI::Instance().CaptureSnapshot();
    
    std::cout << "Dashboard State:\n";
    std::cout << "  Timestamp:         " << state.timestamp << "\n";
    std::cout << "  System Status:     " << state.systemStatus << "\n";
    std::cout << "  Active Agents:     " << state.activeAgentCount << "\n";
    std::cout << "  Executing Intents: " << state.executingIntentCount << "\n";
    std::cout << "  Queued Intents:    " << state.queuedIntentCount << "\n";
    std::cout << "  Available Resources: " << state.availableResources << "\n";
    std::cout << "  Contested Resources: " << state.contestedResources << "\n\n";
    
    std::cout << "Memory Graph:\n";
    std::cout << "  Files:   " << state.memoryGraph.totalFiles << "\n";
    std::cout << "  Symbols: " << state.memoryGraph.totalSymbols << "\n";
    std::cout << "  Edges:   " << state.memoryGraph.totalEdges << "\n";
    std::cout << "  Memory:  " << state.memoryGraph.memoryUsageMB << " MB\n\n";
    
    // Print summary
    ControlPlaneUI::Instance().PrintSummary();
    
    std::cout << "✓ Control Plane demo complete!\n\n";
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "║           SOVEREIGN SUBSTRATE - COMPLETE DEMO                     ║\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "║     Self-Evolving Computational Entity Demonstration              ║\n";
    std::cout << "║                                                                   ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    try {
        // Run all demos
        demo_initialization();
        demo_intent_execution();
        demo_resource_coordination();
        demo_telemetry();
        demo_control_plane();
        
        // Cleanup
        std::cout << "Shutting down Sovereign Substrate...\n";
        ControlPlaneUI::Instance().Shutdown();
        IntentExecutionPipeline::Instance().Shutdown();
        AgentKernel::Instance().Shutdown();
        RepositoryGraph::Instance().Shutdown();
        
        std::cout << "\n╔═══════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║  ✓ DEMO COMPLETE                                                  ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
        std::cout << "\n";
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\n✗ ERROR: " << e.what() << "\n\n";
        return 1;
    }
}

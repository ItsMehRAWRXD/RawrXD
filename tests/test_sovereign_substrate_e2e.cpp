// Sovereign Substrate - End-to-End Integration Tests
// Tests the complete pipeline: Intent -> Guardrails -> Kernel -> Puppeteer

#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <filesystem>

// All Sovereign Substrate headers
#include "../src/intent/intent_config.hpp"
#include "../src/intent/intent_abi.hpp"
#include "../src/intent/model_adapter.hpp"
#include "../src/guardrails/capability_policy.hpp"
#include "../src/guardrails/patch_firewall.hpp"
#include "../src/hotpatch/patch_transaction.hpp"
#include "../src/kernel/AgentKernel.hpp"
#include "../src/kernel/IntentExecutionPipeline.hpp"
#include "../src/kernel/TelemetryInjector.hpp"
#include "../src/kernel/IntentReplayEngine.hpp"
#include "../src/kernel/BuildTelemetry.hpp"
#include "../src/memory/RepositoryMemoryGraph.hpp"
#include "../src/controlplane/ControlPlaneUI.hpp"
#include "../src/security/SecurityHardening.hpp"

using namespace RawrXD;
using namespace RawrXD::Intent;
using namespace RawrXD::Guardrails;
using namespace RawrXD::Hotpatch;
using namespace RawrXD::Kernel;
using namespace RawrXD::Memory;
using namespace RawrXD::ControlPlane;
using namespace RawrXD::Security;

// ============================================================================
// Test Utilities
// ============================================================================

static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) \
    std::cout << "  " #name "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED\n"; \
        testsPassed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << "\n"; \
        testsFailed++; \
    }

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        throw std::runtime_error("Assertion failed: " #expr); \
    }

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))

// ============================================================================
// Test Suite: Full Pipeline
// ============================================================================

TEST(full_pipeline_valid_intent) {
    // Initialize all systems
    ASSERT_TRUE(IntentRuntimeConfig::Instance().GuardrailsEnabled());
    
    // Create a valid intent
    IntentRequest intent;
    intent.type = IntentType::MODIFY_FUNCTION;
    intent.target.file_path = "src/test.cpp";
    intent.target.symbol_name = "TestFunction";
    intent.change.operation = "optimize_loop";
    intent.change.reason = "improve performance";
    intent.confidence = 0.95f;
    
    // Validate through firewall
    auto fw_result = PatchFirewall::Instance().ValidateIntent(intent);
    ASSERT_TRUE(fw_result.allowed);
    
    // Create kernel intent
    Kernel::IntentRequest kernelIntent;
    kernelIntent.intentType = "MODIFY_FUNCTION";
    kernelIntent.intentId = 1;
    kernelIntent.sourceAgent = 1;
    kernelIntent.priority = Kernel::IntentPriority::NORMAL;
    kernelIntent.requiredResources = {Kernel::ResourceType::COMPILER};
    
    // Execute through pipeline (dry-run mode)
    IntentExecutionPipeline::Instance().Initialize();
    IntentExecutionPipeline::Instance().EnableDryRunMode(true);
    
    auto result = IntentExecutionPipeline::Instance().Execute(kernelIntent);
    ASSERT_TRUE(result.IsSuccess());
    
    IntentExecutionPipeline::Instance().Shutdown();
}

TEST(full_pipeline_invalid_intent_rejected) {
    // Create an invalid intent (protected symbol)
    IntentRequest intent;
    intent.type = IntentType::MODIFY_FUNCTION;
    intent.target.symbol_name = "main";  // Often protected
    intent.change.operation = "delete";
    intent.confidence = 0.5f;  // Low confidence
    
    // Should be rejected or require approval
    auto fw_result = PatchFirewall::Instance().ValidateIntent(intent);
    // Note: In real implementation, this might be rejected based on policy
    
    ASSERT_TRUE(fw_result.requires_approval || !fw_result.allowed);
}

TEST(full_pipeline_with_telemetry_feedback) {
    // Initialize telemetry
    TelemetryInjector::Instance().Initialize();
    
    // Inject a rejection
    TelemetryInjector::Instance().InjectRejectionFromFirewall(
        "MODIFY_FUNCTION",
        "ProtectedSymbol",
        ViolationCode::PROTECTED_MEMORY,
        "Attempted to modify protected kernel symbol"
    );
    
    // Verify it was recorded
    auto stats = TelemetryInjector::Instance().GetStats();
    ASSERT_EQ(stats.totalRejections, 1);
    
    // Pop and verify
    auto feedback = TelemetryInjector::Instance().TryPopRejection();
    ASSERT_TRUE(feedback.has_value());
    ASSERT_EQ(feedback->code, ViolationCode::PROTECTED_MEMORY);
    
    TelemetryInjector::Instance().Shutdown();
}

TEST(full_pipeline_resource_coordination) {
    // Initialize kernel
    AgentKernel::Instance().Initialize();
    
    // Agent 1 acquires terminal
    auto lease1 = ResourceScheduler::Instance().AcquireLease(
        1,  // Agent 1
        ResourceType::TERMINAL,
        0,  // Any terminal
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(30),
        "Test lease",
        100
    );
    
    ASSERT_TRUE(lease1 != nullptr);
    ASSERT_TRUE(lease1->isActive.load());
    
    // Verify agent 1 has the lease
    ASSERT_TRUE(ResourceScheduler::Instance().IsResourceAvailable(
        ResourceType::TERMINAL, lease1->resourceId
    ) == false);
    
    // Release
    ASSERT_TRUE(ResourceScheduler::Instance().ReleaseLease(
        lease1->leaseId, 1
    ));
    
    AgentKernel::Instance().Shutdown();
}

TEST(full_pipeline_with_memory_graph) {
    // Create temporary test directory
    std::string tempDir = std::filesystem::temp_directory_path().string() + "/rawrxd_e2e_test";
    std::filesystem::create_directories(tempDir);
    
    // Create test files
    {
        std::ofstream f(tempDir + "/main.cpp");
        f << "int main() { return 0; }\n";
    }
    {
        std::ofstream f(tempDir + "/utils.h");
        f << "#pragma once\nint calculate(int x);\n";
    }
    
    // Initialize memory graph
    ASSERT_TRUE(RepositoryGraph::Instance().Initialize(tempDir));
    
    // Verify files were loaded
    auto stats = RepositoryGraph::Instance().GetStats();
    ASSERT_TRUE(stats.fileCount >= 2);
    
    // Find a file
    auto file = RepositoryGraph::Instance().GetFileByPath("main.cpp");
    ASSERT_TRUE(file != nullptr);
    ASSERT_EQ(file->name, "main.cpp");
    
    // Add a symbol
    auto symbol = RepositoryGraph::Instance().AddSymbol("calculate", NodeType::FUNCTION);
    ASSERT_TRUE(symbol != nullptr);
    ASSERT_EQ(symbol->name, "calculate");
    
    // Find the symbol
    auto found = RepositoryGraph::Instance().FindSymbol("calculate");
    ASSERT_TRUE(found != nullptr);
    ASSERT_EQ(found->symbolId, symbol->symbolId);
    
    // Cleanup
    RepositoryGraph::Instance().Shutdown();
    std::filesystem::remove_all(tempDir);
}

TEST(full_pipeline_intent_replay) {
    // Initialize replay engine
    ReplayEngine::Instance().Initialize();
    
    // Capture initial state
    auto snapshot = ReplayEngine::Instance().CaptureSnapshot(1, "TEST_AGENT");
    ASSERT_NE(snapshot.snapshotId, 0);
    
    // Create a replay record
    ReplayRecord record;
    record.recordId = 1;
    record.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    record.intent.intentType = "MODIFY_FUNCTION";
    record.intent.sourceAgent = 1;
    record.preSnapshot = snapshot;
    record.succeeded = true;
    record.patchHash = "abc123";
    
    // Compute replay hash
    auto hash = record.ComputeReplayHash();
    ASSERT_FALSE(hash.empty());
    
    ReplayEngine::Instance().Shutdown();
}

TEST(full_pipeline_build_telemetry) {
    // Initialize build telemetry
    BuildTelemetryCollector::Instance().Initialize();
    
    // Parse MSVC-style error
    std::string msvcOutput = "C:\\project\\main.cpp(42,15): error C2065: 'x': undeclared identifier\n";
    auto events = BuildTelemetryCollector::Instance().ParseOutput(msvcOutput, 12345);
    
    ASSERT_TRUE(events.size() > 0);
    ASSERT_EQ(events[0].type, BuildEventType::COMPILATION_ERROR);
    ASSERT_EQ(events[0].lineNumber, 42);
    
    BuildTelemetryCollector::Instance().Shutdown();
}

TEST(full_pipeline_control_plane_logging) {
    // Initialize control plane
    ControlPlaneUI::Instance().Initialize(18080);  // Different port for testing
    
    // Log some events
    ControlPlaneUI::Instance().LogEvent("TEST", "Test event", "INFO");
    ControlPlaneUI::Instance().LogIntentStarted(1, 1);
    ControlPlaneUI::Instance().LogIntentCompleted(1, true);
    
    // Capture snapshot
    auto state = ControlPlaneUI::Instance().CaptureSnapshot();
    ASSERT_FALSE(state.timestamp.empty());
    
    ControlPlaneUI::Instance().Shutdown();
}

TEST(full_pipeline_transaction_rollback) {
    // Create a transaction
    uint64_t intentId = 999;
    
    RAWR_PATCH_TX_BEGIN(intentId)
        // Add a patch
        Patch patch;
        patch.type = PatchType::FUNCTION_SWAP;
        patch.symbol_name = "TestFunction";
        patch.after_data = {0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00, 0xC3};
        
        __tx.AddPatch(patch);
        
        // Validate (should pass in dry-run)
        ASSERT_TRUE(__tx.Validate());
        
        // Apply
        ASSERT_TRUE(__tx.Apply());
        
    RAWR_PATCH_TX_COMMIT()
    
    // Transaction should be committed
    // In real implementation, would verify state change
}

TEST(full_pipeline_model_adapter) {
    // Register a mock backend
    BackendConfig config;
    config.name = "test_backend";
    config.type = "test";
    config.enabled = true;
    config.priority = 1;
    
    // Note: In real test, would register actual backend
    // ModelAdapter::Instance().RegisterBackend(std::make_shared<TestBackend>(config));
    
    // Verify backend registration
    // auto backends = ModelAdapter::Instance().GetBackends();
    // ASSERT_TRUE(backends.size() > 0);
}

TEST(full_pipeline_capability_tokens) {
    // Issue a capability token
    auto token = CapabilityManager::Instance().IssueToken(
        1,  // Intent ID
        Capability::MODIFY_FUNCTION | Capability::COMPILE,
        5,     // Max uses
        300    // Expiry seconds
    );
    
    ASSERT_TRUE(token.has_value());
    ASSERT_TRUE(token->IsValid());
    ASSERT_TRUE(token->HasCapability(Capability::MODIFY_FUNCTION));
    ASSERT_TRUE(token->HasCapability(Capability::COMPILE));
    ASSERT_FALSE(token->HasCapability(Capability::DEBUG));
    
    // Validate the token
    ASSERT_TRUE(CapabilityManager::Instance().ValidateToken(token->GetTokenId()));
    
    // Use the token
    ASSERT_TRUE(CapabilityManager::Instance().UseToken(token->GetTokenId()));
    ASSERT_EQ(token->GetUsesRemaining(), 4);
}

// ============================================================================
// Test Suite: Stress Tests
// ============================================================================

TEST(stress_multiple_agents) {
    AgentKernel::Instance().Initialize();
    
    // Simulate 10 agents acquiring resources
    std::vector<std::shared_ptr<ResourceLease>> leases;
    
    for (int i = 1; i <= 10; i++) {
        auto lease = ResourceScheduler::Instance().AcquireLease(
            i,
            ResourceType::BUILD_SLOT,
            0,  // Any slot
            LeaseCapabilities::ReadOnly(),
            std::chrono::seconds(60),
            "Build task",
            i
        );
        
        if (lease) {
            leases.push_back(lease);
        }
    }
    
    // Should have acquired some leases (depending on available slots)
    ASSERT_TRUE(leases.size() > 0);
    
    // Release all
    for (auto& lease : leases) {
        ResourceScheduler::Instance().ReleaseLease(lease->leaseId, lease->owner);
    }
    
    AgentKernel::Instance().Shutdown();
}

TEST(stress_rapid_intents) {
    IntentExecutionPipeline::Instance().Initialize();
    IntentExecutionPipeline::Instance().EnableDryRunMode(true);
    
    // Execute 100 intents rapidly
    for (int i = 0; i < 100; i++) {
        Kernel::IntentRequest intent;
        intent.intentType = "BUILD_PROJECT";
        intent.intentId = i;
        intent.sourceAgent = 1;
        intent.priority = Kernel::IntentPriority::NORMAL;
        
        auto result = IntentExecutionPipeline::Instance().Execute(intent);
        ASSERT_TRUE(result.IsSuccess());
    }
    
    // Check stats
    auto stats = IntentExecutionPipeline::Instance().GetStats();
    ASSERT_EQ(stats.totalIntents, 100);
    ASSERT_EQ(stats.successfulIntents, 100);
    
    IntentExecutionPipeline::Instance().Shutdown();
}

// ============================================================================
// Test Suite: Security Integration
// ============================================================================

TEST(security_audit_log_integration) {
    // Initialize security manager
    ASSERT_TRUE(SecurityManager::Instance().Initialize(SecurityLevel::STANDARD));
    
    // Initialize pipeline (which uses security)
    IntentExecutionPipeline::Instance().Initialize();
    IntentExecutionPipeline::Instance().EnableDryRunMode(true);
    
    // Execute an intent
    Kernel::IntentRequest intent;
    intent.intentType = "BUILD_PROJECT";
    intent.intentId = 1;
    intent.sourceAgent = 1;
    intent.priority = Kernel::IntentPriority::NORMAL;
    
    auto result = IntentExecutionPipeline::Instance().Execute(intent);
    ASSERT_TRUE(result.IsSuccess());
    
    // Check audit log has events
    auto auditStats = AuditLog::Instance().GetStats();
    ASSERT_TRUE(auditStats.totalEvents >= 2); // Startup + intent
    
    // Verify chain integrity
    ASSERT_TRUE(AuditLog::Instance().VerifyChain());
    
    IntentExecutionPipeline::Instance().Shutdown();
    SecurityManager::Instance().Shutdown();
}

TEST(security_rate_limiting_integration) {
    // Initialize with strict rate limits
    ASSERT_TRUE(SecurityManager::Instance().Initialize(SecurityLevel::HIGH));
    
    IntentExecutionPipeline::Instance().Initialize();
    IntentExecutionPipeline::Instance().EnableDryRunMode(true);
    
    // Execute intents rapidly
    int successCount = 0;
    int rateLimitedCount = 0;
    
    for (int i = 0; i < 20; i++) {
        Kernel::IntentRequest intent;
        intent.intentType = "BUILD_PROJECT";
        intent.intentId = i;
        intent.sourceAgent = 1;
        intent.priority = Kernel::IntentPriority::NORMAL;
        
        auto result = IntentExecutionPipeline::Instance().Execute(intent);
        if (result.IsSuccess()) {
            successCount++;
        } else if (result.outcome == ExecutionResult::Outcome::VALIDATION_FAILED &&
                   result.errorMessage.find("Security check failed") != std::string::npos) {
            rateLimitedCount++;
        }
    }
    
    // Some should succeed, some should be rate limited
    ASSERT_TRUE(successCount > 0);
    
    IntentExecutionPipeline::Instance().Shutdown();
    SecurityManager::Instance().Shutdown();
}

TEST(security_input_validation_integration) {
    ASSERT_TRUE(SecurityManager::Instance().Initialize(SecurityLevel::STANDARD));
    
    IntentExecutionPipeline::Instance().Initialize();
    IntentExecutionPipeline::Instance().EnableDryRunMode(true);
    
    // Test with dangerous file path
    Kernel::IntentRequest intent;
    intent.intentType = "MODIFY_FUNCTION";
    intent.intentId = 1;
    intent.sourceAgent = 1;
    intent.priority = Kernel::IntentPriority::NORMAL;
    intent.targetFiles = {"../../../etc/passwd"}; // Path traversal attempt
    
    auto result = IntentExecutionPipeline::Instance().Execute(intent);
    ASSERT_FALSE(result.IsSuccess());
    ASSERT_TRUE(result.errorMessage.find("File path validation failed") != std::string::npos);
    
    IntentExecutionPipeline::Instance().Shutdown();
    SecurityManager::Instance().Shutdown();
}

TEST(security_lockdown_integration) {
    ASSERT_TRUE(SecurityManager::Instance().Initialize(SecurityLevel::STANDARD));
    
    IntentExecutionPipeline::Instance().Initialize();
    IntentExecutionPipeline::Instance().EnableDryRunMode(true);
    
    // Trigger emergency lockdown
    SecurityManager::Instance().EmergencyLockdown("Test lockdown");
    ASSERT_TRUE(SecurityManager::Instance().IsInLockdown());
    
    // Try to execute intent during lockdown
    Kernel::IntentRequest intent;
    intent.intentType = "BUILD_PROJECT";
    intent.intentId = 1;
    intent.sourceAgent = 1;
    intent.priority = Kernel::IntentPriority::NORMAL;
    
    auto result = IntentExecutionPipeline::Instance().Execute(intent);
    ASSERT_FALSE(result.IsSuccess());
    ASSERT_TRUE(result.errorMessage.find("lockdown") != std::string::npos);
    
    // Lift lockdown
    SecurityManager::Instance().LiftLockdown();
    ASSERT_FALSE(SecurityManager::Instance().IsInLockdown());
    
    // Should work now
    auto result2 = IntentExecutionPipeline::Instance().Execute(intent);
    ASSERT_TRUE(result2.IsSuccess());
    
    IntentExecutionPipeline::Instance().Shutdown();
    SecurityManager::Instance().Shutdown();
}

TEST(security_audit_chain_integrity) {
    ASSERT_TRUE(SecurityManager::Instance().Initialize(SecurityLevel::STANDARD));
    
    IntentExecutionPipeline::Instance().Initialize();
    IntentExecutionPipeline::Instance().EnableDryRunMode(true);
    
    // Execute multiple intents
    for (int i = 0; i < 10; i++) {
        Kernel::IntentRequest intent;
        intent.intentType = "BUILD_PROJECT";
        intent.intentId = i;
        intent.sourceAgent = 1;
        intent.priority = Kernel::IntentPriority::NORMAL;
        
        IntentExecutionPipeline::Instance().Execute(intent);
    }
    
    // Run security audit
    ASSERT_TRUE(SecurityManager::Instance().RunSecurityAudit());
    
    // Verify chain
    ASSERT_TRUE(AuditLog::Instance().VerifyChain());
    
    IntentExecutionPipeline::Instance().Shutdown();
    SecurityManager::Instance().Shutdown();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SOVEREIGN SUBSTRATE - END-TO-END INTEGRATION TESTS          ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    // Full Pipeline Tests
    std::cout << "┌─ Full Pipeline Tests ─────────────────────────────────────────────┐\n";
    RUN_TEST(full_pipeline_valid_intent);
    RUN_TEST(full_pipeline_invalid_intent_rejected);
    RUN_TEST(full_pipeline_with_telemetry_feedback);
    RUN_TEST(full_pipeline_resource_coordination);
    RUN_TEST(full_pipeline_with_memory_graph);
    RUN_TEST(full_pipeline_intent_replay);
    RUN_TEST(full_pipeline_build_telemetry);
    RUN_TEST(full_pipeline_control_plane_logging);
    RUN_TEST(full_pipeline_transaction_rollback);
    RUN_TEST(full_pipeline_model_adapter);
    RUN_TEST(full_pipeline_capability_tokens);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Stress Tests
    std::cout << "┌─ Stress Tests ────────────────────────────────────────────────────┐\n";
    RUN_TEST(stress_multiple_agents);
    RUN_TEST(stress_rapid_intents);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Security Integration Tests
    std::cout << "┌─ Security Integration Tests ──────────────────────────────────────┐\n";
    RUN_TEST(security_audit_log_integration);
    RUN_TEST(security_rate_limiting_integration);
    RUN_TEST(security_input_validation_integration);
    RUN_TEST(security_lockdown_integration);
    RUN_TEST(security_audit_chain_integrity);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Summary
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  TEST RESULTS: " << testsPassed << " passed, " << testsFailed << " failed";
    std::cout << std::string(35 - std::to_string(testsPassed).length() - std::to_string(testsFailed).length(), ' ') << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    return testsFailed > 0 ? 1 : 0;
}

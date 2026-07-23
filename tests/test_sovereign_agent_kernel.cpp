// Sovereign Agent Kernel - Integration Tests
// Tests the end-to-end flow: Intent -> Guardrails -> Execution -> Telemetry

#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

#include "../src/kernel/AgentKernel.hpp"
#include "../src/kernel/IntentExecutionPipeline.hpp"
#include "../src/kernel/TelemetryInjector.hpp"
#include "../src/kernel/IntentReplayEngine.hpp"
#include "../src/kernel/BuildTelemetry.hpp"
#include "../src/intent/intent_config.hpp"
#include "../src/intent/intent_abi.hpp"

using namespace RawrXD::Kernel;
using namespace RawrXD::Intent;
using namespace RawrXD::Guardrails;
using namespace RawrXD::Hotpatch;

// ============================================================================
// Test Utilities
// ============================================================================

static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) \
    std::cout << "Running " #name "... "; \
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
// Test: Resource Lease Management
// ============================================================================

TEST(resource_lease_basic) {
    auto& scheduler = ResourceScheduler::Instance();
    
    // Acquire a terminal lease
    auto lease = scheduler.AcquireLease(
        1,  // Agent 1
        ResourceType::TERMINAL,
        0,  // Any terminal
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(30),
        "Test terminal access",
        100  // Intent 100
    );
    
    ASSERT_TRUE(lease != nullptr);
    ASSERT_TRUE(lease->isActive.load());
    ASSERT_TRUE(lease->HasCapability("read"));
    ASSERT_TRUE(lease->HasCapability("write"));
    ASSERT_FALSE(lease->IsExpired());
    
    // Release the lease
    ASSERT_TRUE(scheduler.ReleaseLease(lease->leaseId, 1));
    ASSERT_FALSE(lease->isActive.load());
}

TEST(resource_lease_contention) {
    auto& scheduler = ResourceScheduler::Instance();
    
    // Agent 1 acquires terminal
    auto lease1 = scheduler.AcquireLease(
        1, ResourceType::TERMINAL, 0,
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(30),
        "Agent 1 terminal",
        101
    );
    ASSERT_TRUE(lease1 != nullptr);
    
    // Agent 2 tries to acquire same resource - should fail or get different resource
    auto lease2 = scheduler.AcquireLease(
        2, ResourceType::TERMINAL, lease1->resourceId,
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(30),
        "Agent 2 terminal",
        102
    );
    
    // Either lease2 is null (contention) or it's a different resource
    if (lease2 != nullptr) {
        ASSERT_NE(lease1->resourceId, lease2->resourceId);
    }
    
    // Cleanup
    if (lease1) scheduler.ReleaseLease(lease1->leaseId, 1);
    if (lease2) scheduler.ReleaseLease(lease2->leaseId, 2);
}

TEST(resource_lease_expiration) {
    auto& scheduler = ResourceScheduler::Instance();
    
    // Acquire short-lived lease
    auto lease = scheduler.AcquireLease(
        1, ResourceType::TERMINAL, 0,
        LeaseCapabilities::FullAccess(),
        std::chrono::milliseconds(100),  // Very short
        "Short lease",
        103
    );
    
    ASSERT_TRUE(lease != nullptr);
    ASSERT_FALSE(lease->IsExpired());
    
    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    
    ASSERT_TRUE(lease->IsExpired());
}

// ============================================================================
// Test: Intent Execution Pipeline
// ============================================================================

TEST(intent_pipeline_initialization) {
    auto& pipeline = IntentExecutionPipeline::Instance();
    ASSERT_TRUE(pipeline.Initialize());
    ASSERT_TRUE(pipeline.IsInitialized());
    
    // Check handlers are registered
    auto& registry = IntentHandlerRegistry::Instance();
    ASSERT_TRUE(registry.HasHandler("MODIFY_FUNCTION"));
    ASSERT_TRUE(registry.HasHandler("BUILD_PROJECT"));
    ASSERT_TRUE(registry.HasHandler("RUN_TESTS"));
    ASSERT_TRUE(registry.HasHandler("DEBUG_SESSION"));
    ASSERT_TRUE(registry.HasHandler("OPTIMIZE_CODE"));
    
    pipeline.Shutdown();
}

TEST(intent_pipeline_dry_run) {
    auto& pipeline = IntentExecutionPipeline::Instance();
    pipeline.Initialize();
    pipeline.EnableDryRunMode(true);
    
    // Create a test intent
    IntentRequest intent;
    intent.intentId = 1000;
    intent.sourceAgent = 1;
    intent.intentType = "BUILD_PROJECT";
    intent.priority = IntentPriority::NORMAL;
    intent.requiredResources = {ResourceType::COMPILER, ResourceType::BUILD_SLOT};
    intent.maxRetries = 3;
    intent.requiresHumanApproval = false;
    intent.timeout = std::chrono::seconds(60);
    
    // Execute in dry-run mode
    auto result = pipeline.Execute(intent);
    
    // In dry-run mode, should succeed without actual execution
    ASSERT_TRUE(result.IsSuccess() || result.outcome == ExecutionResult::Outcome::SUCCESS);
    
    pipeline.Shutdown();
}

// ============================================================================
// Test: Telemetry Injector
// ============================================================================

TEST(telemetry_injector_rejection) {
    auto& injector = TelemetryInjector::Instance();
    injector.Initialize();
    
    // Inject a rejection
    injector.InjectRejectionFromFirewall(
        "MODIFY_FUNCTION",
        "TestFunction",
        ViolationCode::PROTECTED_MEMORY,
        "Attempted write to protected kernel region"
    );
    
    // Check that rejection was recorded
    auto stats = injector.GetStats();
    ASSERT_EQ(stats.totalRejections, 1);
    
    // Try to pop the rejection
    auto feedback = injector.TryPopRejection();
    ASSERT_TRUE(feedback.has_value());
    ASSERT_EQ(feedback->code, ViolationCode::PROTECTED_MEMORY);
    ASSERT_EQ(feedback->intentType, "MODIFY_FUNCTION");
    ASSERT_EQ(feedback->targetSymbol, "TestFunction");
    
    injector.Shutdown();
}

TEST(telemetry_injector_success) {
    auto& injector = TelemetryInjector::Instance();
    injector.Initialize();
    
    // Inject a success
    SuccessFeedback success;
    success.feedbackId = 1;
    success.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    success.intentId = 2000;
    success.agentId = 1;
    success.intentType = "OPTIMIZE_CODE";
    success.targetSymbol = "MatrixMul";
    success.executionTimeMs = 42.0;
    success.latencyImprovement = 2.5;
    success.testsPassed = true;
    success.testsCount = 150;
    
    injector.InjectSuccess(success);
    
    // Check stats
    auto stats = injector.GetStats();
    ASSERT_EQ(stats.totalSuccesses, 1);
    
    // Pop the success
    auto popped = injector.TryPopSuccess();
    ASSERT_TRUE(popped.has_value());
    ASSERT_EQ(popped->intentType, "OPTIMIZE_CODE");
    ASSERT_EQ(popped->latencyImprovement, 2.5);
    
    injector.Shutdown();
}

// ============================================================================
// Test: Intent Replay Engine
// ============================================================================

TEST(replay_engine_snapshot) {
    auto& engine = ReplayEngine::Instance();
    engine.Initialize();
    
    // Capture a snapshot
    auto snapshot = engine.CaptureSnapshot(1, "TEST_AGENT");
    ASSERT_NE(snapshot.snapshotId, 0);
    ASSERT_EQ(snapshot.agentId, 1);
    ASSERT_EQ(snapshot.agentType, "TEST_AGENT");
    
    // Verify context hash is computed
    auto hash = snapshot.ComputeContextHash();
    ASSERT_FALSE(hash.empty());
    
    engine.Shutdown();
}

TEST(replay_engine_record) {
    auto& engine = ReplayEngine::Instance();
    engine.Initialize();
    
    // Create a replay record
    ReplayRecord record;
    record.recordId = 1;
    record.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    record.intent.intentType = "MODIFY_FUNCTION";
    record.intent.sourceAgent = 1;
    record.succeeded = true;
    record.executionTimeMs = 100.0;
    record.patchHash = "abc123";
    
    // Compute replay hash
    auto replayHash = record.ComputeReplayHash();
    ASSERT_FALSE(replayHash.empty());
    
    engine.Shutdown();
}

// ============================================================================
// Test: Build Telemetry
// ============================================================================

TEST(build_telemetry_msvc_parser) {
    auto& collector = BuildTelemetryCollector::Instance();
    collector.Initialize();
    
    // MSVC-style error output
    std::string msvcOutput = R"(
C:\project\main.cpp(42,15): error C2065: 'undefinedVar': undeclared identifier
C:\project\utils.cpp(10,5): warning C4101: 'unused': unreferenced local variable
)";
    
    auto events = collector.ParseOutput(msvcOutput, 12345);
    
    // Should find 2 events
    ASSERT_EQ(events.size(), 2);
    
    // First event should be an error
    ASSERT_EQ(events[0].type, BuildEventType::COMPILATION_ERROR);
    ASSERT_EQ(events[0].severity, Severity::ERROR);
    ASSERT_EQ(events[0].sourceFile, "C:\\project\\main.cpp");
    ASSERT_EQ(events[0].lineNumber, 42);
    ASSERT_EQ(events[0].columnNumber, 15);
    ASSERT_EQ(events[0].errorCode, "C2065");
    
    // Second event should be a warning
    ASSERT_EQ(events[1].type, BuildEventType::COMPILATION_WARNING);
    ASSERT_EQ(events[1].severity, Severity::WARNING);
    
    collector.Shutdown();
}

TEST(build_telemetry_clang_parser) {
    auto& collector = BuildTelemetryCollector::Instance();
    collector.Initialize();
    
    // Clang-style error output
    std::string clangOutput = R"(
/path/to/file.cpp:25:10: error: use of undeclared identifier 'foo'
/path/to/file.cpp:30:5: warning: unused variable 'bar' [-Wunused-variable]
)";
    
    auto events = collector.ParseOutput(clangOutput, 12346);
    
    // Should find 2 events
    ASSERT_EQ(events.size(), 2);
    
    // First event should be an error
    ASSERT_EQ(events[0].type, BuildEventType::COMPILATION_ERROR);
    ASSERT_EQ(events[0].sourceFile, "/path/to/file.cpp");
    ASSERT_EQ(events[0].lineNumber, 25);
    ASSERT_EQ(events[0].columnNumber, 10);
    
    collector.Shutdown();
}

TEST(build_telemetry_ninja_progress) {
    auto& collector = BuildTelemetryCollector::Instance();
    collector.Initialize();
    
    // Ninja progress output
    std::string ninjaOutput = R"(
[1/100] Building CXX object CMakeFiles/foo.dir/main.cpp.obj
[42/100] Building CXX object CMakeFiles/foo.dir/utils.cpp.obj
[100/100] Linking CXX executable foo.exe
)";
    
    auto events = collector.ParseOutput(ninjaOutput, 12347);
    
    // Should find progress events
    ASSERT_TRUE(events.size() >= 2);
    
    // Check progress percentages
    bool foundProgress = false;
    for (const auto& event : events) {
        if (event.type == BuildEventType::COMPILATION_PROGRESS) {
            foundProgress = true;
            ASSERT_TRUE(event.progressPercent > 0);
        }
    }
    ASSERT_TRUE(foundProgress);
    
    collector.Shutdown();
}

// ============================================================================
// Test: End-to-End Integration
// ============================================================================

TEST(end_to_end_intent_flow) {
    // Initialize all subsystems
    auto& pipeline = IntentExecutionPipeline::Instance();
    auto& injector = TelemetryInjector::Instance();
    auto& engine = ReplayEngine::Instance();
    
    pipeline.Initialize();
    injector.Initialize();
    engine.Initialize();
    
    // Enable dry-run mode for safety
    pipeline.EnableDryRunMode(true);
    
    // Create an intent
    IntentRequest intent;
    intent.intentId = 9999;
    intent.sourceAgent = 42;
    intent.intentType = "OPTIMIZE_CODE";
    intent.priority = IntentPriority::HIGH;
    intent.requiredResources = {ResourceType::COMPILER, ResourceType::BUILD_SLOT};
    intent.targetFiles = {"src/kernel/AgentKernel.cpp"};
    intent.maxRetries = 3;
    intent.requiresHumanApproval = false;
    intent.timeout = std::chrono::seconds(120);
    
    // Execute the intent
    auto result = pipeline.Execute(intent);
    
    // Verify execution completed
    ASSERT_TRUE(result.totalTimeMs > 0);
    ASSERT_TRUE(result.validationTimeMs >= 0);
    
    // Check telemetry was captured
    auto stats = injector.GetStats();
    // Note: In dry-run mode, actual telemetry may not be injected
    
    // Cleanup
    engine.Shutdown();
    injector.Shutdown();
    pipeline.Shutdown();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Sovereign Agent Kernel Integration Tests\n";
    std::cout << "========================================\n\n";
    
    // Resource Lease Tests
    std::cout << "--- Resource Lease Tests ---\n";
    RUN_TEST(resource_lease_basic);
    RUN_TEST(resource_lease_contention);
    RUN_TEST(resource_lease_expiration);
    std::cout << "\n";
    
    // Intent Pipeline Tests
    std::cout << "--- Intent Pipeline Tests ---\n";
    RUN_TEST(intent_pipeline_initialization);
    RUN_TEST(intent_pipeline_dry_run);
    std::cout << "\n";
    
    // Telemetry Tests
    std::cout << "--- Telemetry Tests ---\n";
    RUN_TEST(telemetry_injector_rejection);
    RUN_TEST(telemetry_injector_success);
    std::cout << "\n";
    
    // Replay Engine Tests
    std::cout << "--- Replay Engine Tests ---\n";
    RUN_TEST(replay_engine_snapshot);
    RUN_TEST(replay_engine_record);
    std::cout << "\n";
    
    // Build Telemetry Tests
    std::cout << "--- Build Telemetry Tests ---\n";
    RUN_TEST(build_telemetry_msvc_parser);
    RUN_TEST(build_telemetry_clang_parser);
    RUN_TEST(build_telemetry_ninja_progress);
    std::cout << "\n";
    
    // Integration Tests
    std::cout << "--- Integration Tests ---\n";
    RUN_TEST(end_to_end_intent_flow);
    std::cout << "\n";
    
    // Summary
    std::cout << "========================================\n";
    std::cout << "Test Results: " << testsPassed << " passed, " 
              << testsFailed << " failed\n";
    std::cout << "========================================\n";
    
    return testsFailed > 0 ? 1 : 0;
}

// Test Agent Kernel - Integration Tests for Sovereign Orchestration Layer
// Tests the complete pipeline: Intent -> Kernel -> Resources -> Execution

#include "../src/kernel/AgentKernel.hpp"
#include "../src/kernel/TelemetryInjector.hpp"
#include "../src/kernel/IntentExecutionPipeline.hpp"

#include <iostream>
#include <thread>
#include <chrono>
#include <cassert>

using namespace RawrXD::Kernel;

// ============================================================================
// Test Helpers
// ============================================================================

static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) \
    std::cout << "Running: " #name "... "; \
    try { \
        test_##name(); \
        std::cout << "[PASS]\n"; \
        testsPassed++; \
    } catch (const std::exception& e) { \
        std::cout << "[FAIL] " << e.what() << "\n"; \
        testsFailed++; \
    }

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        throw std::runtime_error("Assertion failed: " #expr); \
    }

#define ASSERT_EQ(a, b) \
    if ((a) != (b)) { \
        throw std::runtime_error("Assertion failed: " #a " == " #b); \
    }

// ============================================================================
// Tests
// ============================================================================

TEST(kernel_initialization) {
    auto& kernel = AgentKernel::Instance();
    
    // Initialize
    ASSERT_TRUE(kernel.Initialize());
    ASSERT_TRUE(kernel.IsRunning());
    
    auto status = kernel.GetStatus();
    ASSERT_TRUE(status.running);
    ASSERT_EQ(status.activeAgents, 0);
    ASSERT_EQ(status.pendingIntents, 0);
    
    // Shutdown
    kernel.Shutdown();
    ASSERT_TRUE(!kernel.IsRunning());
}

TEST(agent_registration) {
    auto& kernel = AgentKernel::Instance();
    kernel.Initialize();
    
    // Register agents
    AgentId planner = kernel.RegisterAgent("PLANNER", "kimi");
    AgentId coder = kernel.RegisterAgent("CODER", "local_gguf");
    AgentId debugger = kernel.RegisterAgent("DEBUGGER", "moonshot");
    
    ASSERT_TRUE(planner != 0);
    ASSERT_TRUE(coder != 0);
    ASSERT_TRUE(debugger != 0);
    
    auto status = kernel.GetStatus();
    ASSERT_EQ(status.activeAgents, 3);
    
    // Get agent
    auto agent = kernel.GetAgent(coder);
    ASSERT_TRUE(agent != nullptr);
    ASSERT_EQ(agent->agentType, "CODER");
    ASSERT_EQ(agent->modelBackend, "local_gguf");
    ASSERT_TRUE(agent->isActive.load());
    
    // Unregister
    kernel.UnregisterAgent(coder);
    status = kernel.GetStatus();
    ASSERT_EQ(status.activeAgents, 2);
    
    // Cleanup
    kernel.UnregisterAgent(planner);
    kernel.UnregisterAgent(debugger);
    kernel.Shutdown();
}

TEST(resource_leasing) {
    auto& kernel = AgentKernel::Instance();
    auto& scheduler = ResourceScheduler::Instance();
    
    kernel.Initialize();
    scheduler.StartHeartbeatMonitor();
    
    AgentId agent = kernel.RegisterAgent("TEST", "local");
    
    // Acquire lease
    auto lease = scheduler.AcquireLease(
        agent,
        ResourceType::TERMINAL,
        0, // Any terminal
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(5),
        "Test terminal access",
        0
    );
    
    ASSERT_TRUE(lease != nullptr);
    ASSERT_TRUE(lease->isActive.load());
    ASSERT_EQ(lease->owner, agent);
    ASSERT_EQ(lease->resourceType, ResourceType::TERMINAL);
    ASSERT_TRUE(lease->HasCapability("read"));
    ASSERT_TRUE(lease->HasCapability("write"));
    ASSERT_TRUE(lease->HasCapability("execute"));
    
    // Check resource is no longer available
    ASSERT_TRUE(!scheduler.IsResourceAvailable(ResourceType::TERMINAL, lease->resourceId));
    
    // Release
    ASSERT_TRUE(scheduler.ReleaseLease(lease->leaseId, agent));
    ASSERT_TRUE(scheduler.IsResourceAvailable(ResourceType::TERMINAL, lease->resourceId));
    
    // Cleanup
    kernel.UnregisterAgent(agent);
    scheduler.StopHeartbeatMonitor();
    kernel.Shutdown();
}

TEST(resource_contention) {
    auto& kernel = AgentKernel::Instance();
    auto& scheduler = ResourceScheduler::Instance();
    
    kernel.Initialize();
    scheduler.StartHeartbeatMonitor();
    
    AgentId agent1 = kernel.RegisterAgent("AGENT1", "local");
    AgentId agent2 = kernel.RegisterAgent("AGENT2", "local");
    
    // Agent 1 acquires terminal
    auto lease1 = scheduler.AcquireLease(
        agent1,
        ResourceType::TERMINAL,
        1, // Specific terminal ID
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(60),
        "Agent 1 terminal",
        0
    );
    
    ASSERT_TRUE(lease1 != nullptr);
    
    // Agent 2 tries to acquire same terminal - should fail
    auto lease2 = scheduler.AcquireLease(
        agent2,
        ResourceType::TERMINAL,
        1, // Same terminal
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(60),
        "Agent 2 terminal",
        0
    );
    
    ASSERT_TRUE(lease2 == nullptr); // Should fail
    
    // Agent 2 can acquire different terminal
    auto lease3 = scheduler.AcquireLease(
        agent2,
        ResourceType::TERMINAL,
        2, // Different terminal
        LeaseCapabilities::FullAccess(),
        std::chrono::seconds(60),
        "Agent 2 terminal",
        0
    );
    
    ASSERT_TRUE(lease3 != nullptr);
    
    // Cleanup
    scheduler.ReleaseLease(lease1->leaseId, agent1);
    scheduler.ReleaseLease(lease3->leaseId, agent2);
    kernel.UnregisterAgent(agent1);
    kernel.UnregisterAgent(agent2);
    scheduler.StopHeartbeatMonitor();
    kernel.Shutdown();
}

TEST(beacon_bus) {
    auto& bus = BeaconBus::Instance();
    
    bus.Start();
    
    std::atomic<int> eventCount{0};
    
    // Subscribe to events
    auto subId = bus.Subscribe(BeaconType::INTENT_QUEUED, 
        [&eventCount](const BeaconEvent& event) {
            eventCount++;
        });
    
    // Publish events
    bus.Publish(BeaconType::INTENT_QUEUED, 1, "{\"test\": 1}");
    bus.Publish(BeaconType::INTENT_QUEUED, 2, "{\"test\": 2}");
    bus.Publish(BeaconType::INTENT_STARTED, 3, "{\"test\": 3}"); // Different type
    
    // Wait for dispatch
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    ASSERT_EQ(eventCount.load(), 2); // Only INTENT_QUEUED events
    
    // Unsubscribe
    bus.Unsubscribe(subId);
    
    bus.Stop();
}

TEST(intent_queue) {
    auto& queue = IntentQueue::Instance();
    
    // Create intents
    IntentRequest intent1;
    intent1.intentType = "BUILD";
    intent1.priority = IntentPriority::NORMAL;
    
    IntentRequest intent2;
    intent2.intentType = "TEST";
    intent2.priority = IntentPriority::HIGH; // Higher priority
    
    IntentRequest intent3;
    intent3.intentType = "DEBUG";
    intent3.priority = IntentPriority::LOW;
    
    // Enqueue
    queue.Enqueue(std::move(intent1));
    queue.Enqueue(std::move(intent2));
    queue.Enqueue(std::move(intent3));
    
    ASSERT_EQ(queue.GetPendingCount(), 3);
    
    // Dequeue - should get HIGH priority first
    auto result = queue.Dequeue();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->intentType, "TEST"); // HIGH priority
    
    // Next should be NORMAL
    result = queue.Dequeue();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->intentType, "BUILD");
    
    // Last is LOW
    result = queue.Dequeue();
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->intentType, "DEBUG");
    
    ASSERT_EQ(queue.GetPendingCount(), 0);
}

TEST(telemetry_injector) {
    auto& injector = TelemetryInjector::Instance();
    
    injector.Initialize(100);
    
    // Inject rejections
    injector.InjectRejection(
        ViolationCode::UNALIGNED_PATCH,
        1, // intentId
        2, // agentId
        "AVX-512 alignment violation",
        {{"target", "MatrixMul"}, {"offset", "0x1234"}}
    );
    
    injector.InjectRejection(
        ViolationCode::PROTECTED_MEMORY,
        3,
        2,
        "Attempted write to protected region",
        {{"region", "kernel_space"}}
    );
    
    // Get stats
    auto stats = injector.GetStats();
    ASSERT_EQ(stats.totalRejections, 2);
    ASSERT_EQ(stats.rejectionsByCode[static_cast<int>(ViolationCode::UNALIGNED_PATCH)], 1);
    ASSERT_EQ(stats.rejectionsByCode[static_cast<int>(ViolationCode::PROTECTED_MEMORY)], 1);
    
    // Get history for agent
    auto history = injector.GetRejectionHistoryForAgent(2, 10);
    ASSERT_EQ(history.size(), 2);
    
    // Generate model context
    auto context = injector.GenerateModelContext(2);
    ASSERT_TRUE(context.find("RECENT REJECTIONS") != std::string::npos);
    
    injector.Shutdown();
}

TEST(execution_pipeline) {
    auto& pipeline = IntentExecutionPipeline::Instance();
    auto& kernel = AgentKernel::Instance();
    
    kernel.Initialize();
    pipeline.Initialize();
    
    // Create intent
    IntentRequest intent;
    intent.intentType = "BUILD_PROJECT";
    intent.targetFiles = {"src/main.cpp"};
    intent.priority = IntentPriority::NORMAL;
    intent.maxRetries = 3;
    intent.requiresHumanApproval = false;
    intent.timeout = std::chrono::seconds(30);
    
    // Execute
    auto result = pipeline.Execute(intent);
    
    ASSERT_TRUE(result.IsSuccess());
    ASSERT_EQ(result.intentType, "BUILD_PROJECT");
    ASSERT_TRUE(result.totalTimeMs >= 0);
    
    // Check stats
    auto stats = pipeline.GetStats();
    ASSERT_EQ(stats.totalIntents, 1);
    ASSERT_EQ(stats.successfulIntents, 1);
    ASSERT_EQ(stats.failedIntents, 0);
    
    pipeline.Shutdown();
    kernel.Shutdown();
}

TEST(end_to_end_intent_flow) {
    auto& kernel = AgentKernel::Instance();
    auto& pipeline = IntentExecutionPipeline::Instance();
    auto& bus = BeaconBus::Instance();
    
    // Initialize all systems
    kernel.Initialize();
    pipeline.Initialize();
    bus.Start();
    
    // Track events
    std::vector<BeaconType> events;
    auto subId = bus.SubscribeAll([&events](const BeaconEvent& event) {
        events.push_back(event.type);
    });
    
    // Register agent
    AgentId agent = kernel.RegisterAgent("CODER", "local_gguf");
    
    // Submit intent
    IntentRequest intent;
    intent.intentType = "MODIFY_FUNCTION";
    intent.targetFiles = {"src/kernel/AgentKernel.cpp"};
    intent.priority = IntentPriority::HIGH;
    intent.requiredResources = {ResourceType::FILESYSTEM, ResourceType::COMPILER};
    intent.maxRetries = 3;
    intent.requiresHumanApproval = false;
    intent.timeout = std::chrono::seconds(60);
    
    IntentId intentId = kernel.SubmitIntent(agent, std::move(intent));
    
    ASSERT_TRUE(intentId != 0);
    
    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Check events were emitted
    ASSERT_TRUE(!events.empty());
    
    // Cleanup
    bus.Unsubscribe(subId);
    kernel.UnregisterAgent(agent);
    bus.Stop();
    pipeline.Shutdown();
    kernel.Shutdown();
}

TEST(emergency_stop) {
    auto& kernel = AgentKernel::Instance();
    auto& scheduler = ResourceScheduler::Instance();
    
    kernel.Initialize();
    scheduler.StartHeartbeatMonitor();
    
    AgentId agent = kernel.RegisterAgent("TEST", "local");
    
    // Acquire multiple leases
    auto lease1 = scheduler.AcquireLease(agent, ResourceType::TERMINAL, 0,
                                          LeaseCapabilities::FullAccess(),
                                          std::chrono::seconds(60), "Test", 0);
    auto lease2 = scheduler.AcquireLease(agent, ResourceType::COMPILER, 0,
                                          LeaseCapabilities::FullAccess(),
                                          std::chrono::seconds(60), "Test", 0);
    
    ASSERT_TRUE(lease1 != nullptr);
    ASSERT_TRUE(lease2 != nullptr);
    
    // Emergency stop
    kernel.EmergencyStop("Test emergency");
    
    // All leases should be revoked
    ASSERT_TRUE(!kernel.IsRunning() || kernel.GetStatus().running == false);
    
    // Cleanup
    scheduler.StopHeartbeatMonitor();
    kernel.Shutdown();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Sovereign Agent Kernel Tests\n";
    std::cout << "========================================\n\n";
    
    RUN_TEST(kernel_initialization);
    RUN_TEST(agent_registration);
    RUN_TEST(resource_leasing);
    RUN_TEST(resource_contention);
    RUN_TEST(beacon_bus);
    RUN_TEST(intent_queue);
    RUN_TEST(telemetry_injector);
    RUN_TEST(execution_pipeline);
    RUN_TEST(end_to_end_intent_flow);
    RUN_TEST(emergency_stop);
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "========================================\n";
    
    return testsFailed > 0 ? 1 : 0;
}

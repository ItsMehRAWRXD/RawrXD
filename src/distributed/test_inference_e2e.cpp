// RawrXD End-to-End Distributed Inference Tests
// Copyright (c) 2026 RawrXD Team

#include "RawrXD_RPC.hpp"
#include "RawrXD_RPC_Handlers.hpp"
#include "InferenceRuntime.hpp"
#include "SovereignNodeDiscovery.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <cassert>

using namespace RawrXD::Distributed;
using namespace RawrXD::RPC;
using namespace Sovereign::Distributed;

// ============================================================================
// Test Framework
// ============================================================================

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void test_##name()
#define ASSERT_TRUE(x) if (!(x)) { \
    std::cerr << "FAILED: " << #x << " at line " << __LINE__ << std::endl; \
    tests_failed++; return; \
}
#define ASSERT_EQ(a, b) if ((a) != (b)) { \
    std::cerr << "FAILED: " << #a << " == " << #b << " at line " << __LINE__ << std::endl; \
    tests_failed++; return; \
}

void run_test(const char* name, void (*test)()) {
    std::cout << "Running " << name << "... ";
    test();
    std::cout << "PASSED" << std::endl;
    tests_passed++;
}

#define RUN_TEST(name) run_test(#name, test_##name)

// ============================================================================
// End-to-End Tests
// ============================================================================

TEST(inference_request_submission) {
    // Initialize inference runtime
    InitializeInferenceRuntime();
    
    // Create a request
    InferenceRequestPayload payload{};
    payload.request_id = 1;
    payload.model_id = 1;
    payload.batch_size = 1;
    payload.seq_length = 128;
    payload.priority = 1;
    payload.flags = 0;
    
    // Submit request
    uint64_t request_id = GetInferenceRuntime()->SubmitRequest(payload);
    ASSERT_TRUE(request_id != 0);
    
    // Verify request is in PENDING state
    RequestState state = GetInferenceRuntime()->GetRequestState(request_id);
    ASSERT_TRUE(state == RequestState::PENDING || state == RequestState::ASSIGNED || 
                state == RequestState::RUNNING || state == RequestState::STREAMING);
    
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    state = GetInferenceRuntime()->GetRequestState(request_id);
    ASSERT_TRUE(state == RequestState::COMPLETED || state == RequestState::STREAMING);
    
    // Cleanup
    ShutdownInferenceRuntime();
}

TEST(inference_async_completion) {
    // Initialize inference runtime
    InitializeInferenceRuntime();
    
    // Create a request
    InferenceRequestPayload payload{};
    payload.request_id = 2;
    payload.model_id = 1;
    payload.batch_size = 1;
    payload.seq_length = 64;
    
    // Submit async request
    auto future = GetInferenceRuntime()->SubmitRequestAsync(payload);
    
    // Wait for completion with timeout
    auto status = future.wait_for(std::chrono::seconds(5));
    ASSERT_TRUE(status == std::future_status::ready);
    
    InferenceResponse response = future.get();
    ASSERT_EQ(response.request_id, 2);
    ASSERT_EQ(response.status, 0);  // Success
    ASSERT_TRUE(response.tokens_generated > 0);
    
    // Cleanup
    ShutdownInferenceRuntime();
}

TEST(inference_cancellation) {
    // Initialize inference runtime
    InferenceRuntime::Config config;
    InitializeInferenceRuntime();
    
    // Create a request
    InferenceRequestPayload payload{};
    payload.request_id = 3;
    payload.model_id = 1;
    payload.batch_size = 1;
    payload.seq_length = 256;  // Longer sequence
    
    // Submit request
    uint64_t request_id = GetInferenceRuntime()->SubmitRequest(payload);
    ASSERT_TRUE(request_id != 0);
    
    // Cancel immediately
    bool cancelled = GetInferenceRuntime()->CancelRequest(request_id);
    ASSERT_TRUE(cancelled);
    
    // Verify cancelled state
    RequestState state = GetInferenceRuntime()->GetRequestState(request_id);
    ASSERT_TRUE(state == RequestState::CANCELLED);
    
    // Cleanup
    ShutdownInferenceRuntime();
}

TEST(load_balancer_worker_selection) {
    // Initialize inference runtime
    InferenceRuntime::Config config;
    InitializeInferenceRuntime();
    
    auto* runtime = GetInferenceRuntime();
    
    // Register workers
    WorkerLoad worker1{1, 0, 0, 50.0, 16.0, 100.0, 0};
    WorkerLoad worker2{2, 0, 0, 30.0, 16.0, 150.0, 0};
    
    runtime->RegisterWorker(1, worker1);
    runtime->RegisterWorker(2, worker2);
    
    // Create a request
    InferenceRequestPayload payload{};
    payload.request_id = 4;
    payload.model_id = 1;
    payload.batch_size = 1;
    payload.seq_length = 64;
    
    // Submit request - should be assigned to worker with lower load
    uint64_t request_id = runtime->SubmitRequest(payload);
    ASSERT_TRUE(request_id != 0);
    
    // Wait for assignment
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    auto* tracker = &runtime->GetTracker();
    auto request = tracker->GetRequest(request_id);
    ASSERT_TRUE(request != nullptr);
    
    // Cleanup
    ShutdownInferenceRuntime();
}

TEST(request_queue_priority) {
    // Initialize inference runtime
    InferenceRuntime::Config config;
    InitializeInferenceRuntime();
    
    auto* runtime = GetInferenceRuntime();
    
    // Submit multiple requests with different priorities
    InferenceRequestPayload low_priority{};
    low_priority.request_id = 5;
    low_priority.priority = 1;
    low_priority.batch_size = 1;
    low_priority.seq_length = 64;
    
    InferenceRequestPayload high_priority{};
    high_priority.request_id = 6;
    high_priority.priority = 10;  // Higher priority
    high_priority.batch_size = 1;
    high_priority.seq_length = 64;
    
    // Submit low priority first
    uint64_t low_id = runtime->SubmitRequest(low_priority);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // Submit high priority second
    uint64_t high_id = runtime->SubmitRequest(high_priority);
    
    ASSERT_TRUE(low_id != 0);
    ASSERT_TRUE(high_id != 0);
    
    // Both should complete
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto low_state = runtime->GetRequestState(low_id);
    auto high_state = runtime->GetRequestState(high_id);
    
    ASSERT_TRUE(low_state == RequestState::COMPLETED || low_state == RequestState::STREAMING);
    ASSERT_TRUE(high_state == RequestState::COMPLETED || high_state == RequestState::STREAMING);
    
    // Cleanup
    ShutdownInferenceRuntime();
}

TEST(runtime_statistics) {
    // Initialize inference runtime
    InferenceRuntime::Config config;
    InitializeInferenceRuntime();
    
    auto* runtime = GetInferenceRuntime();
    
    // Reset stats
    runtime->ResetStats();
    
    // Submit some requests
    for (int i = 0; i < 3; ++i) {
        InferenceRequestPayload payload{};
        payload.request_id = 10 + i;
        payload.batch_size = 1;
        payload.seq_length = 32;
        runtime->SubmitRequest(payload);
    }
    
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Check stats
    auto stats = runtime->GetStats();
    ASSERT_TRUE(stats.requests_submitted >= 3);
    ASSERT_TRUE(stats.requests_completed > 0);
    
    // Cleanup
    ShutdownInferenceRuntime();
}

TEST(handler_integration) {
    // Initialize inference runtime
    InferenceRuntime::Config config;
    InitializeInferenceRuntime();
    
    // Create handler registry
    RPCHandlerRegistry registry;
    registry.RegisterInferenceHandlers();
    
    // Create a mock discovery
    class MockDiscovery : public NodeDiscovery {
    public:
        MockDiscovery() : NodeDiscovery({}) {}
    };
    
    MockDiscovery discovery;
    
    // Create node context
    NodeContext ctx;
    ctx.self_node_id = "test_node";
    ctx.peer_node_id = "peer_node";
    ctx.discovery = &discovery;
    
    // Test INFERENCE_REQUEST handler
    InferenceRequestPayload payload{};
    payload.request_id = 100;
    payload.model_id = 1;
    payload.batch_size = 1;
    payload.seq_length = 64;
    
    RawrPacket packet = build_packet(
        static_cast<uint32_t>(RawrCommand::CMD_INFERENCE_REQUEST),
        0, 0, 0);
    packet.payload.resize(sizeof(payload));
    std::memcpy(packet.payload.data(), &payload, sizeof(payload));
    
    HandlerResult result = registry.Dispatch(packet, ctx);
    ASSERT_EQ(result.status, HandlerStatus::SUCCESS);
    
    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Cleanup
    ShutdownInferenceRuntime();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD End-to-End Inference Tests" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;
    
    try {
        RUN_TEST(inference_request_submission);
        RUN_TEST(inference_async_completion);
        RUN_TEST(inference_cancellation);
        RUN_TEST(load_balancer_worker_selection);
        RUN_TEST(request_queue_priority);
        RUN_TEST(runtime_statistics);
        RUN_TEST(handler_integration);
        
        std::cout << std::endl << "========================================" << std::endl;
        std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;
        std::cout << "========================================" << std::endl;
        
        return tests_failed > 0 ? 1 : 0;
    } catch (const std::exception& e) {
        std::cerr << std::endl << "========================================" << std::endl;
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        std::cerr << "========================================" << std::endl;
        return 1;
    }
}

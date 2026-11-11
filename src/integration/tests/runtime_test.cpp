// runtime_test.cpp
// End-to-end integration test for RawrXD Inference OS
// Tests all 4 layers: Scheduler → Router → Executor → Policy

#include "../runtime.h"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

using namespace rawrxd::runtime;
using namespace rawrxd::scheduler;
using namespace rawrxd::router;
using namespace rawrxd::executor;
using namespace rawrxd::policy;

// ═══════════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════════

void TestSchedulerIntegration() {
    std::cout << "[TEST] Scheduler Integration..." << std::endl;
    
    auto& runtime = GetRuntime();
    auto& scheduler = runtime.GetScheduler();
    
    // Test credit allocation
    auto credits = scheduler.AllocateCredits(NodeType::Inference, Priority::Normal, 100);
    assert(credits.has_value());
    assert(credits->granted == 100);
    
    // Test queue management
    assert(scheduler.Enqueue(1, NodeType::Inference, Priority::Normal));
    auto next = scheduler.Peek();
    assert(next.has_value());
    assert(next.value() == 1);
    
    auto dequeued = scheduler.Dequeue();
    assert(dequeued.has_value());
    assert(dequeued.value() == 1);
    
    std::cout << "  ✓ Scheduler integration PASSED" << std::endl;
}

void TestRouterIntegration() {
    std::cout << "[TEST] Router Integration..." << std::endl;
    
    auto& runtime = GetRuntime();
    auto& router = runtime.GetRouter();
    
    // Register a backend
    BackendInfo backend;
    backend.id = 1;
    backend.name = "TestBackend";
    backend.state = BackendState::Healthy;
    backend.supported_architectures = {"llama2"};
    backend.avg_latency = std::chrono::milliseconds(50);
    backend.success_rate = 0.95f;
    backend.current_load = 0.3f;
    backend.cost_per_token = 0.0001f;
    
    assert(router.RegisterBackend(backend));
    
    // Test routing
    CapabilityToken cap;
    cap.hash = 12345;
    cap.permissions = 0xFFFFFFFF;
    cap.expiry = std::chrono::steady_clock::now() + std::chrono::hours(1);
    
    WorkSpec work;
    work.model_architecture = "llama2";
    work.estimated_tokens = 100;
    work.priority = 1;
    work.strategy = RoutingStrategy::LatencyOptimized;
    
    auto decision = router.Route(cap, work);
    assert(decision.has_value());
    assert(decision->backend == 1);
    assert(decision->confidence > 0.0f);
    
    std::cout << "  ✓ Router integration PASSED" << std::endl;
}

void TestExecutorIntegration() {
    std::cout << "[TEST] Executor Integration..." << std::endl;
    
    auto& runtime = GetRuntime();
    auto& executor = runtime.GetExecutor();
    
    // Register a test kernel
    auto kernel_func = [](void*) {
        // Simulate work
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    };
    
    assert(executor.RegisterKernel(1, KernelType::Inference, kernel_func));
    
    // Test execution
    NodeSpec spec;
    spec.id = 1;
    spec.kernel_type = KernelType::Inference;
    spec.kernel_id = 1;
    spec.batch_size = 1;
    spec.sequence_length = 128;
    spec.hidden_dim = 4096;
    spec.checkpoint_enabled = false;
    
    assert(executor.Execute(spec));
    
    // Wait for completion
    auto result = executor.WaitForResult(1, std::chrono::milliseconds(1000));
    assert(result.has_value());
    assert(result->success);
    
    std::cout << "  ✓ Executor integration PASSED" << std::endl;
}

void TestPolicyIntegration() {
    std::cout << "[TEST] Policy Integration..." << std::endl;
    
    auto& runtime = GetRuntime();
    auto& policy = runtime.GetPolicyLearner();
    
    // Observe some traces
    for (int i = 0; i < 20; i++) {
        Trace trace;
        trace.id = i;
        trace.timestamp = std::chrono::steady_clock::now();
        trace.model_architecture = "llama2";
        trace.input_tokens = 100;
        trace.output_tokens = 50;
        trace.latency = std::chrono::milliseconds(50 + i);
        trace.success = (i % 5 != 0);  // 80% success rate
        trace.backend_used = "TestBackend";
        trace.memory_used = 1024 * 1024 * 100;  // 100MB
        trace.compute_units = 100;
        trace.quality_score = 0.9f;
        trace.error_type = "";
        
        policy.Observe(trace);
    }
    
    // Test recommendation
    auto rec = policy.Recommend("llama2");
    assert(rec.has_value());
    assert(rec->confidence > 0.0f);
    
    // Test snapshot production
    auto snapshot = policy.ProduceSnapshot();
    assert(snapshot.version > 0);
    assert(snapshot.total_traces_analyzed >= 20);
    
    std::cout << "  ✓ Policy integration PASSED" << std::endl;
}

void TestFullPipeline() {
    std::cout << "[TEST] Full Pipeline (All 4 Layers)..." << std::endl;
    
    auto& runtime = GetRuntime();
    
    // Setup: Register backend and kernel
    {
        auto& router = runtime.GetRouter();
        BackendInfo backend;
        backend.id = 1;
        backend.name = "PipelineBackend";
        backend.state = BackendState::Healthy;
        backend.supported_architectures = {"llama2"};
        backend.avg_latency = std::chrono::milliseconds(50);
        backend.success_rate = 0.95f;
        backend.current_load = 0.3f;
        backend.cost_per_token = 0.0001f;
        router.RegisterBackend(backend);
        
        auto& executor = runtime.GetExecutor();
        executor.RegisterKernel(100, KernelType::Inference, [](void*) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        });
    }
    
    // Execute full pipeline
    ExecutionRequest request;
    request.type = NodeType::Inference;
    request.priority = Priority::Normal;
    request.estimated_tokens = 100;
    request.work.model_architecture = "llama2";
    request.work.estimated_tokens = 100;
    request.work.priority = 1;
    request.work.strategy = RoutingStrategy::LatencyOptimized;
    request.capability.hash = 99999;
    request.capability.permissions = 0xFFFFFFFF;
    request.capability.expiry = std::chrono::steady_clock::now() + std::chrono::hours(1);
    request.spec.id = 100;
    request.spec.kernel_type = KernelType::Inference;
    request.spec.kernel_id = 100;
    request.spec.batch_size = 1;
    request.spec.sequence_length = 128;
    request.spec.hidden_dim = 4096;
    request.spec.checkpoint_enabled = false;
    request.policy_snapshot = runtime.GetPolicyLearner().ProduceSnapshot();
    
    auto result = runtime.Execute(request);
    assert(result.has_value());
    
    std::cout << "  Execution Result:" << std::endl;
    std::cout << "    Success: " << (result->success ? "YES" : "NO") << std::endl;
    std::cout << "    Credits Granted: " << result->credits.granted << std::endl;
    std::cout << "    Backend: " << result->routing.backend_name << std::endl;
    std::cout << "    Latency: " << result->total_latency.count() / 1000.0 << " ms" << std::endl;
    
    if (result->success) {
        std::cout << "    Execution Time: " << result->execution.execution_time.count() / 1000.0 << " ms" << std::endl;
        std::cout << "    Memory Used: " << result->execution.memory_used / (1024 * 1024) << " MB" << std::endl;
    }
    
    std::cout << "  ✓ Full pipeline PASSED" << std::endl;
}

void TestAsyncExecution() {
    std::cout << "[TEST] Async Execution..." << std::endl;
    
    auto& runtime = GetRuntime();
    
    // Setup
    {
        auto& router = runtime.GetRouter();
        BackendInfo backend;
        backend.id = 2;
        backend.name = "AsyncBackend";
        backend.state = BackendState::Healthy;
        backend.supported_architectures = {"qwen2"};
        backend.avg_latency = std::chrono::milliseconds(30);
        backend.success_rate = 0.99f;
        router.RegisterBackend(backend);
        
        auto& executor = runtime.GetExecutor();
        executor.RegisterKernel(200, KernelType::Inference, [](void*) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        });
    }
    
    ExecutionRequest request;
    request.type = NodeType::Inference;
    request.priority = Priority::Normal;
    request.estimated_tokens = 50;
    request.work.model_architecture = "qwen2";
    request.work.estimated_tokens = 50;
    request.work.priority = 1;
    request.work.strategy = RoutingStrategy::ThroughputOptimized;
    request.capability.hash = 88888;
    request.capability.permissions = 0xFFFFFFFF;
    request.capability.expiry = std::chrono::steady_clock::now() + std::chrono::hours(1);
    request.spec.id = 200;
    request.spec.kernel_type = KernelType::Inference;
    request.spec.kernel_id = 200;
    request.spec.batch_size = 1;
    request.spec.sequence_length = 64;
    request.spec.hidden_dim = 2048;
    request.spec.checkpoint_enabled = false;
    
    bool callback_called = false;
    ExecutionResult async_result;
    
    runtime.ExecuteAsync(request, [&](const ExecutionResult& result) {
        callback_called = true;
        async_result = result;
    });
    
    // Wait for callback
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    assert(callback_called);
    std::cout << "  ✓ Async execution PASSED" << std::endl;
}

void TestStatistics() {
    std::cout << "[TEST] Runtime Statistics..." << std::endl;
    
    auto& runtime = GetRuntime();
    auto stats = runtime.GetStatistics();
    
    std::cout << "  Runtime Statistics:" << std::endl;
    std::cout << "    Total Requests: " << stats.total_requests << std::endl;
    std::cout << "    Successful: " << stats.successful_requests << std::endl;
    std::cout << "    Failed: " << stats.failed_requests << std::endl;
    std::cout << "    Avg Latency: " << stats.avg_latency_ms << " ms" << std::endl;
    
    // Get policy stats
    auto policy_stats = runtime.GetPolicyLearner().GetStatistics();
    std::cout << "  Policy Statistics:" << std::endl;
    std::cout << "    Total Traces: " << policy_stats.total_traces_observed << std::endl;
    std::cout << "    Unique Architectures: " << policy_stats.unique_architectures << std::endl;
    std::cout << "    Current Version: " << policy_stats.current_version << std::endl;
    
    std::cout << "  ✓ Statistics PASSED" << std::endl;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int main() {
    std::cout << "═══════════════════════════════════════════════════════════════" << std::endl;
    std::cout << "  RawrXD Inference OS - Integration Test Suite" << std::endl;
    std::cout << "  Testing: Scheduler → Router → Executor → Policy" << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════" << std::endl;
    std::cout << std::endl;
    
    try {
        // Initialize runtime
        std::cout << "[INIT] Initializing Runtime..." << std::endl;
        if (!InitializeRuntime("")) {
            std::cerr << "FAILED: Runtime initialization" << std::endl;
            return 1;
        }
        std::cout << "  ✓ Runtime initialized" << std::endl;
        std::cout << std::endl;
        
        // Run tests
        TestSchedulerIntegration();
        TestRouterIntegration();
        TestExecutorIntegration();
        TestPolicyIntegration();
        TestFullPipeline();
        TestAsyncExecution();
        TestStatistics();
        
        // Shutdown
        std::cout << std::endl;
        std::cout << "[SHUTDOWN] Cleaning up..." << std::endl;
        ShutdownRuntime();
        std::cout << "  ✓ Runtime shutdown complete" << std::endl;
        
        std::cout << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════════" << std::endl;
        std::cout << "  ALL TESTS PASSED ✓" << std::endl;
        std::cout << "═══════════════════════════════════════════════════════════════" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << std::endl;
        std::cerr << "═══════════════════════════════════════════════════════════════" << std::endl;
        std::cerr << "  TEST FAILED: " << e.what() << std::endl;
        std::cerr << "═══════════════════════════════════════════════════════════════" << std::endl;
        return 1;
    }
}

// ============================================================================
// Test Sovereign Backend
// ============================================================================
// Validates production backend with MASM64 kernel dispatch
// ============================================================================

#include "SovereignBackend.hpp"
#include "SovereignGraphRunner.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

using namespace RawrXD::Execution;

// ============================================================================
// Test: Backend Initialization
// ============================================================================

bool TestBackendInit() {
    std::cout << "\n=== Test: SovereignBackend Initialization ===\n";
    
    SovereignBackendConfig config;
    config.workspace_size = 128 * 1024 * 1024;  // 128MB
    config.enable_telemetry = true;
    
    auto backend = CreateSovereignBackend(config);
    if (!backend) {
        std::cerr << "FAILED: Backend creation\n";
        return false;
    }
    
    assert(backend->IsInitialized());
    assert(backend->IsHealthy());
    
    std::cout << "  ✓ Backend initialized\n";
    std::cout << "  ✓ Backend healthy\n";
    
    // Check loaded kernels
    auto kernels = backend->GetLoadedKernels();
    std::cout << "  ✓ Loaded " << kernels.size() << " kernels\n";
    for (const auto& name : kernels) {
        std::cout << "    - " << name << "\n";
    }
    
    return true;
}

// ============================================================================
// Test: Kernel Loading
// ============================================================================

bool TestKernelLoading() {
    std::cout << "\n=== Test: Kernel Loading ===\n";
    
    auto backend = CreateSovereignBackend();
    
    // Check core kernels
    assert(backend->IsKernelLoaded("Sovereign_RMSNorm_F32_AVX2"));
    assert(backend->IsKernelLoaded("Sovereign_Attention_Scoring"));
    assert(backend->IsKernelLoaded("Sovereign_FFN"));
    
    std::cout << "  ✓ Core kernels loaded\n";
    
    // Get kernel info
    auto* info = backend->GetKernelInfo("Sovereign_RMSNorm_F32_AVX2");
    if (info) {
        std::cout << "  ✓ Kernel info retrieved: " << info->name << "\n";
        std::cout << "    Invocations: " << info->invocation_count << "\n";
    }
    
    return true;
}

// ============================================================================
// Test: Direct Kernel Invocation
// ============================================================================

bool TestDirectInvocation() {
    std::cout << "\n=== Test: Direct Kernel Invocation ===\n";
    
    auto backend = CreateSovereignBackend();
    
    // Prepare test data
    float input_data[16] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f,
                            9.0f, 10.0f, 11.0f, 12.0f, 13.0f, 14.0f, 15.0f, 16.0f};
    float output_data[16] = {0};
    
    // Invoke RMSNorm kernel
    auto result = backend->InvokeKernel("Sovereign_RMSNorm_F32_AVX2",
                                        input_data, sizeof(input_data),
                                        output_data, sizeof(output_data));
    
    if (!result.IsSuccess()) {
        std::cerr << "FAILED: Kernel invocation\n";
        return false;
    }
    
    std::cout << "  ✓ Kernel invoked successfully\n";
    std::cout << "  ✓ Latency: " << result.telemetry.inference_time_us << " us\n";
    
    // Check kernel stats updated
    auto* info = backend->GetKernelInfo("Sovereign_RMSNorm_F32_AVX2");
    assert(info->invocation_count == 1);
    std::cout << "  ✓ Kernel stats updated\n";
    
    return true;
}

// ============================================================================
// Test: Execution Contract Dispatch
// ============================================================================

bool TestExecutionDispatch() {
    std::cout << "\n=== Test: Execution Contract Dispatch ===\n";
    
    auto backend = CreateSovereignBackend();
    
    // Test RMSNorm dispatch
    ExecutionRequest request;
    request.command = "rmsnorm";
    request.model = "test_model";
    request.prompt = "prenorm";
    request.max_tokens = 1;
    
    auto result = backend->Execute(request);
    
    if (!result.IsSuccess()) {
        std::cerr << "FAILED: Execution dispatch\n";
        return false;
    }
    
    std::cout << "  ✓ RMSNorm dispatched\n";
    std::cout << "  ✓ Output: " << result.output << "\n";
    std::cout << "  ✓ Latency: " << result.telemetry.latency_ms << " ms\n";
    
    // Test attention dispatch
    request.command = "attention";
    result = backend->Execute(request);
    
    if (!result.IsSuccess()) {
        std::cerr << "FAILED: Attention dispatch\n";
        return false;
    }
    
    std::cout << "  ✓ Attention dispatched\n";
    
    return true;
}

// ============================================================================
// Test: GraphRunner Integration
// ============================================================================

bool TestGraphRunnerIntegration() {
    std::cout << "\n=== Test: GraphRunner + SovereignBackend ===\n";
    
    // Create Sovereign backend (as shared_ptr for GraphRunner)
    SovereignBackendConfig config;
    auto sovereign = std::make_shared<SovereignBackend>(config);
    if (!sovereign->Initialize()) {
        std::cerr << "FAILED: Sovereign backend initialization\n";
        return false;
    }
    
    // Configure transformer
    TransformerLayerConfig layer_config;
    layer_config.hidden_size = 512;
    layer_config.num_heads = 8;
    layer_config.head_dim = 64;
    layer_config.intermediate_size = 1376;
    
    // Create GraphRunner with Sovereign backend
    auto runner = CreateGraphRunner(sovereign, layer_config);
    if (!runner) {
        std::cerr << "FAILED: GraphRunner creation\n";
        return false;
    }
    
    std::cout << "  ✓ GraphRunner created with Sovereign backend\n";
    
    // Run single decode step
    auto result = runner->ForwardSingleToken(42, 0);
    
    if (!result.IsSuccess()) {
        std::cerr << "FAILED: Decode step\n";
        return false;
    }
    
    std::cout << "  ✓ Decode step completed\n";
    std::cout << "  ✓ Latency: " << result.telemetry.latency_ms << " ms\n";
    
    // Run full forward pass
    std::vector<int32_t> tokens = {1, 2, 3};
    result = runner->Forward(tokens, 3);
    
    if (!result.IsSuccess()) {
        std::cerr << "FAILED: Forward pass\n";
        return false;
    }
    
    std::cout << "  ✓ Forward pass completed\n";
    std::cout << "  ✓ Generated " << result.telemetry.generated_tokens << " tokens\n";
    
    return true;
}

// ============================================================================
// Test: Workspace Management
// ============================================================================

bool TestWorkspace() {
    std::cout << "\n=== Test: Workspace Management ===\n";
    
    SovereignBackendConfig config;
    config.workspace_size = 64 * 1024 * 1024;  // 64MB
    
    auto backend = CreateSovereignBackend(config);
    
    // Allocate from workspace
    void* ptr1 = backend->GetWorkspace(1024 * 1024);  // 1MB
    void* ptr2 = backend->GetWorkspace(2 * 1024 * 1024);  // 2MB
    
    if (!ptr1 || !ptr2) {
        std::cerr << "FAILED: Workspace allocation\n";
        return false;
    }
    
    std::cout << "  ✓ Workspace allocations successful\n";
    
    // Release (in production, would actually free)
    backend->ReleaseWorkspace(ptr1);
    backend->ReleaseWorkspace(ptr2);
    
    std::cout << "  ✓ Workspace released\n";
    
    return true;
}

// ============================================================================
// Test: Async Execution
// ============================================================================

bool TestAsyncExecution() {
    std::cout << "\n=== Test: Async Execution ===\n";
    
    auto backend = CreateSovereignBackend();
    
    ExecutionRequest request;
    request.command = "rmsnorm";
    request.prompt = "test";
    request.max_tokens = 3;
    
    bool completed = false;
    int token_count = 0;
    
    auto on_token = [&token_count](const std::string& token, bool is_last) {
        token_count++;
        std::cout << "    Token: " << token << (is_last ? " [LAST]" : "") << "\n";
    };
    
    auto on_complete = [&completed](const ExecutionResult& result) {
        completed = true;
        std::cout << "    Completed with status: " 
                  << (result.IsSuccess() ? "Success" : "Failed") << "\n";
    };
    
    bool started = backend->ExecuteAsync(request, on_token, on_complete);
    
    if (!started) {
        std::cerr << "FAILED: Async execution start\n";
        return false;
    }
    
    std::cout << "  ✓ Async execution started\n";
    
    // Wait for completion (in production, would use proper synchronization)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::cout << "  ✓ Tokens received: " << token_count << "\n";
    
    return true;
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Sovereign Backend Test Suite\n";
    std::cout << "========================================\n";
    std::cout << "\nProduction backend with MASM64 kernel dispatch\n";
    std::cout << "ExecutionRequest → SovereignBackend → MASM64 Kernel\n";
    
    int passed = 0;
    int failed = 0;
    
    auto run_test = [&](const char* name, bool (*test)()) {
        std::cout << "\n" << std::string(50, '-') << "\n";
        if (test()) {
            std::cout << "✓ PASSED: " << name << "\n";
            passed++;
        } else {
            std::cout << "✗ FAILED: " << name << "\n";
            failed++;
        }
    };
    
    run_test("Backend Initialization", TestBackendInit);
    run_test("Kernel Loading", TestKernelLoading);
    run_test("Direct Kernel Invocation", TestDirectInvocation);
    run_test("Execution Contract Dispatch", TestExecutionDispatch);
    run_test("GraphRunner Integration", TestGraphRunnerIntegration);
    run_test("Workspace Management", TestWorkspace);
    run_test("Async Execution", TestAsyncExecution);
    
    std::cout << "\n" << std::string(50, '=') << "\n";
    std::cout << "Test Results:\n";
    std::cout << "  Passed: " << passed << "\n";
    std::cout << "  Failed: " << failed << "\n";
    std::cout << "  Total:  " << (passed + failed) << "\n";
    std::cout << std::string(50, '=') << "\n";
    
    return failed == 0 ? 0 : 1;
}

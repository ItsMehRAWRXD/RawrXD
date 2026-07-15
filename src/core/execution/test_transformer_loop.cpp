// ============================================================================
// Test Transformer Loop
// ============================================================================
// Validates the canonical decode step: Embedding → PreNorm → Attention → FFN
// Uses execution contracts and SovereignGraphRunner
// ============================================================================

#include "SovereignGraphRunner.hpp"
#include "SimulatorBackend.hpp"
#include <iostream>
#include <cassert>
#include <cmath>

using namespace RawrXD::Execution;

// ============================================================================
// Test Configuration
// ============================================================================

struct TestConfig {
    uint32_t hidden_size = 512;      // Small for testing
    uint32_t num_heads = 8;
    uint32_t head_dim = 64;          // 512 / 8
    uint32_t intermediate_size = 1376; // ~2.7x hidden for SwiGLU
    uint32_t max_seq_len = 128;
};

// ============================================================================
// Test: Graph Runner Initialization
// ============================================================================

bool TestGraphRunnerInit() {
    std::cout << "\n=== Test: GraphRunner Initialization ===\n";
    
    // Create simulator backend (no real model needed)
    auto backend = std::make_shared<SimulatorBackend>(SimulationProfile::Fast());
    if (!backend->Initialize()) {
        std::cerr << "FAILED: Backend initialization\n";
        return false;
    }
    
    // Configure transformer
    TransformerLayerConfig config;
    config.hidden_size = 512;
    config.num_heads = 8;
    config.head_dim = 64;
    config.intermediate_size = 1376;
    config.max_seq_len = 128;
    
    // Create graph runner
    auto runner = CreateGraphRunner(backend, config);
    if (!runner) {
        std::cerr << "FAILED: GraphRunner creation\n";
        return false;
    }
    
    // Verify initialization
    assert(runner->IsInitialized());
    assert(runner->HasKernel(KernelRole::PreNorm));
    assert(runner->HasKernel(KernelRole::SelfAttention));
    assert(runner->HasKernel(KernelRole::FFN));
    
    std::cout << "  ✓ GraphRunner initialized\n";
    std::cout << "  ✓ Kernels registered: PreNorm, Attention, FFN\n";
    
    return true;
}

// ============================================================================
// Test: Single Decode Step
// ============================================================================

bool TestSingleDecodeStep() {
    std::cout << "\n=== Test: Single Decode Step ===\n";
    
    auto backend = std::make_shared<SimulatorBackend>(SimulationProfile::Fast());
    backend->Initialize();
    
    TransformerLayerConfig config;
    config.hidden_size = 512;
    config.num_heads = 8;
    config.head_dim = 64;
    config.intermediate_size = 1376;
    
    auto runner = CreateGraphRunner(backend, config);
    
    // Execute single token
    int32_t input_token = 42;  // Arbitrary token ID
    uint32_t position = 0;
    
    std::cout << "  Input token: " << input_token << "\n";
    std::cout << "  Position: " << position << "\n";
    
    auto result = runner->ForwardSingleToken(input_token, position);
    
    if (!result.IsSuccess()) {
        std::cerr << "FAILED: Decode step failed\n";
        return false;
    }
    
    // Verify telemetry
    std::cout << "  Latency: " << result.telemetry.latency_ms << " ms\n";
    std::cout << "  Tokens: " << result.telemetry.generated_tokens << "\n";
    
    assert(result.telemetry.latency_ms > 0);
    assert(result.telemetry.generated_tokens == 1);
    
    std::cout << "  ✓ Single decode step completed\n";
    
    return true;
}

// ============================================================================
// Test: Full Forward Pass (Multiple Tokens)
// ============================================================================

bool TestFullForwardPass() {
    std::cout << "\n=== Test: Full Forward Pass ===\n";
    
    auto backend = std::make_shared<SimulatorBackend>(SimulationProfile::Fast());
    backend->Initialize();
    
    TransformerLayerConfig config;
    config.hidden_size = 512;
    config.num_heads = 8;
    config.head_dim = 64;
    config.intermediate_size = 1376;
    
    auto runner = CreateGraphRunner(backend, config);
    
    // Input prompt tokens
    std::vector<int32_t> input_tokens = {1, 2, 3};  // "Hello world"
    uint32_t max_new_tokens = 5;
    
    std::cout << "  Input tokens: " << input_tokens.size() << "\n";
    std::cout << "  Max new tokens: " << max_new_tokens << "\n";
    
    auto result = runner->Forward(input_tokens, max_new_tokens);
    
    if (!result.IsSuccess()) {
        std::cerr << "FAILED: Forward pass failed\n";
        return false;
    }
    
    // Verify results
    std::cout << "  Total latency: " << result.telemetry.latency_ms << " ms\n";
    std::cout << "  Generated tokens: " << result.telemetry.generated_tokens << "\n";
    std::cout << "  Throughput: " << result.telemetry.tokens_per_second << " tok/s\n";
    
    assert(result.telemetry.generated_tokens == max_new_tokens);
    assert(result.telemetry.tokens_per_second > 0);
    
    std::cout << "  ✓ Full forward pass completed\n";
    
    return true;
}

// ============================================================================
// Test: Layer-by-Layer Execution
// ============================================================================

bool TestLayerByLayer() {
    std::cout << "\n=== Test: Layer-by-Layer Execution ===\n";
    
    auto backend = std::make_shared<SimulatorBackend>(SimulationProfile::Fast());
    backend->Initialize();
    
    TransformerLayerConfig config;
    config.hidden_size = 512;
    config.num_heads = 8;
    config.head_dim = 64;
    config.intermediate_size = 1376;
    
    auto runner = CreateGraphRunner(backend, config);
    
    std::cout << "  Executing transformer layers:\n";
    
    // Embedding
    auto embed = runner->RunEmbedding(42);
    if (!embed.IsSuccess()) {
        std::cerr << "FAILED: Embedding\n";
        return false;
    }
    std::cout << "    ✓ Embedding\n";
    
    // PreNorm
    auto prenorm = runner->RunPreNorm();
    if (!prenorm.IsSuccess()) {
        std::cerr << "FAILED: PreNorm\n";
        return false;
    }
    std::cout << "    ✓ PreNorm (RMSNorm)\n";
    
    // Self-attention
    auto attn = runner->RunSelfAttention();
    if (!attn.IsSuccess()) {
        std::cerr << "FAILED: SelfAttention\n";
        return false;
    }
    std::cout << "    ✓ SelfAttention (QKV → RoPE → Attn → Output)\n";
    
    // FFN
    auto ffn = runner->RunFFN();
    if (!ffn.IsSuccess()) {
        std::cerr << "FAILED: FFN\n";
        return false;
    }
    std::cout << "    ✓ FFN\n";
    
    // FinalNorm
    auto finalnorm = runner->RunFinalNorm();
    if (!finalnorm.IsSuccess()) {
        std::cerr << "FAILED: FinalNorm\n";
        return false;
    }
    std::cout << "    ✓ FinalNorm (RMSNorm)\n";
    
    std::cout << "  ✓ All layers executed successfully\n";
    
    return true;
}

// ============================================================================
// Test: Kernel Registry
// ============================================================================

bool TestKernelRegistry() {
    std::cout << "\n=== Test: Kernel Registry ===\n";
    
    auto backend = std::make_shared<SimulatorBackend>(SimulationProfile::Fast());
    backend->Initialize();
    
    TransformerLayerConfig config;
    config.hidden_size = 512;
    config.num_heads = 8;
    
    auto runner = CreateGraphRunner(backend, config);
    
    // Check registered kernels
    std::cout << "  Registered kernels:\n";
    
    auto prenorm_name = runner->GetKernelName(KernelRole::PreNorm);
    std::cout << "    PreNorm: " << prenorm_name << "\n";
    assert(!prenorm_name.empty());
    
    auto attn_name = runner->GetKernelName(KernelRole::SelfAttention);
    std::cout << "    SelfAttention: " << attn_name << "\n";
    assert(!attn_name.empty());
    
    auto ffn_name = runner->GetKernelName(KernelRole::FFN);
    std::cout << "    FFN: " << ffn_name << "\n";
    assert(!ffn_name.empty());
    
    // Register custom kernel
    runner->RegisterKernel(KernelRole::Sampling, "Sovereign_Sampler");
    assert(runner->HasKernel(KernelRole::Sampling));
    std::cout << "    Sampling: Sovereign_Sampler (custom)\n";
    
    std::cout << "  ✓ Kernel registry working\n";
    
    return true;
}

// ============================================================================
// Test: Telemetry Capture
// ============================================================================

bool TestTelemetryCapture() {
    std::cout << "\n=== Test: Telemetry Capture ===\n";
    
    auto backend = std::make_shared<SimulatorBackend>(SimulationProfile::Fast());
    backend->Initialize();
    
    TransformerLayerConfig config;
    config.hidden_size = 512;
    config.num_heads = 8;
    
    auto runner = CreateGraphRunner(backend, config);
    
    // Run a single token (fast profile)
    std::vector<int32_t> tokens = {1};
    auto result = runner->Forward(tokens, 1);
    
    auto telemetry = runner->GetLastTelemetry();
    
    std::cout << "  Telemetry captured:\n";
    std::cout << "    Latency: " << telemetry.latency_ms << " ms\n";
    std::cout << "    Tokens: " << telemetry.generated_tokens << "\n";
    std::cout << "    TPS: " << telemetry.tokens_per_second << "\n";
    std::cout << "    Prompt tokens: " << telemetry.prompt_tokens << "\n";
    std::cout << "    Memory: " << telemetry.peak_memory_bytes / (1024*1024) << " MB\n";
    
    assert(telemetry.latency_ms >= 0);  // Allow 0 for very fast simulation
    assert(telemetry.generated_tokens == 1);
    
    std::cout << "  ✓ Telemetry capture working\n";
    
    return true;
}

// ============================================================================
// Test: Error Handling
// ============================================================================

bool TestErrorHandling() {
    std::cout << "\n=== Test: Error Handling ===\n";
    
    // Test with uninitialized backend
    auto backend = std::make_shared<SimulatorBackend>(SimulationProfile::Fast());
    // Note: NOT initialized
    
    TransformerLayerConfig config;
    auto runner = CreateGraphRunner(backend, config);
    
    if (runner) {
        std::cerr << "FAILED: Should not create runner with bad backend\n";
        return false;
    }
    
    std::cout << "  ✓ Error handling working (rejected bad backend)\n";
    
    return true;
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Sovereign Transformer Loop Test Suite\n";
    std::cout << "========================================\n";
    std::cout << "\nCanonical decode step:\n";
    std::cout << "  Embedding → PreNorm → QKV → RoPE → Attention → Residual → FFN → Residual\n";
    std::cout << "\nUsing execution contracts:\n";
    std::cout << "  ExecutionRequest → IExecutionBackend → ExecutionResult\n";
    
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
    
    run_test("GraphRunner Initialization", TestGraphRunnerInit);
    run_test("Single Decode Step", TestSingleDecodeStep);
    run_test("Full Forward Pass", TestFullForwardPass);
    run_test("Layer-by-Layer Execution", TestLayerByLayer);
    run_test("Kernel Registry", TestKernelRegistry);
    run_test("Telemetry Capture", TestTelemetryCapture);
    run_test("Error Handling", TestErrorHandling);
    
    std::cout << "\n" << std::string(50, '=') << "\n";
    std::cout << "Test Results:\n";
    std::cout << "  Passed: " << passed << "\n";
    std::cout << "  Failed: " << failed << "\n";
    std::cout << "  Total:  " << (passed + failed) << "\n";
    std::cout << std::string(50, '=') << "\n";
    
    return failed == 0 ? 0 : 1;
}

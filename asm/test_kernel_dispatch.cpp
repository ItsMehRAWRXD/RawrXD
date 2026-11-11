// ============================================================================
// test_kernel_dispatch.cpp - Kernel Integration Test
// ============================================================================
// Validates all Sovereign kernels work together
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cmath>
#include "Sovereign_KernelDispatch.h"

// Simple test utilities
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("[FAIL] %s at line %d\n", msg, __LINE__); \
            return false; \
        } \
    } while(0)

#define TEST_PASS(msg) printf("[PASS] %s\n", msg)

// Test RMSNorm
bool TestRMSNorm() {
    printf("\n=== Testing RMSNorm ===\n");
    
    const size_t n = 8;
    float input[n] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float weight[n] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float output[n] = {0};
    
    Sovereign::KernelDispatch dispatch;
    TEST_ASSERT(dispatch.Initialize(), "Failed to initialize kernel dispatch");
    
    TEST_ASSERT(dispatch.RMSNorm(input, output, weight, n, 1e-6f), 
                "RMSNorm failed");
    
    // Verify output is normalized (mean should be close to 0, variance close to 1)
    float sum = 0.0f, sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        sum += output[i];
        sum_sq += output[i] * output[i];
    }
    float mean = sum / n;
    float var = sum_sq / n - mean * mean;
    
    printf("  Mean: %.6f (expected ~0)\n", mean);
    printf("  Variance: %.6f (expected ~1)\n", var);
    
    TEST_ASSERT(std::abs(mean) < 0.1f, "Mean not normalized");
    TEST_ASSERT(std::abs(var - 1.0f) < 0.1f, "Variance not normalized");
    
    TEST_PASS("RMSNorm");
    return true;
}

// Test Residual Add
bool TestResidualAdd() {
    printf("\n=== Testing ResidualAdd ===\n");
    
    const size_t n = 8;
    float input[n] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float residual[n] = {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f};
    float output[n] = {0};
    
    Sovereign::KernelDispatch dispatch;
    TEST_ASSERT(dispatch.Initialize(), "Failed to initialize kernel dispatch");
    
    TEST_ASSERT(dispatch.ResidualAdd(input, residual, output, n),
                "ResidualAdd failed");
    
    // Verify: output[i] = input[i] + residual[i]
    for (size_t i = 0; i < n; i++) {
        float expected = input[i] + residual[i];
        TEST_ASSERT(std::abs(output[i] - expected) < 1e-5f,
                    "ResidualAdd value mismatch");
    }
    
    TEST_PASS("ResidualAdd");
    return true;
}

// Test RoPE
bool TestRoPE() {
    printf("\n=== Testing RoPE ===\n");
    
    const size_t head_dim = 64;
    const size_t max_seq_len = 128;
    const float theta = 10000.0f;
    
    std::vector<float> cache(max_seq_len * head_dim * 2);
    std::vector<float> tensor(max_seq_len * head_dim);
    
    // Initialize tensor with test data
    for (size_t i = 0; i < tensor.size(); i++) {
        tensor[i] = static_cast<float>(i % 10);
    }
    
    Sovereign::KernelDispatch dispatch;
    TEST_ASSERT(dispatch.Initialize(), "Failed to initialize kernel dispatch");
    
    // Precompute frequency cache
    TEST_ASSERT(dispatch.RoPEPrecompute(head_dim, max_seq_len, theta, cache.data()),
                "RoPE precompute failed");
    
    // Apply RoPE
    TEST_ASSERT(dispatch.RoPEApply(tensor.data(), cache.data(), 
                                    max_seq_len, head_dim, 1),
                "RoPE apply failed");
    
    TEST_PASS("RoPE");
    return true;
}

// Test Q4K Dequant
bool TestQ4KDequant() {
    printf("\n=== Testing Q4K Dequant ===\n");
    
    // Create a simple Q4_K block (256 weights)
    const size_t block_size = 256;
    std::vector<uint8_t> quantized(block_size / 2);  // 4 bits per weight
    std::vector<float> output(block_size);
    std::vector<uint8_t> scales(32);  // Scale data
    
    // Fill with test pattern
    for (size_t i = 0; i < quantized.size(); i++) {
        quantized[i] = static_cast<uint8_t>(i % 256);
    }
    
    Sovereign::KernelDispatch dispatch;
    TEST_ASSERT(dispatch.Initialize(), "Failed to initialize kernel dispatch");
    
    size_t result = dispatch.Q4KDequantBlock(quantized.data(), output.data(),
                                              block_size, scales.data());
    TEST_ASSERT(result > 0, "Q4K dequant failed");
    
    printf("  Dequantized %zu weights\n", result);
    
    TEST_PASS("Q4K Dequant");
    return true;
}

// Test full transformer layer simulation
bool TestTransformerLayer() {
    printf("\n=== Testing Transformer Layer Simulation ===\n");
    
    const size_t hidden_dim = 4096;
    const size_t seq_len = 1;
    
    // Allocate buffers
    std::vector<float> hidden_states(hidden_dim);
    std::vector<float> normed_states(hidden_dim);
    std::vector<float> rms_weights(hidden_dim, 1.0f);
    std::vector<float> residual(hidden_dim);
    
    // Initialize with test data
    for (size_t i = 0; i < hidden_dim; i++) {
        hidden_states[i] = static_cast<float>(i % 100) / 100.0f;
    }
    
    Sovereign::KernelDispatch dispatch;
    TEST_ASSERT(dispatch.Initialize(), "Failed to initialize kernel dispatch");
    
    // Simulate: RMSNorm -> Attention -> ResidualAdd
    printf("  Step 1: RMSNorm...\n");
    TEST_ASSERT(dispatch.RMSNorm(hidden_states.data(), normed_states.data(),
                                  rms_weights.data(), hidden_dim, 1e-6f),
                "RMSNorm failed");
    
    printf("  Step 2: Simulated Attention (copy)...\n");
    // In real implementation, this would call attention kernels
    memcpy(residual.data(), normed_states.data(), hidden_dim * sizeof(float));
    
    printf("  Step 3: ResidualAdd...\n");
    TEST_ASSERT(dispatch.ResidualAddInPlace(hidden_states.data(), 
                                             residual.data(), hidden_dim),
                "ResidualAdd failed");
    
    printf("  Output sample: ");
    for (size_t i = 0; i < 5; i++) {
        printf("%.4f ", hidden_states[i]);
    }
    printf("...\n");
    
    TEST_PASS("Transformer Layer Simulation");
    return true;
}

int main(int argc, char** argv) {
    printf("========================================\n");
    printf("Sovereign Kernel Integration Test\n");
    printf("========================================\n");
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (TestRMSNorm()) passed++; else failed++;
    if (TestResidualAdd()) passed++; else failed++;
    if (TestRoPE()) passed++; else failed++;
    if (TestQ4KDequant()) passed++; else failed++;
    if (TestTransformerLayer()) passed++; else failed++;
    
    // Summary
    printf("\n========================================\n");
    printf("Test Summary: %d passed, %d failed\n", passed, failed);
    printf("========================================\n");
    
    return failed > 0 ? 1 : 0;
}

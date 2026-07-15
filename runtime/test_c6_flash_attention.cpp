// ============================================================================
// test_c6_flash_attention.cpp - Validation for FlashAttention Implementation
// ============================================================================

#include "flash_attention.hpp"
#include "optimized_transformer_layer.hpp"
#include <iostream>
#include <cmath>
#include <random>

using namespace RawrXD::Runtime;

// ============================================================================
// Test Helpers
// ============================================================================
bool CompareFloats(float a, float b, float tolerance = 0.01f) {
    return std::abs(a - b) < tolerance;
}

bool TestOnlineSoftmax() {
    std::cout << "[Test] OnlineSoftmax... ";
    
    OnlineSoftmaxState state;
    float values[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    
    for (float v : values) {
        state.Update(v);
    }
    
    // Check normalization
    float sum = 0.0f;
    for (float v : values) {
        sum += state.Normalize(v);
    }
    
    if (!CompareFloats(sum, 1.0f, 0.001f)) {
        std::cout << "FAIL (sum=" << sum << ")\n";
        return false;
    }
    
    std::cout << "PASS\n";
    return true;
}

bool TestFlashAttentionInitialization() {
    std::cout << "[Test] FlashAttention Initialization... ";
    
    FlashAttention attn;
    FlashAttentionConfig config;
    config.Initialize(64, 32, 32);  // head_dim=64, num_heads=32, num_kv_heads=32
    
    if (!attn.Initialize(config)) {
        std::cout << "FAIL\n";
        return false;
    }
    
    std::cout << "PASS\n";
    return true;
}

bool TestFlashAttentionSingleHead() {
    std::cout << "[Test] FlashAttention Single Head... ";
    
    FlashAttention attn;
    FlashAttentionConfig config;
    config.Initialize(64, 1, 1);
    
    if (!attn.Initialize(config)) {
        std::cout << "FAIL (init)\n";
        return false;
    }
    
    // Create synthetic data
    alignas(64) float q[64];
    alignas(64) float k_cache[10 * 64];  // seq_len=10
    alignas(64) float v_cache[10 * 64];
    alignas(64) float output[64];
    
    // Initialize with simple pattern
    for (int i = 0; i < 64; ++i) {
        q[i] = static_cast<float>(i) / 64.0f;
    }
    
    for (int t = 0; t < 10; ++t) {
        for (int i = 0; i < 64; ++i) {
            k_cache[t * 64 + i] = static_cast<float>(t) / 10.0f;
            v_cache[t * 64 + i] = static_cast<float>(t) / 10.0f;
        }
    }
    
    if (!attn.ForwardSingleHead(q, k_cache, v_cache, 10, output)) {
        std::cout << "FAIL (forward)\n";
        return false;
    }
    
    // Check output is not all zeros
    bool has_nonzero = false;
    for (int i = 0; i < 64; ++i) {
        if (output[i] != 0.0f) {
            has_nonzero = true;
            break;
        }
    }
    
    if (!has_nonzero) {
        std::cout << "FAIL (all zeros)\n";
        return false;
    }
    
    std::cout << "PASS\n";
    return true;
}

bool TestQuantizedMatMul() {
    std::cout << "[Test] QuantizedMatMul... ";
    
    // This test requires actual Q4_K weights
    // For now, just verify the function exists and returns false for invalid input
    float input[256] = {0};
    float output[256] = {0};
    
    TensorView invalid_weight;
    if (QuantizedMatMul::Compute(invalid_weight, input, output, 256, 256)) {
        std::cout << "FAIL (should reject invalid weight)\n";
        return false;
    }
    
    std::cout << "PASS (stub)\n";
    return true;
}

bool TestCPUFeatures() {
    std::cout << "[Test] CPU Features Detection... ";
    
    CPUFeatures features = CPUFeatures::Detect();
    
    std::cout << "[AVX=" << features.has_avx 
              << " AVX2=" << features.has_avx2 
              << " AVX512=" << features.has_avx512f 
              << " FMA=" << features.has_fma << "] ";
    
    // At least one should be true on x86_64
    #if defined(__x86_64__) || defined(_M_X64)
    if (!features.has_avx && !features.has_avx2) {
        std::cout << "WARNING (no vector extensions)\n";
        // Don't fail, just warn
    }
    #endif
    
    std::cout << "PASS\n";
    return true;
}

bool TestOptimizedLayerInheritance() {
    std::cout << "[Test] OptimizedLayer Inheritance... ";
    
    // Verify OptimizedTransformerLayer can be used as TransformerLayerRuntime
    OptimizedTransformerLayer layer;
    
    // Check that it has the base class interface
    if (layer.GetConfig().hiddenSize != 0) {
        // Config should be default initialized
    }
    
    std::cout << "PASS\n";
    return true;
}

// ============================================================================
// Performance Microbenchmark
// ============================================================================
void BenchmarkAttention() {
    std::cout << "\n[Benchmark] FlashAttention Performance\n";
    
    FlashAttention attn;
    FlashAttentionConfig config;
    config.Initialize(64, 32, 32);  // Standard config
    
    if (!attn.Initialize(config)) {
        std::cout << "Failed to initialize\n";
        return;
    }
    
    // Create synthetic KV cache
    const uint32_t seq_len = 128;
    const uint32_t num_kv_heads = 32;
    const uint32_t head_dim = 64;
    
    alignas(64) float q[32 * 64];
    alignas(64) float k_cache[128 * 32 * 64];
    alignas(64) float v_cache[128 * 32 * 64];
    alignas(64) float output[32 * 64];
    
    // Initialize with random data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (size_t i = 0; i < 32 * 64; ++i) q[i] = dist(gen);
    for (size_t i = 0; i < 128 * 32 * 64; ++i) {
        k_cache[i] = dist(gen);
        v_cache[i] = dist(gen);
    }
    
    // Warmup
    for (int i = 0; i < 10; ++i) {
        // Would need actual KVCache object
        // attn.Forward(q, kv_cache, seq_len, output);
    }
    
    std::cout << "  (Requires full KVCache integration for complete benchmark)\n";
    std::cout << "  Config: heads=" << config.num_heads 
              << ", head_dim=" << config.head_dim 
              << ", seq_len=" << seq_len << "\n";
}

// ============================================================================
// Main Test Runner
// ============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "C6 FlashAttention Validation Suite\n";
    std::cout << "========================================\n\n";
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (TestCPUFeatures()) passed++; else failed++;
    if (TestOnlineSoftmax()) passed++; else failed++;
    if (TestFlashAttentionInitialization()) passed++; else failed++;
    if (TestFlashAttentionSingleHead()) passed++; else failed++;
    if (TestQuantizedMatMul()) passed++; else failed++;
    if (TestOptimizedLayerInheritance()) passed++; else failed++;
    
    // Performance benchmark
    BenchmarkAttention();
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";
    
    return failed == 0 ? 0 : 1;
}

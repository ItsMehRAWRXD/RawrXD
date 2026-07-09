/**
 * @file attention_avx2_test.cpp
 * @brief RawrXD L4.3.1 AVX2 Attention Tests
 *
 * Validation that AVX2 attention matches reference implementation.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>

#include "../kernels/attention_contracts.h"
#include "../kernels/attention_avx2.h"

using namespace rawrxd;
using namespace rawrxd::attention;

// ============================================================================
// Test Utilities
// ============================================================================

class TestReporter {
public:
    static int tests_run_;
    static int tests_passed_;
    static int tests_failed_;
    
    static void Reset() {
        tests_run_ = 0;
        tests_passed_ = 0;
        tests_failed_ = 0;
    }
    
    static void Report(const char* name, bool passed) {
        tests_run_++;
        if (passed) {
            tests_passed_++;
            std::cout << "  ✅ " << name << "\n";
        } else {
            tests_failed_++;
            std::cout << "  ❌ " << name << "\n";
        }
    }
    
    static void PrintSummary() {
        std::cout << "\n═══════════════════════════════════════════════════════════════\n";
        std::cout << "TEST SUMMARY: " << tests_passed_ << "/" << tests_run_ << " passed\n";
        std::cout << "═══════════════════════════════════════════════════════════════\n";
    }
};

int TestReporter::tests_run_ = 0;
int TestReporter::tests_passed_ = 0;
int TestReporter::tests_failed_ = 0;

// ============================================================================
// Test Cases
// ============================================================================

bool Test_AttentionAVX2_IsAvailable() {
    // Just check if detection works - may or may not be available
    bool available = AttentionAVX2::IsAvailable();
    (void)available;
    return true;  // Test passes if function works
}

bool Test_AttentionAVX2_SingleHead() {
    // Skip if AVX2 not available
    if (!AttentionAVX2::IsAvailable()) {
        std::cout << "    (skipped - AVX2 not available)\n";
        return true;
    }
    
    // Setup config
    AttentionConfig config;
    config.num_heads = 1;
    config.num_kv_heads = 1;
    config.head_dim = 64;
    config.context_length = 128;
    config.causal = true;
    config.ComputeScale();
    
    // Setup inputs
    std::vector<float> q_data(64, 0.1f);
    std::vector<float> k_data(64 * 10, 0.1f);  // 10 positions
    std::vector<float> v_data(64 * 10, 0.1f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 1, 64);
    inputs.key = TensorView::CreateContiguous(k_data.data(), 10, 64);
    inputs.value = TensorView::CreateContiguous(v_data.data(), 10, 64);
    inputs.seq_position = 9;  // 10th position
    inputs.kv_cache = nullptr;
    
    // Setup outputs
    std::vector<float> output_data(64, 0.0f);
    AttentionOutputs outputs;
    outputs.output = TensorView::CreateContiguous(output_data.data(), 1, 64);
    
    // Execute
    bool success = AttentionAVX2::Execute(config, inputs, outputs);
    
    // Check output is non-zero
    bool has_output = false;
    for (float v : output_data) {
        if (v != 0.0f) {
            has_output = true;
            break;
        }
    }
    
    return success && has_output;
}

bool Test_AttentionAVX2_MultiHead() {
    if (!AttentionAVX2::IsAvailable()) {
        std::cout << "    (skipped - AVX2 not available)\n";
        return true;
    }
    
    AttentionConfig config;
    config.num_heads = 8;
    config.num_kv_heads = 8;
    config.head_dim = 64;
    config.context_length = 128;
    config.ComputeScale();
    
    std::vector<float> q_data(8 * 64, 0.1f);
    std::vector<float> k_data(8 * 64 * 5, 0.1f);
    std::vector<float> v_data(8 * 64 * 5, 0.1f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 8, 64);
    inputs.key = TensorView::CreateContiguous(k_data.data(), 5 * 8, 64);
    inputs.value = TensorView::CreateContiguous(v_data.data(), 5 * 8, 64);
    inputs.seq_position = 4;
    inputs.kv_cache = nullptr;
    
    std::vector<float> output_data(8 * 64, 0.0f);
    AttentionOutputs outputs;
    outputs.output = TensorView::CreateContiguous(output_data.data(), 8, 64);
    
    return AttentionAVX2::Execute(config, inputs, outputs);
}

bool Test_AttentionAVX2_GQA() {
    if (!AttentionAVX2::IsAvailable()) {
        std::cout << "    (skipped - AVX2 not available)\n";
        return true;
    }
    
    // GQA: 32 query heads, 8 KV heads
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.context_length = 4096;
    config.ComputeScale();
    
    if (!config.IsGQA()) return false;
    if (config.GetQueryHeadsPerKV() != 4) return false;
    
    std::vector<float> q_data(32 * 128, 0.1f);
    std::vector<float> k_data(8 * 128 * 10, 0.1f);
    std::vector<float> v_data(8 * 128 * 10, 0.1f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 32, 128);
    inputs.key = TensorView::CreateContiguous(k_data.data(), 10 * 8, 128);
    inputs.value = TensorView::CreateContiguous(v_data.data(), 10 * 8, 128);
    inputs.seq_position = 9;
    inputs.kv_cache = nullptr;
    
    std::vector<float> output_data(32 * 128, 0.0f);
    AttentionOutputs outputs;
    outputs.output = TensorView::CreateContiguous(output_data.data(), 32, 128);
    
    return AttentionAVX2::Execute(config, inputs, outputs);
}

bool Test_AttentionAVX2_WithKVCache() {
    if (!AttentionAVX2::IsAvailable()) {
        std::cout << "    (skipped - AVX2 not available)\n";
        return true;
    }
    
    AttentionConfig config;
    config.num_heads = 8;
    config.num_kv_heads = 8;
    config.head_dim = 64;
    config.context_length = 128;
    config.ComputeScale();
    
    // Setup KV cache
    std::vector<float> k_cache(128 * 8 * 64, 0.0f);
    std::vector<float> v_cache(128 * 8 * 64, 0.0f);
    
    KVCache cache;
    cache.Initialize(k_cache.data(), v_cache.data(), 128, 8, 64);
    
    // Pre-populate cache with 5 positions
    for (int pos = 0; pos < 5; ++pos) {
        std::vector<float> new_k(8 * 64, 0.1f);
        std::vector<float> new_v(8 * 64, 0.1f);
        cache.Append(new_k.data(), new_v.data(), 8, 64);
    }
    
    // Current query
    std::vector<float> q_data(8 * 64, 0.1f);
    std::vector<float> new_k(8 * 64, 0.1f);
    std::vector<float> new_v(8 * 64, 0.1f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 8, 64);
    inputs.key = TensorView::CreateContiguous(new_k.data(), 8, 64);
    inputs.value = TensorView::CreateContiguous(new_v.data(), 8, 64);
    inputs.seq_position = 5;  // 6th position (0-indexed)
    inputs.kv_cache = &cache;
    
    std::vector<float> output_data(8 * 64, 0.0f);
    AttentionOutputs outputs;
    outputs.output = TensorView::CreateContiguous(output_data.data(), 8, 64);
    
    bool success = AttentionAVX2::Execute(config, inputs, outputs, &cache);
    
    return success && outputs.kv_cache_updated;
}

bool Test_AttentionAVX2_Validated() {
    if (!AttentionAVX2::IsAvailable()) {
        std::cout << "    (skipped - AVX2 not available)\n";
        return true;
    }
    
    AttentionConfig config;
    config.num_heads = 4;
    config.num_kv_heads = 4;
    config.head_dim = 64;
    config.context_length = 128;
    config.ComputeScale();
    
    std::vector<float> q_data(4 * 64, 0.1f);
    std::vector<float> k_data(4 * 64 * 5, 0.1f);
    std::vector<float> v_data(4 * 64 * 5, 0.1f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 4, 64);
    inputs.key = TensorView::CreateContiguous(k_data.data(), 5 * 4, 64);
    inputs.value = TensorView::CreateContiguous(v_data.data(), 5 * 4, 64);
    inputs.seq_position = 4;
    inputs.kv_cache = nullptr;
    
    std::vector<float> output_data(4 * 64, 0.0f);
    AttentionOutputs outputs;
    outputs.output = TensorView::CreateContiguous(output_data.data(), 4, 64);
    
    ValidationResult validation;
    bool success = AttentionAVX2::ExecuteValidated(config, inputs, outputs, nullptr, &validation);
    
    // Should pass validation
    return success && validation.passed;
}

bool Test_AttentionAVX2_ValidationMetrics() {
    if (!AttentionAVX2::IsAvailable()) {
        std::cout << "    (skipped - AVX2 not available)\n";
        return true;
    }
    
    AttentionConfig config;
    config.num_heads = 2;
    config.num_kv_heads = 2;
    config.head_dim = 32;
    config.context_length = 64;
    config.ComputeScale();
    
    std::vector<float> q_data(2 * 32, 0.1f);
    std::vector<float> k_data(2 * 32 * 3, 0.1f);
    std::vector<float> v_data(2 * 32 * 3, 0.1f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 2, 32);
    inputs.key = TensorView::CreateContiguous(k_data.data(), 3 * 2, 32);
    inputs.value = TensorView::CreateContiguous(v_data.data(), 3 * 2, 32);
    inputs.seq_position = 2;
    inputs.kv_cache = nullptr;
    
    std::vector<float> output_data(2 * 32, 0.0f);
    AttentionOutputs outputs;
    outputs.output = TensorView::CreateContiguous(output_data.data(), 2, 32);
    
    ValidationResult validation;
    bool success = AttentionAVX2::ExecuteValidated(config, inputs, outputs, nullptr, &validation);
    
    // Check metrics are reasonable
    bool metrics_ok = validation.cosine_similarity > 0.99f &&
                      validation.max_absolute_error < 0.1f &&
                      validation.rmse < 0.01f;
    
    return success && validation.passed && metrics_ok;
}

// ============================================================================
// Integration Tests
// ============================================================================

bool Test_AttentionAVX2_FullPipeline() {
    if (!AttentionAVX2::IsAvailable()) {
        std::cout << "    (skipped - AVX2 not available)\n";
        return true;
    }
    
    // Simulate a realistic decode step
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 8;  // GQA
    config.head_dim = 128;
    config.context_length = 4096;
    config.causal = true;
    config.use_rope = true;
    config.rope_theta = 10000.0f;
    config.ComputeScale();
    
    // Setup KV cache with 100 previous tokens
    std::vector<float> k_cache(4096 * 8 * 128, 0.0f);
    std::vector<float> v_cache(4096 * 8 * 128, 0.0f);
    
    KVCache cache;
    cache.Initialize(k_cache.data(), v_cache.data(), 4096, 8, 128);
    cache.current_position = 100;  // 100 tokens cached
    
    // Current token
    std::vector<float> q_data(32 * 128, 0.05f);
    std::vector<float> new_k(8 * 128, 0.05f);
    std::vector<float> new_v(8 * 128, 0.05f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 32, 128);
    inputs.key = TensorView::CreateContiguous(new_k.data(), 8, 128);
    inputs.value = TensorView::CreateContiguous(new_v.data(), 8, 128);
    inputs.seq_position = 100;
    inputs.kv_cache = &cache;
    
    std::vector<float> output_data(32 * 128, 0.0f);
    AttentionOutputs outputs;
    outputs.output = TensorView::CreateContiguous(output_data.data(), 32, 128);
    
    ValidationResult validation;
    bool success = AttentionAVX2::ExecuteValidated(config, inputs, outputs, &cache, &validation);
    
    std::cout << "    Cosine: " << validation.cosine_similarity 
              << ", Max Error: " << validation.max_absolute_error << "\n";
    
    return success && validation.passed;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "RawrXD L4.3.1 AVX2 Attention Tests\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
    
    TestReporter::Reset();
    
    // Basic Tests
    std::cout << "Basic Tests:\n";
    TestReporter::Report("AttentionAVX2_IsAvailable", Test_AttentionAVX2_IsAvailable());
    
    // Functionality Tests
    std::cout << "\nFunctionality Tests:\n";
    TestReporter::Report("AttentionAVX2_SingleHead", Test_AttentionAVX2_SingleHead());
    TestReporter::Report("AttentionAVX2_MultiHead", Test_AttentionAVX2_MultiHead());
    TestReporter::Report("AttentionAVX2_GQA", Test_AttentionAVX2_GQA());
    TestReporter::Report("AttentionAVX2_WithKVCache", Test_AttentionAVX2_WithKVCache());
    
    // Validation Tests
    std::cout << "\nValidation Tests:\n";
    TestReporter::Report("AttentionAVX2_Validated", Test_AttentionAVX2_Validated());
    TestReporter::Report("AttentionAVX2_ValidationMetrics", Test_AttentionAVX2_ValidationMetrics());
    
    // Integration Tests
    std::cout << "\nIntegration Tests:\n";
    TestReporter::Report("AttentionAVX2_FullPipeline", Test_AttentionAVX2_FullPipeline());
    
    TestReporter::PrintSummary();
    
    return TestReporter::tests_failed_ > 0 ? 1 : 0;
}

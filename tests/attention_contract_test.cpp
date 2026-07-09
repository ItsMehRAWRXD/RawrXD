/**
 * @file attention_contract_test.cpp
 * @brief RawrXD L4.3 Attention Contract Tests
 *
 * Validation for tensor layouts, attention config, KV cache ABI.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>

#include "../kernels/attention_contracts.h"

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

bool Test_TensorView_CreateContiguous() {
    std::vector<float> data(100, 1.0f);
    auto view = TensorView::CreateContiguous(data.data(), 10, 10);
    
    return view.IsValid() && 
           view.rows == 10 && 
           view.cols == 10 &&
           view.is_contiguous;
}

bool Test_TensorView_CreateContiguous3D() {
    std::vector<float> data(120, 1.0f);
    auto view = TensorView::CreateContiguous3D(data.data(), 3, 4, 10);
    
    return view.IsValid() && 
           view.depth == 3 && 
           view.rows == 4 &&
           view.cols == 10;
}

bool Test_TensorView_Invalid() {
    TensorView view;
    return !view.IsValid();  // Default should be invalid
}

bool Test_TensorView_MatchesShape() {
    std::vector<float> data(100, 1.0f);
    auto view = TensorView::CreateContiguous(data.data(), 10, 10);
    
    return view.MatchesShape(10, 10) && !view.MatchesShape(5, 20);
}

bool Test_TensorView_Access() {
    std::vector<float> data(100);
    for (int i = 0; i < 100; ++i) data[i] = static_cast<float>(i);
    
    auto view = TensorView::CreateContiguous(data.data(), 10, 10);
    
    return view.at(0, 0) == 0.0f && 
           view.at(1, 0) == 10.0f &&
           view.at(9, 9) == 99.0f;
}

bool Test_AttentionConfig_Valid() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 32;  // MHA
    config.head_dim = 128;
    config.context_length = 4096;
    config.causal = true;
    
    return config.IsValid();
}

bool Test_AttentionConfig_Invalid_ZeroHeads() {
    AttentionConfig config;
    config.num_heads = 0;  // Invalid
    config.num_kv_heads = 32;
    config.head_dim = 128;
    
    return !config.IsValid();
}

bool Test_AttentionConfig_Invalid_GQA() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 8;  // GQA: 32/8 = 4 query heads per KV
    config.head_dim = 128;
    config.context_length = 4096;
    
    // Should be valid (32 % 8 == 0)
    return config.IsValid() && config.IsGQA();
}

bool Test_AttentionConfig_Invalid_UnevenGQA() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 6;  // Invalid: 32 % 6 != 0
    config.head_dim = 128;
    
    return !config.IsValid();
}

bool Test_AttentionConfig_ComputeScale() {
    AttentionConfig config;
    config.head_dim = 64;
    config.scale = 0.0f;  // Not set
    
    config.ComputeScale();
    
    float expected = 1.0f / std::sqrt(64.0f);  // 0.125
    return std::abs(config.scale - expected) < 0.001f;
}

bool Test_AttentionConfig_QueryHeadsPerKV() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    
    return config.GetQueryHeadsPerKV() == 4;
}

bool Test_KVCache_Initialize() {
    std::vector<float> k_buffer(4096 * 8 * 128, 0.0f);
    std::vector<float> v_buffer(4096 * 8 * 128, 0.0f);
    
    KVCache cache;
    bool success = cache.Initialize(
        k_buffer.data(), v_buffer.data(),
        4096, 8, 128
    );
    
    return success && cache.IsValid() && cache.is_initialized;
}

bool Test_KVCache_Invalid_NullBuffer() {
    KVCache cache;
    bool success = cache.Initialize(nullptr, nullptr, 4096, 8, 128);
    
    return !success;
}

bool Test_KVCache_GetKeyValue() {
    std::vector<float> k_buffer(4096 * 8 * 128, 0.0f);
    std::vector<float> v_buffer(4096 * 8 * 128, 0.0f);
    
    KVCache cache;
    cache.Initialize(k_buffer.data(), v_buffer.data(), 4096, 8, 128);
    
    float* k = cache.GetKey(100, 3);
    float* v = cache.GetValue(100, 3);
    
    return k != nullptr && v != nullptr;
}

bool Test_KVCache_Append() {
    std::vector<float> k_buffer(4096 * 8 * 128, 0.0f);
    std::vector<float> v_buffer(4096 * 8 * 128, 0.0f);
    
    KVCache cache;
    cache.Initialize(k_buffer.data(), v_buffer.data(), 4096, 8, 128);
    
    std::vector<float> new_k(8 * 128, 1.0f);
    std::vector<float> new_v(8 * 128, 2.0f);
    
    bool success = cache.Append(new_k.data(), new_v.data(), 8, 128);
    
    return success && cache.current_position == 1;
}

bool Test_KVCache_Reset() {
    std::vector<float> k_buffer(4096 * 8 * 128, 0.0f);
    std::vector<float> v_buffer(4096 * 8 * 128, 0.0f);
    
    KVCache cache;
    cache.Initialize(k_buffer.data(), v_buffer.data(), 4096, 8, 128);
    
    std::vector<float> new_k(8 * 128, 1.0f);
    std::vector<float> new_v(8 * 128, 2.0f);
    cache.Append(new_k.data(), new_v.data(), 8, 128);
    
    cache.Reset();
    
    return cache.current_position == 0;
}

bool Test_KVCache_HasCapacity() {
    std::vector<float> k_buffer(100 * 8 * 128, 0.0f);
    std::vector<float> v_buffer(100 * 8 * 128, 0.0f);
    
    KVCache cache;
    cache.Initialize(k_buffer.data(), v_buffer.data(), 100, 8, 128);
    
    cache.current_position = 99;  // Almost full
    
    return cache.HasCapacity() && !cache.IsFull();
}

bool Test_AttentionInputs_Valid() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 32;
    config.head_dim = 128;
    
    std::vector<float> q_data(32 * 128, 1.0f);
    std::vector<float> k_data(32 * 128, 1.0f);
    std::vector<float> v_data(32 * 128, 1.0f);
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 32, 128);
    inputs.key = TensorView::CreateContiguous(k_data.data(), 32, 128);
    inputs.value = TensorView::CreateContiguous(v_data.data(), 32, 128);
    inputs.seq_position = 0;
    
    return inputs.IsValid(config);
}

bool Test_AttentionInputs_InvalidShape() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 32;
    config.head_dim = 128;
    
    std::vector<float> q_data(16 * 128, 1.0f);  // Wrong shape
    
    AttentionInputs inputs;
    inputs.query = TensorView::CreateContiguous(q_data.data(), 16, 128);
    inputs.seq_position = 0;
    
    return !inputs.IsValid(config);
}

bool Test_ValidationResult_Passing() {
    ValidationResult result;
    result.cosine_similarity = 0.9995f;
    result.max_absolute_error = 0.005f;
    
    return result.IsPassing();
}

bool Test_ValidationResult_Failing() {
    ValidationResult result;
    result.cosine_similarity = 0.99f;  // Below 0.999
    result.max_absolute_error = 0.02f;  // Above 0.01
    
    return !result.IsPassing();
}

bool Test_ValidationResult_AddError() {
    ValidationResult result;
    result.passed = true;  // Start passing
    
    result.AddError("Test error");
    
    return !result.passed && result.errors.size() == 1;
}

// ============================================================================
// Integration Tests
// ============================================================================

bool Test_FullAttentionConfig() {
    // Create a realistic Llama-style config
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 8;  // GQA
    config.head_dim = 128;
    config.context_length = 8192;
    config.causal = true;
    config.use_rope = true;
    config.rope_theta = 10000.0f;
    config.ComputeScale();
    
    if (!config.IsValid()) return false;
    if (!config.IsGQA()) return false;
    if (config.GetQueryHeadsPerKV() != 4) return false;
    
    return true;
}

bool Test_KVCacheWithConfig() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.context_length = 4096;
    
    // Allocate cache
    size_t cache_size = config.context_length * config.num_kv_heads * config.head_dim;
    std::vector<float> k_buffer(cache_size, 0.0f);
    std::vector<float> v_buffer(cache_size, 0.0f);
    
    KVCache cache;
    bool success = cache.Initialize(
        k_buffer.data(), v_buffer.data(),
        config.context_length,
        config.num_kv_heads,
        config.head_dim
    );
    
    return success && cache.IsValid();
}

bool Test_AttentionChainValidation() {
    AttentionConfig config;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.context_length = 4096;
    
    return ValidateAttentionChain(config);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "RawrXD L4.3 Attention Contract Tests\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
    
    TestReporter::Reset();
    
    // TensorView Tests
    std::cout << "TensorView Tests:\n";
    TestReporter::Report("TensorView_CreateContiguous", Test_TensorView_CreateContiguous());
    TestReporter::Report("TensorView_CreateContiguous3D", Test_TensorView_CreateContiguous3D());
    TestReporter::Report("TensorView_Invalid", Test_TensorView_Invalid());
    TestReporter::Report("TensorView_MatchesShape", Test_TensorView_MatchesShape());
    TestReporter::Report("TensorView_Access", Test_TensorView_Access());
    
    // AttentionConfig Tests
    std::cout << "\nAttentionConfig Tests:\n";
    TestReporter::Report("AttentionConfig_Valid", Test_AttentionConfig_Valid());
    TestReporter::Report("AttentionConfig_Invalid_ZeroHeads", Test_AttentionConfig_Invalid_ZeroHeads());
    TestReporter::Report("AttentionConfig_Invalid_GQA", Test_AttentionConfig_Invalid_GQA());
    TestReporter::Report("AttentionConfig_Invalid_UnevenGQA", Test_AttentionConfig_Invalid_UnevenGQA());
    TestReporter::Report("AttentionConfig_ComputeScale", Test_AttentionConfig_ComputeScale());
    TestReporter::Report("AttentionConfig_QueryHeadsPerKV", Test_AttentionConfig_QueryHeadsPerKV());
    
    // KVCache Tests
    std::cout << "\nKVCache Tests:\n";
    TestReporter::Report("KVCache_Initialize", Test_KVCache_Initialize());
    TestReporter::Report("KVCache_Invalid_NullBuffer", Test_KVCache_Invalid_NullBuffer());
    TestReporter::Report("KVCache_GetKeyValue", Test_KVCache_GetKeyValue());
    TestReporter::Report("KVCache_Append", Test_KVCache_Append());
    TestReporter::Report("KVCache_Reset", Test_KVCache_Reset());
    TestReporter::Report("KVCache_HasCapacity", Test_KVCache_HasCapacity());
    
    // AttentionInputs Tests
    std::cout << "\nAttentionInputs Tests:\n";
    TestReporter::Report("AttentionInputs_Valid", Test_AttentionInputs_Valid());
    TestReporter::Report("AttentionInputs_InvalidShape", Test_AttentionInputs_InvalidShape());
    
    // ValidationResult Tests
    std::cout << "\nValidationResult Tests:\n";
    TestReporter::Report("ValidationResult_Passing", Test_ValidationResult_Passing());
    TestReporter::Report("ValidationResult_Failing", Test_ValidationResult_Failing());
    TestReporter::Report("ValidationResult_AddError", Test_ValidationResult_AddError());
    
    // Integration Tests
    std::cout << "\nIntegration Tests:\n";
    TestReporter::Report("FullAttentionConfig", Test_FullAttentionConfig());
    TestReporter::Report("KVCacheWithConfig", Test_KVCacheWithConfig());
    TestReporter::Report("AttentionChainValidation", Test_AttentionChainValidation());
    
    TestReporter::PrintSummary();
    
    return TestReporter::tests_failed_ > 0 ? 1 : 0;
}

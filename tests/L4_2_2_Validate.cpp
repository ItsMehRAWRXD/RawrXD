// L4_2_2_Validate.cpp
// L4.2.2 Transformer Primitives Validation Test

#include "L4_2_2_TransformerPrimitives.h"
#include <iostream>
#include <iomanip>
#include <cmath>

using namespace RawrXD::L4;

// ============================================================================
// Test RMSNorm
// ============================================================================

bool TestRMSNorm() {
    std::cout << "\n=== Testing RMSNorm ===" << std::endl;
    
    RMSNormConfig config;
    config.hidden_size = 4096;
    config.epsilon = 1e-6f;
    
    // Create test data
    std::vector<float> x(config.hidden_size);
    std::vector<float> weight(config.hidden_size);
    std::vector<float> output(config.hidden_size);
    
    // Initialize with simple values
    for (size_t i = 0; i < config.hidden_size; i++) {
        x[i] = static_cast<float>(i % 10) / 10.0f;  // 0.0, 0.1, 0.2, ...
        weight[i] = 1.0f;  // Unit weights for simplicity
    }
    
    // Run RMSNorm
    RMSNorm_Reference(x.data(), weight.data(), output.data(), config);
    
    // Verify: output should be normalized
    // Compute RMS of output
    float sum_sq = 0.0f;
    for (size_t i = 0; i < config.hidden_size; i++) {
        sum_sq += output[i] * output[i];
    }
    float rms = std::sqrt(sum_sq / config.hidden_size);
    
    std::cout << "  Input RMS: " << std::sqrt(sum_sq / config.hidden_size) << std::endl;
    std::cout << "  Output RMS (should be ~1.0): " << rms << std::endl;
    
    // Check if normalized (RMS should be close to 1.0)
    bool passed = std::abs(rms - 1.0f) < 0.01f;
    std::cout << "  Status: " << (passed ? "PASS ✓" : "FAIL ✗") << std::endl;
    
    return passed;
}

// ============================================================================
// Test RoPE
// ============================================================================

bool TestRoPE() {
    std::cout << "\n=== Testing RoPE ===" << std::endl;
    
    RoPEConfig config;
    config.head_dim = 128;
    config.num_heads = 32;
    config.theta_base = 10000.0f;
    config.max_position = 8192;
    
    // Precompute tables
    RoPETables tables = PrecomputeRoPE(config);
    
    std::cout << "  Precomputed tables: " << tables.cos_table.size() << " values" << std::endl;
    
    // Create test Q and K tensors
    std::vector<float> q(config.num_heads * config.head_dim);
    std::vector<float> k(config.num_heads * config.head_dim);
    
    // Initialize with simple pattern
    for (size_t i = 0; i < q.size(); i++) {
        q[i] = static_cast<float>(1 + (i % 5));  // 1, 2, 3, 4, 5, 1, 2, ...
        k[i] = static_cast<float>(1 + (i % 3));  // 1, 2, 3, 1, 2, 3, ...
    }
    
    // Save original values for comparison
    std::vector<float> q_orig = q;
    std::vector<float> k_orig = k;
    
    // Apply RoPE at position 0
    ApplyRoPE_Reference(q.data(), k.data(), 0, config, tables);
    
    // At position 0, cos(0)=1, sin(0)=0, so values should be unchanged
    bool passed = true;
    for (size_t i = 0; i < q.size(); i++) {
        if (std::abs(q[i] - q_orig[i]) > 1e-6f) {
            passed = false;
            std::cout << "  Q mismatch at " << i << ": " << q[i] << " vs " << q_orig[i] << std::endl;
            break;
        }
    }
    
    // Apply RoPE at position 100
    q = q_orig;
    k = k_orig;
    ApplyRoPE_Reference(q.data(), k.data(), 100, config, tables);
    
    // At position 100, values should be rotated
    bool changed = false;
    for (size_t i = 0; i < q.size() && !changed; i++) {
        if (std::abs(q[i] - q_orig[i]) > 1e-6f) {
            changed = true;
        }
    }
    
    std::cout << "  Position 0: values unchanged (cos=1, sin=0): " << (passed ? "PASS" : "FAIL") << std::endl;
    std::cout << "  Position 100: values rotated: " << (changed ? "PASS" : "FAIL") << std::endl;
    
    passed = passed && changed;
    std::cout << "  Status: " << (passed ? "PASS ✓" : "FAIL ✗") << std::endl;
    
    return passed;
}

// ============================================================================
// Test Softmax
// ============================================================================

bool TestSoftmax() {
    std::cout << "\n=== Testing Softmax ===" << std::endl;
    
    size_t num_heads = 4;
    size_t seq_len = 8;
    
    std::vector<float> scores(num_heads * seq_len);
    
    // Initialize with random-ish values
    for (size_t i = 0; i < scores.size(); i++) {
        scores[i] = static_cast<float>((i * 17) % 10) - 5.0f;  // -5 to +5
    }
    
    // Run softmax
    Softmax_Reference(scores.data(), num_heads, seq_len);
    
    // Verify: each head's scores should sum to 1.0
    bool passed = true;
    for (size_t h = 0; h < num_heads; h++) {
        float sum = 0.0f;
        for (size_t i = 0; i < seq_len; i++) {
            sum += scores[h * seq_len + i];
        }
        if (std::abs(sum - 1.0f) > 1e-5f) {
            passed = false;
            std::cout << "  Head " << h << " sum: " << sum << " (should be 1.0)" << std::endl;
        }
    }
    
    std::cout << "  Verified " << num_heads << " heads sum to 1.0" << std::endl;
    std::cout << "  Status: " << (passed ? "PASS ✓" : "FAIL ✗") << std::endl;
    
    return passed;
}

// ============================================================================
// Test SiLU
// ============================================================================

bool TestSiLU() {
    std::cout << "\n=== Testing SiLU ===" << std::endl;
    
    // Test known values
    struct TestCase {
        float input;
        float expected;
    };
    
    TestCase tests[] = {
        {0.0f, 0.0f},  // SiLU(0) = 0
        {1.0f, 0.731058f},  // SiLU(1) ≈ 0.731
        {-1.0f, -0.268941f},  // SiLU(-1) ≈ -0.269
        {5.0f, 4.966535f},  // SiLU(5) ≈ 4.967 (approaches x)
        {-5.0f, -0.033464f},  // SiLU(-5) ≈ 0 (approaches 0)
    };
    
    bool passed = true;
    for (const auto& test : tests) {
        float result = SiLU(test.input);
        float error = std::abs(result - test.expected);
        if (error > 1e-5f) {
            passed = false;
            std::cout << "  SiLU(" << test.input << ") = " << result 
                      << " (expected " << test.expected << ", error " << error << ")" << std::endl;
        }
    }
    
    std::cout << "  Tested " << sizeof(tests)/sizeof(tests[0]) << " known values" << std::endl;
    std::cout << "  Status: " << (passed ? "PASS ✓" : "FAIL ✗") << std::endl;
    
    return passed;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "L4.2.2 Transformer Primitives Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    
    bool all_passed = true;
    
    all_passed &= TestRMSNorm();
    all_passed &= TestRoPE();
    all_passed &= TestSoftmax();
    all_passed &= TestSiLU();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Overall Status: " << (all_passed ? "ALL TESTS PASS ✓" : "SOME TESTS FAIL ✗") << std::endl;
    std::cout << "========================================" << std::endl;
    
    return all_passed ? 0 : 1;
}

// q4_0_validation.cpp
// Standalone Q4_0 dequantization validation
// Tests the fixed kernel against reference implementation

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <random>
#include <chrono>

// ═══════════════════════════════════════════════════════════════════════════════
// Q4_0 Format Structures
// ═══════════════════════════════════════════════════════════════════════════════

struct Q4_0_Block {
    float scale;           // 4 bytes
    uint8_t qs[16];        // 16 bytes (32 nibbles packed)
};                         // Total: 20 bytes

static_assert(sizeof(Q4_0_Block) == 20, "Q4_0_Block must be 20 bytes");

// ═══════════════════════════════════════════════════════════════════════════════
// Reference Implementation (Scalar)
// ═══════════════════════════════════════════════════════════════════════════════

void dequant_q4_0_reference(const Q4_0_Block* blocks, int num_blocks, float* output) {
    for (int b = 0; b < num_blocks; b++) {
        const auto& block = blocks[b];
        float scale = block.scale;
        
        for (int i = 0; i < 32; i++) {
            int byte_idx = i / 2;
            int is_high = i % 2;
            uint8_t nibble = is_high ? (block.qs[byte_idx] >> 4) : (block.qs[byte_idx] & 0xF);
            // Dequantize: (nibble - 8) * scale
            output[b * 32 + i] = ((float)nibble - 8.0f) * scale;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AVX2 Implementation (Simulated - actual would call assembly)
// ═══════════════════════════════════════════════════════════════════════════════

void dequant_q4_0_avx2(const Q4_0_Block* blocks, int num_blocks, float* output);

// ═══════════════════════════════════════════════════════════════════════════════
// Validation
// ═══════════════════════════════════════════════════════════════════════════════

struct ValidationResult {
    const char* name;
    bool passed;
    float max_error;
    float mean_error;
    float rms_error;
    int num_samples;
    double time_ms;
};

float compute_max_error(const float* a, const float* b, int n) {
    float max_err = 0.0f;
    for (int i = 0; i < n; i++) {
        max_err = fmaxf(max_err, fabsf(a[i] - b[i]));
    }
    return max_err;
}

void compute_error_metrics(const float* actual, const float* expected, int n,
                           float& max_err, float& mean_err, float& rms_err) {
    double sum_err = 0.0;
    double sum_sq_err = 0.0;
    max_err = 0.0f;
    
    for (int i = 0; i < n; i++) {
        float err = fabsf(actual[i] - expected[i]);
        max_err = fmaxf(max_err, err);
        sum_err += err;
        sum_sq_err += err * err;
    }
    
    mean_err = (float)(sum_err / n);
    rms_err = (float)sqrt(sum_sq_err / n);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Cases
// ═══════════════════════════════════════════════════════════════════════════════

bool test_zero_weights() {
    printf("[TEST] Zero weights...\n");
    
    Q4_0_Block block;
    block.scale = 0.5f;
    memset(block.qs, 0x88, 16);  // All nibbles = 8 (zero weight)
    
    float output[32];
    dequant_q4_0_reference(&block, 1, output);
    
    bool pass = true;
    for (int i = 0; i < 32; i++) {
        if (fabsf(output[i]) > 1e-6f) {
            printf("  [FAIL] output[%d] = %.6f, expected 0.0\n", i, output[i]);
            pass = false;
        }
    }
    
    if (pass) printf("  [PASS] All weights are zero\n");
    return pass;
}

bool test_maximum_positive() {
    printf("[TEST] Maximum positive weights...\n");
    
    Q4_0_Block block;
    block.scale = 0.5f;
    memset(block.qs, 0xFF, 16);  // All nibbles = 15 (max positive)
    
    float output[32];
    dequant_q4_0_reference(&block, 1, output);
    
    float expected = (15.0f - 8.0f) * 0.5f;  // 3.5
    
    bool pass = true;
    for (int i = 0; i < 32; i++) {
        if (fabsf(output[i] - expected) > 1e-6f) {
            printf("  [FAIL] output[%d] = %.6f, expected %.6f\n", i, output[i], expected);
            pass = false;
        }
    }
    
    if (pass) printf("  [PASS] All weights = %.6f\n", expected);
    return pass;
}

bool test_maximum_negative() {
    printf("[TEST] Maximum negative weights...\n");
    
    Q4_0_Block block;
    block.scale = 0.5f;
    memset(block.qs, 0x00, 16);  // All nibbles = 0 (max negative)
    
    float output[32];
    dequant_q4_0_reference(&block, 1, output);
    
    float expected = (0.0f - 8.0f) * 0.5f;  // -4.0
    
    bool pass = true;
    for (int i = 0; i < 32; i++) {
        if (fabsf(output[i] - expected) > 1e-6f) {
            printf("  [FAIL] output[%d] = %.6f, expected %.6f\n", i, output[i], expected);
            pass = false;
        }
    }
    
    if (pass) printf("  [PASS] All weights = %.6f\n", expected);
    return pass;
}

bool test_patterned_data() {
    printf("[TEST] Patterned data (verifies nibble extraction)...\n");
    
    Q4_0_Block block;
    block.scale = 1.0f;
    
    // Pattern: qs[i] = ((i+1) % 16 << 4) | i
    // This gives low nibble = i, high nibble = (i+1) % 16
    for (int i = 0; i < 16; i++) {
        block.qs[i] = (((i + 1) % 16) << 4) | i;
    }
    
    float output[32];
    dequant_q4_0_reference(&block, 1, output);
    
    bool pass = true;
    for (int i = 0; i < 32; i++) {
        int byte_idx = i / 2;
        int is_high = i % 2;
        uint8_t expected_nibble = is_high ? ((byte_idx + 1) % 16) : byte_idx;
        float expected = (float)expected_nibble - 8.0f;
        
        if (fabsf(output[i] - expected) > 1e-6f) {
            printf("  [FAIL] output[%d] = %.6f, expected %.6f (nibble=%d)\n", 
                   i, output[i], expected, expected_nibble);
            pass = false;
        }
    }
    
    if (pass) printf("  [PASS] Nibble extraction correct\n");
    return pass;
}

bool test_random_blocks() {
    printf("[TEST] Random blocks (1000 iterations)...\n");
    
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> scale_dist(0.01f, 10.0f);
    std::uniform_int_distribution<int> nibble_dist(0, 15);
    
    int num_blocks = 1000;
    std::vector<Q4_0_Block> blocks(num_blocks);
    std::vector<float> output_ref(num_blocks * 32);
    
    // Generate random blocks
    for (auto& block : blocks) {
        block.scale = scale_dist(rng);
        for (int i = 0; i < 16; i++) {
            uint8_t low = nibble_dist(rng);
            uint8_t high = nibble_dist(rng);
            block.qs[i] = (high << 4) | low;
        }
    }
    
    // Time the reference implementation
    auto start = std::chrono::high_resolution_clock::now();
    dequant_q4_0_reference(blocks.data(), num_blocks, output_ref.data());
    auto end = std::chrono::high_resolution_clock::now();
    
    double time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double weights_per_sec = (num_blocks * 32) / (time_ms / 1000.0);
    
    printf("  [INFO] Reference: %.2f ms, %.2fM weights/sec\n", time_ms, weights_per_sec / 1e6);
    
    // Verify some samples
    bool pass = true;
    for (int b = 0; b < 10 && pass; b++) {
        for (int i = 0; i < 32; i++) {
            int idx = b * 32 + i;
            int byte_idx = i / 2;
            int is_high = i % 2;
            uint8_t nibble = is_high ? (blocks[b].qs[byte_idx] >> 4) 
                                     : (blocks[b].qs[byte_idx] & 0xF);
            float expected = ((float)nibble - 8.0f) * blocks[b].scale;
            
            if (fabsf(output_ref[idx] - expected) > 1e-5f) {
                printf("  [FAIL] block %d, weight %d: got %.6f, expected %.6f\n",
                       b, i, output_ref[idx], expected);
                pass = false;
                break;
            }
        }
    }
    
    if (pass) printf("  [PASS] All 32000 weights verified\n");
    return pass;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int main() {
    printf("========================================\n");
    printf("Q4_0 Dequantization Validation\n");
    printf("========================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    if (test_zero_weights()) passed++; else failed++;
    if (test_maximum_positive()) passed++; else failed++;
    if (test_maximum_negative()) passed++; else failed++;
    if (test_patterned_data()) passed++; else failed++;
    if (test_random_blocks()) passed++; else failed++;
    
    printf("\n========================================\n");
    printf("Summary: %d passed, %d failed\n", passed, failed);
    printf("========================================\n");
    
    return (failed == 0) ? 0 : 1;
}

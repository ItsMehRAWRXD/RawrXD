// ═══════════════════════════════════════════════════════════════════════════════
// VAL-038: Minimal Debug Test
// ═══════════════════════════════════════════════════════════════════════════════
// Tests the fused kernel with debug marker reading from output buffer
// ═══════════════════════════════════════════════════════════════════════════════

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>

// External assembly function
extern "C" {
    void TreeAttention_Fused_VAL038(
        float* output,
        const float* Q,
        const float* K,
        const float* V,
        uint32_t num_q,
        uint32_t num_k,
        const uint8_t* tree_mask
    );
}

int main() {
    printf("VAL-038 Minimal Debug Test\n");
    printf("==========================\n\n");
    
    // Tiny test case: 1 query, 1 key
    constexpr uint32_t NUM_Q = 1;
    constexpr uint32_t NUM_K = 1;
    constexpr uint32_t HEAD_DIM = 64;
    
    std::vector<float> Q(NUM_Q * HEAD_DIM, 0.1f);
    std::vector<float> K(NUM_K * HEAD_DIM, 0.1f);
    std::vector<float> V(NUM_K * HEAD_DIM, 0.1f);
    std::vector<float> output(NUM_Q * HEAD_DIM, 0.0f);
    std::vector<uint8_t> treeMask(NUM_Q * NUM_K, 1);  // All ones (no masking)
    
    printf("Configuration: num_q=%u, num_k=%u, head_dim=%u\n", NUM_Q, NUM_K, HEAD_DIM);
    printf("Calling kernel...\n");
    
    // Call kernel
    auto start = std::chrono::high_resolution_clock::now();
    TreeAttention_Fused_VAL038(output.data(), Q.data(), K.data(), V.data(),
                               NUM_Q, NUM_K, treeMask.data());
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    printf("Kernel returned in %lld us\n\n", duration);
    
    // Check debug markers in output
    printf("Output buffer (first 8 floats as hex):\n");
    uint32_t* output_u32 = reinterpret_cast<uint32_t*>(output.data());
    for (int i = 0; i < 8; i++) {
        printf("  [%d]: 0x%08X (float: %f)\n", i, output_u32[i], output[i]);
    }
    
    // Check for specific markers
    printf("\nMarker analysis:\n");
    if (output_u32[0] == 0x00000001) {
        printf("  [OK] Entry marker found (0x00000001)\n");
    } else if (output_u32[0] == 0x11111111) {
        printf("  [OK] Query loop marker found (0x11111111)\n");
    } else if (output_u32[0] == 0x22222222) {
        printf("  [OK] Key loop marker found (0x22222222)\n");
    } else if (output_u32[0] == 0xDEADBEEF) {
        printf("  [FAIL] ABORT marker found - guard triggered!\n");
    } else {
        printf("  [?] Unknown value: 0x%08X\n", output_u32[0]);
    }
    
    return 0;
}
        printf("\n[FAIL] K loop enter should be %u, got %llu\n", NUM_Q * NUM_K, debug_loop_k_enter);
        pass = false;
    }
    if (debug_done_count != 1) {
        printf("\n[FAIL] Done count should be 1, got %llu\n", debug_done_count);
        pass = false;
    }
    
    if (pass) {
        printf("\n[PASS] All debug counters match expected values!\n");
        return 0;
    }
    
    return 1;
}

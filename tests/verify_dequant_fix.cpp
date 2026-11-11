// Quick verification test for Q4_0 dequantization fixes
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>

// External assembly function
extern "C" void Dequant_Q4_0_AVX2(void* blocks, uint64_t num_blocks, void* output, float* scale_override);

struct Q4_0_Block {
    float scale;
    uint8_t qs[16];  // 32 nibbles packed
};

int main() {
    printf("=== Q4_0 Dequantization Fix Verification ===\n\n");
    
    // Create test block with known pattern
    Q4_0_Block block;
    block.scale = 0.5f;
    
    // Fill qs with pattern: qs[i] = ((i*2+1) << 4) | (i*2)
    // This gives us nibbles: 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
    for (int i = 0; i < 16; i++) {
        uint8_t low_nibble = i * 2;
        uint8_t high_nibble = i * 2 + 1;
        block.qs[i] = (high_nibble << 4) | low_nibble;
    }
    
    printf("Input Q4_0 block:\n");
    printf("  scale = %.2f\n", block.scale);
    printf("  qs bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", block.qs[i]);
    }
    printf("\n\n");
    
    // Expected weights (dequantized):
    // weight = ((nibble - 8) * scale)
    // For nibble = i*2: weight = ((i*2 - 8) * 0.5) = (i - 4) * 0.5
    // For nibble = i*2+1: weight = ((i*2+1 - 8) * 0.5) = (i - 3.5) * 0.5
    printf("Expected weights:\n");
    for (int i = 0; i < 32; i++) {
        int byte_idx = i / 2;
        int is_high = i % 2;
        uint8_t nibble = is_high ? (block.qs[byte_idx] >> 4) : (block.qs[byte_idx] & 0xF);
        float expected = (nibble - 8) * block.scale;
        printf("  w[%2d] = nibble %2d -> %.3f\n", i, nibble, expected);
    }
    
    // Allocate output buffer
    alignas(32) float output[32] = {0};
    
    // Call the assembly kernel
    Dequant_Q4_0_AVX2(&block, 1, output, nullptr);
    
    printf("\n\nActual output from kernel:\n");
    bool all_correct = true;
    for (int i = 0; i < 32; i++) {
        int byte_idx = i / 2;
        int is_high = i % 2;
        uint8_t nibble = is_high ? (block.qs[byte_idx] >> 4) : (block.qs[byte_idx] & 0xF);
        float expected = (nibble - 8) * block.scale;
        float actual = output[i];
        float diff = fabsf(expected - actual);
        const char* status = (diff < 0.001f) ? "✓" : "✗ FAIL";
        if (diff >= 0.001f) all_correct = false;
        printf("  w[%2d] = %.3f (expected %.3f) %s\n", i, actual, expected, status);
    }
    
    printf("\n=== Result: %s ===\n", all_correct ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    
    return all_correct ? 0 : 1;
}

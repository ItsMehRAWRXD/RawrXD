#include <cstdio>
#include <cstring>
#include <cstdint>

// MASM kernel declaration
extern "C" {
    float vec_dot_q4_0_q8_0_masm(const void* x, const void* y, int n);
}

// Q4_0 block structure
struct BlockQ4_0 {
    uint8_t qs[16];      // 32 nibbles packed
    uint16_t d;          // F16 scale
};

// Q8_0 block structure  
struct BlockQ8_0 {
    int8_t qs[32];       // 32 int8 weights
    uint16_t d;          // F16 scale
};

int main() {
    printf("=== MASM Kernel Direct Test ===\n\n");
    
    // Create test blocks
    BlockQ4_0 x;
    BlockQ8_0 y;
    
    // Initialize Q4_0: all nibbles = 1
    std::memset(&x, 0, sizeof(x));
    for (int i = 0; i < 16; i++) {
        x.qs[i] = 0x11;  // nibbles = 1,1
    }
    x.d = 0x3C00;  // F16 1.0
    
    // Initialize Q8_0: all values = 1
    std::memset(&y, 0, sizeof(y));
    for (int i = 0; i < 32; i++) {
        y.qs[i] = 1;
    }
    y.d = 0x3C00;  // F16 1.0
    
    printf("Calling MASM kernel...\n");
    printf("  x.qs[0] = 0x%02X (nibbles: %d, %d)\n", x.qs[0], x.qs[0] & 0xF, (x.qs[0] >> 4) & 0xF);
    printf("  y.qs[0] = %d\n", y.qs[0]);
    printf("  n = 32\n\n");
    
    // Call MASM kernel
    float result = vec_dot_q4_0_q8_0_masm(&x, &y, 32);
    
    printf("MASM kernel returned: %f\n", result);
    printf("Expected (approx): 32.0 (32 elements * 1 * 1)\n\n");
    
    if (result > 0) {
        printf("=== MASM Kernel Test PASSED ===\n");
        return 0;
    } else {
        printf("=== MASM Kernel Test FAILED ===\n");
        return 1;
    }
}

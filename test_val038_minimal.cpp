// Minimal test for VAL-038 calling convention
#include <cstdio>
#include <cstdint>

// Assembly function declaration
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
    printf("VAL-038 Minimal Test\n");
    printf("====================\n\n");
    
    float output[64] = {0};
    float Q[64] = {0.1f};
    float K[64] = {0.1f};
    float V[64] = {0.1f};
    uint8_t mask[256] = {1};
    
    uint32_t num_q = 16;
    uint32_t num_k = 16;
    
    printf("Calling TreeAttention_Fused_VAL038:\n");
    printf("  output = %p\n", output);
    printf("  Q = %p\n", Q);
    printf("  K = %p\n", K);
    printf("  V = %p\n", V);
    printf("  num_q = %u\n", num_q);
    printf("  num_k = %u\n", num_k);
    printf("  tree_mask = %p\n\n", mask);
    
    TreeAttention_Fused_VAL038(output, Q, K, V, num_q, num_k, mask);
    
    printf("Returned!\n\n");
    
    printf("Output buffer (first 10 values as hex):\n");
    uint32_t* output_u32 = reinterpret_cast<uint32_t*>(output);
    for (int i = 0; i < 10; i++) {
        printf("  [%d]: 0x%08X\n", i, output_u32[i]);
    }
    
    return 0;
}

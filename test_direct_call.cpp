// Direct test of TreeAttention_Fused_VAL038 calling convention
#include <cstdio>
#include <cstdint>
#include <vector>

// Declare the assembly function
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
    printf("Direct Call Test\n");
    printf("==================\n\n");
    
    constexpr uint32_t NUM_Q = 16;
    constexpr uint32_t NUM_K = 16;
    constexpr uint32_t HEAD_DIM = 64;
    
    std::vector<float> Q(NUM_Q * HEAD_DIM, 0.1f);
    std::vector<float> K(NUM_K * HEAD_DIM, 0.1f);
    std::vector<float> V(NUM_K * HEAD_DIM, 0.1f);
    std::vector<float> output(NUM_Q * HEAD_DIM, 0.0f);
    std::vector<uint8_t> treeMask(NUM_Q * NUM_K, 1);
    
    printf("Calling TreeAttention_Fused_VAL038 with:\n");
    printf("  output = %p\n", output.data());
    printf("  Q = %p\n", Q.data());
    printf("  K = %p\n", K.data());
    printf("  V = %p\n", V.data());
    printf("  num_q = %u\n", NUM_Q);
    printf("  num_k = %u\n", NUM_K);
    printf("  tree_mask = %p\n\n", treeMask.data());
    
    TreeAttention_Fused_VAL038(output.data(), Q.data(), K.data(), V.data(),
                               NUM_Q, NUM_K, treeMask.data());
    
    printf("Returned!\n\n");
    
    uint32_t* output_u32 = reinterpret_cast<uint32_t*>(output.data());
    printf("Output[0] = 0x%08X (expected: 0xEEEEEEEE)\n", output_u32[0]);
    printf("Output[1] = 0x%08X (expected: 0x00000010 for num_q=16)\n", output_u32[1]);
    printf("Output[2] = 0x%08X (expected: 0x00000010 for num_k=16)\n", output_u32[2]);
    
    return 0;
}

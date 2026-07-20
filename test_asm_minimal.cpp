#include <cstdio>
#include <cstdint>

// External assembly function
extern "C" void TreeAttention_AVX512(
    const float* Q,
    const float* K,
    const float* V,
    float* output,
    const uint8_t* tree_mask,
    uint32_t num_nodes,
    uint32_t head_dim
);

int main() {
    printf("Test 1: Creating buffers...\n");
    
    float Q[16] = {1.0f};
    float K[16] = {2.0f};
    float V[16] = {3.0f};
    float output[16] = {0.0f};
    uint8_t mask[256] = {0};
    
    printf("Test 2: Calling TreeAttention_AVX512...\n");
    TreeAttention_AVX512(Q, K, V, output, mask, 16, 64);
    printf("Test 3: Returned from TreeAttention_AVX512\n");
    
    printf("Output[0] = %f\n", output[0]);
    
    return 0;
}

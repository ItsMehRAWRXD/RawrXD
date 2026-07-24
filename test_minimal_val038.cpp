// Minimal VAL-038 test - isolate the hang
#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>

// Minimal assembly function
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
    printf("=== Minimal VAL-038 Test ===\n");
    
    // Tiny test case: 1 query, 1 key, 64 head_dim
    constexpr uint32_t HEAD_DIM = 64;
    constexpr uint32_t NUM_Q = 1;
    constexpr uint32_t NUM_K = 1;
    
    std::vector<float> Q(NUM_Q * HEAD_DIM, 0.5f);
    std::vector<float> K(NUM_K * HEAD_DIM, 0.5f);
    std::vector<float> V(NUM_K * HEAD_DIM, 1.0f);
    std::vector<float> output(NUM_Q * HEAD_DIM, 0.0f);
    std::vector<uint8_t> mask(NUM_Q * NUM_K, 1);
    
    printf("Calling kernel with: num_q=%u, num_k=%u, head_dim=%u\n", NUM_Q, NUM_K, HEAD_DIM);
    printf("Output before: %f\n", output[0]);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Call the assembly kernel
    TreeAttention_Fused_VAL038(
        output.data(),
        Q.data(),
        K.data(),
        V.data(),
        NUM_Q,
        NUM_K,
        mask.data()
    );
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("Kernel returned!\n");
    printf("Output after: %f\n", output[0]);
    printf("Time: %lld µs\n", duration);
    
    return 0;
}

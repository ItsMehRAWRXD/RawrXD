// VAL-038: Debug Test - Reads output buffer markers
#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>

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
    printf("VAL-038 Debug Test\n");
    printf("==================\n\n");
    
    constexpr uint32_t NUM_Q = 1;
    constexpr uint32_t NUM_K = 1;
    constexpr uint32_t HEAD_DIM = 64;
    
    std::vector<float> Q(NUM_Q * HEAD_DIM, 0.1f);
    std::vector<float> K(NUM_K * HEAD_DIM, 0.1f);
    std::vector<float> V(NUM_K * HEAD_DIM, 0.1f);
    std::vector<float> output(NUM_Q * HEAD_DIM, 0.0f);
    std::vector<uint8_t> treeMask(NUM_Q * NUM_K, 1);
    
    printf("Config: num_q=%u, num_k=%u, head_dim=%u\n", NUM_Q, NUM_K, HEAD_DIM);
    printf("Calling kernel...\n");
    
    auto start = std::chrono::high_resolution_clock::now();
    TreeAttention_Fused_VAL038(output.data(), Q.data(), K.data(), V.data(),
                               NUM_Q, NUM_K, treeMask.data());
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    printf("Returned in %lld us\n\n", duration);
    
    uint32_t* output_u32 = reinterpret_cast<uint32_t*>(output.data());
    printf("Output[0] = 0x%08X\n", output_u32[0]);
    printf("Output[1] = 0x%08X\n", output_u32[1]);
    
    if (output_u32[0] == 0x00000001) {
        printf("Marker: ENTRY\n");
    } else if (output_u32[0] == 0x11111111) {
        printf("Marker: QUERY LOOP (idx=%u)\n", output_u32[1]);
    } else if (output_u32[0] == 0x22222222) {
        printf("Marker: KEY LOOP (idx=%u)\n", output_u32[1]);
    } else if (output_u32[0] == 0xDEADBEEF) {
        printf("Marker: ABORT (guard triggered)\n");
    } else {
        printf("Marker: UNKNOWN (0x%08X)\n", output_u32[0]);
    }
    
    return 0;
}

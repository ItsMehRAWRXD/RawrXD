// Simple LoRA test - minimal validation
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdint>

extern "C" {
    int ApplyLoRA_Optimized(
        const float* base_output,
        const float* input,
        float* result,
        const void* beacon,
        uint64_t token_count
    );
}

struct LoRABeaconState {
    uint32_t version;
    uint32_t status;
    uint32_t rank;
    uint32_t hidden_dim;
    float* ptr_A;
    float* ptr_B;
    float scale_factor;
    void* next_adapter;
};

int main() {
    printf("Simple LoRA Test\n");
    
    const uint32_t rank = 8;
    const uint32_t hidden_dim = 768;
    
    // Allocate memory
    float* A = (float*)_aligned_malloc(rank * hidden_dim * sizeof(float), 64);
    float* B = (float*)_aligned_malloc(hidden_dim * rank * sizeof(float), 64);
    float* input = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    float* base_output = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    float* result = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    
    if (!A || !B || !input || !base_output || !result) {
        printf("Memory allocation failed\n");
        return 1;
    }
    
    // Initialize
    for (uint32_t i = 0; i < rank * hidden_dim; i++) A[i] = 0.01f;
    for (uint32_t i = 0; i < hidden_dim * rank; i++) B[i] = 0.01f;
    for (uint32_t i = 0; i < hidden_dim; i++) {
        input[i] = 0.1f;
        base_output[i] = 0.5f;
        result[i] = 0.0f;
    }
    
    // Setup beacon
    LoRABeaconState beacon = {};
    beacon.version = 1;
    beacon.status = 1;
    beacon.rank = rank;
    beacon.hidden_dim = hidden_dim;
    beacon.ptr_A = A;
    beacon.ptr_B = B;
    beacon.scale_factor = 1.0f;
    beacon.next_adapter = nullptr;
    
    printf("Calling ApplyLoRA_Optimized...\n");
    printf("Beacon: version=%u, status=%u, rank=%u, hidden_dim=%u\n", 
           beacon.version, beacon.status, beacon.rank, beacon.hidden_dim);
    printf("A=%p, B=%p, scale=%f\n", (void*)beacon.ptr_A, (void*)beacon.ptr_B, beacon.scale_factor);
    
    int ret = ApplyLoRA_Optimized(base_output, input, result, &beacon, 1);
    
    printf("Return value: %d\n", ret);
    printf("base_output[0]: %f\n", base_output[0]);
    printf("input[0]: %f\n", input[0]);
    printf("A[0]: %f, A[1]: %f\n", A[0], A[1]);
    printf("B[0]: %f, B[1]: %f\n", B[0], B[1]);
    printf("Result[0]: %f\n", result[0]);
    printf("Result[100]: %f\n", result[100]);
    printf("Result[500]: %f\n", result[500]);
    
    _aligned_free(A);
    _aligned_free(B);
    _aligned_free(input);
    _aligned_free(base_output);
    _aligned_free(result);
    
    printf("Test complete!\n");
    return 0;
}

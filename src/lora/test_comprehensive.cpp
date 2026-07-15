#include <iostream>
#include <cstdint>

// Tensor structure matching assembly layout
struct TensorDesc {
    uint64_t dims[4];       // Dimensions [d0, d1, d2, d3]
    uint64_t strides[4];    // Strides in elements
    float* data;            // Pointer to float data
    uint64_t elem_count;    // Total element count
    uint32_t flags;         // Ownership/alignment flags
    uint32_t dtype;         // Data type enum
    uint8_t padding[16];    // Pad to 96 bytes
};

// Assembly function declaration
extern "C" int BlockedGemm_Single_Tensor(
    const TensorDesc* A,
    const TensorDesc* B,
    TensorDesc* C
);

int main() {
    std::cout << "Comprehensive BlockedGemm_Single_Tensor test..." << std::endl;
    
    // Test 1: 4x4 matrices
    {
        const int M = 4, N = 4, K = 4;
        float A_data[M * K] = {0};
        float B_data[K * N] = {0};
        float C_data[M * N] = {0};
        
        for (int i = 0; i < M * K; i++) A_data[i] = 2.0f;
        for (int i = 0; i < K * N; i++) B_data[i] = 3.0f;
        
        TensorDesc A = {{M, K, 0, 0}, {K, 1, 0, 0}, A_data, M * K, 0, 0, {0}};
        TensorDesc B = {{K, N, 0, 0}, {N, 1, 0, 0}, B_data, K * N, 0, 0, {0}};
        TensorDesc C = {{M, N, 0, 0}, {N, 1, 0, 0}, C_data, M * N, 0, 0, {0}};
        
        int result = BlockedGemm_Single_Tensor(&A, &B, &C);
        std::cout << "4x4 test: result=" << result << ", C[0]=" << C_data[0] << " (expected: 24.0)" << std::endl;
    }
    
    // Test 2: 16x16 matrices
    {
        const int M = 16, N = 16, K = 16;
        float A_data[M * K] = {0};
        float B_data[K * N] = {0};
        float C_data[M * N] = {0};
        
        for (int i = 0; i < M * K; i++) A_data[i] = 1.0f;
        for (int i = 0; i < K * N; i++) B_data[i] = 1.0f;
        
        TensorDesc A = {{M, K, 0, 0}, {K, 1, 0, 0}, A_data, M * K, 0, 0, {0}};
        TensorDesc B = {{K, N, 0, 0}, {N, 1, 0, 0}, B_data, K * N, 0, 0, {0}};
        TensorDesc C = {{M, N, 0, 0}, {N, 1, 0, 0}, C_data, M * N, 0, 0, {0}};
        
        int result = BlockedGemm_Single_Tensor(&A, &B, &C);
        std::cout << "16x16 test: result=" << result << ", C[0]=" << C_data[0] << " (expected: 16.0)" << std::endl;
    }
    
    std::cout << "Comprehensive test completed!" << std::endl;
    return 0;
}
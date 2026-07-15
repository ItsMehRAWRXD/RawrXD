#include <iostream>
#include <cstdint>
#include <cstring>

// Tensor descriptor structure
struct TensorDesc {
    uint64_t dims[4];       // Dimensions [d0, d1, d2, d3]
    uint64_t strides[4];    // Strides in elements
    float* data;            // Pointer to float data
    uint64_t elem_count;    // Total element count
    uint32_t flags;         // Ownership/alignment flags
    uint32_t dtype;         // Data type enum
    uint8_t padding[16];    // Pad to 96 bytes
};

// Forward declaration of our assembly function
extern "C" int BlockedGemm_Single_Tensor(
    const TensorDesc* A,
    const TensorDesc* B,
    TensorDesc* C
);

int main() {
    std::cout << "Testing BlockedGemm_Single_Tensor assembly bridge..." << std::endl;
    
    // Create simple test matrices
    const int M = 8, N = 8, K = 8;
    float A_data[M * K] = {0};
    float B_data[K * N] = {0};
    float C_data[M * N] = {0};
    
    // Initialize with simple values
    for (int i = 0; i < M * K; i++) A_data[i] = 1.0f;
    for (int i = 0; i < K * N; i++) B_data[i] = 1.0f;
    
    // Create tensor descriptors
    TensorDesc A_tensor = {0};
    TensorDesc B_tensor = {0};
    TensorDesc C_tensor = {0};
    
    A_tensor.dims[0] = M;
    A_tensor.dims[1] = K;
    A_tensor.strides[0] = K;
    A_tensor.strides[1] = 1;
    A_tensor.data = A_data;
    A_tensor.elem_count = M * K;
    
    B_tensor.dims[0] = K;
    B_tensor.dims[1] = N;
    B_tensor.strides[0] = N;
    B_tensor.strides[1] = 1;
    B_tensor.data = B_data;
    B_tensor.elem_count = K * N;
    
    C_tensor.dims[0] = M;
    C_tensor.dims[1] = N;
    C_tensor.strides[0] = N;
    C_tensor.strides[1] = 1;
    C_tensor.data = C_data;
    C_tensor.elem_count = M * N;
    
    // Call our assembly function
    int result = BlockedGemm_Single_Tensor(&A_tensor, &B_tensor, &C_tensor);
    
    if (result != 0) {
        std::cout << "BlockedGemm_Single_Tensor failed with error: " << result << std::endl;
        return result;
    }
    
    std::cout << "BlockedGemm_Single_Tensor test completed successfully!" << std::endl;
    
    // Check result - should be 8.0 for each element (8 ones summed)
    std::cout << "Result matrix C[0] = " << C_data[0] << " (expected: 8.0)" << std::endl;
    
    // Check a few more elements
    for (int i = 0; i < 5; i++) {
        std::cout << "C[" << i << "] = " << C_data[i] << std::endl;
    }
    
    return 0;
}
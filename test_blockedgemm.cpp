// ============================================================================
// test_blockedgemm.cpp - Test BlockedGemm_Single interface
// ============================================================================
#include <iostream>
#include <cstdint>

// Tensor descriptor structure (matches assembly layout)
struct TensorDesc {
    int64_t dims[4];     // Dimensions
    int64_t strides[4];  // Strides
    float* data;         // Data pointer
    int64_t elem_count;  // Total elements
    int32_t flags;       // Flags
    int32_t dtype;       // Data type
    char padding[16];    // Padding to 64 bytes
};

// External assembly function
extern "C" int BlockedGemm_Single(
    TensorDesc* A,
    TensorDesc* B,
    TensorDesc* C
);

int main() {
    std::cout << "Testing BlockedGemm_Single interface..." << std::endl;
    
    // Create test tensors
    TensorDesc A, B, C;
    
    // Initialize dimensions
    A.dims[0] = 128; // M
    A.dims[1] = 256; // K
    B.dims[0] = 256; // K  
    B.dims[1] = 128; // N
    C.dims[0] = 128; // M
    C.dims[1] = 128; // N
    
    // Initialize other fields
    A.elem_count = A.dims[0] * A.dims[1];
    B.elem_count = B.dims[0] * B.dims[1];
    C.elem_count = C.dims[0] * C.dims[1];
    
    // Allocate and initialize data
    A.data = new float[A.elem_count];
    B.data = new float[B.elem_count];
    C.data = new float[C.elem_count];
    
    // Debug: check data pointer offsets
    std::cout << "A.data pointer: " << A.data << std::endl;
    std::cout << "A.data offset: " << (int64_t)((char*)极A.data - (char*)极A) << std::endl;
    
    // Initialize with some test data
    for (int64_t i = 0; i < A.elem_count; i++) A.data[i] = 1.0f;
    for (int64_t i = 0; i < B.elem_count; i++) B.data[i] = 2.0f;
    for (int64_t i = 0; i < C.elem_count; i++) C.data[i] = 0.0f;
    
    std::cout << "Tensor dimensions:" << std::endl;
    std::cout << "A: " << A.dims[0] << " x " << A.dims[1] << std::endl;
    std::cout << "B: " << B.dims[0] << " x " << B.dims[1] << std::endl;
    std::cout << "C: " << C.dims[0] << " x " << C.dims[1] << std::endl;
    
    // Test calling the assembly function
    int result = BlockedGemm_Single(&A, &B, &C);
    
    std::cout << "BlockedGemm_Single returned: " << result << std::endl;
    
    if (result == 0) {
        std::cout << "SUCCESS: Interface is working correctly!" << std::endl;
    } else {
        std::cout << "ERROR: Function returned error code " << result << std::endl;
    }
    
    return 0;
}
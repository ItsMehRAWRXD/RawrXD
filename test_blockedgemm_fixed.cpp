// ============================================================================
// test_blockedgemm_fixed.cpp - Test BlockedGemm_Single interface
// ============================================================================
#include <iostream>
#include <cstdint>

// Tensor descriptor structure (matches assembly layout)
struct TensorDesc {
    int64_t dims[4];     // Dimensions (offset 0-31)
    int64_t strides[4];  // Strides (offset 32-63)
    float* data;         // Data pointer (offset 64)
    int64_t elem_count;  // Total elements (offset 72)
    int32_t flags;       // Flags (offset 80)
    int32_t dtype;       // Data type (offset 84)
    char padding[16];    // Padding to 64 bytes (offset 88-151)
};

// External assembly function
extern "C" int BlockedGemm_Single_Tensor(
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
    
    // Initialize with some test data
    for (int64_t i = 0; i < A.elem_count; i++) A.data[i] = 1.0f;
    for (int64_t i = 0; i < B.elem_count; i++) B.data[i] = 2.0f;
    for (int64_t i = 0; i < C.elem_count; i++) C.data[i] = 0.0f;
    
    std::cout << "Tensor dimensions:" << std::endl;
    std::cout << "A: " << A.dims[0] << " x " << A.dims[1] << std::endl;
    std::cout << "B: " << B.dims[0] << " x " << B.dims[1] << std::endl;
    std::cout << "C: " << C.dims[0] << " x " << C.dims[1] << std::endl;
    
    // Debug: check data pointer offsets
    std::cout << "A.data pointer: " << A.data << std::endl;
    std::cout << "A.data offset: " << (int64_t)((char*)&A.data - (char*)&A) << std::endl;
    
    // Test calling the assembly function
    int result = BlockedGemm_Single_Tensor(&A, &B, &C);
    
    std::cout << "BlockedGemm_Single_Tensor returned: " << result << std::endl;
    
    if (result == 0) {
        std::cout << "SUCCESS: Interface is working correctly!" << std::endl;
        
        // Check if output tensor was modified
        std::cout << "Output tensor first element: " << C.data[0] << std::endl;
        std::cout << "Output tensor last element: " << C.data[C.elem_count - 1] << std::endl;
    } else {
        std::cout << "ERROR: Function returned error code " << result << std::endl;
        
        // Debug: check what the assembly function is seeing
        std::cout << "Debug - Tensor A data pointer: " << A.data << std::endl;
        std::cout << "Debug - Tensor B data pointer: " << B.data << std::endl;
        std::cout << "Debug - Tensor C data pointer: " << C.data << std::endl;
        std::cout << "Debug - Tensor A dims[0]: " << A.dims[0] << std::endl;
        std::cout << "Debug - Tensor A dims[1]: " << A.dims[1] << std::endl;
        std::cout << "Debug - Tensor B dims[0]: " << B.dims[0] << std::endl;
        std::cout << "Debug - Tensor B dims[1]: " << B.dims[1] << std::endl;
        std::cout << "Debug - Tensor C dims[0]: " << C.dims[0] << std::endl;
        std::cout << "Debug - Tensor C dims[1]: " << C.dims[1] << std::endl;
    }
    
    // Clean up
    delete[] A.data;
    delete[] B.data;
    delete[] C.data;
    
    return 0;
}
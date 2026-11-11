// ============================================================================
// direct_test.cpp - Direct microkernel test
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "src/lora/BlockedGemm.hpp"

int main() {
    printf("Direct microkernel test...\n");
    
    // Test case: 2x2 identity multiplication
    // A = [[1, 0], [0, 1]] (packed)
    // B = [[1, 0], [0, 1]]
    // Expected: C = [[1, 0], [0, 1]]
    
    float A_packed[2*2] = {1.0f, 0.0f,   // A[0,0], A[1,0]
                            0.0f, 1.0f};  // A[0,1], A[1,1]
    
    float B[2*2] = {1.0f, 0.0f,           // B[0,0], B[0,1]
                    0.0f, 1.0f};          // B[1,0], B[1,1]
    
    float C[2*2] = {0};  // Zero initialize
    
    printf("Calling microkernel with identity matrices...\n");
    int result = Gemm_8x8_Microkernel(A_packed, B, C, 2, 2);
    
    printf("Result: %d\n", result);
    printf("C matrix:\n");
    printf("  [%.1f, %.1f]\n", C[0], C[1]);
    printf("  [%.1f, %.1f]\n", C[2], C[3]);
    
    // Should be identity matrix
    if (C[0] == 1.0f && C[1] == 0.0f && C[2] == 0.0f && C[3] == 1.0f) {
        printf("SUCCESS: Identity test passed!\n");
    } else {
        printf("FAIL: Identity test failed!\n");
    }
    
    return 0;
}
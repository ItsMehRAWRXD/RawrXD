// ============================================================================
// minimal_test.cpp - Minimal microkernel test
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "src/lora/BlockedGemm.hpp"

int main() {
    printf("Minimal microkernel test...\n");
    
    // Simple 2x2x2 test case
    float A_packed[2*2] = {1.0f, 2.0f,  // A[0,0], A[1,0]
                           1.0f, 2.0f}; // A[0,1], A[1,1]
    
    // B packed as K×8: for K=2, we need 2×8 = 16 elements
    // But we only use first 2 columns, rest are zero-padded
    float B_packed[2*8] = {1.0f, 2.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f,  // K=0
                           3.0f, 4.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f}; // K=1
    
    float C[2*2] = {0};  // Zero initialize
    
    printf("Calling microkernel with K=2, ldc=2...\n");
    int result = Gemm_8x8_Microkernel(A_packed, B_packed, C, 2, 2);
    
    printf("Result: %d\n", result);
    printf("C matrix:\n");
    printf("  [%.1f, %.1f]\n", C[0], C[1]);
    printf("  [%.1f, %.1f]\n", C[2], C[3]);
    
    // Expected: C = A × B
    // A = [[1, 1], [2, 2]] (but packed as column-major for rows)
    // B = [[1, 2], [3, 4]]
    // C[0,0] = 1*1 + 1*3 = 4
    // C[0,1] = 1*2 + 1*4 = 6
    // C[1,0] = 2*1 + 2*3 = 8  
    // C[1,1] = 2*2 + 2*4 = 12
    
    printf("Expected:\n");
    printf("  [4.0, 6.0]\n");
    printf("  [8.0, 12.0]\n");
    
    return 0;
}
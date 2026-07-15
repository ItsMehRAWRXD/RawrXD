// ============================================================================
// debug_rax.cpp - Debug the rax value in microkernel
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "src/lora/BlockedGemm.hpp"

// Modified microkernel with debug output
int main() {
    printf("Testing microkernel with debug...\n");
    
    // Very simple test
    float A_packed[8*8] = {0};
    float B[8*8] = {0};
    float C[8*8] = {0};
    
    // Initialize with simple values
    for (int i = 0; i < 8*8; i++) {
        A_packed[i] = 1.0f;
        B[i] = 1.0f;
    }
    
    // Zero C
    for (int i = 0; i < 8*8; i++) C[i] = 0.0f;
    
    printf("About to call microkernel...\n");
    
    // Call microkernel
    int result = Gemm_8x8_Microkernel(A_packed, B, C, 8, 8);
    
    printf("Microkernel returned: %d\n", result);
    
    // Check individual elements
    printf("C[0,0]: %f\n", C[0]);
    printf("C[1,0]: %f\n", C[8]);   // Row 1, Col 0
    printf("C[1,1]: %f\n", C[9]);   // Row 1, Col 1
    printf("C[1,7]: %f\n", C[15]);  // Row 1, Col 7
    printf("C[2,0]: %f\n", C[16]);  // Row 2, Col 0
    
    return 0;
}
// ============================================================================
// debug_accumulators.cpp - Debug microkernel accumulators
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "src/lora/BlockedGemm.hpp"

// Simple test to debug accumulator values
int main() {
    printf("Testing microkernel accumulators...\n");
    
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
    printf("C matrix:\n");
    for (int m = 0; m < 8; m++) {
        for (int n = 0; n < 8; n++) {
            printf("%6.1f ", C[m*8 + n]);
        }
        printf("\n");
    }
    
    // Test individual rows
    printf("\nTesting individual row computation...\n");
    
    // Row 0 should be sum of B rows
    float row0_sum = 0.0f;
    for (int k = 0; k < 8; k++) {
        for (int n = 0; n < 8; n++) {
            row0_sum += B[k*8 + n];
        }
    }
    printf("Expected row 0 sum: %.1f\n", row0_sum);
    printf("Actual row 0 sum: %.1f\n", C[0] + C[1] + C[2] + C[3] + C[4] + C[5] + C[6] + C[7]);
    
    return 0;
}
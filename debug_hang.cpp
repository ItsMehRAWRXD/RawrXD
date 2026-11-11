// ============================================================================
// debug_hang.cpp - Debug hanging microkernel
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "src/lora/BlockedGemm.hpp"

// Simple test to see if microkernel hangs
int main() {
    printf("Testing microkernel call...\n");
    
    // Very simple test
    float A_packed[8*8] = {0};
    float B[8*8] = {0};
    float C[8*8] = {0};
    
    // Initialize with simple values
    for (int i = 0; i < 8*8; i++) {
        A_packed[i] = 1.0f;
        B[i] = 1.0f;
    }
    
    printf("About to call microkernel...\n");
    fflush(stdout);
    
    // Call microkernel
    int result = Gemm_8x8_Microkernel(A_packed, B, C, 8, 8);
    
    printf("Microkernel returned: %d\n", result);
    printf("First element of C: %f\n", C[0]);
    
    return 0;
}
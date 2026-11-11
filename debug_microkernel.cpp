// ============================================================================
// debug_microkernel.cpp - Debug the 8x8 microkernel
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>
#include "src/lora/BlockedGemm.hpp"

int main() {
    printf("Testing 8x8 microkernel directly...\n");
    
    // Simple 8x8x8 test
    float A[8*8] = {0};
    float B[8*8] = {0};
    float C_ref[8*8] = {0};
    float C_micro[8*8] = {0};
    
    // Initialize with simple pattern
    for (int i = 0; i < 8*8; i++) {
        A[i] = (i % 8) + 1.0f;
        B[i] = (i / 8) + 1.0f;
    }
    
    // Reference computation
    for (int m = 0; m < 8; m++) {
        for (int n = 0; n < 8; n++) {
            float acc = 0.0f;
            for (int k = 0; k < 8; k++) {
                acc += A[m*8 + k] * B[k*8 + n];
            }
            C_ref[m*8 + n] = acc;
        }
    }
    
    // Pack A for microkernel
    float A_packed[8*8] = {0};
    for (int k = 0; k < 8; k++) {
        for (int m = 0; m < 8; m++) {
            A_packed[k*8 + m] = A[m*8 + k];
        }
    }
    
    // Call microkernel (it accumulates into existing C, so zero first)
    printf("Calling Gemm_8x8_Microkernel...\n");
    for (int i = 0; i < 8*8; i++) C_micro[i] = 0.0f;
    Gemm_8x8_Microkernel(A_packed, B, C_micro, 8, 8);
    
    // Compare
    printf("Reference result:\n");
    for (int m = 0; m < 8; m++) {
        for (int n = 0; n < 8; n++) {
            printf("%6.1f ", C_ref[m*8 + n]);
        }
        printf("\n");
    }
    
    printf("Microkernel result:\n");
    for (int m = 0; m < 8; m++) {
        for (int n = 0; n < 8; n++) {
            printf("%6.1f ", C_micro[m*8 + n]);
        }
        printf("\n");
    }
    
    return 0;
}
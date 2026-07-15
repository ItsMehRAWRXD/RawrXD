// ============================================================================
// test_minimal.cpp - Minimal RMSNorm test
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// External MASM kernel
extern "C" void RMSNorm_Minimal(
    const float* x, 
    const float* weight, 
    float* out, 
    float epsilon, 
    size_t dim
);

int main() {
    printf("Testing Minimal RMSNorm...\n");
    
    // Simple test case
    const size_t dim = 8;
    const float epsilon = 1e-6f;
    
    float x[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float out[8] = {0};
    
    printf("About to call RMSNorm_Minimal...\n");
    fflush(stdout);
    
    // Call the kernel
    RMSNorm_Minimal(x, weight, out, epsilon, dim);
    
    printf("RMSNorm_Minimal completed. First element: 0x%08X\n", *(int*)&out[0]);
    
    return 0;
}
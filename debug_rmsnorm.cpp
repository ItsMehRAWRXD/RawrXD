// ============================================================================
// debug_rmsnorm.cpp - Debug RMSNorm Kernel
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// External MASM kernel
extern "C" void RMSNorm_Kernel(
    const float* x, 
    const float* weight, 
    float* out, 
    float epsilon, 
    size_t dim
);

int main() {
    printf("Debugging RMSNorm Kernel...\n");
    
    // Simple test case
    const size_t dim = 8;
    const float epsilon = 1e-6f;
    
    float x[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float out[8] = {0};
    
    printf("About to call RMSNorm_Kernel...\n");
    fflush(stdout);
    
    // Call the kernel
    RMSNorm_Kernel(x, weight, out, epsilon, dim);
    
    printf("RMSNorm completed. Results:\n");
    for (size_t i = 0; i < dim; i++) {
        printf("  out[%zu] = %f\n", i, out[i]);
    }
    
    return 0;
}
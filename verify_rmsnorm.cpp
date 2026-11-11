// ============================================================================
// verify_rmsnorm.cpp - Verify RMSNorm results
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>

// External MASM kernel
extern "C" void RMSNorm_Kernel(
    const float* x, 
    const float* weight, 
    float* out, 
    float epsilon, 
    size_t dim
);

// Reference RMSNorm implementation
void ReferenceRMSNorm(const float* x, const float* weight, float* out, float epsilon, size_t dim) {
    // Calculate sum of squares
    float sum_sq = 0.0f;
    for (size_t i = 0; i < dim; i++) {
        sum_sq += x[i] * x[i];
    }
    
    // Calculate RMS scale factor
    float rms = std::sqrt(sum_sq / dim + epsilon);
    float scale = 1.0f / rms;
    
    // Apply normalization and scaling
    for (size_t i = 0; i < dim; i++) {
        out[i] = x[i] * scale * weight[i];
    }
}

int main() {
    printf("Verifying RMSNorm Kernel...\n");
    
    // Test case
    const size_t dim = 8;
    const float epsilon = 1e-6f;
    
    float x[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float out_asm[8] = {0};
    float out_ref[8] = {0};
    
    // ASM kernel computation
    RMSNorm_Kernel(x, weight, out_asm, epsilon, dim);
    
    // Reference computation
    ReferenceRMSNorm(x, weight, out_ref, epsilon, dim);
    
    printf("ASM Results:\n");
    for (size_t i = 0; i < dim; i++) {
        printf("  out_asm[%zu] = %.6f\n", i, out_asm[i]);
    }
    
    printf("\nReference Results:\n");
    for (size_t i = 0; i < dim; i++) {
        printf("  out_ref[%zu] = %.6f\n", i, out_ref[i]);
    }
    
    printf("\nDifferences:\n");
    for (size_t i = 0; i < dim; i++) {
        float diff = std::abs(out_asm[i] - out_ref[i]);
        printf("  diff[%zu] = %.6f\n", i, diff);
    }
    
    return 0;
}
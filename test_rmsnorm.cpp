// ============================================================================
// test_rmsnorm.cpp - RMSNorm Kernel Test
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>
#include <vector>

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

bool compare_vectors(const float* a, const float* b, size_t dim, float tolerance = 0.001f) {
    for (size_t i = 0; i < dim; i++) {
        if (std::abs(a[i] - b[i]) > tolerance) {
            printf("Mismatch at [%zu]: got %.6f, expected %.6f (diff=%.6f)\n", 
                   i, a[i], b[i], std::abs(a[i] - b[i]));
            return false;
        }
    }
    return true;
}

int main() {
    printf("Testing RMSNorm Kernel...\n");
    
    // Test dimensions (must be multiple of 8 for AVX)
    const size_t dim = 32;
    const float epsilon = 1e-6f;
    
    // Allocate memory
    std::vector<float> x(dim);
    std::vector<float> weight(dim);
    std::vector<float> out_ref(dim);
    std::vector<float> out_asm(dim);
    
    // Initialize with test pattern
    for (size_t i = 0; i < dim; i++) {
        x[i] = (i % 8) + 1.0f;  // Pattern: 1,2,3,4,5,6,7,8,1,2,3,...
        weight[i] = 1.0f + (i % 3) * 0.1f;  // Pattern: 1.0, 1.1, 1.2, 1.0, 1.1, ...
    }
    
    // Reference computation
    ReferenceRMSNorm(x.data(), weight.data(), out_ref.data(), epsilon, dim);
    
    // ASM kernel computation
    RMSNorm_Kernel(x.data(), weight.data(), out_asm.data(), epsilon, dim);
    
    // Compare results
    bool pass = compare_vectors(out_asm.data(), out_ref.data(), dim);
    
    if (pass) {
        printf("RMSNorm Kernel: PASS ✓\n");
        
        // Show first few elements
        printf("First 8 elements:\n");
        for (size_t i = 0; i < 8; i++) {
            printf("  [%zu]: ref=%.6f, asm=%.6f\n", i, out_ref[i], out_asm[i]);
        }
    } else {
        printf("RMSNorm Kernel: FAIL ✗\n");
    }
    
    return pass ? 0 : 1;
}
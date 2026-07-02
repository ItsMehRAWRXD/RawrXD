// =============================================================================
// test_kernel_bridge.cpp
// "Hello World" kernel integration test
// Verifies C++ to MASM calling convention before full transformer wiring
// =============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

// Include the kernel declarations from rawrxd_kernels.h
extern "C" {
    // Simplest kernel to test: Dequantize Q4_0 blocks
    // void DequantQ4_0_AVX2(void* src, uint16_t* dst, size_t blocks);
    
    // RMSNorm: float* x, float* weight, int size, float eps
    void RMSNorm_AVX512(float* x, float* weight, int size, float eps);
    
    // MatMul: y = x @ W
    void MatMul_F16_AVX512(float* y, const float* x, const float* w, int n, int d);
}

// =============================================================================
// Test 1: RMSNorm Sanity Check
// =============================================================================
bool Test_RMSNorm() {
    printf("[Test] RMSNorm_AVX512...\n");
    
    const int size = 64;  // Must be multiple of 16 for AVX-512
    float input[size];
    float weight[size];
    float output[size];
    
    // Initialize with known values
    for (int i = 0; i < size; i++) {
        input[i] = 1.0f;   // All ones
        weight[i] = 1.0f;  // All ones (no scaling)
        output[i] = 0.0f;  // Clear output
    }
    
    // Copy input to output (RMSNorm is in-place)
    memcpy(output, input, sizeof(input));
    
    // Call the kernel
    // RMSNorm: x = x / sqrt(mean(x^2) + eps) * weight
    // With all ones: mean(x^2) = 1, sqrt(1 + eps) ≈ 1, so x stays ~1
    RMSNorm_AVX512(output, weight, size, 1e-6f);
    
    // Verify output is reasonable (should be close to 1.0)
    bool pass = true;
    for (int i = 0; i < size; i++) {
        if (std::abs(output[i] - 1.0f) > 0.01f) {
            printf("[Test] FAIL: output[%d] = %f (expected ~1.0)\n", i, output[i]);
            pass = false;
            break;
        }
    }
    
    if (pass) {
        printf("[Test] RMSNorm_AVX512: PASS ✓\n");
    }
    return pass;
}

// =============================================================================
// Test 2: MatMul Sanity Check
// =============================================================================
bool Test_MatMul() {
    printf("[Test] MatMul_F16_AVX512...\n");
    
    // Simple case: identity-like multiplication
    // y[4] = x[8] @ W[8x4]
    const int n = 8;   // input dim
    const int d = 4;   // output dim
    
    float x[8] = {1, 0, 0, 0, 0, 0, 0, 0};  // One-hot
    float W[8*4];  // 8x4 matrix
    float y[4] = {0, 0, 0, 0};
    
    // Initialize W as identity (first row = [1, 0, 0, 0])
    memset(W, 0, sizeof(W));
    for (int i = 0; i < 4; i++) {
        W[i * 8 + i] = 1.0f;  // Diagonal = 1
    }
    
    // Call the kernel
    MatMul_F16_AVX512(y, x, W, n, d);
    
    // With identity matrix and one-hot input, output should be [1, 0, 0, 0]
    bool pass = true;
    if (std::abs(y[0] - 1.0f) > 0.01f) {
        printf("[Test] FAIL: y[0] = %f (expected 1.0)\n", y[0]);
        pass = false;
    }
    for (int i = 1; i < 4; i++) {
        if (std::abs(y[i]) > 0.01f) {
            printf("[Test] FAIL: y[%d] = %f (expected 0.0)\n", i, y[i]);
            pass = false;
        }
    }
    
    if (pass) {
        printf("[Test] MatMul_F16_AVX512: PASS ✓\n");
    }
    return pass;
}

// =============================================================================
// Main Entry
// =============================================================================
int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("RawrXD Kernel Bridge Test\n");
    printf("Verifying C++ to MASM calling convention\n");
    printf("=================================================================\n\n");
    
    int passed = 0;
    int total = 0;
    
    // Test 1: RMSNorm
    total++;
    if (Test_RMSNorm()) passed++;
    printf("\n");
    
    // Test 2: MatMul
    total++;
    if (Test_MatMul()) passed++;
    printf("\n");
    
    // Summary
    printf("=================================================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("=================================================================\n");
    
    if (passed == total) {
        printf("\n✓ Kernel bridge is SOLID. Ready for full integration.\n");
        return 0;
    } else {
        printf("\n✗ Kernel bridge has issues. Check calling convention.\n");
        return 1;
    }
}

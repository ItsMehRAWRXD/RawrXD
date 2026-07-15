// LoRA_Kernel Test Harness
// test_lora_kernel.cpp

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>

// External MASM function
extern "C" void ApplyLoRA_VectorAdd(float* a, float* b, float* dest, size_t count);

// Aligned memory allocator
template<typename T>
T* aligned_alloc(size_t count, size_t alignment = 32) {
    void* ptr = _aligned_malloc(count * sizeof(T), alignment);
    return static_cast<T*>(ptr);
}

void aligned_free(void* ptr) {
    _aligned_free(ptr);
}

// Verify results
bool verify_results(float* a, float* b, float* dest, size_t count) {
    for (size_t i = 0; i < count; i++) {
        float expected = a[i] + b[i];
        if (dest[i] != expected) {
            printf("  Mismatch at index %zu: got %f, expected %f\n", i, dest[i], expected);
            return false;
        }
    }
    return true;
}

int main() {
    printf("========================================\n");
    printf("LoRA_Kernel Test Harness\n");
    printf("========================================\n\n");
    
    // Test 1: Small count (remainder path)
    printf("[Test 1] Small count (5 elements)...\n");
    {
        float* a = aligned_alloc<float>(5);
        float* b = aligned_alloc<float>(5);
        float* dest = aligned_alloc<float>(5);
        
        for (int i = 0; i < 5; i++) {
            a[i] = (float)i;
            b[i] = (float)(i * 2);
            dest[i] = 0.0f;
        }
        
        ApplyLoRA_VectorAdd(a, b, dest, 5);
        
        bool pass = verify_results(a, b, dest, 5);
        printf("  Result: %s\n\n", pass ? "PASS ✓" : "FAIL ✗");
        
        aligned_free(a);
        aligned_free(b);
        aligned_free(dest);
        
        if (!pass) return 1;
    }
    
    // Test 2: Exact multiple of 8 (AVX path only)
    printf("[Test 2] Exact multiple of 8 (16 elements)...\n");
    {
        float* a = aligned_alloc<float>(16);
        float* b = aligned_alloc<float>(16);
        float* dest = aligned_alloc<float>(16);
        
        for (int i = 0; i < 16; i++) {
            a[i] = (float)i * 0.5f;
            b[i] = (float)i * 0.25f;
            dest[i] = 0.0f;
        }
        
        ApplyLoRA_VectorAdd(a, b, dest, 16);
        
        bool pass = verify_results(a, b, dest, 16);
        printf("  Result: %s\n\n", pass ? "PASS ✓" : "FAIL ✗");
        
        aligned_free(a);
        aligned_free(b);
        aligned_free(dest);
        
        if (!pass) return 1;
    }
    
    // Test 3: Large count (AVX + remainder)
    printf("[Test 3] Large count (1000 elements)...\n");
    {
        float* a = aligned_alloc<float>(1000);
        float* b = aligned_alloc<float>(1000);
        float* dest = aligned_alloc<float>(1000);
        
        for (int i = 0; i < 1000; i++) {
            a[i] = (float)i * 0.01f;
            b[i] = (float)(999 - i) * 0.01f;
            dest[i] = 0.0f;
        }
        
        // Time the kernel
        uint64_t start = __rdtsc();
        ApplyLoRA_VectorAdd(a, b, dest, 1000);
        uint64_t end = __rdtsc();
        
        bool pass = verify_results(a, b, dest, 1000);
        printf("  Result: %s\n", pass ? "PASS ✓" : "FAIL ✗");
        printf("  Cycles: %llu\n", end - start);
        printf("  Cycles/element: %.2f\n\n", (double)(end - start) / 1000.0);
        
        aligned_free(a);
        aligned_free(b);
        aligned_free(dest);
        
        if (!pass) return 1;
    }
    
    // Test 4: Edge case - count = 0
    printf("[Test 4] Edge case (0 elements)...\n");
    {
        float dummy = 0.0f;
        ApplyLoRA_VectorAdd(&dummy, &dummy, &dummy, 0);
        printf("  Result: PASS ✓ (no crash)\n\n");
    }
    
    // Test 5: Edge case - count = 8 (single AVX iteration)
    printf("[Test 5] Edge case (8 elements)...\n");
    {
        float* a = aligned_alloc<float>(8);
        float* b = aligned_alloc<float>(8);
        float* dest = aligned_alloc<float>(8);
        
        for (int i = 0; i < 8; i++) {
            a[i] = 1.0f;
            b[i] = 2.0f;
            dest[i] = 0.0f;
        }
        
        ApplyLoRA_VectorAdd(a, b, dest, 8);
        
        bool pass = true;
        for (int i = 0; i < 8; i++) {
            if (dest[i] != 3.0f) {
                pass = false;
                break;
            }
        }
        printf("  Result: %s\n\n", pass ? "PASS ✓" : "FAIL ✗");
        
        aligned_free(a);
        aligned_free(b);
        aligned_free(dest);
        
        if (!pass) return 1;
    }
    
    printf("========================================\n");
    printf("All Tests PASSED\n");
    printf("========================================\n");
    
    return 0;
}

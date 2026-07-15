// ============================================================================
// test_tensor_standalone.cpp - Standalone Tensor Test (No GEMM dependency)
// ============================================================================
// Tests the MASM tensor abstraction in isolation
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

// MASM function declarations
extern "C" {
    // Arena
    struct Arena {
        unsigned long long base;
        unsigned long long current;
        unsigned long long capacity;
        unsigned long long allocated;
        unsigned long long _reserved[4];
    };
    int Arena_Init(Arena* arena, size_t capacity);
    void* Arena_Alloc(Arena* arena, size_t bytes);
    void Arena_Reset(Arena* arena);
    void Arena_Free(Arena* arena);
    
    // Tensor
    struct Tensor {
        unsigned long long dims[4];
        unsigned long long strides[4];
        unsigned long long data;
        unsigned long long elem_count;  // Renamed from 'size' to match MASM
        unsigned int flags;
        unsigned int dtype;
        unsigned long long _padding[2];
    };
    int Tensor_Init(Tensor* tensor, float* data, size_t dim0, size_t dim1, size_t dim2 = 0, size_t dim3 = 0);
    int Tensor_Alloc(Tensor* tensor, Arena* arena, size_t dim0, size_t dim1, size_t dim2 = 0, size_t dim3 = 0);
    float* Tensor_GetElement(Tensor* tensor, size_t i0, size_t i1, size_t i2 = 0, size_t i3 = 0);
    void Tensor_Zero(Tensor* tensor);
}

// Aligned allocation helper
float* aligned_alloc_float(size_t count) {
    void* ptr = nullptr;
    #ifdef _WIN32
    ptr = _aligned_malloc(count * sizeof(float), 32);
    #else
    posix_memalign(&ptr, 32, count * sizeof(float));
    #endif
    return static_cast<float*>(ptr);
}

void aligned_free_float(float* ptr) {
    #ifdef _WIN32
    _aligned_free(ptr);
    #else
    free(ptr);
    #endif
}

// ============================================================================
// Test 1: Arena Allocator
// ============================================================================
bool test_arena_allocator() {
    printf("[Test 1] Arena Allocator... ");
    
    Arena arena;
    int result = Arena_Init(&arena, 1024 * 1024); // 1MB
    if (result != 0) {
        printf("FAIL - Arena_Init returned %d\n", result);
        return false;
    }
    
    // Allocate some memory
    void* ptr1 = Arena_Alloc(&arena, 128);
    void* ptr2 = Arena_Alloc(&arena, 256);
    void* ptr3 = Arena_Alloc(&arena, 512);
    
    if (!ptr1 || !ptr2 || !ptr3) {
        printf("FAIL - Arena_Alloc returned NULL\n");
        Arena_Free(&arena);
        return false;
    }
    
    // Check alignment
    if ((uintptr_t)ptr1 % 32 != 0 || (uintptr_t)ptr2 % 32 != 0 || (uintptr_t)ptr3 % 32 != 0) {
        printf("FAIL - Memory not 32-byte aligned\n");
        Arena_Free(&arena);
        return false;
    }
    
    // Reset and allocate again
    Arena_Reset(&arena);
    void* ptr4 = Arena_Alloc(&arena, 1024);
    
    if (ptr4 != (void*)arena.base) {
        printf("FAIL - Arena_Reset didn't reset to base\n");
        Arena_Free(&arena);
        return false;
    }
    
    Arena_Free(&arena);
    printf("PASS ✓\n");
    return true;
}

// ============================================================================
// Test 2: Tensor Initialization
// ============================================================================
bool test_tensor_init() {
    printf("[Test 2] Tensor Initialization... ");
    
    float data[64];
    for (int i = 0; i < 64; i++) data[i] = (float)i;
    
    Tensor tensor;
    int result = Tensor_Init(&tensor, data, 8, 8);
    if (result != 0) {
        printf("FAIL - Tensor_Init returned %d\n", result);
        return false;
    }
    
    // Check dimensions
    if (tensor.dims[0] != 8 || tensor.dims[1] != 8) {
        printf("FAIL - Dimensions incorrect: [%llu, %llu]\n", tensor.dims[0], tensor.dims[1]);
        return false;
    }
    
    // Check size
    if (tensor.elem_count != 64) {
        printf("FAIL - Size incorrect: %llu\n", tensor.elem_count);
        return false;
    }
    
    // Check strides (row-major)
    if (tensor.strides[0] != 8 || tensor.strides[1] != 1) {
        printf("FAIL - Strides incorrect: [%llu, %llu]\n", tensor.strides[0], tensor.strides[1]);
        return false;
    }
    
    // Check element access
    float* elem = Tensor_GetElement(&tensor, 2, 3);
    if (!elem || *elem != 19.0f) { // 2*8 + 3 = 19
        printf("FAIL - Element access incorrect: expected 19.0, got %.1f\n", elem ? *elem : -1.0f);
        return false;
    }
    
    printf("PASS ✓\n");
    return true;
}

// ============================================================================
// Test 3: Tensor Zero
// ============================================================================
bool test_tensor_zero() {
    printf("[Test 3] Tensor Zero... ");
    
    float* data = aligned_alloc_float(64);
    for (int i = 0; i < 64; i++) data[i] = (float)(i + 1);
    
    Tensor tensor;
    Tensor_Init(&tensor, data, 8, 8);
    Tensor_Zero(&tensor);
    
    // Check all zeros
    for (int i = 0; i < 64; i++) {
        if (data[i] != 0.0f) {
            printf("FAIL - Element %d not zero: %.1f\n", i, data[i]);
            aligned_free_float(data);
            return false;
        }
    }
    
    aligned_free_float(data);
    printf("PASS ✓\n");
    return true;
}

// ============================================================================
// Test 4: Tensor 3D
// ============================================================================
bool test_tensor_3d() {
    printf("[Test 4] Tensor 3D... ");
    
    float data[128];
    for (int i = 0; i < 128; i++) data[i] = (float)i;
    
    Tensor tensor;
    int result = Tensor_Init(&tensor, data, 4, 4, 8);
    if (result != 0) {
        printf("FAIL - Tensor_Init returned %d\n", result);
        return false;
    }
    
    // Check dimensions
    if (tensor.dims[0] != 4 || tensor.dims[1] != 4 || tensor.dims[2] != 8) {
        printf("FAIL - Dimensions incorrect: [%llu, %llu, %llu]\n", 
               tensor.dims[0], tensor.dims[1], tensor.dims[2]);
        return false;
    }
    
    // Check size
    if (tensor.elem_count != 128) {
        printf("FAIL - Size incorrect: %llu\n", tensor.elem_count);
        return false;
    }
    
    // Check strides (row-major 3D)
    // stride[2] = 1
    // stride[1] = dim2 = 8
    // stride[0] = dim1 * dim2 = 32
    if (tensor.strides[0] != 32 || tensor.strides[1] != 8 || tensor.strides[2] != 1) {
        printf("FAIL - Strides incorrect: [%llu, %llu, %llu]\n",
               tensor.strides[0], tensor.strides[1], tensor.strides[2]);
        return false;
    }
    
    // Check element access: tensor[1, 2, 3] = 1*32 + 2*8 + 3 = 51
    float* elem = Tensor_GetElement(&tensor, 1, 2, 3);
    if (!elem || *elem != 51.0f) {
        printf("FAIL - Element access incorrect: expected 51.0, got %.1f\n", elem ? *elem : -1.0f);
        return false;
    }
    
    printf("PASS ✓\n");
    return true;
}

// ============================================================================
// Test 5: Arena Tensor Allocation
// ============================================================================
bool test_arena_tensor_alloc() {
    printf("[Test 5] Arena Tensor Allocation... ");
    
    Arena arena;
    int result = Arena_Init(&arena, 1024 * 1024);
    if (result != 0) {
        printf("FAIL - Arena_Init returned %d\n", result);
        return false;
    }
    
    Tensor tensor;
    result = Tensor_Alloc(&tensor, &arena, 16, 16);
    if (result != 0) {
        printf("FAIL - Tensor_Alloc returned %d\n", result);
        Arena_Free(&arena);
        return false;
    }
    
    // Check dimensions
    if (tensor.dims[0] != 16 || tensor.dims[1] != 16) {
        printf("FAIL - Dimensions incorrect\n");
        Arena_Free(&arena);
        return false;
    }
    
    // Check size
    if (tensor.elem_count != 256) {
        printf("FAIL - Size incorrect: %llu\n", tensor.elem_count);
        Arena_Free(&arena);
        return false;
    }
    
    // Check alignment
    if ((uintptr_t)tensor.data % 32 != 0) {
        printf("FAIL - Data not 32-byte aligned\n");
        Arena_Free(&arena);
        return false;
    }
    
    // Check ownership flag
    if (!(tensor.flags & 0x01)) { // TENSOR_FLAG_OWNED
        printf("FAIL - Ownership flag not set\n");
        Arena_Free(&arena);
        return false;
    }
    
    // Zero the tensor
    Tensor_Zero(&tensor);
    
    // Verify zeros
    float* data = (float*)tensor.data;
    for (int i = 0; i < 256; i++) {
        if (data[i] != 0.0f) {
            printf("FAIL - Element %d not zero after Tensor_Zero\n", i);
            Arena_Free(&arena);
            return false;
        }
    }
    
    Arena_Free(&arena);
    printf("PASS ✓\n");
    return true;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("============================================================================\n");
    printf("Tensor Abstraction Test Suite (Standalone)\n");
    printf("============================================================================\n\n");
    
    int passed = 0;
    int total = 5;
    
    if (test_arena_allocator()) passed++;
    if (test_tensor_init()) passed++;
    if (test_tensor_zero()) passed++;
    if (test_tensor_3d()) passed++;
    if (test_arena_tensor_alloc()) passed++;
    
    printf("\n============================================================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("============================================================================\n");
    
    return (passed == total) ? 0 : 1;
}
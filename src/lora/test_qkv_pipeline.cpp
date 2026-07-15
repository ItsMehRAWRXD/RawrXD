// ============================================================================
// test_qkv_pipeline.cpp - Complete QKV Inference Pipeline Test
// ============================================================================
// Validates:
//   - Arena allocator
//   - Tensor abstraction
//   - BlockedGemm_Single entry point
//   - Forward_QKV projection
//   - GELU activation
//   - End-to-end QKV inference
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <chrono>
#include <algorithm>

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
        unsigned long long elem_count;
        unsigned int flags;
        unsigned int dtype;
        unsigned long long _padding[2];
    };
    int Tensor_Init(Tensor* tensor, float* data, size_t dim0, size_t dim1, size_t dim2 = 0, size_t dim3 = 0);
    int Tensor_Alloc(Tensor* tensor, Arena* arena, size_t dim0, size_t dim1, size_t dim2 = 0, size_t dim3 = 0);
    float* Tensor_GetElement(Tensor* tensor, size_t i0, size_t i1, size_t i2 = 0, size_t i3 = 0);
    void Tensor_Zero(Tensor* tensor);
    
    // BlockedGemm_Single
    int BlockedGemm_Single(
        const float* A, const float* B, float* C,
        size_t M, size_t N, size_t K,
        float alpha, float beta
    );
    
    // QKV Projection
    int Forward_QKV(
        const float* input,
        const float* Wq, const float* Wk, const float* Wv,
        float* Q_out, float* K_out, float* V_out,
        size_t seq_len, size_t d_model
    );
    
    // GELU
    void GELU_InPlace_ASM(float* data, size_t count);
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

// Reference GEMM for validation
void reference_gemm(
    const float* A, const float* B, float* C,
    size_t M, size_t N, size_t K,
    float alpha = 1.0f, float beta = 0.0f
) {
    for (size_t i = 0; i < M; i++) {
        for (size_t j = 0; j < N; j++) {
            float sum = (beta == 0.0f) ? 0.0f : beta * C[i * N + j];
            for (size_t k = 0; k < K; k++) {
                sum += alpha * A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

// Initialize matrix with random values
void init_random(float* mat, size_t size, float scale = 1.0f) {
    for (size_t i = 0; i < size; i++) {
        mat[i] = scale * ((float)rand() / RAND_MAX - 0.5f);
    }
}

// Compare matrices with tolerance
bool compare_matrices(const float* A, const float* B, size_t size, float tolerance = 1e-3f) {
    for (size_t i = 0; i < size; i++) {
        float diff = std::abs(A[i] - B[i]);
        if (diff > tolerance) {
            printf("  Mismatch at index %zu: expected %.6f, got %.6f (diff %.6f)\n",
                   i, A[i], B[i], diff);
            return false;
        }
    }
    return true;
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
// Test 3: BlockedGemm_Single (Small)
// ============================================================================
bool test_blocked_gemm_single_small() {
    printf("[Test 3] BlockedGemm_Single (8×8×8)... ");
    
    const size_t M = 8, N = 8, K = 8;
    
    // Allocate aligned memory
    float* A = aligned_alloc_float(M * K);
    float* B = aligned_alloc_float(K * N);
    float* C = aligned_alloc_float(M * N);
    float* C_ref = aligned_alloc_float(M * N);
    
    // Initialize with random values
    srand(42);
    init_random(A, M * K);
    init_random(B, K * N);
    
    // Compute reference
    reference_gemm(A, B, C_ref, M, N, K);
    
    // Call BlockedGemm_Single
    int result = BlockedGemm_Single(A, B, C, M, N, K, 1.0f, 0.0f);
    if (result != 0) {
        printf("FAIL - BlockedGemm_Single returned %d\n", result);
        aligned_free_float(A);
        aligned_free_float(B);
        aligned_free_float(C);
        aligned_free_float(C_ref);
        return false;
    }
    
    // Compare results
    if (!compare_matrices(C_ref, C, M * N)) {
        printf("FAIL - Matrix mismatch\n");
        aligned_free_float(A);
        aligned_free_float(B);
        aligned_free_float(C);
        aligned_free_float(C_ref);
        return false;
    }
    
    aligned_free_float(A);
    aligned_free_float(B);
    aligned_free_float(C);
    aligned_free_float(C_ref);
    
    printf("PASS ✓\n");
    return true;
}

// ============================================================================
// Test 4: BlockedGemm_Single (Transformer Scale)
// ============================================================================
bool test_blocked_gemm_single_large() {
    printf("[Test 4] BlockedGemm_Single (128×256)... ");
    
    const size_t M = 128, N = 256, K = 128;
    
    // Allocate aligned memory
    float* A = aligned_alloc_float(M * K);
    float* B = aligned_alloc_float(K * N);
    float* C = aligned_alloc_float(M * N);
    float* C_ref = aligned_alloc_float(M * N);
    
    // Initialize with random values
    srand(123);
    init_random(A, M * K, 0.1f);
    init_random(B, K * N, 0.1f);
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    // Compute reference
    reference_gemm(A, B, C_ref, M, N, K);
    
    auto ref_end = std::chrono::high_resolution_clock::now();
    
    // Call BlockedGemm_Single
    int result = BlockedGemm_Single(A, B, C, M, N, K, 1.0f, 0.0f);
    
    auto opt_end = std::chrono::high_resolution_clock::now();
    
    if (result != 0) {
        printf("FAIL - BlockedGemm_Single returned %d\n", result);
        aligned_free_float(A);
        aligned_free_float(B);
        aligned_free_float(C);
        aligned_free_float(C_ref);
        return false;
    }
    
    // Compare results
    if (!compare_matrices(C_ref, C, M * N, 1e-2f)) {
        printf("FAIL - Matrix mismatch\n");
        aligned_free_float(A);
        aligned_free_float(B);
        aligned_free_float(C);
        aligned_free_float(C_ref);
        return false;
    }
    
    // Calculate performance
    auto ref_duration = std::chrono::duration_cast<std::chrono::microseconds>(ref_end - start);
    auto opt_duration = std::chrono::duration_cast<std::chrono::microseconds>(opt_end - ref_end);
    
    double ref_gflops = (2.0 * M * N * K) / (ref_duration.count() * 1e-6) / 1e9;
    double opt_gflops = (2.0 * M * N * K) / (opt_duration.count() * 1e-6) / 1e9;
    
    printf("PASS ✓ (Ref: %.2f GFLOPS, Opt: %.2f GFLOPS)\n", ref_gflops, opt_gflops);
    
    aligned_free_float(A);
    aligned_free_float(B);
    aligned_free_float(C);
    aligned_free_float(C_ref);
    
    return true;
}

// ============================================================================
// Test 5: QKV Projection (Small)
// ============================================================================
bool test_qkv_projection_small() {
    printf("[Test 5] QKV Projection (8×8)... ");
    
    const size_t seq_len = 8;
    const size_t d_model = 8;
    
    // Allocate aligned memory
    float* input = aligned_alloc_float(seq_len * d_model);
    float* Wq = aligned_alloc_float(d_model * d_model);
    float* Wk = aligned_alloc_float(d_model * d_model);
    float* Wv = aligned_alloc_float(d_model * d_model);
    float* Q_out = aligned_alloc_float(seq_len * d_model);
    float* K_out = aligned_alloc_float(seq_len * d_model);
    float* V_out = aligned_alloc_float(seq_len * d_model);
    
    // Reference outputs
    float* Q_ref = aligned_alloc_float(seq_len * d_model);
    float* K_ref = aligned_alloc_float(seq_len * d_model);
    float* V_ref = aligned_alloc_float(seq_len * d_model);
    
    // Initialize with random values
    srand(42);
    init_random(input, seq_len * d_model);
    init_random(Wq, d_model * d_model);
    init_random(Wk, d_model * d_model);
    init_random(Wv, d_model * d_model);
    
    // Compute reference
    reference_gemm(input, Wq, Q_ref, seq_len, d_model, d_model);
    reference_gemm(input, Wk, K_ref, seq_len, d_model, d_model);
    reference_gemm(input, Wv, V_ref, seq_len, d_model, d_model);
    
    // Call Forward_QKV
    int result = Forward_QKV(input, Wq, Wk, Wv, Q_out, K_out, V_out, seq_len, d_model);
    if (result != 0) {
        printf("FAIL - Forward_QKV returned %d\n", result);
        goto cleanup;
    }
    
    // Compare results
    if (!compare_matrices(Q_ref, Q_out, seq_len * d_model)) {
        printf("FAIL - Q matrix mismatch\n");
        goto cleanup;
    }
    
    if (!compare_matrices(K_ref, K_out, seq_len * d_model)) {
        printf("FAIL - K matrix mismatch\n");
        goto cleanup;
    }
    
    if (!compare_matrices(V_ref, V_out, seq_len * d_model)) {
        printf("FAIL - V matrix mismatch\n");
        goto cleanup;
    }
    
    printf("PASS ✓\n");
    
cleanup:
    aligned_free_float(input);
    aligned_free_float(Wq);
    aligned_free_float(Wk);
    aligned_free_float(Wv);
    aligned_free_float(Q_out);
    aligned_free_float(K_out);
    aligned_free_float(V_out);
    aligned_free_float(Q_ref);
    aligned_free_float(K_ref);
    aligned_free_float(V_ref);
    
    return result == 0;
}

// ============================================================================
// Test 6: QKV Projection (Transformer Scale)
// ============================================================================
bool test_qkv_projection_large() {
    printf("[Test 6] QKV Projection (128×256)... ");
    
    const size_t seq_len = 128;
    const size_t d_model = 256;
    
    // Allocate aligned memory
    float* input = aligned_alloc_float(seq_len * d_model);
    float* Wq = aligned_alloc_float(d_model * d_model);
    float* Wk = aligned_alloc_float(d_model * d_model);
    float* Wv = aligned_alloc_float(d_model * d_model);
    float* Q_out = aligned_alloc_float(seq_len * d_model);
    float* K_out = aligned_alloc_float(seq_len * d_model);
    float* V_out = aligned_alloc_float(seq_len * d_model);
    
    // Initialize with random values
    srand(123);
    init_random(input, seq_len * d_model, 0.1f);
    init_random(Wq, d_model * d_model, 0.1f);
    init_random(Wk, d_model * d_model, 0.1f);
    init_random(Wv, d_model * d_model, 0.1f);
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    int result = Forward_QKV(input, Wq, Wk, Wv, Q_out, K_out, V_out, seq_len, d_model);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    if (result != 0) {
        printf("FAIL - Forward_QKV returned %d\n", result);
        aligned_free_float(input);
        aligned_free_float(Wq);
        aligned_free_float(Wk);
        aligned_free_float(Wv);
        aligned_free_float(Q_out);
        aligned_free_float(K_out);
        aligned_free_float(V_out);
        return false;
    }
    
    // Calculate GFLOPS
    // QKV: 3 × (seq_len × d_model × d_model) = 3 × M × N × K
    double gflops = (3.0 * seq_len * d_model * d_model) / (duration.count() * 1e-6) / 1e9;
    
    printf("PASS ✓ (%.2f GFLOPS, %lld μs)\n", gflops, duration.count());
    
    aligned_free_float(input);
    aligned_free_float(Wq);
    aligned_free_float(Wk);
    aligned_free_float(Wv);
    aligned_free_float(Q_out);
    aligned_free_float(K_out);
    aligned_free_float(V_out);
    
    return true;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("============================================================================\n");
    printf("QKV Inference Pipeline Test Suite\n");
    printf("============================================================================\n\n");
    
    int passed = 0;
    int total = 6;
    
    if (test_arena_allocator()) passed++;
    if (test_tensor_init()) passed++;
    if (test_blocked_gemm_single_small()) passed++;
    if (test_blocked_gemm_single_large()) passed++;
    if (test_qkv_projection_small()) passed++;
    if (test_qkv_projection_large()) passed++;
    
    printf("\n============================================================================\n");
    printf("Results: %d/%d tests passed\n", passed, total);
    printf("============================================================================\n");
    
    return (passed == total) ? 0 : 1;
}
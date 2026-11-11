// gpu_validation_test.cpp - GPU vs CPU Numerical Validation
// Phase 8.3 - Prove GPU backend works with numerical correctness

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <windows.h>

// Include GPU backend
#include "gpu_backend.h"
#include "vulkan/vulkan_backend.h"

// Include CPU reference
extern "C" {
    void cpu_rmsnorm(float* output, const float* input, const float* weight, 
                     float epsilon, uint32_t n);
    void cpu_rope(float* query, float* key, uint32_t n_heads, uint32_t seq_len, 
                  uint32_t head_dim, uint32_t position, float theta);
    void cpu_softmax(float* output, const float* input, uint32_t n);
    void cpu_matmul(float* output, const float* a, const float* b, 
                    uint32_t m, uint32_t n, uint32_t k);
    void cpu_swiglu(float* output, const float* gate, const float* up, uint32_t n);
    void cpu_attention(float* output, const float* query, const float* key, 
                       const float* value, uint32_t n_heads, uint32_t seq_len, uint32_t head_dim);
}

// Error metrics
struct ErrorMetrics {
    float max_error;
    float mean_error;
    float max_relative;
    uint32_t mismatches;
    uint32_t total;
};

void calculate_error(ErrorMetrics* metrics, const float* gpu, const float* cpu, uint32_t n) {
    metrics->max_error = 0.0f;
    metrics->mean_error = 0.0f;
    metrics->max_relative = 0.0f;
    metrics->mismatches = 0;
    metrics->total = n;
    
    double sum_error = 0.0;
    
    for (uint32_t i = 0; i < n; i++) {
        float diff = fabsf(gpu[i] - cpu[i]);
        float rel = (fabsf(cpu[i]) > 1e-6f) ? diff / fabsf(cpu[i]) : diff;
        
        sum_error += diff;
        if (diff > metrics->max_error) metrics->max_error = diff;
        if (rel > metrics->max_relative) metrics->max_relative = rel;
        if (diff > 1e-4f) metrics->mismatches++;
    }
    
    metrics->mean_error = (float)(sum_error / n);
}

void print_error(const char* name, const ErrorMetrics* m) {
    printf("  %-15s | Max: %10.6f | Mean: %10.6f | Rel: %8.4f%% | Mismatch: %u/%u\n",
           name, m->max_error, m->mean_error, m->max_relative * 100.0f, 
           m->mismatches, m->total);
}

// Helper to create tensor
GPUTensor make_tensor(void* data, size_t size, GPUDataType dtype, 
                      uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3, uint32_t ndims) {
    GPUTensor t;
    t.device_data = data;
    t.staging_data = NULL;
    t.size = size;
    t.dtype = dtype;
    t.dims[0] = d0; t.dims[1] = d1; t.dims[2] = d2; t.dims[3] = d3;
    t.n_dims = ndims;
    t.is_on_gpu = 0;
    return t;
}

// Test RMSNorm
int test_rmsnorm(GPUBackend* backend) {
    printf("\n[TEST] RMSNorm\n");
    printf("================================================\n");
    
    const uint32_t n = 4096;
    float* input = (float*)malloc(n * sizeof(float));
    float* weight = (float*)malloc(n * sizeof(float));
    float* cpu_output = (float*)malloc(n * sizeof(float));
    float* gpu_output = (float*)malloc(n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < n; i++) {
        input[i] = (float)(i % 100) / 100.0f;
        weight[i] = 1.0f;
    }
    
    // CPU reference
    cpu_rmsnorm(cpu_output, input, weight, 1e-5f, n);
    
    // GPU execution - allocate and upload
    GPUTensor gpu_input = make_tensor(NULL, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    GPUTensor gpu_weight = make_tensor(NULL, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    GPUTensor gpu_out = make_tensor(NULL, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    
    Vulkan_Upload(backend, &gpu_input, input);
    Vulkan_Upload(backend, &gpu_weight, weight);
    Vulkan_Upload(backend, &gpu_out, gpu_output);  // Allocate output buffer
    
    GPUStatus status = Vulkan_RMSNorm(backend, &gpu_out, &gpu_input, &gpu_weight, 1e-5f, n);
    if (status != GPU_SUCCESS) {
        printf("  ERROR: GPU kernel failed with status %d\n", status);
        free(input); free(weight); free(cpu_output); free(gpu_output);
        return 0;
    }
    
    Vulkan_Synchronize(backend);
    Vulkan_Download(backend, &gpu_out, gpu_output);
    
    // Compare
    ErrorMetrics metrics;
    calculate_error(&metrics, gpu_output, cpu_output, n);
    print_error("RMSNorm", &metrics);
    
    int pass = (metrics.max_relative < 0.01f) ? 1 : 0;
    printf("  %s\n", pass ? "✓ PASS" : "✗ FAIL");
    
    free(input); free(weight); free(cpu_output); free(gpu_output);
    return pass;
}

// Test RoPE
int test_rope(GPUBackend* backend) {
    printf("\n[TEST] RoPE\n");
    printf("================================================\n");
    
    const uint32_t n_heads = 8;
    const uint32_t seq_len = 128;
    const uint32_t head_dim = 64;
    const uint32_t n = n_heads * seq_len * head_dim;
    
    float* query = (float*)malloc(n * sizeof(float));
    float* key = (float*)malloc(n * sizeof(float));
    float* cpu_query = (float*)malloc(n * sizeof(float));
    float* cpu_key = (float*)malloc(n * sizeof(float));
    float* gpu_query = (float*)malloc(n * sizeof(float));
    float* gpu_key = (float*)malloc(n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < n; i++) {
        query[i] = cpu_query[i] = gpu_query[i] = (float)(rand() % 100) / 50.0f - 1.0f;
        key[i] = cpu_key[i] = gpu_key[i] = (float)(rand() % 100) / 50.0f - 1.0f;
    }
    
    // CPU reference
    cpu_rope(cpu_query, cpu_key, n_heads, seq_len, head_dim, 0, 10000.0f);
    
    // GPU execution
    GPUTensor gpu_q = make_tensor(gpu_query, n * sizeof(float), GPU_FLOAT32, n_heads, seq_len, head_dim, 1, 3);
    GPUTensor gpu_k = make_tensor(gpu_key, n * sizeof(float), GPU_FLOAT32, n_heads, seq_len, head_dim, 1, 3);
    
    GPUStatus status = Vulkan_RoPE(backend, &gpu_q, &gpu_k, n_heads, head_dim, 0, 10000.0f);
    if (status != GPU_SUCCESS) {
        printf("  ERROR: GPU kernel failed with status %d\n", status);
        free(query); free(key); free(cpu_query); free(cpu_key); free(gpu_query); free(gpu_key);
        return 0;
    }
    
    Vulkan_Synchronize(backend);
    Vulkan_Download(backend, &gpu_q, gpu_query);
    Vulkan_Download(backend, &gpu_k, gpu_key);
    
    // Compare
    ErrorMetrics q_metrics, k_metrics;
    calculate_error(&q_metrics, gpu_query, cpu_query, n);
    calculate_error(&k_metrics, gpu_key, cpu_key, n);
    print_error("RoPE Query", &q_metrics);
    print_error("RoPE Key", &k_metrics);
    
    int pass = (q_metrics.max_relative < 0.01f && k_metrics.max_relative < 0.01f) ? 1 : 0;
    printf("  %s\n", pass ? "✓ PASS" : "✗ FAIL");
    
    free(query); free(key); free(cpu_query); free(cpu_key); free(gpu_query); free(gpu_key);
    return pass;
}

// Test Softmax
int test_softmax(GPUBackend* backend) {
    printf("\n[TEST] Softmax\n");
    printf("================================================\n");
    
    const uint32_t n = 4096;
    float* input = (float*)malloc(n * sizeof(float));
    float* cpu_output = (float*)malloc(n * sizeof(float));
    float* gpu_output = (float*)malloc(n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < n; i++) {
        input[i] = (float)(rand() % 100) / 10.0f - 5.0f;
    }
    
    // CPU reference
    cpu_softmax(cpu_output, input, n);
    
    // GPU execution
    GPUTensor gpu_input = make_tensor(input, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    GPUTensor gpu_out = make_tensor(gpu_output, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    
    GPUStatus status = Vulkan_Softmax(backend, &gpu_out, &gpu_input, n);
    if (status != GPU_SUCCESS) {
        printf("  ERROR: GPU kernel failed with status %d\n", status);
        free(input); free(cpu_output); free(gpu_output);
        return 0;
    }
    
    Vulkan_Synchronize(backend);
    Vulkan_Download(backend, &gpu_out, gpu_output);
    
    // Compare
    ErrorMetrics metrics;
    calculate_error(&metrics, gpu_output, cpu_output, n);
    print_error("Softmax", &metrics);
    
    int pass = (metrics.max_relative < 0.01f) ? 1 : 0;
    printf("  %s\n", pass ? "✓ PASS" : "✗ FAIL");
    
    free(input); free(cpu_output); free(gpu_output);
    return pass;
}

// Test MatMul
int test_matmul(GPUBackend* backend) {
    printf("\n[TEST] MatMul\n");
    printf("================================================\n");
    
    const uint32_t m = 128;
    const uint32_t n = 128;
    const uint32_t k = 128;
    
    float* a = (float*)malloc(m * k * sizeof(float));
    float* b = (float*)malloc(k * n * sizeof(float));
    float* cpu_output = (float*)malloc(m * n * sizeof(float));
    float* gpu_output = (float*)malloc(m * n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < m * k; i++) a[i] = (float)(rand() % 100) / 100.0f;
    for (uint32_t i = 0; i < k * n; i++) b[i] = (float)(rand() % 100) / 100.0f;
    
    // CPU reference
    cpu_matmul(cpu_output, a, b, m, n, k);
    
    // GPU execution
    GPUTensor gpu_a = make_tensor(a, m * k * sizeof(float), GPU_FLOAT32, m, k, 1, 1, 2);
    GPUTensor gpu_b = make_tensor(b, k * n * sizeof(float), GPU_FLOAT32, k, n, 1, 1, 2);
    GPUTensor gpu_out = make_tensor(gpu_output, m * n * sizeof(float), GPU_FLOAT32, m, n, 1, 1, 2);
    
    GPUStatus status = Vulkan_MatMul(backend, &gpu_out, &gpu_a, &gpu_b, m, n, k, GPU_FLOAT32);
    if (status != GPU_SUCCESS) {
        printf("  ERROR: GPU kernel failed with status %d\n", status);
        free(a); free(b); free(cpu_output); free(gpu_output);
        return 0;
    }
    
    Vulkan_Synchronize(backend);
    Vulkan_Download(backend, &gpu_out, gpu_output);
    
    // Compare
    ErrorMetrics metrics;
    calculate_error(&metrics, gpu_output, cpu_output, m * n);
    print_error("MatMul", &metrics);
    
    int pass = (metrics.max_relative < 0.01f) ? 1 : 0;
    printf("  %s\n", pass ? "✓ PASS" : "✗ FAIL");
    
    free(a); free(b); free(cpu_output); free(gpu_output);
    return pass;
}

// Test SwiGLU
int test_swiglu(GPUBackend* backend) {
    printf("\n[TEST] SwiGLU\n");
    printf("================================================\n");
    
    const uint32_t n = 4096;
    float* gate = (float*)malloc(n * sizeof(float));
    float* up = (float*)malloc(n * sizeof(float));
    float* cpu_output = (float*)malloc(n * sizeof(float));
    float* gpu_output = (float*)malloc(n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < n; i++) {
        gate[i] = (float)(rand() % 100) / 50.0f - 1.0f;
        up[i] = (float)(rand() % 100) / 50.0f - 1.0f;
    }
    
    // CPU reference
    cpu_swiglu(cpu_output, gate, up, n);
    
    // GPU execution
    GPUTensor gpu_gate = make_tensor(gate, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    GPUTensor gpu_up = make_tensor(up, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    GPUTensor gpu_out = make_tensor(gpu_output, n * sizeof(float), GPU_FLOAT32, n, 1, 1, 1, 1);
    
    GPUStatus status = Vulkan_SwiGLU(backend, &gpu_out, &gpu_gate, &gpu_up, n);
    if (status != GPU_SUCCESS) {
        printf("  ERROR: GPU kernel failed with status %d\n", status);
        free(gate); free(up); free(cpu_output); free(gpu_output);
        return 0;
    }
    
    Vulkan_Synchronize(backend);
    Vulkan_Download(backend, &gpu_out, gpu_output);
    
    // Compare
    ErrorMetrics metrics;
    calculate_error(&metrics, gpu_output, cpu_output, n);
    print_error("SwiGLU", &metrics);
    
    int pass = (metrics.max_relative < 0.01f) ? 1 : 0;
    printf("  %s\n", pass ? "✓ PASS" : "✗ FAIL");
    
    free(gate); free(up); free(cpu_output); free(gpu_output);
    return pass;
}

// Test Attention
int test_attention(GPUBackend* backend) {
    printf("\n[TEST] Attention\n");
    printf("================================================\n");
    
    const uint32_t n_heads = 4;
    const uint32_t seq_len = 32;
    const uint32_t head_dim = 64;
    const uint32_t n = n_heads * seq_len * head_dim;
    
    float* query = (float*)malloc(n * sizeof(float));
    float* key = (float*)malloc(n * sizeof(float));
    float* value = (float*)malloc(n * sizeof(float));
    float* cpu_output = (float*)malloc(n * sizeof(float));
    float* gpu_output = (float*)malloc(n * sizeof(float));
    
    // Initialize
    for (uint32_t i = 0; i < n; i++) {
        query[i] = (float)(rand() % 100) / 100.0f;
        key[i] = (float)(rand() % 100) / 100.0f;
        value[i] = (float)(rand() % 100) / 100.0f;
    }
    
    // CPU reference
    cpu_attention(cpu_output, query, key, value, n_heads, seq_len, head_dim);
    
    // GPU execution
    GPUTensor gpu_q = make_tensor(query, n * sizeof(float), GPU_FLOAT32, n_heads, seq_len, head_dim, 1, 3);
    GPUTensor gpu_k = make_tensor(key, n * sizeof(float), GPU_FLOAT32, n_heads, seq_len, head_dim, 1, 3);
    GPUTensor gpu_v = make_tensor(value, n * sizeof(float), GPU_FLOAT32, n_heads, seq_len, head_dim, 1, 3);
    GPUTensor gpu_out = make_tensor(gpu_output, n * sizeof(float), GPU_FLOAT32, n_heads, seq_len, head_dim, 1, 3);
    
    GPUStatus status = Vulkan_Attention(backend, &gpu_out, &gpu_q, &gpu_k, &gpu_v, 
                                        n_heads, seq_len, head_dim);
    if (status != GPU_SUCCESS) {
        printf("  ERROR: GPU kernel failed with status %d\n", status);
        free(query); free(key); free(value); free(cpu_output); free(gpu_output);
        return 0;
    }
    
    Vulkan_Synchronize(backend);
    Vulkan_Download(backend, &gpu_out, gpu_output);
    
    // Compare
    ErrorMetrics metrics;
    calculate_error(&metrics, gpu_output, cpu_output, n);
    print_error("Attention", &metrics);
    
    int pass = (metrics.max_relative < 0.01f) ? 1 : 0;
    printf("  %s\n", pass ? "✓ PASS" : "✗ FAIL");
    
    free(query); free(key); free(value); free(cpu_output); free(gpu_output);
    return pass;
}

int main() {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║     GPU BACKEND NUMERICAL VALIDATION                         ║\n");
    printf("║     Phase 8.3 - GPU vs CPU Numerical Correctness             ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    srand((unsigned)time(NULL));
    
    // Enumerate devices
    printf("Enumerating GPU devices...\n");
    GPUDeviceInfo devices[8];
    int device_count = Vulkan_EnumerateDevices(devices, 8);
    
    if (device_count == 0) {
        printf("ERROR: No GPU devices found!\n");
        return 1;
    }
    
    printf("Found %d device(s):\n", device_count);
    for (int i = 0; i < device_count; i++) {
        printf("  [%d] %s (VRAM: %.2f GB)\n", i, devices[i].name, 
               devices[i].vram_size / (1024.0 * 1024.0 * 1024.0));
    }
    
    // Create backend
    printf("\nCreating Vulkan backend...\n");
    GPUBackend* backend = Vulkan_BackendCreate();
    if (!backend) {
        printf("ERROR: Failed to create Vulkan backend!\n");
        return 1;
    }
    printf("✓ Backend created successfully\n\n");
    
    // Run tests
    int passed = 0;
    int total = 6;
    
    passed += test_rmsnorm(backend);
    passed += test_rope(backend);
    passed += test_softmax(backend);
    passed += test_matmul(backend);
    passed += test_swiglu(backend);
    passed += test_attention(backend);
    
    // Cleanup
    Vulkan_BackendDestroy(backend);
    
    // Summary
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║           GPU VALIDATION SUMMARY                              ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║                                                              ║\n");
    printf("║  Tests Passed:    %-3d                                        ║\n", passed);
    printf("║  Tests Failed:    %-3d                                        ║\n", total - passed);
    printf("║  Total Tests:     %-3d                                        ║\n", total);
    printf("║                                                              ║\n");
    if (passed == total) {
        printf("║  ✓ ALL TESTS PASSED - GPU backend is numerically correct!     ║\n");
    } else {
        printf("║  ⚠ SOME TESTS FAILED - Review errors above                  ║\n");
    }
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    return (passed == total) ? 0 : 1;
}

/*
 * Phase 8.3 GPU Backend Test
 * Validates Vulkan, DirectML, and CUDA backends
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>
#include <cmath>

#include "src/gpu/gpu_backend.h"

// ============================================================================
// Test Results
// ============================================================================

struct TestResult {
    const char* name;
    bool passed;
    const char* details;
    double duration_ms;
};

std::vector<TestResult> g_results;

void RecordTest(const char* name, bool passed, const char* details, double duration_ms) {
    g_results.push_back({name, passed, details, duration_ms});
    
    const char* status = passed ? "✅ PASS" : "❌ FAIL";
    printf("[%s] %s: %s (%.2f ms)\n", status, name, details, duration_ms);
}

// ============================================================================
// G12: Vulkan Compute Backend
// ============================================================================

bool Test_VulkanBackend() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== G12: Vulkan Compute Backend ===\n");
    
    // Enumerate devices
    GPUDeviceInfo devices[8];
    int num_devices = GPU_EnumerateDevices(GPU_BACKEND_VULKAN, devices, 8);
    
    printf("  Found %d Vulkan-capable device(s)\n", num_devices);
    
    for (int i = 0; i < num_devices; i++) {
        printf("    [%d] %s\n", i, devices[i].name);
        printf("        VRAM: %.2f GB\n", devices[i].vram_size / (1024.0 * 1024.0 * 1024.0));
        printf("        FP16: %s\n", devices[i].supports_fp16 ? "YES" : "NO");
    }
    
    if (num_devices == 0) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordTest("G12-Vulkan", false, "No Vulkan devices found", duration);
        return false;
    }
    
    // Create backend
    GPUBackend* backend = GPU_BackendCreate(GPU_BACKEND_VULKAN);
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!backend) {
        RecordTest("G12-Vulkan", false, "Failed to create backend", duration);
        return false;
    }
    
    // Get device info
    GPUDeviceInfo info;
    memcpy(&info, &backend->device_info, sizeof(info));
    
    printf("  Backend created: %s\n", GPU_GetBackendName(GPU_BACKEND_VULKAN));
    printf("  Device: %s\n", info.name);
    
    // Test tensor creation
    uint32_t dims[] = {2048};
    GPUTensor* tensor = GPU_TensorCreate(backend, dims, 1, GPU_FLOAT32);
    
    if (!tensor) {
        GPU_BackendDestroy(backend);
        RecordTest("G12-Vulkan", false, "Failed to create tensor", duration);
        return false;
    }
    
    printf("  Tensor created: %zu bytes\n", tensor->size);
    
    // Upload test data
    std::vector<float> test_data(2048);
    for (int i = 0; i < 2048; i++) {
        test_data[i] = (float)i / 2048.0f;
    }
    
    GPUStatus status = GPU_TensorUpload(backend, tensor, test_data.data());
    if (status != GPU_SUCCESS) {
        GPU_TensorDestroy(backend, tensor);
        GPU_BackendDestroy(backend);
        RecordTest("G12-Vulkan", false, "Failed to upload tensor", duration);
        return false;
    }
    
    printf("  Tensor uploaded successfully\n");
    
    // Download and verify
    std::vector<float> result_data(2048);
    status = GPU_TensorDownload(backend, tensor, result_data.data());
    
    bool data_correct = true;
    for (int i = 0; i < 2048 && i < 10; i++) {
        if (fabs(result_data[i] - test_data[i]) > 0.0001f) {
            data_correct = false;
            break;
        }
    }
    
    printf("  Download %s\n", data_correct ? "verified" : "MISMATCH");
    
    // Cleanup
    GPU_TensorDestroy(backend, tensor);
    GPU_BackendDestroy(backend);
    
    bool passed = data_correct;
    
    char details[256];
    snprintf(details, sizeof(details), "%s, %zu MB VRAM", 
             info.name, info.vram_size / (1024 * 1024));
    
    RecordTest("G12-Vulkan", passed, details, duration);
    
    return passed;
}

// ============================================================================
// G13: DirectML Backend
// ============================================================================

bool Test_DirectMLBackend() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== G13: DirectML Backend ===\n");
    
    // Check if DirectML is available
    int num_devices = GPU_EnumerateDevices(GPU_BACKEND_DIRECTML, nullptr, 0);
    
    printf("  DirectML devices: %d\n", num_devices);
    
    if (num_devices == 0) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordTest("G13-DirectML", false, "DirectML not available", duration);
        return false;
    }
    
    // Create backend
    GPUBackend* backend = GPU_BackendCreate(GPU_BACKEND_DIRECTML);
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!backend) {
        RecordTest("G13-DirectML", false, "Failed to create backend", duration);
        return false;
    }
    
    printf("  Backend created: %s\n", GPU_GetBackendName(GPU_BACKEND_DIRECTML));
    
    GPU_BackendDestroy(backend);
    
    RecordTest("G13-DirectML", true, "DirectML backend initialized", duration);
    
    return true;
}

// ============================================================================
// G14: CUDA Backend (Optional)
// ============================================================================

bool Test_CUDABackend() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== G14: CUDA Backend ===\n");
    
    // Check if CUDA is available
    int num_devices = GPU_EnumerateDevices(GPU_BACKEND_CUDA, nullptr, 0);
    
    printf("  CUDA devices: %d\n", num_devices);
    
    if (num_devices == 0) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordTest("G14-CUDA", false, "CUDA not available (optional)", duration);
        return false;  // CUDA is optional
    }
    
    // Create backend
    GPUBackend* backend = GPU_BackendCreate(GPU_BACKEND_CUDA);
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!backend) {
        RecordTest("G14-CUDA", false, "Failed to create CUDA backend", duration);
        return false;
    }
    
    printf("  Backend created: %s\n", GPU_GetBackendName(GPU_BACKEND_CUDA));
    
    GPU_BackendDestroy(backend);
    
    RecordTest("G14-CUDA", true, "CUDA backend initialized", duration);
    
    return true;
}

// ============================================================================
// G15: Kernel Execution
// ============================================================================

bool Test_KernelExecution() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== G15: Kernel Execution ===\n");
    
    // Try to create Vulkan backend for testing
    GPUBackend* backend = GPU_BackendCreate(GPU_BACKEND_VULKAN);
    
    if (!backend) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordTest("G15-Kernels", false, "No GPU backend available", duration);
        return false;
    }
    
    // Test RMSNorm kernel
    uint32_t dims[] = {2048};
    GPUTensor* input = GPU_TensorCreate(backend, dims, 1, GPU_FLOAT32);
    GPUTensor* weight = GPU_TensorCreate(backend, dims, 1, GPU_FLOAT32);
    GPUTensor* output = GPU_TensorCreate(backend, dims, 1, GPU_FLOAT32);
    
    if (!input || !weight || !output) {
        GPU_BackendDestroy(backend);
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordTest("G15-Kernels", false, "Failed to create tensors", duration);
        return false;
    }
    
    // Upload test data
    std::vector<float> input_data(2048, 1.0f);
    std::vector<float> weight_data(2048, 1.0f);
    
    GPU_TensorUpload(backend, input, input_data.data());
    GPU_TensorUpload(backend, weight, weight_data.data());
    
    // Execute RMSNorm
    GPUStatus status = GPU_RMSNorm(backend, output, input, weight, 1e-5f, 2048);
    
    bool kernel_success = (status == GPU_SUCCESS);
    
    printf("  RMSNorm kernel: %s\n", kernel_success ? "SUCCESS" : "FAILED");
    
    // Cleanup
    GPU_TensorDestroy(backend, input);
    GPU_TensorDestroy(backend, weight);
    GPU_TensorDestroy(backend, output);
    GPU_BackendDestroy(backend);
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    RecordTest("G15-Kernels", kernel_success, "RMSNorm executed", duration);
    
    return kernel_success;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║           PHASE 8.3: GPU Backend Test                          ║\n");
    printf("║                                                              ║\n");
    printf("║  Testing: Vulkan, DirectML, CUDA backends                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    // Run all tests
    bool all_passed = true;
    
    all_passed &= Test_VulkanBackend();
    all_passed &= Test_DirectMLBackend();
    all_passed &= Test_CUDABackend();
    all_passed &= Test_KernelExecution();
    
    // Summary
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                      TEST SUMMARY                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    
    int passed = 0;
    for (const auto& r : g_results) {
        const char* status = r.passed ? "✅" : "❌";
        printf("║ %s %-15s: %-40s ║\n", status, r.name, r.details);
        if (r.passed) passed++;
    }
    
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Result: %d/%zu tests passed                                   ║\n", 
           passed, g_results.size());
    printf("║ Status: %s\n", all_passed ? "PHASE 8.3 ✅ PASS" : "PHASE 8.3 ❌ FAIL");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    return all_passed ? 0 : 1;
}

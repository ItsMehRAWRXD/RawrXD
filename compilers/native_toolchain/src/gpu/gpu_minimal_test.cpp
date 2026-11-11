// gpu_minimal_test.cpp - Minimal GPU validation test

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "gpu_backend.h"
#include "vulkan/vulkan_backend.h"

int main() {
    printf("GPU Minimal Test - Checking shader execution\n");
    printf("============================================\n\n");
    
    // Enumerate devices
    GPUDeviceInfo devices[8];
    int device_count = Vulkan_EnumerateDevices(devices, 8);
    printf("Found %d device(s)\n", device_count);
    for (int i = 0; i < device_count; i++) {
        printf("  [%d] %s\n", i, devices[i].name);
    }
    
    // Create backend
    printf("\nCreating backend...\n");
    GPUBackend* backend = Vulkan_BackendCreate();
    if (!backend) {
        printf("FAILED: Could not create backend\n");
        return 1;
    }
    printf("OK: Backend created on %s\n", backend->device_info.name);
    
    // Simple test: copy data through GPU
    const uint32_t n = 256;
    float* input = (float*)malloc(n * sizeof(float));
    float* output = (float*)malloc(n * sizeof(float));
    
    for (uint32_t i = 0; i < n; i++) {
        input[i] = (float)i;
        output[i] = 0.0f;
    }
    
    // Create tensor and upload
    GPUTensor tensor;
    tensor.device_data = NULL;
    tensor.staging_data = NULL;
    tensor.size = n * sizeof(float);
    tensor.dtype = GPU_FLOAT32;
    tensor.dims[0] = n;
    tensor.dims[1] = 1;
    tensor.dims[2] = 1;
    tensor.dims[3] = 1;
    tensor.n_dims = 1;
    tensor.is_on_gpu = 0;
    
    printf("\nUploading data...\n");
    GPUStatus status = Vulkan_Upload(backend, &tensor, input);
    if (status != GPU_SUCCESS) {
        printf("FAILED: Upload error %d\n", status);
        free(input); free(output);
        Vulkan_BackendDestroy(backend);
        return 1;
    }
    printf("OK: Data uploaded\n");
    
    // Download back
    printf("\nDownloading data...\n");
    status = Vulkan_Download(backend, &tensor, output);
    if (status != GPU_SUCCESS) {
        printf("FAILED: Download error %d\n", status);
        free(input); free(output);
        Vulkan_BackendDestroy(backend);
        return 1;
    }
    printf("OK: Data downloaded\n");
    
    // Verify
    printf("\nVerifying data integrity...\n");
    int errors = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (input[i] != output[i]) {
            if (errors < 5) {
                printf("  Mismatch at %u: expected %.1f, got %.1f\n", i, input[i], output[i]);
            }
            errors++;
        }
    }
    
    if (errors == 0) {
        printf("OK: All %u values match!\n", n);
    } else {
        printf("FAILED: %d mismatches\n", errors);
    }
    
    // Cleanup
    free(input);
    free(output);
    Vulkan_BackendDestroy(backend);
    
    printf("\n============================================\n");
    printf("Test %s\n", errors == 0 ? "PASSED" : "FAILED");
    
    return errors == 0 ? 0 : 1;
}
